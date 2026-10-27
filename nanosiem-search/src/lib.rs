// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Search Service library
//!
//! Standalone microservice for log search and query execution. Parses piped
//! queries, generates SQL, and executes searches against ClickHouse.
//!
//! Requirements: 1.3, 3.1, 3.2, 3.3

mod inputlookup_egress;
mod auth_cache;
#[cfg(feature = "enterprise")]
mod enterprise_shared_runtime;
pub mod denied_source_audit;
pub mod cache;
mod inflight;
pub mod config;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod openapi;
pub mod otel_lake;
#[cfg(test)]
pub(crate) mod test_support;

use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method,
};
use axum::http::{HeaderName, HeaderValue};
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::time::Instant;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::watch;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use nanosiem_core::audit::{AuditEmitter, AuditEvent};
use nanosiem_core::{
    ip_allowlist::IpAllowlistScope,
    search::{AdmissionConfig, AdmissionController, RedisJobStore, SharedLakeWorkerRegistry},
    settings::{SearchAdmissionSettings, SearchQueryLimitsSettings},
    DualPool, InputLookupConfig, InputLookupService, IpAllowlistService, LookupService,
    PrevalenceService, SearchService,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::{AgentConfigRegistry, AgentConfigRegistryConfig, AiPipeAgent};

pub use config::SearchConfig;
pub use error::SearchError;
pub use metrics::{record_search_query, SearchMetrics};
pub use middleware::{
    auth_middleware, ip_allowlist_middleware, request_id_middleware, sanitize_error_responses,
    AuthContext, AuthState, IpAllowlistState, RequestId, REQUEST_ID_HEADER,
};

/// Shared application state for the Search Service
#[derive(Clone)]
pub struct SearchState {
    /// DualPool for database connections
    pub dual_pool: DualPool,
    /// Search service for query execution
    pub search: Arc<SearchService>,
    /// Lookup service for enrichment
    pub lookup: Arc<LookupService>,
    /// Prevalence service for prevalence data
    pub prevalence: Arc<PrevalenceService>,
    /// Authentication state
    pub auth_state: AuthState,
    /// Fail-closed source-scope resolver (NAN-1797). Shares the Arc-backed
    /// cache with `auth_state.source_scope_resolver`; retained on the shared
    /// state so handlers can resolve the per-user deny set without reaching
    /// through `auth_state`. `None` when source-scoping is not wired
    /// (auth-disabled / minimal setups).
    pub source_scope_resolver: Option<Arc<nanosiem_core::auth::SourceScopeResolver>>,
    /// Audit emitter for logging sharing events
    pub audit_emitter: Arc<AuditEmitter>,
    audit_queue: nanosiem_core::background_queue::BackgroundQueue<AuditEvent>,
    /// Service start time for uptime tracking
    pub start_time: Instant,
    /// Leader election status (None = election disabled, always serve)
    leader_rx: Option<watch::Receiver<bool>>,
    /// Search result cache (Dragonfly/Redis — None if unavailable)
    pub result_cache: Option<cache::SearchResultCache>,
    /// Native OTLP span/metric Iceberg route. `None` retains the legacy
    /// ClickHouse observability path during migration.
    pub otel_lake: Option<otel_lake::OtelLakeClient>,
    /// NAN-2361 wave 6: tenant-pinned native OTLP clients built from the
    /// enterprise-shared worker registry's `otel_ingest` entries. Shared
    /// requests resolve their client here and never touch `otel_lake` or the
    /// ClickHouse fallback.
    hosted_otel_clients: Option<Arc<HashMap<uuid::Uuid, otel_lake::OtelLakeClient>>>,
    /// NAN-3243: lean-lake tenants' OTLP drains (`NANO_LEAN_OTEL_ROUTES_FILE`,
    /// live-reloaded). Consulted for a shared tenant with no registry
    /// `otel_ingest` entry.
    lean_otel_clients: Option<Arc<otel_lake::LeanOtelClients>>,
    /// Shared request ownership used to authorize cancellation on any search replica.
    query_owner_redis: Option<nanosiem_core::redis_transport::ReconnectingConnection>,
    /// Redis backing used to derive tenant-pinned job-store views. Shared mode
    /// refuses async/result routes when this is absent; it never falls back to
    /// a process-local store that another replica/worker cannot see.
    tenant_job_redis: Option<nanosiem_core::redis_transport::ReconnectingConnection>,
    /// Hosted durable-job producers per tenant. NAN-3531 N2a: with
    /// `NANO_SHARED_HOSTED_JOB_CONFIG_DIR` the set reloads live; cached tenant
    /// views re-check their client against it on every hit.
    #[cfg(feature = "enterprise")]
    hosted_producers: Option<Arc<nanosiem_core::search::hosted_producer_reload::HostedProducerReloader>>,
    /// NAN-2361: master key for durable job record signing. Every
    /// enterprise-shared tenant store derives its own HMAC key from it; the
    /// tenant's runner holds only the derived key. Required in shared mode.
    job_signing_master: Option<Arc<nanosiem_core::search::DurableJobSigningMasterKey>>,
    /// Exact tenant -> service view. Every view has a tenant-keyed job store
    /// and is admitted only if the underlying lake client is assigned to the
    /// same tenant UUID.
    shared_search_runtimes: SharedSearchRuntimeRegistry,
    /// NAN-3492: the dedicated singleton re-pinned to the worker-served schema
    /// once it has moved past the boot profile (see [`Self::dedicated_search`]).
    dedicated_schema_view: Arc<std::sync::Mutex<Option<Arc<SearchService>>>>,
    shared_worker_registry: Option<Arc<SharedLakeWorkerRegistry>>,
    /// NAN-2361 wave 5: the signed tenant RLS runtime that backs per-tenant
    /// lookup reads (`TenantLookupStore`) on every tenant service view. `None`
    /// outside enterprise-shared mode, or when the runtime env is absent — a
    /// tenant view then has no lookup service and `lookup` / `inputlookup` /
    /// `ioc in lookup()` fail closed exactly as before this wave.
    #[cfg(feature = "enterprise")]
    tenant_lookup_runtime: Option<Arc<nanosiem_enterprise::melod::TenantAiRlsRuntime>>,
    #[cfg(feature = "enterprise")]
    tenant_ai_factory: Option<Arc<nanosiem_enterprise::melod::TenantSystemAiPrincipalFactory>>,
    /// IP allowlist service for access control
    pub ip_allowlist_service: Arc<IpAllowlistService>,
}

type SharedSearchRuntimeKey = (uuid::Uuid, u64, u64, i64, u16, i64, u64);
/// `base` when `installed` is absent or is the profile `base` was built
/// with; otherwise the cached re-pinned copy for `installed`, built once per
/// installed profile (see [`SearchState::dedicated_search`]).
fn repin_to_installed_schema(
    base: &Arc<SearchService>,
    view: &std::sync::Mutex<Option<Arc<SearchService>>>,
    installed: Option<Arc<dyn nanosiem_core::schema::SchemaProfile>>,
) -> Arc<SearchService> {
    let Some(installed) = installed else {
        return Arc::clone(base);
    };
    if Arc::ptr_eq(base.active_profile(), &installed) {
        return Arc::clone(base);
    }
    let mut view = view.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(current) = view
        .as_ref()
        .filter(|current| Arc::ptr_eq(current.active_profile(), &installed))
    {
        return Arc::clone(current);
    }
    let repinned = Arc::new(base.with_active_profile(installed));
    *view = Some(Arc::clone(&repinned));
    repinned
}

type SharedSearchRuntimeRegistry = Arc<RwLock<HashMap<SharedSearchRuntimeKey, Arc<SearchService>>>>;

// Snapshot ownership only; never hold the registry lock across tracker work
// or an async cleanup. The generic value also permits pure registry tests
// without starting databases or retaining a global tenant service handle.
fn snapshot_runtime_views<T>(registry: &RwLock<HashMap<SharedSearchRuntimeKey, Arc<T>>>)
    -> Result<Vec<Arc<T>>, &'static str>
{
    // NAN-3080: recover a poisoned registry instead of failing every
    // request forever; entries are whole Arc swaps, never half-written.
    Ok(registry.read().unwrap_or_else(std::sync::PoisonError::into_inner).values().cloned().collect())
}

fn cleanup_query_trackers<'a>(trackers: impl IntoIterator<Item = &'a nanosiem_core::search::QueryTracker>,
    max_age: std::time::Duration) -> usize
{
    trackers.into_iter().map(|tracker| tracker.cleanup_stale(max_age)).sum()
}

/// Environment variable naming the durable job signing master key file
/// (32 raw bytes or 64 hex, mode 0400/0600, regular file — mount Secret
/// items with `subPath`).
pub const JOB_SIGNING_MASTER_KEY_FILE_ENV: &str = "NANO_SEARCH_JOB_SIGNING_KEY_FILE";

/// NAN-3475: the process `PrevalenceService` whose Settings the config poll
/// refreshes from `system_settings` (`id = 'default'`), or `None` on
/// enterprise-shared. There that row is deployment-global, not any tenant's
/// Settings: each tenant's rarity threshold comes from its own worker
/// assignment (gen1) or the lean-cell contract, and the process service must
/// never pick up a value a tenant view could be judged by.
fn deployment_prevalence_to_refresh(
    shared_profile: bool,
    prevalence: &Arc<PrevalenceService>,
) -> Option<Arc<PrevalenceService>> {
    (!shared_profile).then(|| Arc::clone(prevalence))
}

/// Load the durable job signing master key. Enterprise-shared deployments
/// must configure it (search refuses to boot otherwise); dedicated
/// deployments may omit it and keep the historical unsigned keyspace.
fn load_job_signing_master(
    shared_profile: bool,
) -> Result<Option<Arc<nanosiem_core::search::DurableJobSigningMasterKey>>, String> {
    match std::env::var(JOB_SIGNING_MASTER_KEY_FILE_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(path) => nanosiem_core::search::DurableJobSigningMasterKey::from_file(
            std::path::Path::new(&path),
        )
        .map(|key| Some(Arc::new(key)))
        .map_err(|error| error.to_string()),
        None if shared_profile => Err(format!(
            "{JOB_SIGNING_MASTER_KEY_FILE_ENV} is required in enterprise_shared mode"
        )),
        None => Ok(None),
    }
}

fn shared_search_runtime_key(
    tenant_id: uuid::Uuid,
    entitlement_revision: u64,
    worker_assignment_revision: u64,
    retention_revision: i64,
    retention_days: u16,
    irreversible_event_time_floor_micros: i64,
) -> SharedSearchRuntimeKey {
    (
        tenant_id,
        entitlement_revision,
        worker_assignment_revision,
        retention_revision,
        retention_days,
        irreversible_event_time_floor_micros,
        0,
    )
}

/// Whether `scope` is a hosted shared-tenant scope. Only the enterprise
/// middleware resolves one; an open build always answers `false`.
pub(crate) fn is_shared_scope(scope: nanosiem_core::search::SearchTenantScope) -> bool {
    #[cfg(feature = "enterprise")]
    {
        scope.is_enterprise_shared()
    }
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = scope;
        false
    }
}

impl SearchState {
    /// Create a new SearchState with the given DualPool
    pub async fn new(dual_pool: DualPool, auth_state: AuthState) -> Self {
        let shared_worker_registry = auth_state.shared_profile().then(|| {
            Arc::new(
                SharedLakeWorkerRegistry::from_env().unwrap_or_else(|error| {
                    panic!("invalid enterprise-shared lake worker registry: {error}")
                }),
            )
        });
        let otel_lake = otel_lake::OtelLakeClient::from_env()
            .unwrap_or_else(|error| panic!("invalid native OTLP lake configuration: {error}"));
        let hosted_otel_clients = shared_worker_registry.as_deref().map(|registry| {
            Arc::new(
                Self::load_hosted_otel_clients(registry)
                    .unwrap_or_else(|error| panic!("invalid enterprise-shared OTLP ingest assignment: {error}")),
            )
        });
        // Never fails boot: a missing or broken routes file is an empty map.
        let lean_otel_clients = auth_state
            .shared_profile()
            .then(otel_lake::LeanOtelClients::from_env)
            .flatten()
            .map(Arc::new);
        let job_signing_master = load_job_signing_master(auth_state.shared_profile())
            .unwrap_or_else(|error| panic!("invalid durable job signing key: {error}"));
        // NAN-3531: per-tenant failures are skipped inside and retried on the
        // next scan; only process-level misconfiguration (bad env, missing
        // signing key, unreadable directory, duplicate tenant) panics.
        // Open builds refuse a hosted producer config instead of ignoring it.
        #[cfg(not(feature = "enterprise"))]
        if std::env::var_os("NANO_SHARED_HOSTED_JOB_CONFIG_DIR").is_some_and(|dir| !dir.is_empty())
            || std::env::var_os("NANO_SHARED_HOSTED_JOB_CONFIG_FILES").is_some()
        {
            panic!("hosted job coordinator configuration is invalid (process-level): hosted producers require the enterprise edition");
        }
        #[cfg(feature = "enterprise")]
        let hosted_producers = Self::load_hosted_producers(shared_worker_registry.as_ref(), job_signing_master.as_ref())
            .await
            .unwrap_or_else(|error| panic!("hosted job coordinator configuration is invalid (process-level): {error}"));
        #[cfg(feature = "enterprise")]
        let tenant_lookup_runtime = if auth_state.enterprise_shared {
            match nanosiem_enterprise::melod::TenantAiRlsRuntime::connect_startup().await {
                Ok(runtime) => Some(Arc::new(runtime)),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "enterprise-shared tenant RLS runtime unavailable; tenant lookup tables stay closed to search"
                    );
                    None
                }
            }
        } else {
            None
        };
        // Create lookup service. Row-data placement is selected by
        // LOOKUP_STORAGE_BACKEND; if it is unset, the primary lake lane uses
        // PostgreSQL and legacy event deployments use ClickHouse. The registry
        // always stays in Postgres. This must match the API's selection so
        // reads and writes agree on one backend.
        let lookup = Arc::new(LookupService::with_backend(
            nanosiem_core::lookup::LookupStorageBackend::from_env(),
            dual_pool.postgres().clone(),
            dual_pool.clickhouse().clone(),
        ));

        // Create prevalence service (uses ClickHouse client directly).
        // P1 audit: build via `with_database_config` so this process honors the
        // persisted admin config (rarity_threshold, tracking toggles) at boot
        // instead of the hardcoded defaults. A background poll below keeps it
        // fresh when the config is changed on nanosiem-api at runtime.
        // NAN-2361 wave-4: the shared profile has no deployment-global
        // prevalence config (`system_settings` is not readable by the shared
        // login; per-tenant values live in the lake worker registry), so do
        // not attempt the global load there.
        let prevalence = Arc::new(if auth_state.shared_profile() {
            PrevalenceService::with_config(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
                nanosiem_core::prevalence::PrevalenceConfig::default(),
            )
        } else {
            PrevalenceService::with_database_config(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
                dual_pool.postgres(),
            )
            .await
        });

        // Try loading admission config from PostgreSQL first, fall back to env vars
        let admission_config = Self::load_admission_config(&dual_pool).await;
        tracing::info!(
            "Admission controller configured: global_adhoc_limit={}, shared_tenant_adhoc_limit={}, per_user_limit={}, max_queue_depth={}, queue_timeout_ms={}",
            admission_config.global_adhoc_limit,
            admission_config.shared_tenant_adhoc_limit,
            admission_config.per_user_limit,
            admission_config.max_queue_depth,
            admission_config.queue_timeout_ms,
        );
        let admission_controller = Arc::new(AdmissionController::new(admission_config));
        admission_controller.start_drain_loop();

        // Create search service with lookup and prevalence support.
        // OCSF Phase 3a (NAN-1241): the search microservice (which actually
        // executes queries) resolves the active schema profile from
        // NANO_SCHEMA_PROFILE so queries run against the selected schema's table
        // and resolve fields under it — mirroring nanosiem-api. Unset selects
        // the canonical OCSF lake profile; a legacy value fails fast (NAN-3491).
        let schema_profile = nanosiem_core::schema::active_profile_from_env()
            .unwrap_or_else(|e| panic!("invalid NANO_SCHEMA_PROFILE: {e}"));
        tracing::info!(schema = ?schema_profile.id(), "Search service schema profile");
        let mut search_svc = SearchService::with_dual_pool_lookup_and_prevalence_and_profile(
            &dual_pool,
            (*lookup).clone(),
            (*prevalence).clone(),
            schema_profile,
        );

        // Wire admission controller into search service
        search_svc.set_admission_controller(admission_controller.clone());

        // Load query safety limits from database on boot
        Self::load_query_limits_on_boot(&dual_pool, &search_svc).await;

        // Start background config polling (checks PostgreSQL every 60s for admin
        // changes). P1 audit: also refresh prevalence config so this process
        // honors runtime rarity_threshold / tracking-toggle changes made on
        // nanosiem-api (cross-process hot-reload, bounded by the poll interval).
        // NAN-3475: never on enterprise-shared, where the deployment row is
        // not any tenant's Settings (see `deployment_prevalence_to_refresh`).
        Self::start_config_polling(
            dual_pool.clone(),
            admission_controller.clone(),
            deployment_prevalence_to_refresh(auth_state.shared_profile(), &prevalence),
        );

        // Add inputlookup service for URL-based enrichment. Wire the internal
        // lookup layer so `| inputlookup <internal_table>` reads the CH/PG-backed
        // lookup table directly (NAN-1581 Phase 5).
        let inputlookup_service = InputLookupService::new(InputLookupConfig::default())
            .with_lookup_service(lookup.clone());
        search_svc.set_inputlookup_service(inputlookup_service);
        tracing::info!("InputLookup service configured for Search Service");

        // Wire AI Pipe agent for inline LLM classification (optional — graceful degradation).
        // AiPipeAgent satisfies extensions::AiClient via the adapter impl in
        // the enterprise crate's melod AI pipe agent. Open-core builds skip
        // wiring; the search service's `Arc<dyn AiClient>` field stays None and
        // `| ai` pipes return rows tagged `ai_verdict = "SKIPPED"`.
        #[cfg(feature = "enterprise")]
        let mut ai_registry = None;
        #[cfg(feature = "enterprise")]
        match Self::create_ai_pipe_agent(&dual_pool).await {
            Ok((agent, registry)) => {
                search_svc.set_ai_client(std::sync::Arc::new(agent));
                ai_registry = Some(registry);
                tracing::info!("AI Pipe agent configured for Search Service");
            }
            Err(e) => {
                tracing::warn!(
                    "AI Pipe agent not available (queries with | ai will return without AI enrichment): {}",
                    e
                );
                // NAN-3185: say WHY on every `| ai` row (instead of the open-core
                // "AI unavailable in this build") and retry lazily, so a config
                // fix in Postgres doesn't need a restart.
                let pool = dual_pool.clone();
                let factory: nanosiem_core::extensions::AiClientFactory =
                    Arc::new(move || {
                        let pool = pool.clone();
                        Box::pin(async move {
                            Self::create_ai_pipe_agent(&pool).await.map(|(agent, _)| {
                                Arc::new(agent) as Arc<dyn nanosiem_core::extensions::AiClient>
                            })
                        })
                    });
                search_svc.set_ai_client(Arc::new(nanosiem_core::extensions::DeferredAiClient::new(
                    "AI not configured for search service",
                    e,
                    std::time::Duration::from_secs(60),
                    factory,
                )));
            }
        }

        #[cfg(feature = "enterprise")]
        let tenant_ai_factory = match (&tenant_lookup_runtime, ai_registry) {
            (Some(rls), Some(registry)) => Some(Arc::new(
                nanosiem_enterprise::melod::TenantSystemAiPrincipalFactory::new(
                    dual_pool.postgres().clone(), Arc::clone(rls),
                    Arc::new(tokio::sync::RwLock::new(Some(registry))),
                ),
            )),
            _ => None,
        };

        // Connect to Dragonfly/Redis for job store, cancellation ownership, and
        // result caching (optional).
        let redis_url = std::env::var("REDIS_URL").ok();
        let query_owner_redis = match redis_url.as_deref() {
            Some(url) => Self::connect_redis(url).await,
            None => None,
        };

        // Wire Redis for job store and cluster-wide admission limits (falls back to in-memory/local)
        if let Some(ref url) = redis_url {
            if let Some(redis_store) = RedisJobStore::connect(url).await {
                search_svc.set_job_store(Arc::new(redis_store));
                tracing::info!("Search job store: Redis (active/active enabled)");
            } else {
                tracing::warn!(
                    "Redis job store connection failed — falling back to in-memory (single-instance mode)"
                );
            }

            // Wire Redis into admission controller for cluster-wide limits
            match Self::connect_redis(url).await {
                Some(conn) => {
                    admission_controller.set_redis(conn).await;
                    tracing::info!("Admission controller: Redis cluster-wide limits enabled");
                }
                None => {
                    tracing::warn!(
                        "Redis admission connection failed — using local per-instance limits"
                    );
                }
            }
        } else {
            tracing::info!(
                "REDIS_URL not set — using in-memory job store and local admission limits"
            );
        }

        let search = Arc::new(search_svc);

        // Start periodic polling for query safety limits (checks PostgreSQL every 60s)
        Self::start_query_limits_polling(dual_pool.clone(), search.clone());

        // Start periodic cleanup tasks for query tracker and job store
        let shared_search_runtimes = Arc::new(RwLock::new(HashMap::new()));
        Self::start_cleanup_tasks(search.clone(), shared_search_runtimes.clone());

        // Create audit emitter for logging sharing events
        let audit_emitter = Arc::new(AuditEmitter::new(dual_pool.clone()));
        let emitter = audit_emitter.clone();
        let audit_queue = nanosiem_core::background_queue::BackgroundQueue::spawn(1024, move |events: Vec<AuditEvent>| {
            let emitter = emitter.clone();
            async move {
                if let Err(error) = emitter.emit_batch(&events).await {
                    for event in events {
                        tracing::error!(%error, event = %serde_json::to_string(&event).unwrap_or_default(), "Search audit persistence unconfirmed");
                    }
                }
            }
        });

        // Connect to Dragonfly/Redis for search result caching (optional)
        // Lake values must pass the worker's current enrichment authority and
        // stamp-expiry return gate. Redis has no such fence; do not replay it.
        let result_cache = match redis_url.filter(|_| search.backend() != nanosiem_core::search::SearchBackend::Lake && shared_worker_registry.is_none()) {
            Some(ref url) => cache::SearchResultCache::connect(url).await,
            None => {
                tracing::info!("REDIS_URL not set — search result caching disabled");
                None
            }
        };

        // Create IP allowlist service for access control
        let ip_allowlist_service = Arc::new(IpAllowlistService::new(dual_pool.postgres().clone()));

        // Share the middleware's fail-closed source-scope resolver (NAN-1797)
        // so handler-side resolution hits the same Arc-backed registry cache.
        let source_scope_resolver = auth_state.source_scope_resolver.clone();

        Self {
            dual_pool,
            search,
            lookup,
            prevalence,
            auth_state,
            source_scope_resolver,
            audit_emitter,
            audit_queue,
            start_time: Instant::now(),
            leader_rx: None,
            result_cache,
            otel_lake,
            hosted_otel_clients,
            lean_otel_clients,
            tenant_job_redis: query_owner_redis.clone(),
            #[cfg(feature = "enterprise")]
            hosted_producers,
            job_signing_master,
            query_owner_redis,
            shared_search_runtimes,
            dedicated_schema_view: Arc::default(),
            shared_worker_registry,
            #[cfg(feature = "enterprise")]
            tenant_lookup_runtime,
            #[cfg(feature = "enterprise")]
            tenant_ai_factory,
            ip_allowlist_service,
        }
    }

    /// The dedicated singleton, re-pinned to the worker-served lake schema
    /// when that has changed since boot.
    ///
    /// NAN-3492: `self.search` is built once, from the profile installed at
    /// boot. The refresh loop in `main.rs` installs every later field set, but
    /// nothing re-pinned the singleton, so a trusted-local install rejected
    /// every field first stored after Search started (`prevalence_min`, the
    /// stamped `enrichments.data.*`, a new source's leaves) as "Unknown
    /// canonical OCSF field" until a restart. A process with no worker-served
    /// schema (UDM, or a manifest-file deployment) keeps the singleton.
    fn dedicated_search(&self) -> Arc<SearchService> {
        repin_to_installed_schema(
            &self.search,
            &self.dedicated_schema_view,
            nanosiem_core::schema::installed_lake_profile(),
        )
    }

    /// Resolve the request's server-authenticated search runtime. Dedicated
    /// deployments receive the historical singleton. Enterprise-shared
    /// requests receive a cached service whose worker assignment and job
    /// keyspace are both pinned to the exact tenant.
    pub fn search_for_tenant(
        &self,
        tenant: nanosiem_core::search::SearchTenantScope,
        entitlement_revision: Option<u64>,
    ) -> Result<Arc<SearchService>, SearchError> {
        let Some(tenant_id) = tenant.tenant_id() else {
            // NAN-3286: an enterprise-shared process never serves the process
            // singleton. Shared middleware always resolves a tenant scope, so
            // a scope without a tenant here is a wiring bug: fail closed.
            if self.auth_state.shared_profile() {
                return Err(SearchError::ServiceUnavailable(
                    "enterprise-shared Search requires a resolved tenant scope".to_string(),
                ));
            }
            return Ok(self.dedicated_search());
        };
        #[cfg(feature = "enterprise")]
        {
            self.shared_tenant_search(tenant, tenant_id, entitlement_revision)
        }
        #[cfg(not(feature = "enterprise"))]
        {
            // Only the enterprise middleware resolves a tenant scope.
            let _ = (tenant_id, entitlement_revision);
            Err(SearchError::ServiceUnavailable(
                "tenant-scoped Search requires the enterprise edition".to_string(),
            ))
        }
    }

    pub fn search_for_auth(
        &self,
        auth: &crate::AuthContext,
    ) -> Result<Arc<SearchService>, SearchError> {
        nanosiem_core::request_timing::timed_sync(nanosiem_core::request_timing::Phase::Authority, || {
            self.search_for_tenant(auth.tenant_scope, auth.shared_search_entitlement_revision)
        })
    }

    /// Bind the AI pipe to the authenticated member on a request-local clone.
    /// Cached cell views are tenant-scoped and must never retain an actor's AI
    /// credential or usage attribution for another member's request.
    pub fn search_with_ai_for_auth(
        &self,
        auth: &crate::AuthContext,
    ) -> Result<Arc<SearchService>, SearchError> {
        let view = self.search_for_auth(auth)?;
        if !view.serves_lake_cell() {
            return Ok(view);
        }
        #[cfg(feature = "enterprise")]
        {
            let Some(factory) = self.tenant_ai_factory.as_ref() else {
                return Ok(view);
            };
            let authority = auth.shared_request_authority.as_ref().ok_or_else(||
                SearchError::ServiceUnavailable("tenant AI request authority is unavailable".to_string()))?;
            if auth.tenant_scope.tenant_id() != Some(authority.tenant.tenant_id) {
                return Err(SearchError::ServiceUnavailable("tenant AI authority mismatch".to_string()));
            }
            let actor = auth.ownership_user_id().ok_or_else(||
                SearchError::ServiceUnavailable("tenant AI actor is unavailable".to_string()))?;
            let mut bound = (*view).clone();
            bound.set_tenant_ai_client(
                Arc::new(factory.search_pipe_client(authority.tenant.clone(), actor)),
                authority.tenant.tenant_id,
            )?;
            return Ok(Arc::new(bound));
        }
        #[cfg(not(feature = "enterprise"))]
        Ok(view)
    }

    /// NAN-3018: prepare the tenant view for a `dataset=risk` request. Only
    /// enterprise-shared requests that select `risk` do anything here; every
    /// other request gets its view back unchanged.
    ///
    /// For those, the caller must hold `risk:view`, and the view must be the
    /// caller's own lean-lake cell view. The tenant's decay and effective
    /// clear state are read in ONE signed transaction as the requesting
    /// member, using the tenant from the server-verified request authority
    /// (never a request field). They are bound to a request-local clone, so
    /// the cached tenant view never keeps one request's snapshot.
    pub async fn bind_shared_risk_dataset(
        &self,
        auth: &crate::AuthContext,
        dataset: Option<&str>,
        view: Arc<SearchService>,
    ) -> Result<Arc<SearchService>, SearchError> {
        if !is_shared_scope(auth.tenant_scope)
            || !dataset.is_some_and(|dataset| dataset.trim().eq_ignore_ascii_case("risk"))
        {
            return Ok(view);
        }
        if !auth
            .claims
            .has_permission(nanosiem_core::auth::permissions::RISK_VIEW)
        {
            return Err(SearchError::Forbidden(
                "dataset `risk` requires the risk:view permission".to_string(),
            ));
        }
        let tenant_id = auth.tenant_scope.tenant_id().ok_or_else(|| {
            SearchError::ServiceUnavailable("tenant identity is unavailable".to_string())
        })?;
        if view.assigned_tenant_id() != Some(tenant_id) {
            return Err(SearchError::Forbidden("Tenant search access denied".to_string()));
        }
        if !view.serves_lake_cell() {
            return Err(SearchError::BadRequest(
                "dataset `risk` is served only for lean-lake (cell) tenants; this tenant's \
                 search runs on the gen1 lake"
                    .to_string(),
            ));
        }
        #[cfg(feature = "enterprise")]
        {
            let runtime = self.tenant_lookup_runtime.as_ref().ok_or_else(|| {
                SearchError::ServiceUnavailable(
                    "tenant risk configuration is temporarily unavailable".to_string(),
                )
            })?;
            let authority = auth.shared_request_authority.as_ref().ok_or_else(|| {
                SearchError::ServiceUnavailable("tenant request authority is unavailable".to_string())
            })?;
            if authority.tenant.tenant_id != tenant_id {
                return Err(SearchError::Forbidden("Tenant search access denied".to_string()));
            }
            let actor = auth.ownership_user_id().ok_or_else(|| {
                SearchError::Forbidden("dataset `risk` requires a member-owned credential".to_string())
            })?;
            let (decay, clear) = runtime
                .tenant_risk_search_state(&authority.tenant, actor)
                .await
                .map_err(|error| match error {
                    nanosiem_enterprise::melod::TenantAiExecutionError::AccessDenied => {
                        SearchError::Forbidden("Tenant risk access denied".to_string())
                    }
                    _ => SearchError::ServiceUnavailable(
                        "tenant risk configuration is temporarily unavailable".to_string(),
                    ),
                })?;
            let mut bound = (*view).clone();
            bound
                .set_tenant_risk_config(tenant_id, decay, &clear)
                .map_err(SearchError::from)?;
            Ok(Arc::new(bound))
        }
        #[cfg(not(feature = "enterprise"))]
        {
            Err(SearchError::BadRequest(
                "dataset `risk` is not available for enterprise-shared tenants in this build".to_string(),
            ))
        }
    }

    /// Deep query-backend readiness. Shared mode verifies the server-owned
    /// tenant registry because it intentionally has no global tenant client.
    pub async fn query_backend_ready(&self) -> bool {
        match self.shared_worker_registry.as_ref() {
            Some(registry) => registry.all_workers_ready().await,
            None => self.search.lake_worker_ready().await,
        }
    }

    fn query_owner_key(request_id: &str) -> String {
        Self::query_owner_key_for(
            nanosiem_core::search::SearchTenantScope::dedicated(),
            request_id,
        )
    }

    fn query_owner_key_for(
        tenant: nanosiem_core::search::SearchTenantScope,
        request_id: &str,
    ) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(request_id.as_bytes());
        tenant.query_owner_key(&hex::encode(digest))
    }

    /// Reserve a client request id for an authenticated user across all search replicas.
    pub async fn reserve_query_owner(
        &self,
        request_id: &str,
        user_id: uuid::Uuid,
    ) -> redis::RedisResult<bool> {
        self.reserve_query_owner_for(
            nanosiem_core::search::SearchTenantScope::dedicated(),
            request_id,
            user_id,
        )
        .await
    }

    pub async fn reserve_query_owner_for(
        &self,
        tenant: nanosiem_core::search::SearchTenantScope,
        request_id: &str,
        user_id: uuid::Uuid,
    ) -> redis::RedisResult<bool> {
        let Some(mut conn) = self.query_owner_redis.clone() else {
            return Ok(true);
        };
        const OWNER_TTL_SECS: u64 = 60 * 60;
        let key = Self::query_owner_key_for(tenant, request_id);
        let owner = user_id.to_string();
        let inserted: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&owner)
            .arg("NX")
            .arg("EX")
            .arg(OWNER_TTL_SECS)
            .query_async(&mut conn)
            .await?;
        if inserted.is_some() {
            return Ok(true);
        }
        let existing: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await?;
        if existing.as_deref() != Some(owner.as_str()) {
            return Ok(false);
        }
        // Companion queries reuse the main request id. Keep the proof alive.
        let _: bool = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(OWNER_TTL_SECS)
            .query_async(&mut conn)
            .await?;
        Ok(true)
    }

    /// Resolve request ownership from the shared active/active registry.
    pub async fn shared_query_owner(
        &self,
        request_id: &str,
    ) -> redis::RedisResult<Option<uuid::Uuid>> {
        self.shared_query_owner_for(
            nanosiem_core::search::SearchTenantScope::dedicated(),
            request_id,
        )
        .await
    }

    pub async fn shared_query_owner_for(
        &self,
        tenant: nanosiem_core::search::SearchTenantScope,
        request_id: &str,
    ) -> redis::RedisResult<Option<uuid::Uuid>> {
        let Some(mut conn) = self.query_owner_redis.clone() else {
            return Ok(None);
        };
        let owner: Option<String> = redis::cmd("GET")
            .arg(Self::query_owner_key_for(tenant, request_id))
            .query_async(&mut conn)
            .await?;
        Ok(owner.and_then(|value| uuid::Uuid::parse_str(&value).ok()))
    }

    /// Start periodic cleanup for query tracker stale entries and expired search jobs.
    fn start_cleanup_tasks(search: Arc<SearchService>, shared_runtimes: SharedSearchRuntimeRegistry) {
        let search_qt = search.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick
            loop {
                interval.tick().await;
                let views = snapshot_runtime_views(&shared_runtimes).unwrap_or_else(|error| {
                    tracing::warn!("Tenant query tracker cleanup skipped: {error}");
                    Vec::new()
                });
                let removed = cleanup_query_trackers(
                    std::iter::once(search_qt.query_tracker())
                        .chain(views.iter().map(|view| view.query_tracker())),
                    std::time::Duration::from_secs(3600),
                );
                if removed > 0 {
                    tracing::info!("Query tracker cleanup removed {} stale entries", removed);
                }
                search_qt.job_store().cleanup().await;
            }
        });
    }

    /// Emit an audit event (fire-and-forget, non-blocking)
    /// Start background polling for admission config changes from PostgreSQL.
    /// Checks every 60 seconds and hot-reloads the admission controller if settings changed.
    fn start_config_polling(
        dual_pool: DualPool,
        controller: Arc<AdmissionController>,
        prevalence: Option<Arc<PrevalenceService>>,
    ) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // Skip immediate first tick (already loaded at startup)

            loop {
                interval.tick().await;

                let settings_repo = SearchAdmissionSettings::new(dual_pool.postgres().clone());
                match settings_repo.get_config().await {
                    Ok(db_config) => {
                        let new_config = AdmissionConfig {
                            global_adhoc_limit: db_config.global_adhoc_limit,
                            shared_tenant_adhoc_limit: Self::shared_tenant_admission_limit(
                                db_config.global_adhoc_limit,
                                db_config.per_user_limit,
                            ),
                            per_user_limit: db_config.per_user_limit,
                            max_queue_depth: db_config.max_queue_depth,
                            queue_timeout_ms: (db_config.queue_timeout_seconds as u64) * 1000,
                        };
                        controller.update_config(new_config).await;
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Config poll: could not read search admission settings: {}",
                            e
                        );
                    }
                }

                // P1 audit: refresh prevalence config so runtime admin changes
                // (rarity_threshold, tracking toggles) take effect here without a
                // restart. update_config also invalidates the prevalence cache.
                let Some(prevalence) = prevalence.as_ref() else {
                    continue;
                };
                let prevalence_settings = nanosiem_core::prevalence::PrevalenceSettings::new(
                    dual_pool.postgres().clone(),
                );
                match prevalence_settings.get_config().await {
                    Ok(cfg) => {
                        // NAN-1691 (P3): only hot-reload when the DB config
                        // actually differs. update_config() wipes the prevalence
                        // LRU; calling it every 60s tick discarded a warm cache
                        // even when nothing had changed.
                        if cfg != prevalence.get_config().await {
                            prevalence.update_config(cfg).await;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Config poll: could not read prevalence settings: {}", e);
                    }
                }
            }
        });
    }

    /// Load admission config from PostgreSQL, falling back to env vars.
    /// Config values are used as-is — when Redis is available, limits are
    /// enforced cluster-wide via atomic counters. Without Redis, they apply
    /// per-instance (same as before Phase 2).
    async fn load_admission_config(dual_pool: &DualPool) -> AdmissionConfig {
        let settings_repo = SearchAdmissionSettings::new(dual_pool.postgres().clone());
        match settings_repo.get_config().await {
            Ok(db_config) => {
                tracing::info!("Loaded search admission config from database");
                AdmissionConfig {
                    global_adhoc_limit: db_config.global_adhoc_limit,
                    shared_tenant_adhoc_limit: Self::shared_tenant_admission_limit(
                        db_config.global_adhoc_limit,
                        db_config.per_user_limit,
                    ),
                    per_user_limit: db_config.per_user_limit,
                    max_queue_depth: db_config.max_queue_depth,
                    queue_timeout_ms: (db_config.queue_timeout_seconds as u64) * 1000,
                }
            }
            Err(e) => {
                tracing::debug!(
                    "Search admission config not in database yet (migration may not have run), using env var defaults: {}",
                    e
                );
                let global_adhoc_limit = std::env::var("SEARCH_GLOBAL_ADHOC_LIMIT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30);
                // NAN-3299: one Search page run holds rows + histogram +
                // field stats at once; 5 failed single searches with 429.
                let per_user_limit = std::env::var("SEARCH_PER_USER_LIMIT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(nanosiem_core::search::admission::DEFAULT_PER_USER_LIMIT);
                AdmissionConfig {
                    global_adhoc_limit,
                    shared_tenant_adhoc_limit: Self::shared_tenant_admission_limit(
                        global_adhoc_limit,
                        per_user_limit,
                    ),
                    per_user_limit,
                    max_queue_depth: std::env::var("SEARCH_MAX_QUEUE_DEPTH")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(100),
                    queue_timeout_ms: std::env::var("SEARCH_QUEUE_TIMEOUT_MS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        // NAN-714: matches Interactive max_execution_time (300s).
                        .unwrap_or(300_000),
                }
            }
        }
    }

    fn shared_tenant_admission_limit(global_limit: u32, per_user_limit: u32) -> u32 {
        // One tenant's default share stays at the historical 10 slots (it
        // was 2x the old per-user default of 5) unless one user may hold
        // more; the per-user raise to 10 (NAN-3299) must not double every
        // tenant's share of the cell.
        let safe_default = per_user_limit
            .max(nanosiem_core::search::AdmissionConfig::default().shared_tenant_adhoc_limit)
            .min(global_limit);
        std::env::var("SEARCH_SHARED_TENANT_ADHOC_LIMIT")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|limit| *limit > 0 && *limit <= global_limit)
            .unwrap_or(safe_default)
    }

    /// Load query safety limits from database on boot
    async fn load_query_limits_on_boot(dual_pool: &DualPool, search_svc: &SearchService) {
        let settings_repo = SearchQueryLimitsSettings::new(dual_pool.postgres().clone());
        match settings_repo.get_config().await {
            Ok(config) => {
                tracing::info!(
                    "Loaded query safety limits from database: max_group_array_size={}, max_mvexpand_rows={}, block_on_cost_errors={}",
                    config.max_group_array_size,
                    config.max_mvexpand_rows,
                    config.block_on_cost_errors
                );
                search_svc.update_query_limits(config).await;
            }
            Err(e) => {
                tracing::debug!(
                    "Query safety limits not in database yet (migration may not have run), using defaults: {}",
                    e
                );
            }
        }
    }

    /// Start background polling for query safety limits changes from PostgreSQL.
    /// Checks every 60 seconds and hot-reloads if settings changed.
    fn start_query_limits_polling(dual_pool: DualPool, search: Arc<SearchService>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // Skip immediate first tick (already loaded at startup)

            loop {
                interval.tick().await;

                let settings_repo = SearchQueryLimitsSettings::new(dual_pool.postgres().clone());
                match settings_repo.get_config().await {
                    Ok(config) => {
                        search.update_query_limits(config).await;
                    }
                    Err(e) => {
                        tracing::debug!("Config poll: could not read query safety limits: {}", e);
                    }
                }
            }
        });
    }

    /// One tenant-pinned OTLP client per registry assignment carrying an
    /// `otel_ingest` block. Tenants without one answer a typed 503 on every
    /// OTLP route (`otel_lake_for`).
    fn load_hosted_otel_clients(
        registry: &SharedLakeWorkerRegistry,
    ) -> Result<HashMap<uuid::Uuid, otel_lake::OtelLakeClient>, otel_lake::OtelLakeClientError> {
        let mut clients = HashMap::new();
        for (tenant_id, assignment) in registry.otel_ingest_assignments() {
            clients.insert(tenant_id, otel_lake::OtelLakeClient::from_shared_assignment(assignment)?);
        }
        Ok(clients)
    }

    /// The native OTLP client a request may use. Shared requests are pinned
    /// to their tenant's `lake_otel_ingest`; a tenant with no provisioned
    /// drain gets a typed 503 (the same fact `/api/log-sources/ingest-endpoint`
    /// reports as `otlp_telemetry_ingested: false`), never the process-global
    /// client and never the ClickHouse fallback. Dedicated requests keep the
    /// historical `otel_lake` / ClickHouse switch.
    pub fn otel_lake_for(
        &self,
        auth: &AuthContext,
    ) -> Result<Option<otel_lake::OtelLakeRef<'_>>, SearchError> {
        if !is_shared_scope(auth.tenant_scope) {
            return Ok(self.otel_lake.as_ref().map(otel_lake::OtelLakeRef::Borrowed));
        }
        let tenant_id = auth.tenant_scope.tenant_id().ok_or_else(|| {
            SearchError::ServiceUnavailable(
                "enterprise-shared telemetry requires a resolved tenant".to_string(),
            )
        })?;
        if let Some(client) = self.hosted_otel_clients.as_ref().and_then(|clients| clients.get(&tenant_id)) {
            return Ok(Some(otel_lake::OtelLakeRef::Borrowed(client)));
        }
        // NAN-3243: a lean-lake tenant's drain, by the authenticated tenant only.
        self.lean_otel_clients
            .as_ref()
            .and_then(|clients| clients.client(tenant_id))
            .map(|client| Some(otel_lake::OtelLakeRef::Shared(client)))
            .ok_or_else(|| {
                SearchError::ServiceUnavailable(
                    "telemetry_not_ingested: no lake_otel_ingest drain is provisioned for this tenant"
                        .to_string(),
                )
            })
    }

    /// Boot the hosted producer set (NAN-3531). `Ok(None)` when neither
    /// `NANO_SHARED_HOSTED_JOB_CONFIG_DIR` nor `NANO_SHARED_HOSTED_JOB_CONFIG_FILES`
    /// is set. A live directory is then rescanned in the background.
    #[cfg(feature = "enterprise")]
    async fn load_hosted_producers(
        registry: Option<&Arc<SharedLakeWorkerRegistry>>,
        master: Option<&Arc<nanosiem_core::search::DurableJobSigningMasterKey>>,
    ) -> Result<Option<Arc<nanosiem_core::search::hosted_producer_reload::HostedProducerReloader>>, String> {
        use nanosiem_core::search::hosted_producer_reload::HostedProducerSource;
        if !HostedProducerSource::configured_in_env() {
            return Ok(None);
        }
        {
            use nanosiem_core::search::{
                hosted_producer_reload::{CoordinatorAttestor, HostedProducerReloader, HostedProducerReloaderConfig},
                job_coordinator_config::CellRoutedProducers,
            };
            let registry = registry.ok_or("hosted producers require the shared lake worker registry")?;
            let source = HostedProducerSource::from_env(registry)
                .map_err(|error| error.to_string())?
                .ok_or("hosted producer source vanished from the environment")?;
            let reloader = HostedProducerReloader::boot(HostedProducerReloaderConfig {
                source,
                registry: Arc::clone(registry),
                master: master.cloned(),
                // A cell tenant's hosted client is optional job control here.
                cell_routed: CellRoutedProducers::Attest,
                attestor: Arc::new(CoordinatorAttestor),
                publish_process_status: true,
            })
            .await
            .map_err(|error| error.to_string())?;
            if reloader.spawn_rescans().is_some() {
                tracing::info!("hosted producer configs reload live from the config directory");
            }
            Ok(Some(reloader))
        }
    }

    /// NAN-3531 N2a: the hosted job control a view of this tenant and
    /// binding must carry now; `None` when the live set has no producer for
    /// it or the producer is bound to another assignment.
    fn expected_hosted_control(
        &self,
        tenant: nanosiem_core::search::SearchTenantScope,
        tenant_id: uuid::Uuid,
        entitlement_revision: u64,
        worker_assignment_revision: u64,
    ) -> Option<Arc<dyn nanosiem_core::search::job_control_store::DurableJobControlStore>> {
        #[cfg(not(feature = "enterprise"))]
        {
            // Hosted producers are enterprise-only (NAN-3861).
            let _ = (tenant, tenant_id, entitlement_revision, worker_assignment_revision);
            None
        }
        #[cfg(feature = "enterprise")]
        {
            let producers = self.hosted_producers.as_ref()?.current();
            let control = producers.producer(tenant_id)?.control();
            let binding = nanosiem_core::search::job_coordinator_client::HostedAssignment {
                entitlement_revision: i64::try_from(entitlement_revision).ok()?,
                worker_revision: worker_assignment_revision,
            };
            control.matches_binding(tenant, binding).then(|| Arc::clone(control))
        }
    }

    /// Connect to Redis for admission counters (separate from job store connection).
    async fn connect_redis(
        redis_url: &str,
    ) -> Option<nanosiem_core::redis_transport::ReconnectingConnection> {
        let client = nanosiem_core::redis_transport::client_from_url(redis_url).ok()?;
        nanosiem_core::redis_transport::ReconnectingConnection::new(client)
            .await
            .ok()
    }

    /// Create an AI Pipe agent backed by the config registry.
    /// The agent re-reads the DB config on each query, so model changes
    /// made in the Settings UI are picked up without restarting the service.
    /// Returns Err if Cloudflare AI Gateway is not configured — this is expected in many deployments.
    #[cfg(feature = "enterprise")]
    async fn create_ai_pipe_agent(dual_pool: &DualPool) -> Result<(AiPipeAgent, Arc<AgentConfigRegistry>), String> {
        let ai_gateway_url = std::env::var("CLOUDFLARE_AI_GATEWAY_URL").map_err(|_| {
            "CLOUDFLARE_AI_GATEWAY_URL not set — AI pipe agent requires Cloudflare AI Gateway"
                .to_string()
        })?;

        // Build CF AI Gateway metadata for per-org analytics
        let cf_aig_metadata = {
            let org_id = std::env::var("NANO_ORG_ID").unwrap_or_default();
            let deployment_id = std::env::var("NANO_DEPLOYMENT_ID").unwrap_or_default();
            let tier = std::env::var("NANO_TIER").unwrap_or_else(|_| "unrestricted".to_string());
            if !org_id.is_empty() || !deployment_id.is_empty() {
                Some(
                    serde_json::json!({
                        "org_id": org_id,
                        "deployment_id": deployment_id,
                        "tier": tier
                    })
                    .to_string(),
                )
            } else {
                None
            }
        };

        let registry_config = AgentConfigRegistryConfig {
            ai_gateway_url,
            cf_auth_token: std::env::var("CF_AIG_AUTH_TOKEN").ok(),
            cf_aig_metadata,
            requests_per_minute: std::env::var("AI_REQUESTS_PER_MINUTE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            // NAN-3891: the `| ai` pipe obeys the region's AI provider region.
            ai_provider_region: nanosiem_core::ai_provider_region::AiProviderRegionPin::from_env(),
        };

        let credential_resolver = Arc::new(nanosiem_enterprise::melod::CredentialResolver::new(
            dual_pool.postgres().clone(),
        ));
        let registry = Arc::new(AgentConfigRegistry::new(
            dual_pool.postgres().clone(),
            registry_config,
            credential_resolver,
        ));

        // Initial config load — if this fails, AI is not available
        registry
            .load_configs()
            .await
            .map_err(|e| format!("Failed to load agent configs: {}", e))?;

        Ok((AiPipeAgent::from_registry(Arc::clone(&registry)), registry))
    }

    /// Set the leader election receiver (called from main.rs when election is enabled)
    pub fn set_leader_rx(&mut self, rx: watch::Receiver<bool>) {
        self.leader_rx = Some(rx);
    }

    /// Returns `true` if this instance is the active leader (or election is disabled).
    pub fn is_leader(&self) -> bool {
        match &self.leader_rx {
            Some(rx) => *rx.borrow(),
            None => true, // Election disabled = always leader (single-node mode)
        }
    }

    pub fn emit_audit(&self, event: AuditEvent) {
        if let Err(event) = nanosiem_core::request_timing::timed_sync(nanosiem_core::request_timing::Phase::Audit, || self.audit_queue.try_send(event)) {
            ::metrics::counter!("nanosiem_search_audit_dropped_total").increment(1);
            tracing::error!(event = %serde_json::to_string(&event).unwrap_or_default(), "Search audit queue full or closed; persistence unconfirmed");
        }
    }
}

/// Create the Axum router for the Search Service
pub fn create_router(
    state: SearchState,
    search_metrics: SearchMetrics,
    prometheus_layer: axum_prometheus::PrometheusMetricLayer<'static>,
    config: &SearchConfig,
) -> Router {
    // Configure CORS with explicit origins (security best practice)
    let cors = if config.cors_origins.is_empty() {
        // No origins configured - deny all cross-origin requests (secure default)
        tracing::warn!(
            "CORS_ORIGINS not configured - cross-origin requests will be blocked. Set CORS_ORIGINS environment variable."
        );
        CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
    } else if config.cors_origins.len() == 1 && config.cors_origins[0] == "*" {
        // Wildcard - allow all origins (NOT recommended for production)
        tracing::warn!(
            "CORS configured to allow ALL origins (*) - this should only be used in development!"
        );
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
    } else {
        // Specific origins - parse and validate each one
        let origins: Vec<_> = config
            .cors_origins
            .iter()
            .filter_map(|origin| {
                origin.parse().ok().or_else(|| {
                    tracing::warn!("Invalid CORS origin '{}' - skipping", origin);
                    None
                })
            })
            .collect();

        if origins.is_empty() {
            tracing::error!(
                "No valid CORS origins configured - cross-origin requests will be blocked"
            );
            CorsLayer::new()
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
        } else {
            tracing::info!("CORS configured for origins: {:?}", config.cors_origins);
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT])
        }
    };

    // Build IP allowlist state for middleware
    let ip_allowlist_state = IpAllowlistState {
        service: state.ip_allowlist_service.clone(),
        scope: IpAllowlistScope::Search,
    };

    // Clone auth_state for the middleware layer
    let auth_state = state.auth_state.clone();
    let shared_profile = auth_state.shared_profile();

    let app = Router::new()
        // Search endpoints
        .route("/api/search", post(handlers::search))
        .route("/api/search/stream", post(handlers::search_stream))
        .route("/api/search/{request_id}", delete(handlers::cancel_search))
        .route("/api/search/sql", post(handlers::search_sql))
        .route("/api/search/explain", post(handlers::explain))
        .route("/api/search/log", post(handlers::fetch_log))
        .route(
            "/api/search/prevalence-artifacts",
            post(handlers::prevalence_artifacts),
        )
        .route(
            "/api/search/field-stats",
            post(handlers::field_stats_for_query),
        )
        .route("/api/search/field-values", post(handlers::field_values))
        .route("/api/search/histogram", post(handlers::search_histogram))
        // IOC retro-hunt rollup (NAN-1580): companion to the `/api/search` retro marker
        .route("/api/search/retro", post(handlers::retro))
        // NAN-3088: lean Prevalence export and rare list (durable cell jobs)
        .route(
            "/api/search/prevalence/export",
            get(handlers::lean_prevalence_export),
        )
        .route(
            "/api/search/prevalence/rare",
            get(handlers::lean_rare_artifacts),
        )
        // OpenTelemetry observability (NAN-1528): trace waterfall + metric series
        .route("/api/search/trace/{trace_id}", get(handlers::get_trace))
        .route(
            "/api/search/metrics/timeseries",
            post(handlers::get_metric_timeseries),
        )
        // OTLP explorers (NAN-1534): recent-traces list + metric-names dropdown
        .route("/api/search/traces", get(handlers::list_traces))
        .route(
            "/api/search/metrics/names",
            get(handlers::list_metric_names),
        )
        // Metrics v2 (NAN-1540): tag-key / tag-value enumeration for the
        // group-by / filter pickers.
        .route("/api/search/metrics/tags", get(handlers::list_metric_tags))
        // Observability console (NAN-1536): services overview + service detail
        .route("/api/search/services", get(handlers::list_services))
        .route(
            "/api/search/services/{service}",
            get(handlers::get_service_detail),
        )
        // Observability ↔ Security convergence (NAN-2361): OCSF Detection
        // Findings touching a service's span hosts, via the lake.
        .route(
            "/api/search/services/{service}/security-signals",
            get(handlers::get_service_security_signals),
        )
        // Observability console (NAN-1537): infra hosts overview + RUM summary
        .route("/api/search/infra/hosts", get(handlers::list_infra_hosts))
        .route("/api/search/rum", get(handlers::get_rum_summary))
        // Asset events pagination
        .route("/api/search/asset-events", post(handlers::get_asset_events))
        // Cloud events pagination
        .route("/api/search/cloud-events", post(handlers::get_cloud_events))
        // Cloud user timeline
        .route(
            "/api/search/cloud-user-timeline",
            post(handlers::get_cloud_user_timeline),
        )
        // Cloud entity pivot
        .route(
            "/api/search/cloud-entity-pivot",
            post(handlers::get_cloud_entity_pivot),
        )
        // Asset true time range (lazy-loaded first/last seen)
        .route(
            "/api/search/asset-true-time-range",
            post(handlers::get_asset_true_time_range),
        )
        // Asset artifacts (lazy-loaded artifact summaries for prevalence scatter)
        .route(
            "/api/search/asset-artifacts",
            post(handlers::get_asset_artifacts),
        )
        // Asset dossier (aggregates for the redesigned Asset view)
        .route(
            "/api/search/asset-dossier",
            post(handlers::get_asset_dossier),
        )
        // Cloud overview (aggregates for the redesigned `| cloud` landing view, NAN-394)
        .route(
            "/api/search/cloud-overview",
            post(handlers::get_cloud_overview),
        )
        // Cloud principal dossier (`| cloud principal=X`, NAN-395)
        .route(
            "/api/search/cloud-dossier",
            post(handlers::get_cloud_dossier),
        )
        // Identity resolution
        .route("/api/identity/resolve", get(handlers::resolve_identity))
        // Async search jobs
        .route("/api/search/tree-page", post(handlers::get_tree_page))
        .route("/api/search/jobs", get(handlers::list_search_jobs))
        .route("/api/search/jobs/{job_id}", get(handlers::get_search_job))
        .route(
            "/api/search/jobs/{job_id}/results/{page}",
            get(handlers::get_search_job_result_page),
        )
        .route(
            "/api/search/jobs/{job_id}/download",
            get(handlers::download_search_job_result),
        )
        .route(
            "/api/search/jobs/{job_id}",
            delete(handlers::cancel_search_job),
        )
        // Admin search jobs (requires settings:system permission)
        .route(
            "/api/search/admin/jobs",
            get(handlers::admin_list_search_jobs),
        )
        .route("/api/search/admin/stats", get(handlers::admin_get_stats))
        .route(
            "/api/search/admin/jobs/{job_id}",
            delete(handlers::admin_cancel_search_job),
        )
        // Saved searches
        .route("/api/search/saved", get(handlers::list_saved_searches))
        .route("/api/search/saved", post(handlers::create_saved_search))
        .route(
            "/api/search/saved/shared",
            get(handlers::list_shared_searches),
        )
        .route(
            "/api/search/saved/mine",
            get(handlers::list_my_saved_searches),
        )
        .route("/api/search/saved/{id}", get(handlers::get_saved_search))
        .route("/api/search/saved/{id}", put(handlers::update_saved_search))
        .route(
            "/api/search/saved/{id}",
            delete(handlers::delete_saved_search),
        )
        .route(
            "/api/search/saved/{id}/share",
            post(handlers::share_saved_search),
        )
        // Health endpoint (not metrics - that's handled by prometheus)
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        // Shallow liveness/readiness probe — no dep checks (NAN-1786).
        .route("/livez", get(handlers::livez))
        // Add middleware
        // M9: Limit request body size to 256KB to prevent DoS via oversized payloads
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        // M10: Catch panics to prevent search service crashes from taking down the process
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(axum_middleware::from_fn(sanitize_error_responses))
        .layer(CompressionLayer::new().gzip(true))
        // Security headers (match nanosiem-api)
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("0"),
        ))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(prometheus_layer)
        // NAN-3222: audit searches naming a source the caller cannot see
        // (inside auth: needs AuthContext; response untouched).
        .layer(axum_middleware::from_fn_with_state(
            denied_source_audit::SearchDeniedSourceAuditSink::new(state.clone()),
            denied_source_audit::denied_source_audit_middleware,
        ))
        // NAN-3282: per-request + process-wide memory budget for product views.
        .layer(axum_middleware::from_fn(middleware::product_view_memory_middleware))
        // NAN-4664: the caller's admission wait budget for every search.
        .layer(axum_middleware::from_fn(middleware::admission_wait_budget_middleware))
        // NAN-3077: opt-in route-wide lake evidence (inside auth: needs AuthContext).
        .layer(axum_middleware::from_fn(handlers::lake_debug_middleware))
        // Add auth middleware
        .layer(axum_middleware::from_fn(
            nanosiem_api_lib::tenant_path::enforce_tenant_path,
        ))
        .layer(axum_middleware::from_fn_with_state(
            auth_state,
            auth_middleware,
        ));
    // Shared auth checks the tenant IP policy after verifying tenant identity.
    // The legacy global policy belongs only to non-shared deployments.
    let app = if shared_profile {
        app
    } else {
        app.layer(axum_middleware::from_fn_with_state(
            ip_allowlist_state,
            ip_allowlist_middleware,
        ))
    };
    let app = app
        .merge(inputlookup_egress::router())
        // Add request ID middleware (outermost - runs first)
        .layer(axum_middleware::from_fn(request_id_middleware))
        .with_state(state)
        // Merge the prometheus metrics endpoint
        .merge(search_metrics.metrics_router())
        // NAN-3531 N2a: outside auth like /metrics. The platform reads it
        // through the API-server pod proxy; it carries no secrets.
        .merge(hosted_config_router());
    if shared_profile {
        nanosiem_api_lib::tenant_path::scoped_api_router(app)
    } else {
        app
    }
}

/// `GET /internal/hosted-config`: the hosted producer set this process has
/// loaded (revision, tenants, failed tenants, last scan time). Enterprise
/// only; open builds never load hosted producers (NAN-3861).
#[cfg(not(feature = "enterprise"))]
pub fn hosted_config_router() -> Router {
    Router::new()
}

#[cfg(feature = "enterprise")]
pub fn hosted_config_router() -> Router {
    Router::new().route(
        "/internal/hosted-config",
        get(|| async {
            axum::Json(nanosiem_core::search::hosted_producer_reload::process_hosted_config_status())
        }),
    )
}

/// Whether a cached view's hosted control is exactly `expected` (by pointer).
fn same_hosted_control(
    cached: Option<&Arc<dyn nanosiem_core::search::job_control_store::DurableJobControlStore>>,
    expected: Option<&Arc<dyn nanosiem_core::search::job_control_store::DurableJobControlStore>>,
) -> bool {
    match (cached, expected) {
        (None, None) => true,
        (Some(cached), Some(expected)) => std::ptr::addr_eq(Arc::as_ptr(cached), Arc::as_ptr(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod query_owner_tests {
    use super::{cleanup_query_trackers, shared_search_runtime_key, snapshot_runtime_views, SearchState};
    use nanosiem_core::search::{QueryTracker, SearchTenantScope};
    use std::{collections::HashMap, sync::{Arc, RwLock}, time::Duration};
    use uuid::Uuid;

    #[test]
    fn cleanup_sweeps_each_isolated_tenant_and_singleton_without_evicting_views() {
        let singleton = QueryTracker::new();
        let a = Arc::new(QueryTracker::new());
        let b = Arc::new(QueryTracker::new());
        for tracker in [&singleton, a.as_ref(), b.as_ref()] {
            assert!(tracker.reserve_request("same-client-id".into(), Uuid::now_v7()));
        }
        let registry = RwLock::new(HashMap::from([
            (shared_search_runtime_key(Uuid::from_u128(1), 1, 1, 1, 365, 0), a.clone()),
            (shared_search_runtime_key(Uuid::from_u128(2), 1, 1, 1, 365, 0), b.clone()),
        ]));
        let views = snapshot_runtime_views(&registry).unwrap();
        assert!(registry.try_write().is_ok(), "snapshot must release the registry read lock");
        assert_eq!(cleanup_query_trackers(std::iter::once(&singleton).chain(views.iter().map(Arc::as_ref)), Duration::from_secs(3600)), 0);
        assert_eq!(cleanup_query_trackers(std::iter::once(&singleton).chain(views.iter().map(Arc::as_ref)), Duration::ZERO), 3);
        assert_eq!(singleton.active_count() + a.active_count() + b.active_count(), 0);
        assert_eq!(registry.read().unwrap().len(), 2, "cleanup must not evict authority-bearing views");
    }

    #[test]
    fn subsequent_cleanup_observes_new_and_replaced_runtime_views() {
        let old = Arc::new(QueryTracker::new());
        let key = shared_search_runtime_key(Uuid::from_u128(1), 1, 1, 1, 365, 0);
        let registry = RwLock::new(HashMap::from([(key, old.clone())]));
        let first = snapshot_runtime_views(&registry).unwrap();
        let replacement = Arc::new(QueryTracker::new());
        assert!(replacement.reserve_request("new".into(), Uuid::now_v7()));
        registry.write().unwrap().insert(key, replacement.clone());
        assert_eq!(cleanup_query_trackers(first.iter().map(Arc::as_ref), Duration::ZERO), 0);
        assert_eq!(replacement.active_count(), 1);
        let second = snapshot_runtime_views(&registry).unwrap();
        assert_eq!(cleanup_query_trackers(second.iter().map(Arc::as_ref), Duration::ZERO), 1);
    }

    #[test]
    fn query_owner_keys_are_stable_and_do_not_embed_client_ids() {
        let key = SearchState::query_owner_key("customer-visible-request-id");
        assert_eq!(
            key,
            SearchState::query_owner_key("customer-visible-request-id")
        );
        assert_ne!(key, SearchState::query_owner_key("other-request-id"));
        assert!(!key.contains("customer-visible-request-id"));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_query_owner_keys_are_tenant_pinned() {
        let a = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xa));
        let b = SearchTenantScope::EnterpriseShared(Uuid::from_u128(0xb));
        let request_id = "identical-client-request-id";
        assert_ne!(
            SearchState::query_owner_key_for(a, request_id),
            SearchState::query_owner_key_for(b, request_id)
        );
        assert_eq!(
            SearchState::query_owner_key(request_id),
            SearchState::query_owner_key_for(SearchTenantScope::dedicated(), request_id)
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_worker_rotation_invalidates_runtime_identity() {
        let tenant = Uuid::from_u128(0xa);
        let revision_one = shared_search_runtime_key(tenant, 7, 1, 11, 365, 0);
        let revision_two = shared_search_runtime_key(tenant, 7, 2, 11, 365, 0);

        assert_ne!(revision_one, revision_two);
        assert_eq!(
            revision_one,
            shared_search_runtime_key(tenant, 7, 1, 11, 365, 0)
        );
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod cross_tenant_isolation;

#[cfg(all(test, feature = "enterprise"))]
mod full_event_contract;
#[cfg(test)]
mod operator_probe_unreachable;

#[cfg(test)]
mod dedicated_schema_tests {
    use super::repin_to_installed_schema;
    use nanosiem_core::schema::{FieldType, OcsfProfile, SchemaProfile};
    use nanosiem_core::{DualPool, SearchService};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    fn lake_profile(fields: &[&str]) -> Arc<dyn SchemaProfile> {
        let fields = fields
            .iter()
            .map(|field| (field.to_string(), FieldType::Integer))
            .collect::<BTreeMap<_, _>>();
        Arc::new(OcsfProfile::try_lake_1_9_with_snapshot_field_types(fields).unwrap())
    }

    /// NAN-3492: the live trusted-local gate rejected `| where prevalence_min
    /// <= 3` with "Unknown canonical OCSF field" because the dedicated Search
    /// singleton kept the profile installed at boot, before the tenant's part
    /// schema carried the lean `prevalence_*` stamp columns.
    #[tokio::test]
    async fn dedicated_search_follows_the_installed_worker_schema() {
        let dual_pool = DualPool::new_lake_control_plane(&nanosiem_core::DualPoolConfig::with_auth(
            "postgres://fixture:fixture@127.0.0.1:1/never_connect",
            "http://127.0.0.1:1",
            "fixture",
            "fixture",
            "fixture",
        ))
        .await
        .unwrap();
        dual_pool.postgres().close().await;
        let boot = lake_profile(&["metadata.uid"]);
        let base = Arc::new(SearchService::with_dual_pool(&dual_pool).with_active_profile(boot.clone()));
        let view = Mutex::new(None);
        assert!(!base.active_profile().is_known_field("prevalence_min"));

        // No worker-served schema, or the boot one: the singleton itself.
        assert!(Arc::ptr_eq(&repin_to_installed_schema(&base, &view, None), &base));
        assert!(Arc::ptr_eq(&repin_to_installed_schema(&base, &view, Some(boot)), &base));
        assert!(view.lock().unwrap().is_none());

        // The worker's field set moved: a re-pinned copy, built once.
        let refreshed = lake_profile(&["metadata.uid", "prevalence_min"]);
        let first = repin_to_installed_schema(&base, &view, Some(refreshed.clone()));
        assert!(!Arc::ptr_eq(&first, &base));
        assert!(Arc::ptr_eq(first.active_profile(), &refreshed));
        assert!(first.active_profile().is_known_field("prevalence_min"));
        let again = repin_to_installed_schema(&base, &view, Some(refreshed));
        assert!(Arc::ptr_eq(&first, &again));

        // A later change replaces the cached copy.
        let later = lake_profile(&["metadata.uid", "prevalence_min", "prevalence_dest_ip"]);
        let next = repin_to_installed_schema(&base, &view, Some(later.clone()));
        assert!(Arc::ptr_eq(next.active_profile(), &later));
        assert!(!Arc::ptr_eq(&next, &first));
    }
}
