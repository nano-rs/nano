// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Search Service library
//!
//! Standalone microservice for log search and query execution. Parses piped
//! queries, generates SQL, and executes searches against ClickHouse.
//!
//! Requirements: 1.3, 3.1, 3.2, 3.3

pub mod cache;
pub mod config;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod openapi;

use axum::http::{HeaderName, HeaderValue};
use axum::http::{
    Method,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
};
use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use nanosiem_core::audit::{AuditEmitter, AuditEvent};
use nanosiem_core::{
    DualPool, InputLookupConfig, InputLookupService, IpAllowlistService, LookupService,
    PrevalenceService, SearchService,
    ip_allowlist::IpAllowlistScope,
    search::{AdmissionConfig, AdmissionController, RedisJobStore},
    settings::{SearchAdmissionSettings, SearchQueryLimitsSettings},
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::{AgentConfigRegistry, AgentConfigRegistryConfig, AiPipeAgent};

pub use config::SearchConfig;
pub use error::SearchError;
pub use metrics::{SearchMetrics, record_search_query};
pub use middleware::{
    AuthContext, AuthState, IpAllowlistState, REQUEST_ID_HEADER, RequestId, auth_middleware,
    ip_allowlist_middleware, request_id_middleware, sanitize_error_responses,
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
    /// Audit emitter for logging sharing events
    pub audit_emitter: Arc<AuditEmitter>,
    /// Service start time for uptime tracking
    pub start_time: Instant,
    /// Leader election status (None = election disabled, always serve)
    leader_rx: Option<watch::Receiver<bool>>,
    /// Search result cache (Dragonfly/Redis — None if unavailable)
    pub result_cache: Option<cache::SearchResultCache>,
    /// Shared request ownership used to authorize cancellation on any search replica.
    query_owner_redis: Option<redis::aio::ConnectionManager>,
    /// IP allowlist service for access control
    pub ip_allowlist_service: Arc<IpAllowlistService>,
}

impl SearchState {
    /// Create a new SearchState with the given DualPool
    pub async fn new(dual_pool: DualPool, auth_state: AuthState) -> Self {
        // Create lookup service. NAN-1581: row-data backend selected by
        // LOOKUP_STORAGE_BACKEND (default ClickHouse); registry stays in Postgres.
        // Must match the API's selection so reads/writes agree on a backend.
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
        let prevalence = Arc::new(
            PrevalenceService::with_database_config(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
                dual_pool.postgres(),
            )
            .await,
        );

        // Try loading admission config from PostgreSQL first, fall back to env vars
        let admission_config = Self::load_admission_config(&dual_pool).await;
        tracing::info!(
            "Admission controller configured: global_adhoc_limit={}, per_user_limit={}, max_queue_depth={}, queue_timeout_ms={}",
            admission_config.global_adhoc_limit,
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
        // (`ocsf_logs` for OCSF) and resolve fields under it — mirroring
        // nanosiem-api. Default `udm`; an unrecognized value fails fast (NAN-800).
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
        Self::start_config_polling(
            dual_pool.clone(),
            admission_controller.clone(),
            prevalence.clone(),
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
        // nanosiem-enterprise/src/melod/ai_pipe_agent.rs. Open-core builds skip
        // wiring; the search service's `Arc<dyn AiClient>` field stays None and
        // `| ai` pipes return rows tagged `ai_verdict = "SKIPPED"`.
        #[cfg(feature = "enterprise")]
        match Self::create_ai_pipe_agent(&dual_pool).await {
            Ok(agent) => {
                search_svc.set_ai_client(std::sync::Arc::new(agent));
                tracing::info!("AI Pipe agent configured for Search Service");
            }
            Err(e) => {
                tracing::warn!(
                    "AI Pipe agent not available (queries with | ai will return without AI enrichment): {}",
                    e
                );
            }
        }

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
        Self::start_cleanup_tasks(search.clone());

        // Create audit emitter for logging sharing events
        let audit_emitter = Arc::new(AuditEmitter::new(dual_pool.clone()));

        // Connect to Dragonfly/Redis for search result caching (optional)
        let result_cache = match redis_url {
            Some(ref url) => cache::SearchResultCache::connect(url).await,
            None => {
                tracing::info!("REDIS_URL not set — search result caching disabled");
                None
            }
        };

        // Create IP allowlist service for access control
        let ip_allowlist_service = Arc::new(IpAllowlistService::new(dual_pool.postgres().clone()));

        Self {
            dual_pool,
            search,
            lookup,
            prevalence,
            auth_state,
            audit_emitter,
            start_time: Instant::now(),
            leader_rx: None,
            result_cache,
            query_owner_redis,
            ip_allowlist_service,
        }
    }

    fn query_owner_key(request_id: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(request_id.as_bytes());
        format!("nanosiem:search:query-owner:{}", hex::encode(digest))
    }

    /// Reserve a client request id for an authenticated user across all search replicas.
    pub async fn reserve_query_owner(
        &self,
        request_id: &str,
        user_id: uuid::Uuid,
    ) -> redis::RedisResult<bool> {
        let Some(mut conn) = self.query_owner_redis.clone() else {
            return Ok(true);
        };
        const OWNER_TTL_SECS: u64 = 60 * 60;
        let key = Self::query_owner_key(request_id);
        let owner = user_id.to_string();
        let inserted: Option<String> = redis::cmd("SET")
            .arg(&key).arg(&owner).arg("NX").arg("EX").arg(OWNER_TTL_SECS)
            .query_async(&mut conn).await?;
        if inserted.is_some() {
            return Ok(true);
        }
        let existing: Option<String> = redis::cmd("GET")
            .arg(&key).query_async(&mut conn).await?;
        if existing.as_deref() != Some(owner.as_str()) {
            return Ok(false);
        }
        // Companion queries reuse the main request id. Keep the proof alive.
        let _: bool = redis::cmd("EXPIRE")
            .arg(&key).arg(OWNER_TTL_SECS).query_async(&mut conn).await?;
        Ok(true)
    }

    /// Resolve request ownership from the shared active/active registry.
    pub async fn shared_query_owner(
        &self,
        request_id: &str,
    ) -> redis::RedisResult<Option<uuid::Uuid>> {
        let Some(mut conn) = self.query_owner_redis.clone() else {
            return Ok(None);
        };
        let owner: Option<String> = redis::cmd("GET")
            .arg(Self::query_owner_key(request_id)).query_async(&mut conn).await?;
        Ok(owner.and_then(|value| uuid::Uuid::parse_str(&value).ok()))
    }

    /// Start periodic cleanup for query tracker stale entries and expired search jobs.
    fn start_cleanup_tasks(search: Arc<SearchService>) {
        let search_qt = search.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick
            loop {
                interval.tick().await;
                let removed = search_qt
                    .query_tracker()
                    .cleanup_stale(std::time::Duration::from_secs(3600));
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
        prevalence: Arc<PrevalenceService>,
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
                let prevalence_settings =
                    nanosiem_core::prevalence::PrevalenceSettings::new(dual_pool.postgres().clone());
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
                AdmissionConfig {
                    global_adhoc_limit: std::env::var("SEARCH_GLOBAL_ADHOC_LIMIT")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(30),
                    per_user_limit: std::env::var("SEARCH_PER_USER_LIMIT")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(5),
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

    /// Connect to Redis for admission counters (separate from job store connection).
    async fn connect_redis(redis_url: &str) -> Option<redis::aio::ConnectionManager> {
        let client = redis::Client::open(redis_url).ok()?;
        redis::aio::ConnectionManager::new(client).await.ok()
    }

    /// Create an AI Pipe agent backed by the config registry.
    /// The agent re-reads the DB config on each query, so model changes
    /// made in the Settings UI are picked up without restarting the service.
    /// Returns Err if Cloudflare AI Gateway is not configured — this is expected in many deployments.
    #[cfg(feature = "enterprise")]
    async fn create_ai_pipe_agent(dual_pool: &DualPool) -> Result<AiPipeAgent, String> {
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

        Ok(AiPipeAgent::from_registry(registry))
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
        let emitter = self.audit_emitter.clone();
        tokio::spawn(async move {
            if let Err(e) = emitter.emit(&event).await {
                tracing::warn!(
                    source = %event.source,
                    action = %event.action,
                    error = %e,
                    "Failed to emit audit event"
                );
            }
        });
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

    Router::new()
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
        // IOC retro-hunt rollup (NAN-1580): companion to the `/api/search` retro marker
        .route("/api/search/retro", post(handlers::retro))
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
        .route(
            "/api/search/metrics/tags",
            get(handlers::list_metric_tags),
        )
        // Observability console (NAN-1536): services overview + service detail
        .route("/api/search/services", get(handlers::list_services))
        .route(
            "/api/search/services/{service}",
            get(handlers::get_service_detail),
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
        .route("/api/search/jobs", get(handlers::list_search_jobs))
        .route("/api/search/jobs/{job_id}", get(handlers::get_search_job))
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
        // Add auth middleware
        .layer(axum_middleware::from_fn_with_state(
            auth_state,
            auth_middleware,
        ))
        // IP allowlist middleware (runs before auth — denied IPs never hit authentication)
        .layer(axum_middleware::from_fn_with_state(
            ip_allowlist_state,
            ip_allowlist_middleware,
        ))
        // Add request ID middleware (outermost - runs first)
        .layer(axum_middleware::from_fn(request_id_middleware))
        .with_state(state)
        // Merge the prometheus metrics endpoint
        .merge(search_metrics.metrics_router())
}

#[cfg(test)]
mod query_owner_tests {
    use super::SearchState;

    #[test]
    fn query_owner_keys_are_stable_and_do_not_embed_client_ids() {
        let key = SearchState::query_owner_key("customer-visible-request-id");
        assert_eq!(key, SearchState::query_owner_key("customer-visible-request-id"));
        assert_ne!(key, SearchState::query_owner_key("other-request-id"));
        assert!(!key.contains("customer-visible-request-id"));
    }
}
