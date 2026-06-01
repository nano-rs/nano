// SPDX-License-Identifier: AGPL-3.0-or-later

//! Application state
//!
//! Manages shared application state including database connections and services.
//! Supports dual database architecture with ClickHouse for log storage and PostgreSQL
//! for metadata, configuration, and AI-related data.

mod cleanup;
mod constructors;
mod lifecycle;
#[cfg(feature = "enterprise")]
mod melod;
mod schedulers;

use nanosiem_core::audit::{AuditEmitter, AuditQueryService};
use nanosiem_core::auth::{
    ApiKeyRepository, ApiKeyService, AuditRepository, AuthConfig, AuthService, GroupRepository,
    OidcRepository, OidcService, PermissionService, RoleRepository, SessionConfig,
    SessionRepository, SessionService, TokenConfig, TokenService, UserRepository,
};
use nanosiem_core::db::repository::RateLimitRepository;
use nanosiem_core::db::DualPool;
use nanosiem_core::detection::{MaterializedViewGenerator, RealtimeEvaluator, SignalProcessor};
use nanosiem_core::enrichment::EnrichmentService;
use nanosiem_core::identity::IdentitySyncService;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::{
    AgentConfigRegistry, MelodJobRepository, MelodService, MelodSessionRepository,
    WizardSessionRepository,
};
use nanosiem_core::onboarding::OnboardingRepository;
use nanosiem_core::tuning::{NotificationService, TuningRepository};
use nanosiem_core::{
    DetectionService, DiskPressureService, DistributedDetectionScheduler, FeedService,
    IpAllowlistService, LogSourceService, LogTelemetryService, ParserService,
    QueryLibraryRepository, SearchService, SourceConfigService,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::risk::RiskAnalyticsService;
use sqlx::PgPool;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::ApiConfig;

// `CaseChangeEvent` was lifted to `nanosiem_enterprise::cases::CaseChangeEvent`
// in NAN-752 alongside the cases handler module. Re-exported here so the
// existing pg_notify consumer in `state/lifecycle.rs` keeps resolving the
// type through `super::CaseChangeEvent`.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::cases::CaseChangeEvent;

/// Get the Vector config directory from environment or use default
fn get_vector_config_dir() -> String {
    std::env::var("VECTOR_CONFIG_DIR").unwrap_or_else(|_| "config/vector".to_string())
}

/// Shared application state
///
/// Dual-database architecture: ClickHouse for logs, PostgreSQL for metadata.
/// Both pools are required — boot fails fast if ClickHouse is unreachable
/// (the PG-only "degraded" fallback was removed in NAN-800).
#[derive(Clone)]
pub struct AppState {
    /// PostgreSQL connection pool
    pub pool: PgPool,
    /// DualPool for ClickHouse + PostgreSQL
    pub dual_pool: DualPool,
    /// Search service
    pub search_service: SearchService,
    /// Detection service
    pub detection_service: DetectionService,
    /// Detection scheduler (legacy, kept for trigger_rule API)
    /// Distributed detection scheduler (SKIP LOCKED, runs on all nodes)
    pub distributed_scheduler: Arc<RwLock<Option<Arc<DistributedDetectionScheduler>>>>,
    /// Node ID for distributed scheduling
    pub node_id: String,
    /// Real-time evaluator for incoming events
    pub realtime_evaluator: Arc<RealtimeEvaluator>,
    /// Enrichment service
    pub enrichment: Arc<RwLock<EnrichmentService>>,
    /// Feed service
    pub feed_service: FeedService,
    /// Parser service
    pub parser_service: ParserService,
    /// Log source service
    pub log_source_service: LogSourceService,
    /// Log telemetry rollup service (per-source_type events/bytes/last_event_at)
    pub log_telemetry_service: LogTelemetryService,
    /// Source configuration service
    pub source_config_service: SourceConfigService,
    /// meloD AI assistant service (optional, dynamically reloadable)
    #[cfg(feature = "enterprise")]
    pub melod_service: Arc<RwLock<Option<Arc<MelodService>>>>,
    /// Risk analytics service (enterprise — RiskAnalyticsService is lifted to
    /// `nanosiem-enterprise::risk` in Phase 3.4 of NAN-744; open-core surfaces
    /// risk via `extensions::CloudRiskProvider` and the `Noop` impl)
    #[cfg(feature = "enterprise")]
    pub risk_service: RiskAnalyticsService,
    /// Query library repository
    pub query_library: QueryLibraryRepository,
    /// Materialized view generator
    pub materialized_view_generator: Arc<MaterializedViewGenerator>,
    /// API configuration
    pub config: Arc<ApiConfig>,
    // Authentication and RBAC services
    /// Authentication service
    pub auth_service: Arc<AuthService>,
    /// Token service for JWT operations
    pub token_service: Arc<TokenService>,
    /// API key service
    pub api_key_service: Arc<ApiKeyService>,
    /// Session service
    pub session_service: Arc<SessionService>,
    /// Permission service
    pub permission_service: Arc<PermissionService>,
    /// User repository
    pub user_repo: UserRepository,
    /// Group repository
    pub group_repo: GroupRepository,
    /// Role repository
    pub role_repo: RoleRepository,
    /// Audit repository
    pub audit_repo: Arc<AuditRepository>,
    /// OIDC repository
    pub oidc_repo: OidcRepository,
    /// OIDC service
    oidc_service: Arc<OidcService>,
    /// Whether authentication is enabled
    pub auth_enabled: bool,
    /// Notification service for tuning alerts
    pub notification_service: Arc<NotificationService>,
    /// Tuning repository for proposal management
    pub tuning_repository: Arc<TuningRepository>,
    /// Task handles for graceful shutdown
    task_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    /// PostgreSQL-backed job repository for async meloD operations
    #[cfg(feature = "enterprise")]
    pub melod_job_repo: MelodJobRepository,
    /// PostgreSQL-backed repository for wizard sessions
    #[cfg(feature = "enterprise")]
    pub wizard_session_repo: WizardSessionRepository,
    /// PostgreSQL-backed repository for meloD AI session persistence
    #[cfg(feature = "enterprise")]
    pub melod_session_repo: MelodSessionRepository,
    /// Unified audit emitter for ClickHouse
    pub audit_emitter: Arc<AuditEmitter>,
    /// Audit query service for reading audit events from ClickHouse
    pub audit_query_service: AuditQueryService,
    /// Agent configuration registry for per-agent model settings
    #[cfg(feature = "enterprise")]
    pub agent_config_registry: Arc<RwLock<Option<Arc<AgentConfigRegistry>>>>,
    /// Signal processor for bridging ClickHouse signals to PostgreSQL alerts
    pub signal_processor: Arc<SignalProcessor>,
    /// Disk pressure service for automatic partition eviction
    pub disk_pressure_service: Arc<DiskPressureService>,
    /// Shared flag: set to true by disk pressure service to pause ingestion
    pub ingestion_paused: Arc<AtomicBool>,
    /// Identity sync service for provider management and user directory
    pub identity_service: Arc<IdentitySyncService>,
    /// IP allowlist service for access control
    pub ip_allowlist_service: Arc<IpAllowlistService>,
    /// Onboarding wizard progress repository
    pub onboarding_repo: OnboardingRepository,
    /// Demo service (only initialized when DEPLOYMENT_MODE=demo)
    pub demo_service: Option<std::sync::Arc<nanosiem_core::demo::DemoService>>,
    /// Cached license status for BYOC enforcement (shared with middleware).
    /// Enterprise-only: stripped from the open edition (NAN-1193).
    #[cfg(feature = "enterprise")]
    pub license_status: Arc<RwLock<nanosiem_core::license::LicenseStatus>>,
    /// Encryption service for MFA secrets and other sensitive data
    pub encryption_service: Arc<nanosiem_core::crypto::EncryptionService>,
    /// Broadcast sender for real-time case change events (SSE).
    /// Phase 3.2 (NAN-744): cases lifted to enterprise — field only present
    /// when the enterprise feature is enabled.
    #[cfg(feature = "enterprise")]
    pub case_events_tx: tokio::sync::broadcast::Sender<CaseChangeEvent>,
    /// In-memory collab-presence tracker for the Cases list/detail pages
    /// (NAN-420). Heartbeat-driven; zeros on process restart.
    /// Phase 3.2 (NAN-744): cases::PresenceTracker is enterprise-only.
    #[cfg(feature = "enterprise")]
    pub presence_tracker: Arc<nanosiem_enterprise::PresenceTracker>,
    /// Shared Dragonfly-backed cache for the marketplace coverage hero
    /// (NAN-609). Disabled (no-op) when `REDIS_URL` is unset, in which case
    /// every request runs the full ClickHouse aggregate.
    pub marketplace_coverage_cache: Arc<nanosiem_core::marketplace::MarketplaceCoverageCache>,
    /// Shared Dragonfly-backed cache for full search responses (NAN-702).
    /// Mirrors `nanosiem-search`'s `state.result_cache` so dashboard panel
    /// queries — which call `search_with_admission` directly instead of
    /// going through the search HTTP handler — also benefit from the 7-day
    /// compressed result cache. `None` when `REDIS_URL` is unset.
    pub search_result_cache: Option<nanosiem_search::cache::SearchResultCache>,
    /// In-flight tracker for the rule live tester (NAN-741). Each test fans
    /// out up to 16 concurrent ClickHouse queries; capping each user to one
    /// concurrent test prevents click-spam from amplifying that into a
    /// thundering herd against the database.
    pub rule_test_in_flight: Arc<dashmap::DashMap<uuid::Uuid, ()>>,
    /// Shared shadow-investigation hook. On enterprise this is the live
    /// `ShadowInvestigationService` (also wired into detection_service /
    /// signal_processor / realtime_evaluator). On open-core it's the no-op
    /// hook so the cases handlers can blindly call it. Held here so the
    /// per-request `CaseService` built in handlers can pick it up via
    /// `CasesAppState::shadow_investigation_hook`, which is what makes the
    /// add-alert re-triage path (NAN-1059) fire.
    pub shadow_investigation_hook:
        Arc<dyn nanosiem_core::extensions::ShadowInvestigationHook>,
}

impl AppState {
    /// Initialize authentication services
    fn init_auth_services(
        pool: PgPool,
        _config: &ApiConfig,
    ) -> (
        Arc<AuthService>,
        Arc<TokenService>,
        Arc<ApiKeyService>,
        Arc<SessionService>,
        Arc<PermissionService>,
        UserRepository,
        GroupRepository,
        RoleRepository,
        Arc<AuditRepository>,
        bool,
    ) {
        // Check if auth is enabled (default: true in production, can be disabled for dev)
        let auth_enabled = std::env::var("AUTH_ENABLED")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        // Get JWT secret from environment - REQUIRED for security
        let jwt_secret = if !auth_enabled {
            // If auth is disabled, use a placeholder (dev/testing only)
            tracing::warn!("Authentication is DISABLED - this should only be used in development");
            "dev-placeholder-secret".to_string()
        } else {
            // In production with auth enabled, JWT_SECRET MUST be set
            let secret = std::env::var("JWT_SECRET")
                .expect("CRITICAL SECURITY ERROR: JWT_SECRET environment variable must be set when authentication is enabled");

            // Validate that the secret is not the old insecure default
            if secret == "nanosiem-dev-secret-change-in-production" {
                panic!("CRITICAL SECURITY ERROR: JWT_SECRET is set to the insecure default value. Please generate a secure random secret.");
            }

            // Validate minimum length (at least 32 characters for security)
            if secret.len() < 32 {
                panic!("CRITICAL SECURITY ERROR: JWT_SECRET must be at least 32 characters long. Current length: {}", secret.len());
            }

            tracing::info!(
                "JWT secret loaded successfully (length: {} characters)",
                secret.len()
            );
            secret
        };

        // Create repositories
        let user_repo = UserRepository::new(pool.clone());
        let group_repo = GroupRepository::new(pool.clone());
        let role_repo = RoleRepository::new(pool.clone());
        let session_repo = SessionRepository::new(pool.clone());
        let audit_repo = Arc::new(AuditRepository::new(pool.clone()));
        let api_key_repo = ApiKeyRepository::new(pool.clone());

        // Create token service with a shared JTI denylist across both instances
        let token_config = TokenConfig::new(jwt_secret.clone());
        let token_service = Arc::new(TokenService::new(token_config));
        let shared_denylist = token_service.revoked_jtis_handle();

        // H8: Load persisted revoked JTIs from PostgreSQL on startup.
        // Spawn a dedicated thread with its own runtime since we're in a sync
        // constructor that may be called from within the main tokio runtime.
        {
            let pool_clone = pool.clone();
            let denylist_clone = shared_denylist.clone();
            let _ = std::thread::spawn(move || {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    match nanosiem_core::auth::token::load_revoked_tokens(&pool_clone, &denylist_clone).await {
                        Ok(count) if count > 0 => {
                            tracing::info!(count, "Loaded persisted token revocations from database");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to load persisted token revocations (table may not exist yet)");
                        }
                        _ => {}
                    }
                })
            }).join();
        }

        // Second token service for AuthService shares the same denylist
        let token_config_for_auth = TokenConfig::new(jwt_secret);
        let token_service_for_auth =
            TokenService::new_with_shared_denylist(token_config_for_auth, shared_denylist);

        // Create auth service
        let auth_config = AuthConfig::default();
        let auth_service = Arc::new(AuthService::new(
            user_repo.clone(),
            session_repo.clone(),
            group_repo.clone(),
            (*audit_repo).clone(),
            token_service_for_auth,
            auth_config,
        ));

        // Create API key service
        let api_key_service = Arc::new(ApiKeyService::new(
            api_key_repo,
            (*audit_repo).clone(),
            RateLimitRepository::new(pool.clone()),
        ));

        // Create session service
        let session_config = SessionConfig::default();
        let session_service = Arc::new(SessionService::new(
            session_repo,
            user_repo.clone(),
            (*audit_repo).clone(),
            session_config,
        ));

        // Create permission service (only needs group_repo)
        let permission_service = Arc::new(PermissionService::new(group_repo.clone()));

        (
            auth_service,
            token_service,
            api_key_service,
            session_service,
            permission_service,
            user_repo,
            group_repo,
            role_repo,
            audit_repo,
            auth_enabled,
        )
    }

    /// Get a reference to the DualPool
    pub fn dual_pool(&self) -> &DualPool {
        &self.dual_pool
    }

    /// Set the meloD service
    #[cfg(feature = "enterprise")]
    pub async fn set_melod_service(&self, service: MelodService) {
        let mut guard = self.melod_service.write().await;
        *guard = Some(Arc::new(service));
    }

    /// Get the meloD service if available
    #[cfg(feature = "enterprise")]
    pub async fn get_melod_service(&self) -> Option<Arc<MelodService>> {
        let guard = self.melod_service.read().await;
        guard.clone()
    }

    /// Get the OIDC service
    pub fn get_oidc_service(&self) -> Arc<OidcService> {
        self.oidc_service.clone()
    }

    /// Initialize demo service if DEPLOYMENT_MODE=demo.
    /// Call this after state creation. Runs demo migrations and sets up the service.
    pub async fn init_demo_if_enabled(&mut self) -> anyhow::Result<()> {
        if !self.config.deployment_mode.is_demo() {
            return Ok(());
        }

        tracing::info!("Demo mode enabled — initializing demo service");

        // Run demo-specific migrations (creates demo.* schema)
        nanosiem_core::demo::run_demo_migrations(&self.pool).await?;

        // Create demo service
        let demo_service = nanosiem_core::demo::DemoService::new(
            self.pool.clone(),
            self.user_repo.clone(),
            nanosiem_core::auth::SessionRepository::new(self.pool.clone()),
            self.token_service.clone(),
            self.config.demo_session_ttl_hours,
            self.config.demo_max_sessions_per_ip,
        );

        self.demo_service = Some(Arc::new(demo_service));

        tracing::info!("Demo service initialized");
        Ok(())
    }

    /// Track a resource created by a demo user. No-op if not in demo mode
    /// or if the user is not a demo user. Safe to call unconditionally.
    pub fn track_demo_resource(
        &self,
        user_id: uuid::Uuid,
        resource_type: nanosiem_core::demo::DemoResourceType,
        resource_id: uuid::Uuid,
    ) {
        if let Some(ref demo_service) = self.demo_service {
            let svc = demo_service.clone();
            tokio::spawn(async move {
                if let Err(e) = svc
                    .track_resource(user_id, resource_type, resource_id)
                    .await
                {
                    tracing::debug!(
                        user_id = %user_id,
                        resource_type = %resource_type,
                        resource_id = %resource_id,
                        error = %e,
                        "Failed to track demo resource (user may not be a demo user)"
                    );
                }
            });
        }
    }

    /// Get IDs of resources created by OTHER demo users that should be hidden.
    /// Returns empty set when not in demo mode or for non-demo users.
    pub async fn get_demo_exclude_ids(
        &self,
        user_id: uuid::Uuid,
        resource_type: nanosiem_core::demo::DemoResourceType,
    ) -> std::collections::HashSet<uuid::Uuid> {
        if let Some(ref demo_service) = self.demo_service {
            demo_service
                .get_other_demo_resource_ids(user_id, resource_type)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect()
        } else {
            std::collections::HashSet::new()
        }
    }

    /// Add a task handle for graceful shutdown management
    pub async fn add_task_handle(&self, handle: tokio::task::JoinHandle<()>) {
        let mut handles = self.task_handles.write().await;
        handles.push(handle);
    }
}

// ----------------------------------------------------------------------------
// Enterprise handler trait bridges (NAN-751 Phase 2)
// ----------------------------------------------------------------------------
// The OIDC handler module was lifted from `nanosiem-api/src/handlers/oidc/`
// into `nanosiem-enterprise/src/handlers/oidc/`. Those handlers are generic
// over the `OidcAppState` trait so the enterprise crate doesn't have to
// import `AppState` directly (which would create a circular dependency).
// We implement the trait here on the concrete `AppState` so that
// `Router::with_state(app_state)` lights up with the lifted handlers.
//
// `OidcAppState: AuditExt` — the canonical `AuditExt` impl on `AppState`
// lives in `crate::handlers::mod` (it's the only place that knows about the
// `audit_emitter` + `user_repo` fields). NAN-752 lifted the trait itself
// into `nanosiem-api-lib` so this impl block doesn't need an `emit_audit`
// shim anymore — the `AuditExt` super-trait bound on `OidcAppState` is
// satisfied by the existing impl.
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::oidc::OidcAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn oidc_repo(&self) -> &OidcRepository {
        &self.oidc_repo
    }

    fn user_repo(&self) -> &UserRepository {
        &self.user_repo
    }

    fn group_repo(&self) -> &GroupRepository {
        &self.group_repo
    }

    fn auth_service(&self) -> &Arc<AuthService> {
        &self.auth_service
    }

    fn token_service(&self) -> &Arc<TokenService> {
        &self.token_service
    }

    fn oidc_service(&self) -> Arc<OidcService> {
        self.oidc_service.clone()
    }
}

// --------------------------------------------------------------------------
// NAN-752 Phase 2B trait bridges — risk analytics handlers
// --------------------------------------------------------------------------
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::risk::RiskAppState for AppState {
    fn risk_service(&self) -> &RiskAnalyticsService {
        &self.risk_service
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::agent_enrichment::AgentEnrichmentAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::entity_context::EntityContextAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    fn risk_service(&self) -> &RiskAnalyticsService {
        &self.risk_service
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::custom_enrichment::CustomEnrichmentAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    fn dual_pool(&self) -> &nanosiem_core::db::DualPool {
        &self.dual_pool
    }
    fn agent_config_registry(&self) -> &Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> {
        &self.agent_config_registry
    }
    fn melod_service(&self) -> &Arc<RwLock<Option<Arc<MelodService>>>> {
        &self.melod_service
    }
    fn encryption_service(&self) -> &Arc<nanosiem_core::crypto::EncryptionService> {
        &self.encryption_service
    }
}

#[cfg(feature = "enterprise")]
#[async_trait::async_trait]
impl nanosiem_enterprise::handlers::melod::MelodAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    fn melod_job_repo(&self) -> &nanosiem_enterprise::melod::job_repository::MelodJobRepository {
        &self.melod_job_repo
    }
    fn agent_config_registry(&self) -> &Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> {
        &self.agent_config_registry
    }
    async fn get_melod_service(&self) -> Option<Arc<MelodService>> {
        AppState::get_melod_service(self).await
    }
}

#[cfg(feature = "enterprise")]
#[async_trait::async_trait]
impl nanosiem_enterprise::handlers::cases::CasesAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    fn dual_pool(&self) -> &nanosiem_core::db::DualPool {
        &self.dual_pool
    }
    fn user_repo(&self) -> &UserRepository {
        &self.user_repo
    }
    fn group_repo(&self) -> &GroupRepository {
        &self.group_repo
    }
    fn case_events_tx(
        &self,
    ) -> &tokio::sync::broadcast::Sender<nanosiem_enterprise::cases::CaseChangeEvent> {
        &self.case_events_tx
    }
    fn presence_tracker(&self) -> &Arc<nanosiem_enterprise::PresenceTracker> {
        &self.presence_tracker
    }
    fn shadow_investigation_hook(
        &self,
    ) -> Arc<dyn nanosiem_core::extensions::ShadowInvestigationHook> {
        self.shadow_investigation_hook.clone()
    }
    fn track_demo_resource(
        &self,
        user_id: uuid::Uuid,
        resource_type: nanosiem_core::demo::DemoResourceType,
        resource_id: uuid::Uuid,
    ) {
        AppState::track_demo_resource(self, user_id, resource_type, resource_id)
    }
    async fn get_demo_exclude_ids(
        &self,
        user_id: uuid::Uuid,
        resource_type: nanosiem_core::demo::DemoResourceType,
    ) -> std::collections::HashSet<uuid::Uuid> {
        AppState::get_demo_exclude_ids(self, user_id, resource_type).await
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::notebooks::NotebooksAppState for AppState {
    fn melod_job_repo(&self) -> &nanosiem_enterprise::melod::job_repository::MelodJobRepository {
        &self.melod_job_repo
    }
    fn agent_config_registry(&self) -> &Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> {
        &self.agent_config_registry
    }
    fn search_service(&self) -> &nanosiem_core::SearchService {
        &self.search_service
    }
    fn log_source_service(&self) -> &nanosiem_core::LogSourceService {
        &self.log_source_service
    }
    fn create_data_access_layer(&self) -> nanosiem_enterprise::melod::data_access::DataAccessLayer {
        AppState::create_data_access_layer(self)
    }
}
