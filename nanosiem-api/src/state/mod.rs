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
mod schema_profile;
mod vector_config;

use nanosiem_core::audit::{AuditEmitter, AuditQueryService};
use nanosiem_core::auth::source_scope_resolver::SourceScopeResolver;
use nanosiem_core::auth::{
    ApiKeyRepository, ApiKeyService, AuthConfig, AuthService, GroupRepository, OidcRepository,
    OidcService, PermissionService, RoleRepository, SessionConfig, SessionRepository,
    SessionService, TokenConfig, TokenService, UserRepository,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::db::repository::TenantCaseNotebookService;
use nanosiem_core::db::repository::{RateLimitRepository, SourceScopeRepository};
use nanosiem_core::db::DualPool;
use nanosiem_core::detection::{MaterializedViewGenerator, SignalProcessor};
use nanosiem_core::enrichment::EnrichmentService;
use nanosiem_core::identity::IdentitySyncService;
use nanosiem_core::onboarding::OnboardingRepository;
use nanosiem_core::settings::local_auth::LocalAuthSettings;
use nanosiem_core::tuning::{NotificationService, TuningRepository};
use nanosiem_core::{
    DetectionService, DiskPressureService, DistributedDetectionScheduler, FeedService,
    IpAllowlistService, LogSourceService, LogTelemetryService, ParserService,
    QueryLibraryRepository, SearchService, SourceConfigService,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::detection_shared_runtime::TenantDetectionRuntimeLoop;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::{
    AgentConfigRegistry, MelodJobRepository, MelodService, MelodSessionRepository,
    TenantAiExecutionRepository, TenantAiRlsRuntime, TenantSearchRuntimeResolver,
    WizardSessionRepository,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::risk::RiskAnalyticsService;
use sqlx::PgPool;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::ApiConfig;
pub use schema_profile::{
    run_schema_refresh_loop, SchemaDriftStatus, SharedSchemaProfile, SCHEMA_REFRESH_INTERVAL,
};

// `CaseChangeEvent` was lifted to `enterprise::cases::CaseChangeEvent`
// in NAN-752 alongside the cases handler module. Re-exported here so the
// existing pg_notify consumer in `state/lifecycle.rs` keeps resolving the
// type through `super::CaseChangeEvent`.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::cases::CaseChangeEvent;

/// Get the Vector config directory from environment or use default
fn get_vector_config_dir() -> String {
    std::env::var("VECTOR_CONFIG_DIR").unwrap_or_else(|_| "config/vector".to_string())
}

/// NAN-3080: every registered task is supervised. Release panics unwind, so
/// without this a panicking (or returning) background loop would just stop
/// while the pod stays Ready. A supervised death exits the process
/// (`process_supervision`); the exit fn is injectable for tests.
#[derive(Clone)]
struct TaskRegistry {
    handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    shutdown: nanosiem_core::shutdown::ShutdownToken,
    exit: nanosiem_core::process_supervision::ExitFn,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            handles: Arc::default(),
            shutdown: nanosiem_core::shutdown::ShutdownToken::default(),
            exit: nanosiem_core::process_supervision::process_exit(),
        }
    }
}

impl TaskRegistry {
    fn supervise(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<()>,
        policy: nanosiem_core::process_supervision::TaskPolicy,
    ) -> tokio::task::JoinHandle<()> {
        nanosiem_core::process_supervision::supervise(
            name,
            handle,
            policy,
            self.shutdown.clone(),
            self.exit.clone(),
        )
    }

    async fn add_handle(&self, handle: tokio::task::JoinHandle<()>) -> bool {
        self.add_supervised(
            "background_loop",
            handle,
            nanosiem_core::process_supervision::TaskPolicy::Loop,
        )
        .await
    }

    async fn add_supervised(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<()>,
        policy: nanosiem_core::process_supervision::TaskPolicy,
    ) -> bool {
        let mut pending = Some(handle);
        {
            let mut handles = self.handles.write().await;
            if !self.shutdown.is_cancelled() {
                let handle = pending.take().expect("task handle must be present");
                handles.push(self.supervise(name, handle, policy));
            }
        }

        let Some(handle) = pending else {
            return true;
        };

        handle.abort();
        match handle.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => tracing::warn!(?error, "Late background task failed during shutdown"),
        }
        false
    }

    async fn spawn_tracked<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut handles = self.handles.write().await;
        if self.shutdown.is_cancelled() {
            return false;
        }

        // One-shot work (a feed sync): completing is fine, a panic is not.
        handles.push(self.supervise(
            "tracked_task",
            tokio::spawn(future),
            nanosiem_core::process_supervision::TaskPolicy::MayComplete,
        ));
        true
    }

    async fn begin_shutdown(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = self.handles.write().await;
        self.shutdown.cancel();
        std::mem::take(&mut *handles)
    }

    fn shutdown_token(&self) -> nanosiem_core::shutdown::ShutdownToken {
        self.shutdown.clone()
    }
}

/// Shared application state
///
/// PostgreSQL always owns control-plane state. Legacy mode also requires
/// ClickHouse; canonical lake mode routes event reads to the lake worker and
/// carries no ClickHouse runtime connection.
#[derive(Clone)]
pub struct AppState {
    /// PostgreSQL connection pool
    pub pool: PgPool,
    /// PostgreSQL plus the active event-backend compatibility handles
    pub dual_pool: DualPool,
    /// Search service
    pub search_service: SearchService,
    /// Flag-aware lookup service (NAN-1581). Shared with the lookup MANAGEMENT
    /// handlers so create/upload/row ops honor LOOKUP_STORAGE_BACKEND (registry
    /// ops always stay in Postgres; row ops follow the backend).
    pub lookup_service: nanosiem_core::lookup::LookupService,
    /// Detection service
    pub detection_service: DetectionService,
    /// Prevalence service (Clone-shared with the search + detection services).
    /// Held on AppState so the settings PUT handler can hot-reload prevalence
    /// config in-process without a restart (P1 audit).
    pub prevalence_service: nanosiem_core::prevalence::PrevalenceService,
    /// Detection scheduler (legacy, kept for trigger_rule API)
    /// Distributed detection scheduler (SKIP LOCKED, runs on all nodes)
    pub distributed_scheduler: Arc<RwLock<Option<Arc<DistributedDetectionScheduler>>>>,
    /// Node ID for distributed scheduling
    pub node_id: String,
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
    /// DB-authoritative publisher for immutable Vector configuration generations.
    pub vector_config_publisher: Arc<nanosiem_core::VectorConfigPublisher>,
    /// meloD AI assistant service (optional, dynamically reloadable)
    #[cfg(feature = "enterprise")]
    pub melod_service: Arc<RwLock<Option<Arc<MelodService>>>>,
    /// Risk analytics service (enterprise — RiskAnalyticsService is lifted to
    /// `enterprise::risk` in Phase 3.4 of NAN-744; open-core surfaces
    /// risk via `extensions::CloudRiskProvider` and the `Noop` impl)
    #[cfg(feature = "enterprise")]
    pub risk_service: RiskAnalyticsService,
    /// Query library repository
    pub query_library: QueryLibraryRepository,
    /// Materialized view generator
    pub materialized_view_generator: Arc<MaterializedViewGenerator>,
    /// API configuration
    pub config: Arc<ApiConfig>,
    /// Active schema profile, resolved ONCE at boot (NAN-2361). Read through
    /// [`AppState::schema_profile`]; never rebuild it per request — under the
    /// canonical lake backend building it parses the tenant source manifest.
    pub schema_profile: SharedSchemaProfile,
    // Authentication and RBAC services
    /// Authentication service
    pub auth_service: Arc<AuthService>,
    /// Tenant toggle for local password sign-in (NAN-2181). Read by the public
    /// `/api/auth/methods` endpoint and by the admin settings handlers; the
    /// enforcement copy lives inside `AuthService`.
    pub local_auth_settings: LocalAuthSettings,
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
    /// Per-source RBAC scope repository (restricted source_type registry +
    /// group grants). PG-backed; shared with the source-scopes admin handlers
    /// (NAN-1799). Mutations must call `source_scope_resolver.invalidate()`.
    pub source_scope_repo: SourceScopeRepository,
    /// Per-source RBAC scope resolver. Resolves a user's `ScopeSet` (deny-set
    /// of restricted source_types) from the registry + their group grants,
    /// FAIL-CLOSED on PG unavailability. Populated into `AuthContext` by the
    /// auth middleware; invalidated after any registry/grant mutation.
    pub source_scope_resolver: SourceScopeResolver,
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
    /// Atomic task registration and cooperative shutdown state.
    task_registry: TaskRegistry,
    /// PostgreSQL-backed job repository for async meloD operations
    #[cfg(feature = "enterprise")]
    pub melod_job_repo: MelodJobRepository,
    /// PostgreSQL-backed repository for wizard sessions
    #[cfg(feature = "enterprise")]
    pub wizard_session_repo: WizardSessionRepository,
    /// PostgreSQL-backed repository for meloD AI session persistence
    #[cfg(feature = "enterprise")]
    pub melod_session_repo: MelodSessionRepository,
    /// Startup-immutable tenant Search worker/job-store resolver for shared
    /// pivt. `None` fails the shared surface closed; dedicated handlers never
    /// consult this field and retain their historical singleton service.
    #[cfg(feature = "enterprise")]
    pub tenant_search_runtime_resolver: Option<Arc<TenantSearchRuntimeResolver>>,
    /// Exact-role, signed-transaction runtime for shared tenant AI ledgers.
    /// It is never backed by the API control pool.
    #[cfg(feature = "enterprise")]
    pub tenant_ai_rls_runtime: Option<Arc<TenantAiRlsRuntime>>,
    #[cfg(feature = "enterprise")]
    pub soar_service: Option<Arc<nanosiem_enterprise::soar::service::SoarService>>,
    /// Bounded tenant-signed Cases/Notebooks data plane. This is derived only
    /// from the startup-attested shared RLS runtime and remains absent in every
    /// dedicated/open-core profile. The shared router fails closed when it is
    /// absent; it never falls back to the legacy global repositories.
    #[cfg(feature = "enterprise")]
    pub tenant_case_notebook_service: Option<TenantCaseNotebookService>,
    /// Private service-owned shared detection operator runtime. It is present
    /// only when the exact worker registry, Redis namespace factory, runtime
    /// database role, and signing authority all pass startup validation.
    #[cfg(feature = "enterprise")]
    pub tenant_detection_runtime: Option<Arc<TenantDetectionRuntimeLoop>>,
    /// Private tenant scheduled-report runner (NAN-2361). Derived from the
    /// same worker registry / job-store factory / signed RLS runtime as the
    /// detection loop; absent in every dedicated profile and whenever any of
    /// those startup inputs is missing (the shared report routes then fail
    /// closed on `run`, while CRUD/read surfaces stay available).
    #[cfg(feature = "enterprise")]
    pub tenant_report_runtime: Option<Arc<nanosiem_enterprise::reports_shared_runtime::TenantReportRuntime>>,
    /// NAN-2361 wave 3: per-tenant outbound webhook delivery runner (transactional
    /// outbox claimed inside signed tenant transactions). `None` when the RLS
    /// runtime or the worker identity is missing; deliveries then stay queued.
    #[cfg(feature = "enterprise")]
    pub tenant_webhook_runtime: Option<Arc<nanosiem_enterprise::webhooks_shared_runtime::TenantWebhookRuntime>>,
    /// NAN-2361 wave 4: per-tenant identity directory sync (lake-observed identities).
    #[cfg(feature = "enterprise")]
    pub tenant_identity_sync_runtime: Option<Arc<nanosiem_enterprise::identity_shared_runtime::TenantIdentitySyncRuntime>>,
    /// NAN-2361 wave 4: platform erasure runner (execute-only runner login; lake rewrite + snapshot).
    #[cfg(feature = "enterprise")]
    pub tenant_erasure_runtime: Option<Arc<nanosiem_enterprise::erasure_shared_runtime::TenantErasureRuntime>>,
    /// NAN-2361 wave 5: shadow investigation runner for alert-derived tenant cases.
    #[cfg(feature = "enterprise")]
    pub tenant_shadow_investigation_runtime: Option<Arc<nanosiem_enterprise::shadow_investigation_shared_runtime::TenantShadowInvestigationRuntime>>,
    /// NAN-2361 wave 7: background AI triage of new tenant alerts (jobs binary).
    #[cfg(feature = "enterprise")]
    pub tenant_alert_triage_runtime: Option<Arc<nanosiem_enterprise::alert_triage_shared_runtime::TenantAlertTriageRuntime>>,
    /// NAN-2361 wave 8: scheduled tenant SIEM-health reports.
    #[cfg(feature = "enterprise")]
    pub tenant_siem_health_runtime: Option<Arc<nanosiem_enterprise::siem_health_shared_runtime::TenantSiemHealthRuntime>>,
    /// NAN-3196: shared feed-staleness monitor (started leader-only).
    #[cfg(feature = "enterprise")]
    pub tenant_observability_eval_runtime: Option<Arc<nanosiem_enterprise::observability_eval_shared_runtime::TenantObservabilityEvalRuntime>>,
    #[cfg(feature = "enterprise")]
    pub tenant_feed_staleness_runtime: Option<Arc<nanosiem_enterprise::feed_staleness_shared_runtime::TenantFeedStalenessRuntime>>,
    /// NAN-2361 wave 8: platform readiness attestor (activation receipt sets).
    #[cfg(feature = "enterprise")]
    pub tenant_platform_readiness_attestor: Option<Arc<nanosiem_enterprise::platform_readiness_shared_runtime::TenantPlatformReadinessAttestor>>,
    /// NAN-2361 wave 5: tenant lookup ingestion runner (scheduled + triggered feeds).
    #[cfg(feature = "enterprise")]
    pub tenant_lookup_ingestion_runtime: Option<Arc<nanosiem_enterprise::lookup_ingestion_shared_runtime::TenantLookupIngestionRuntime>>,
    /// NAN-2361 wave 5: queued prevalence/audit exports (tenant job ledger).
    #[cfg(feature = "enterprise")]
    pub tenant_export_runtime: Option<Arc<nanosiem_enterprise::exports_shared_runtime::TenantExportRuntime>>,
    /// NAN-2361 wave 5: per-tenant custom-enrichment sandbox executor.
    #[cfg(feature = "enterprise")]
    pub tenant_custom_enrichment_executor: Option<Arc<nanosiem_enterprise::custom_enrichment::TenantCustomEnrichmentExecutor>>,
    /// NAN-2361 wave 6: scheduled custom-enrichment runs.
    #[cfg(feature = "enterprise")]
    pub tenant_custom_enrichment_runtime: Option<Arc<nanosiem_enterprise::custom_enrichment_shared_runtime::TenantCustomEnrichmentRuntime>>,
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
    /// Named per-sender ingest tokens + Vector tokens file (NAN-3770)
    pub ingest_token_service: Arc<nanosiem_core::ingest_tokens::IngestTokenService>,
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
    /// Cross-replica per-user admission for the rule live tester. Each test
    /// fans out up to 16 ClickHouse queries, so production uses a Dragonfly
    /// lease instead of multiplying the cap by API replica count.
    pub rule_test_admission: Arc<nanosiem_core::RuleTestAdmission>,
    /// Shared shadow-investigation hook. On enterprise this is the live
    /// `ShadowInvestigationService` (also wired into detection_service /
    /// signal_processor). On open-core it's the no-op
    /// hook so the cases handlers can blindly call it. Held here so the
    /// per-request `CaseService` built in handlers can pick it up via
    /// `CasesAppState::shadow_investigation_hook`, which is what makes the
    /// add-alert re-triage path (NAN-1059) fire.
    pub shadow_investigation_hook: Arc<dyn nanosiem_core::extensions::ShadowInvestigationHook>,
}

impl AppState {
    /// Initialize authentication services
    fn init_auth_services(
        pool: PgPool,
        config: &ApiConfig,
    ) -> (
        Arc<AuthService>,
        Arc<TokenService>,
        Arc<ApiKeyService>,
        Arc<SessionService>,
        Arc<PermissionService>,
        UserRepository,
        GroupRepository,
        RoleRepository,
        bool,
    ) {
        // Check if auth is enabled (default: true in production, can be disabled for dev)
        let auth_enabled = std::env::var("AUTH_ENABLED")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        #[cfg(feature = "enterprise")]
        if config.deployment_mode.is_enterprise_shared() && !auth_enabled {
            panic!("CRITICAL SECURITY ERROR: AUTH_ENABLED cannot be disabled in enterprise_shared");
        }

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
        let api_key_repo = ApiKeyRepository::new(pool.clone());

        // Create token service with a shared JTI denylist across both instances
        let token_config = TokenConfig::new(jwt_secret.clone());
        let token_service = Arc::new(TokenService::new(token_config));
        let shared_denylist = token_service.revoked_jtis_handle();

        // The async constructor loads persisted revocations on the pool's
        // existing runtime before returning AppState. Never borrow this pool
        // from a temporary runtime or block an executor thread with join().

        // Second token service for AuthService shares the same denylist
        let token_config_for_auth = TokenConfig::new(jwt_secret);
        let token_service_for_auth =
            TokenService::new_with_shared_denylist(token_config_for_auth, shared_denylist);

        // Create auth service
        let auth_config = AuthConfig::default();
        let auth_service = AuthService::new(
            user_repo.clone(),
            session_repo.clone(),
            group_repo.clone(),
            token_service_for_auth,
            auth_config,
            LocalAuthSettings::new(pool.clone()),
        );
        #[cfg(feature = "enterprise")]
        let auth_service = if config.deployment_mode.is_enterprise_shared() {
            auth_service.with_enterprise_shared_tenants(
                nanosiem_core::auth::TenantMembershipResolver::new(pool.clone()),
            )
        } else {
            auth_service
        };
        let auth_service = Arc::new(auth_service);

        // Create API key service
        let api_key_service = Arc::new(ApiKeyService::new(
            api_key_repo,
            RateLimitRepository::new(pool.clone()),
        ));

        // Create session service
        let session_config = SessionConfig::default();
        let session_service = Arc::new(SessionService::new(
            session_repo,
            user_repo.clone(),
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

    /// Register an already-spawned task, stopping it if shutdown already won.
    /// Register a LONG-RUNNING background loop. It is supervised: if it
    /// panics, or returns while the process is not shutting down, the process
    /// exits non-zero so the orchestrator restarts it (NAN-3080).
    pub async fn add_task_handle(&self, handle: tokio::task::JoinHandle<()>) -> bool {
        self.task_registry.add_handle(handle).await
    }

    /// Register a supervised task with an explicit name and policy
    /// (`MayComplete` for a task that may legitimately finish; only a panic
    /// is then fatal).
    pub async fn add_supervised_task(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<()>,
        policy: nanosiem_core::process_supervision::TaskPolicy,
    ) -> bool {
        self.task_registry.add_supervised(name, handle, policy).await
    }

    /// Supervise tasks this state does NOT register (the leader-scoped
    /// schedulers, whose handles the leader loop aborts on leadership loss;
    /// aborting a supervisor aborts its task and never exits).
    pub fn supervise_tasks(
        &self,
        name: &'static str,
        handles: Vec<tokio::task::JoinHandle<()>>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        handles
            .into_iter()
            .map(|handle| {
                self.task_registry.supervise(
                    name,
                    handle,
                    nanosiem_core::process_supervision::TaskPolicy::Loop,
                )
            })
            .collect()
    }

    /// Atomically check shutdown state, spawn, and register a task.
    pub async fn spawn_tracked<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.task_registry.spawn_tracked(future).await
    }

    /// Shared cancellation token for background tasks owned by this process.
    pub fn shutdown_token(&self) -> nanosiem_core::shutdown::ShutdownToken {
        self.task_registry.shutdown_token()
    }

    /// The active schema profile. One atomic load and an `Arc` clone — this is
    /// the only form request handlers may use (NAN-2361; the old
    /// `config.schema_profile()` re-parsed the lake source manifest per call).
    pub fn schema_profile(&self) -> Arc<dyn nanosiem_core::schema::SchemaProfile> {
        self.schema_profile.load()
    }

    /// The schema profile for one tenant's request (NAN-2718). In
    /// hosted shared mode this is that tenant's own lake inventory from
    /// the tenant-keyed cache (or the canonical empty-inventory profile) and
    /// NEVER the process profile; dedicated deployments have one tenant and
    /// keep [`schema_profile`](Self::schema_profile).
    pub fn schema_profile_for_tenant(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nanosiem_core::schema::SchemaProfile> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = tenant_id;
            self.schema_profile()
        }
        #[cfg(feature = "enterprise")]
        {
            if self.config.deployment_mode.is_enterprise_shared() {
                nanosiem_core::schema::tenant_lake_schema::profile_for_tenant(tenant_id)
            } else {
                self.schema_profile()
            }
        }
    }
}

#[cfg(test)]
mod task_registry_tests {
    use super::*;
    use futures::poll;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    struct RunningGuard(Arc<AtomicBool>);

    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_wins_queued_registration_and_joins_late_handle() {
        let registry = TaskRegistry::default();
        let running = Arc::new(AtomicBool::new(true));
        let started = Arc::new(tokio::sync::Notify::new());
        let task_running = Arc::clone(&running);
        let task_started = Arc::clone(&started);
        let handle = tokio::spawn(async move {
            let _guard = RunningGuard(task_running);
            task_started.notify_one();
            std::future::pending::<()>().await;
        });
        started.notified().await;

        let registry_lock = registry.handles.write().await;
        let mut shutdown = Box::pin(registry.begin_shutdown());
        assert!(matches!(poll!(shutdown.as_mut()), Poll::Pending));
        let mut registration = Box::pin(registry.add_handle(handle));
        assert!(matches!(poll!(registration.as_mut()), Poll::Pending));
        drop(registry_lock);

        let snapshot = shutdown.await;
        let accepted = registration.await;

        assert!(snapshot.is_empty());
        assert!(!accepted);
        assert!(!running.load(Ordering::SeqCst));
        assert!(registry.handles.read().await.is_empty());
    }

    fn recording_registry() -> (TaskRegistry, Arc<std::sync::atomic::AtomicI32>) {
        let code = Arc::new(std::sync::atomic::AtomicI32::new(-1));
        let seen = Arc::clone(&code);
        let registry = TaskRegistry {
            exit: Arc::new(move |c| seen.store(c, Ordering::SeqCst)),
            ..TaskRegistry::default()
        };
        (registry, code)
    }

    async fn wait_for_exit(code: &std::sync::atomic::AtomicI32) -> i32 {
        for _ in 0..200 {
            let value = code.load(Ordering::SeqCst);
            if value != -1 {
                return value;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        code.load(Ordering::SeqCst)
    }

    /// NAN-3080: a registered loop that panics takes the process-exit path.
    #[tokio::test]
    async fn a_registered_loop_that_panics_exits_the_process() {
        let (registry, code) = recording_registry();
        let handle = tokio::spawn(async {
            tokio::task::yield_now().await;
            if std::hint::black_box(true) {
                panic!("detection scheduler loop panicked");
            }
        });
        assert!(registry.add_handle(handle).await);
        assert_eq!(
            wait_for_exit(&code).await,
            nanosiem_core::process_supervision::BACKGROUND_TASK_EXIT_CODE
        );
    }

    /// A tracked one-shot may complete; a panicking one is still fatal.
    #[tokio::test]
    async fn tracked_one_shots_may_complete_but_not_panic() {
        let (registry, code) = recording_registry();
        assert!(registry.spawn_tracked(async {}).await);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(code.load(Ordering::SeqCst), -1, "completion is fine");
        assert!(
            registry
                .spawn_tracked(async {
                    if std::hint::black_box(true) {
                        panic!("feed sync panicked");
                    }
                })
                .await
        );
        assert_eq!(
            wait_for_exit(&code).await,
            nanosiem_core::process_supervision::BACKGROUND_TASK_EXIT_CODE
        );
    }

    /// Loops that stop because shutdown began never trigger the exit.
    #[tokio::test]
    async fn loops_stopping_for_shutdown_do_not_exit() {
        let (registry, code) = recording_registry();
        let token = registry.shutdown_token();
        let handle = tokio::spawn(async move { token.cancelled().await });
        assert!(registry.add_handle(handle).await);
        let handles = registry.begin_shutdown().await;
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(code.load(Ordering::SeqCst), -1);
    }

    #[tokio::test]
    async fn pre_cancelled_spawn_is_never_polled() {
        let registry = TaskRegistry::default();
        let snapshot = registry.begin_shutdown().await;
        assert!(snapshot.is_empty());

        let polled = Arc::new(AtomicBool::new(false));
        let task_polled = Arc::clone(&polled);
        let accepted = registry
            .spawn_tracked(async move {
                task_polled.store(true, Ordering::SeqCst);
            })
            .await;
        tokio::task::yield_now().await;

        assert!(!accepted);
        assert!(!polled.load(Ordering::SeqCst));
        assert!(registry.handles.read().await.is_empty());
    }
}

// ----------------------------------------------------------------------------
// Enterprise handler trait bridges (NAN-751 Phase 2)
// ----------------------------------------------------------------------------
// The OIDC handler module was lifted from `nanosiem-api/src/handlers/oidc/`
// into `enterprise/src/handlers/oidc/`. Those handlers are generic
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

    fn local_auth_settings(&self) -> &LocalAuthSettings {
        &self.local_auth_settings
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::oidc::SharedOidcAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn user_repo(&self) -> &UserRepository {
        &self.user_repo
    }

    fn token_service(&self) -> &Arc<TokenService> {
        &self.token_service
    }

    fn deployment_is_enterprise_shared(&self) -> bool {
        self.config.deployment_mode.is_enterprise_shared()
    }

    fn tenant_oidc_allowed_origin(&self) -> Option<String> {
        std::env::var("NANOSIEM_BASE_URL").ok().or_else(|| {
            std::env::var("NANOSIEM_HOSTNAME")
                .ok()
                .map(|hostname| format!("https://{hostname}"))
        })
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::oidc::SharedOidcAdminAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn deployment_is_enterprise_shared(&self) -> bool {
        self.config.deployment_mode.is_enterprise_shared()
    }

    fn shared_oidc_admin_origin(&self) -> Option<String> {
        std::env::var("NANOSIEM_BASE_URL").ok().or_else(|| {
            std::env::var("NANOSIEM_HOSTNAME")
                .ok()
                .map(|hostname| format!("https://{hostname}"))
        })
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::shared_activation::SharedActivationAppState for AppState {
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn token_service(&self) -> &Arc<TokenService> {
        &self.token_service
    }

    fn deployment_is_enterprise_shared(&self) -> bool {
        self.config.deployment_mode.is_enterprise_shared()
    }

    fn follow_platform_catalogs(
        &self,
        tenant_id: uuid::Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            match nanosiem_enterprise::handlers::platform_catalog_follow::subscribe(self, tenant_id).await {
                Ok(Some(outcome)) => tracing::info!(%tenant_id, current = outcome.current(), "Platform catalogs followed after activation (background)"),
                Ok(None) => tracing::info!(%tenant_id, "No member may follow a platform catalog yet; the follow pass will"),
                Err(error) => tracing::warn!(%tenant_id, %error, "Platform catalog follow after activation failed; the follow pass retries"),
            }
        })
    }

    fn record_activation_audit(
        &self,
        tenant: nanosiem_core::auth::TrustedTenantContext,
        actor_id: uuid::Uuid,
        event: nanosiem_core::audit::AuditEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let runtime = self.tenant_ai_rls_runtime.as_ref().ok_or("no signed tenant runtime")?;
            runtime.tenant_pre_session_audit().record(&tenant, actor_id, &event).await.map_err(|error| error.to_string())
        })
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::shared_membership_acceptance::SharedMembershipAcceptanceAppState
    for AppState
{
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn deployment_is_enterprise_shared(&self) -> bool {
        self.config.deployment_mode.is_enterprise_shared()
    }

    fn shared_browser_origin(&self) -> Option<String> {
        std::env::var("NANOSIEM_BASE_URL").ok().or_else(|| {
            std::env::var("NANOSIEM_HOSTNAME")
                .ok()
                .map(|hostname| format!("https://{hostname}"))
        })
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::shared_automation_keys::SharedAutomationKeysAppState
    for AppState
{
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn deployment_is_enterprise_shared(&self) -> bool {
        self.config.deployment_mode.is_enterprise_shared()
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_cases_notebooks::EnterpriseSharedCasesNotebooksAppState
    for AppState
{
    fn deployment_mode(&self) -> &str {
        self.config.deployment_mode.system_api_value()
    }

    fn tenant_case_notebook_service(&self) -> Option<&TenantCaseNotebookService> {
        self.tenant_case_notebook_service.as_ref()
    }

    fn tenant_membership_resolver(&self) -> nanosiem_core::auth::TenantMembershipResolver {
        nanosiem_core::auth::TenantMembershipResolver::new(self.pool.clone())
    }

    fn tenant_entitlement_resolver(
        &self,
    ) -> nanosiem_core::tenant_entitlements::TenantEntitlementResolver {
        nanosiem_core::tenant_entitlements::TenantEntitlementResolver::new(self.pool.clone())
    }

    fn tenant_control_pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_detections::EnterpriseSharedDetectionsAppState for AppState {
    fn deployment_mode(&self) -> &str { self.config.deployment_mode.system_api_value() }
    fn detection_runtime(&self) -> Option<&TenantAiRlsRuntime> { self.tenant_ai_rls_runtime.as_deref() }
    fn detection_control_pool(&self) -> &PgPool { &self.pool }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_reports::EnterpriseSharedReportsAppState for AppState {
    fn report_runtime(&self) -> Option<&Arc<nanosiem_enterprise::reports_shared_runtime::TenantReportRuntime>> {
        self.tenant_report_runtime.as_ref()
    }
}

// NAN-2361 Rules dashboard port: the editor's interactive lake rule test and
// the rule-repository sync need a little more than the base detections state.
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_detection_editor::EnterpriseSharedDetectionEditorAppState for AppState {
    fn tenant_search_runtime_resolver(&self) -> Option<Arc<TenantSearchRuntimeResolver>> { self.tenant_search_runtime_resolver.clone() }
    fn base_detection_service(&self) -> &DetectionService { &self.detection_service }
    fn rule_test_admission(&self) -> &nanosiem_core::RuleTestAdmission { &self.rule_test_admission }
    fn tenant_schema_profile(&self, tenant_id: uuid::Uuid) -> Arc<dyn nanosiem_core::schema::SchemaProfile> { AppState::schema_profile_for_tenant(self, tenant_id) }
}
// NAN-2771: shared dashboard panels run on the same attested tenant Search
// resolver as the rule editor's interactive test.
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_dashboard_panels::EnterpriseSharedDashboardPanelsAppState for AppState {
    fn panel_search_runtime_resolver(&self) -> Option<Arc<TenantSearchRuntimeResolver>> { self.tenant_search_runtime_resolver.clone() }
}
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_rule_repositories::EnterpriseSharedRuleRepositoriesAppState for AppState {
    fn rule_repository_egress_enabled(&self) -> bool { self.config.egress_jobs_enabled() }
    fn rule_repository_search_resolver(&self) -> Option<Arc<TenantSearchRuntimeResolver>> { self.tenant_search_runtime_resolver.clone() }
}

// NAN-2361 wave 2: the remaining product areas on the tenant substrate.
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_sources::EnterpriseSharedSourcesAppState for AppState {
    fn tenant_ingest_domain(&self) -> String { "ingest.nano.rs".to_string() }
    fn credential_cipher(&self) -> Option<Arc<nanosiem_core::crypto::EncryptionService>> { Some(self.encryption_service.clone()) }
    /// NAN-2592: nano-main's content-free fulfilment wake-up, e.g.
    /// `https://app.nano.rs/api/shared-lake/ingest-credential-requests/wake`.
    /// Unset = no wake-up; nano-main's 5 s poll still fulfils every request.
    fn ingest_credential_wake_url(&self) -> Option<String> {
        static WAKE_URL: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        WAKE_URL
            .get_or_init(|| std::env::var("NANO_MAIN_INGEST_CREDENTIAL_WAKE_URL").ok().filter(|v| !v.trim().is_empty()))
            .clone()
    }
}
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_enrichment::EnterpriseSharedEnrichmentAppState for AppState {
    fn tenant_search_runtime_resolver(&self) -> Option<Arc<TenantSearchRuntimeResolver>> { self.tenant_search_runtime_resolver.clone() }
    fn platform_ip_enrichment(&self) -> Option<Arc<RwLock<nanosiem_core::enrichment::EnrichmentService>>> { Some(self.enrichment.clone()) }
    fn tenant_ip_context_enrichment(&self) -> Option<Arc<RwLock<nanosiem_core::enrichment::EnrichmentService>>> { Some(self.enrichment.clone()) }
    fn enrichment_cipher(&self) -> Option<Arc<nanosiem_core::crypto::EncryptionService>> { Some(self.encryption_service.clone()) }
    fn tenant_custom_enrichment_executor(&self) -> Option<Arc<nanosiem_enterprise::custom_enrichment::TenantCustomEnrichmentExecutor>> { self.tenant_custom_enrichment_executor.clone() }
}
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_melod::EnterpriseSharedMelodAppState for AppState {
    fn melod_rls_runtime(&self) -> Option<Arc<TenantAiRlsRuntime>> { self.tenant_ai_rls_runtime.clone() }
    fn melod_agent_registry(&self) -> &Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> { &self.agent_config_registry }
}
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_cases_extras::EnterpriseSharedCasesExtrasAppState for AppState {
    fn presence_tracker(&self) -> Option<&Arc<nanosiem_enterprise::PresenceTracker>> { Some(&self.presence_tracker) }
    fn tenant_audit_query_service(&self) -> Option<nanosiem_core::audit::TenantAuditQueryService> {
        self.tenant_ai_rls_runtime.as_ref().map(|r| r.tenant_audit_query_service())
    }
}

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_playbooks::EnterpriseSharedPlaybooksAppState for AppState {
    fn playbook_repository_egress_enabled(&self) -> bool { self.config.egress_jobs_enabled() }
    fn playbook_execution_search_resolver(&self) -> Option<Arc<TenantSearchRuntimeResolver>> { self.tenant_search_runtime_resolver.clone() }
    fn playbook_soar_service(&self) -> Option<Arc<nanosiem_enterprise::soar::service::SoarService>> { self.soar_service.clone() }
}
#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::enterprise_shared_marketplace::EnterpriseSharedMarketplaceAppState for AppState {
    fn encryption_service(&self) -> Option<Arc<nanosiem_core::crypto::EncryptionService>> { Some(self.encryption_service.clone()) }
    fn detection_code_target_egress_enabled(&self) -> bool { self.config.egress_jobs_enabled() }
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
impl nanosiem_enterprise::handlers::integration_generation::IntegrationGenerationAppState
    for AppState
{
    fn pool(&self) -> &PgPool {
        &self.pool
    }
    fn agent_config_registry(&self) -> &Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> {
        &self.agent_config_registry
    }
    fn melod_service(&self) -> &Arc<RwLock<Option<Arc<MelodService>>>> {
        &self.melod_service
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
    fn deployment_is_enterprise_shared(&self) -> bool {
        self.config.deployment_mode.is_enterprise_shared()
    }
    fn tenant_search_runtime_resolver(
        &self,
    ) -> Option<Arc<dyn nanosiem_enterprise::melod::TenantQuerySearchRuntime>> {
        self.tenant_search_runtime_resolver
            .as_ref()
            .map(|resolver| resolver.clone() as Arc<_>)
    }
    fn tenant_ai_execution_repository(&self) -> Option<TenantAiExecutionRepository> {
        self.tenant_ai_rls_runtime.as_ref().map(|runtime| {
            TenantAiExecutionRepository::new_shared(self.pool.clone(), Arc::clone(runtime))
        })
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

#[cfg(feature = "enterprise")]
impl nanosiem_enterprise::handlers::soar::SoarAppState for AppState {
    fn soar_service(&self)->Option<Arc<nanosiem_enterprise::soar::service::SoarService>> { self.soar_service.clone() }
}
