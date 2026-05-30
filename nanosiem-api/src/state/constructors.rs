// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;
use super::get_vector_config_dir;

use nanosiem_core::audit::{AuditEmitter, AuditQueryService};
use nanosiem_core::auth::{OidcRepository, OidcService};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::cases::ShadowInvestigationService;
use nanosiem_core::db::{ClickHouseMigrator, DualPool, DualPoolConfig, DualPoolError};
use nanosiem_core::detection::{
    MaterializedViewGenerator, RealtimeEvaluator, SignalProcessor, SignalProcessorConfig,
};
use nanosiem_core::enrichment::{EnrichmentRepository, EnrichmentService};
use nanosiem_core::identity::{IdentityRepository, IdentitySyncService};
use nanosiem_core::inputlookup::{InputLookupConfig, InputLookupService};
use nanosiem_core::lookup::{LookupRepository, LookupService};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::{
    AgentConfigRegistry, MelodJobRepository, MelodService, MelodSessionRepository,
    WizardSessionRepository,
};
use nanosiem_core::onboarding::OnboardingRepository;
use nanosiem_core::prevalence::PrevalenceService;
use nanosiem_core::tuning::{NotificationService, TuningRepository};
use nanosiem_core::{
    DetectionService, DiskPressureConfig, DiskPressureService, FeedService, IpAllowlistService,
    LogSourceService, LogTelemetryService, ParserService, QueryLibraryRepository, SearchService,
    SourceConfigService, generate_node_id,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::risk::RiskAnalyticsService;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::RwLock;

use crate::config::ApiConfig;

impl AppState {
    /// Create a new application state with DualPool (ClickHouse + PostgreSQL)
    ///
    /// Both pools are required:
    /// - ClickHouse is used for log storage and queries
    /// - PostgreSQL is used for metadata, configuration, and AI-related data
    ///
    /// Requirements: 1.1, 1.2
    pub fn new_with_dual_pool(dual_pool: DualPool, config: ApiConfig) -> Self {
        let pg_pool = dual_pool.postgres().clone();

        let enrichment_repo = EnrichmentRepository::new(pg_pool.clone());
        // NAN-1117: the IP enrichment payload + lookups + record-count stat are
        // ClickHouse-backed. The CH client MUST be attached here, before the
        // service is wrapped in the shared Arc<RwLock<>> below, because the
        // auto-sync scheduler (state/schedulers.rs) runs sync_ipinfo_lite
        // against that same Arc — without it the writer would error.
        let enrichment_service = EnrichmentService::with_defaults(enrichment_repo)
            .with_clickhouse(dual_pool.clickhouse().clone());

        // Create identity sync service. NAN-1117: the user_registry directory
        // feed (the dict payload + browse/lookup/stats reads + soft-delete
        // writes) is ClickHouse-backed, so the repo needs the CH client. PG is
        // retained for identity_providers config/creds.
        let identity_repo =
            IdentityRepository::new_with_clickhouse(pg_pool.clone(), dual_pool.clickhouse().clone());
        // NAN-1151: the identity-sync scheduler runs in this service, so the
        // enrichment-lane client is built from this process's env
        // (VECTOR_INGEST_URL / VECTOR_AUTH_TOKEN — provisioned in api.yaml +
        // docker-compose + the dev script).
        let identity_service = Arc::new(IdentitySyncService::new(
            identity_repo,
            nanosiem_core::enrichment::EnrichmentLaneClient::from_env(),
        ));

        // Create lookup service for search enrichment (uses PostgreSQL)
        let lookup_repo = LookupRepository::new(pg_pool.clone());
        let lookup_service = LookupService::new(lookup_repo);

        // Create prevalence service for search enrichment (uses ClickHouse)
        let prevalence_service =
            PrevalenceService::new(dual_pool.clickhouse().clone(), dual_pool.table_names());

        // Initialize auth services
        let (
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
        ) = Self::init_auth_services(pg_pool.clone(), &config);

        // Create OIDC repository and service
        let oidc_repo = OidcRepository::new(pg_pool.clone());
        let oidc_service = Arc::new(OidcService::new(
            oidc_repo.clone(),
            user_repo.clone(),
            group_repo.clone(),
            (*audit_repo).clone(),
        ));

        // Create notification service for tuning alerts
        let notification_service = Arc::new(NotificationService::new(pg_pool.clone()));

        // Create tuning repository for proposal management
        let tuning_repository = Arc::new(TuningRepository::new(pg_pool.clone()));

        // Create detection service with prevalence support (needed for materialized views)
        let detection_service = DetectionService::with_dual_pool_and_prevalence(
            &dual_pool,
            lookup_service.clone(),
            prevalence_service.clone(),
        );

        // Create materialized view generator for real-time detection rules
        // Uses admin client for DDL operations (CREATE/DROP MATERIALIZED VIEW)
        let mv_generator = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone());

        // Create audit emitter and query service for ClickHouse audit logging
        let audit_emitter = Arc::new(AuditEmitter::new(dual_pool.clone()));
        let audit_query_service = AuditQueryService::new(dual_pool.clone());

        // Create inputlookup service for URL-based enrichment
        let inputlookup_service = InputLookupService::new(InputLookupConfig::default());

        // Create search service and add inputlookup
        let mut search_service = SearchService::with_dual_pool_lookup_and_prevalence(
            &dual_pool,
            lookup_service,
            prevalence_service,
        );
        search_service.set_inputlookup_service(inputlookup_service);

        // Wire the enterprise `CloudRiskProvider` impl onto the search service
        // so cloud overview / dossier surfaces render risk badges. Open-core
        // builds keep the default `NoopCloudRiskProvider` (empty risk data).
        // NAN-873: the bridge impl shipped with NAN-744 Phase 2.5 but neither
        // the `impl CloudRiskProvider for RiskAnalyticsService` nor this setter
        // call ever landed, so production silently returned noop risk data.
        #[cfg(feature = "enterprise")]
        let risk_service = RiskAnalyticsService::with_dual_pool(&dual_pool);
        #[cfg(feature = "enterprise")]
        search_service.set_cloud_risk(Arc::new(risk_service.clone()));

        // Create melod_service Arc (initialized as None, reloaded later in reload_melod_service).
        // Open-core build skips the meloD handles entirely; shadow_investigation
        // wires NoopAiClient and the engine falls back to its non-AI path.
        #[cfg(feature = "enterprise")]
        let melod_service: Arc<RwLock<Option<Arc<MelodService>>>> = Arc::new(RwLock::new(None));

        // Agent config registry (initialized as None, populated in reload_melod_service)
        #[cfg(feature = "enterprise")]
        let agent_config_registry: Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> =
            Arc::new(RwLock::new(None));

        // Create shadow investigation service for auto-triage on new case creation.
        // Phase 3.2 (NAN-744): cases lifted to enterprise — the whole shadow
        // investigation hook only wires up in enterprise builds. Open-core
        // builds default to `NoopShadowInvestigationHook` on signal_processor /
        // realtime_evaluator / detection_service.
        #[cfg(feature = "enterprise")]
        let shadow_investigation = {
            let shadow_ai_client: Arc<dyn nanosiem_core::extensions::AiClient> = Arc::new(
                nanosiem_enterprise::melod::MelodAiClientBridge::live(
                    melod_service.clone(),
                    agent_config_registry.clone(),
                ),
            );
            Arc::new(ShadowInvestigationService::new(
                pg_pool.clone(),
                search_service.clone(),
                shadow_ai_client,
                3, // max 3 concurrent investigations
            ))
        };

        // Build the case-grouping hook for enterprise builds. NAN-744 Phase 2.3
        // added the `CaseGroupingHook` trait surface on detection_service /
        // signal_processor / realtime_evaluator, but the AppState wire-up was
        // never written — so saturn fired alerts but never created cases
        // (case_id stayed NULL). NAN-872 restores the wiring. Open-core
        // builds keep `NoopCaseGroupingHook` on all three services.
        #[cfg(feature = "enterprise")]
        let case_grouping_hook = nanosiem_enterprise::cases::case_grouping_hook(
            pg_pool.clone(),
            dual_pool.clone(),
            shadow_investigation.clone(),
        );

        // Create signal processor; in enterprise also wire shadow investigation
        // and case grouping.
        let signal_processor = {
            let sp = SignalProcessor::new(dual_pool.clone(), SignalProcessorConfig::default());
            #[cfg(feature = "enterprise")]
            let sp = sp
                .with_shadow_investigation(shadow_investigation.clone())
                .with_case_grouping(case_grouping_hook.clone());
            Arc::new(sp)
        };

        // Wire shadow investigation and case grouping into detection service
        // (enterprise only).
        #[cfg(feature = "enterprise")]
        let detection_service = detection_service
            .with_shadow_investigation(shadow_investigation.clone())
            .with_case_grouping(case_grouping_hook.clone());

        // Create realtime evaluator; enterprise wires shadow investigation
        // and case grouping too.
        #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
        let mut realtime_evaluator = RealtimeEvaluator::with_dual_pool(&dual_pool);
        #[cfg(feature = "enterprise")]
        {
            realtime_evaluator.set_shadow_investigation(shadow_investigation.clone());
            realtime_evaluator.set_case_grouping(case_grouping_hook);
        }

        // Trait-object form of the shadow hook stored on AppState so handler-
        // built CaseService instances can wire it up (NAN-1059 re-triage on
        // alert add). Enterprise hands over the live service; open-core uses
        // the no-op so the cases handlers can call into it unconditionally.
        let shadow_investigation_hook: Arc<dyn nanosiem_core::extensions::ShadowInvestigationHook> = {
            #[cfg(feature = "enterprise")]
            {
                shadow_investigation
            }
            #[cfg(not(feature = "enterprise"))]
            {
                Arc::new(nanosiem_core::extensions::NoopShadowInvestigationHook)
            }
        };

        // Create disk pressure service for automatic partition eviction
        let ingestion_paused = Arc::new(AtomicBool::new(false));
        let disk_pressure_service = {
            let dp_config = DiskPressureConfig::default();
            let dp_audit = AuditEmitter::new(dual_pool.clone());
            Arc::new(DiskPressureService::new(
                dual_pool.clickhouse_admin().clone(),
                pg_pool.clone(),
                dp_audit,
                dp_config,
                ingestion_paused.clone(),
            ))
        };

        let node_id = generate_node_id();
        #[cfg(feature = "enterprise")]
        let (case_events_tx, _) = tokio::sync::broadcast::channel(256);

        // NAN-948: wire `SourceConfigService::update_dynamic_router` to
        // the same deploy lock that `ParserService`'s inner
        // `VectorConfigManager` uses. Without this, the two services'
        // read-mutate-write of `_router.toml` can interleave and the
        // later writer clobbers the earlier one's changes.
        let parser_service = ParserService::with_vector_config_dir(
            pg_pool.clone(),
            get_vector_config_dir(),
        );
        let source_config_service = SourceConfigService::with_vector_config_dir(
            pg_pool.clone(),
            get_vector_config_dir(),
        )
        .with_deploy_lock(parser_service.deploy_lock());

        Self {
            // Services using DualPool for ClickHouse log queries
            search_service,
            detection_service,
            realtime_evaluator: Arc::new(realtime_evaluator),
            feed_service: FeedService::with_dual_pool(&dual_pool),

            // Services using PostgreSQL only (or with optional ClickHouse for stats)
            distributed_scheduler: Arc::new(RwLock::new(None)),
            node_id,
            enrichment: Arc::new(RwLock::new(enrichment_service)),
            parser_service,
            log_source_service: LogSourceService::with_dual_pool_and_config_dir(
                &dual_pool,
                get_vector_config_dir(),
            ),
            // ClickHouse-backed rollup of per-source_type events/bytes/last_event_at.
            // Reads through `table_names.read("logs_per_source_5m")` so it picks
            // the `_distributed` wrapper automatically in cluster mode (see
            // `DISTRIBUTED_TABLE_SET` in `nanosiem-core/src/db/dual_pool.rs`).
            log_telemetry_service: LogTelemetryService::new(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
            ),
            source_config_service,
            #[cfg(feature = "enterprise")]
            melod_service,
            // Risk service needs DualPool for time-windowed queries (findings are in ClickHouse)
            // Same instance is also wired into search_service as a CloudRiskProvider above (NAN-873).
            #[cfg(feature = "enterprise")]
            risk_service,
            query_library: QueryLibraryRepository::new(pg_pool.clone()),

            // Store both pools
            #[cfg(feature = "enterprise")]
            melod_job_repo: MelodJobRepository::new(pg_pool.clone()),
            #[cfg(feature = "enterprise")]
            wizard_session_repo: WizardSessionRepository::new(pg_pool.clone()),
            #[cfg(feature = "enterprise")]
            melod_session_repo: MelodSessionRepository::new(pg_pool.clone()),
            ip_allowlist_service: Arc::new(IpAllowlistService::new(pg_pool.clone())),
            onboarding_repo: OnboardingRepository::new(pg_pool.clone()),
            pool: pg_pool,
            dual_pool,
            materialized_view_generator: Arc::new(mv_generator),
            config: Arc::new(config),

            // Auth services
            auth_service,
            token_service,
            api_key_service,
            session_service,
            permission_service,
            user_repo,
            group_repo,
            role_repo,
            audit_repo,
            oidc_repo,
            oidc_service,
            auth_enabled,
            notification_service,
            tuning_repository,
            task_handles: Arc::new(RwLock::new(Vec::new())),
            // Audit emitter and query service for ClickHouse audit logging
            audit_emitter,
            audit_query_service,
            // Agent config registry initialized in reload_melod_service
            #[cfg(feature = "enterprise")]
            agent_config_registry,
            // Signal processor for bridging ClickHouse signals to PostgreSQL alerts
            signal_processor,
            // Disk pressure service for automatic partition eviction
            disk_pressure_service,
            ingestion_paused,
            identity_service,
            demo_service: None,
            license_status: Arc::new(RwLock::new(nanosiem_core::license::LicenseStatus::default())),
            encryption_service: Arc::new(nanosiem_core::crypto::EncryptionService::from_env()),
            #[cfg(feature = "enterprise")]
            case_events_tx,
            #[cfg(feature = "enterprise")]
            presence_tracker: Arc::new(nanosiem_enterprise::PresenceTracker::new()),
            marketplace_coverage_cache: Arc::new(
                nanosiem_core::marketplace::MarketplaceCoverageCache::new(),
            ),
            search_result_cache: None,
            rule_test_in_flight: Arc::new(dashmap::DashMap::new()),
            shadow_investigation_hook,
        }
    }

    /// Try to create application state with DualPool from environment
    ///
    /// Both ClickHouse and PostgreSQL are required — boot fails fast if either is
    /// unavailable. The PG-only fallback was removed in NAN-800.
    ///
    /// Requirements: 1.1, 1.2, 1.3, 1.5
    pub async fn try_with_dual_pool(config: ApiConfig) -> Result<Self, DualPoolError> {
        // Try to load DualPool configuration from environment
        let dual_config = DualPoolConfig::from_env()?;

        // Initialize DualPool
        let mut dual_pool = DualPool::new(&dual_config).await?;

        // Run PostgreSQL migrations. The helper handles fresh-init detection,
        // snapshot apply, and legacy-history backfill (NAN-749) in addition
        // to the canonical sqlx::migrate!() pass. Enterprise overlay stays
        // gated below because nanosiem-core does not see the enterprise
        // feature flag.
        let pg_pool: &sqlx::PgPool = dual_pool.postgres();
        nanosiem_core::db::run_postgres_migrations(pg_pool)
            .await
            .map_err(|e| {
                DualPoolError::PostgresConnectionError(format!("Migration failed: {}", e))
            })?;
        // NAN-747 Phase 6: apply the enterprise schema overlay only on
        // enterprise builds. Idempotent (CREATE TABLE IF NOT EXISTS, etc.)
        // so it's safe against existing tenants whose enterprise tables
        // were already created by the unified `migrations/postgres/`
        // history. ignore_missing(true) so the overlay's validator
        // tolerates the open history's applied rows.
        #[cfg(feature = "enterprise")]
        {
            tracing::info!("Running enterprise PostgreSQL overlay migrations...");
            let mut overlay_migrator = sqlx::migrate!("../migrations/postgres-enterprise");
            overlay_migrator.set_ignore_missing(true);
            overlay_migrator
                .run(pg_pool)
                .await
                .map_err(|e| {
                    DualPoolError::PostgresConnectionError(format!(
                        "Enterprise overlay migration failed: {}",
                        e
                    ))
                })?;
            tracing::info!("Enterprise PostgreSQL overlay complete");
        }

        // Apply tier from NANO_TIER environment variable if set
        if let Ok(tier_str) = std::env::var("NANO_TIER") {
            if let Ok(tier) = tier_str.parse::<nanosiem_core::OrganizationTier>() {
                let tier_settings = nanosiem_core::TierSettings::new(pg_pool.clone());
                match tier_settings.set_tier(tier).await {
                    Ok(limits) => tracing::info!(
                        tier = %tier,
                        max_data_sources = ?limits.max_data_sources,
                        max_detection_rules = ?limits.max_detection_rules,
                        max_team_members = ?limits.max_team_members,
                        "Organization tier set from NANO_TIER env var"
                    ),
                    Err(e) => tracing::warn!(error = %e, "Failed to apply NANO_TIER env var"),
                }
            } else {
                tracing::warn!(
                    tier = %tier_str,
                    "Invalid NANO_TIER value. Valid options: unrestricted, hobby, startup, growth, team, starter, pro, enterprise"
                );
            }
        }

        // ClickHouse schema is managed out-of-process by the clickhouse_migrator
        // binary (NAN-607): K8s pre-deploy Job, or the docker-compose
        // `clickhouse-migrate` service. We only verify the schema is up-to-date
        // here — DDL never executes from the api hot path. A stale schema is a
        // hard startup failure; serving traffic against a behind schema masks
        // upstream deploy bugs and risks corruption.
        tracing::info!("Verifying ClickHouse schema version...");
        let (admin_client, _is_admin) = dual_config.create_admin_clickhouse_client();
        let ch_migrator =
            ClickHouseMigrator::new(admin_client, dual_config.clickhouse_database.clone());
        let ch_migrations_path = std::path::Path::new("./clickhouse");
        ch_migrator
            .check_schema_up_to_date(ch_migrations_path)
            .await
            .map_err(|e| DualPoolError::SchemaBehind(e.to_string()))?;
        // NAN-747 Phase 6: when enterprise ClickHouse overlay migrations
        // start landing under `./clickhouse-enterprise/`, also verify
        // them here on enterprise builds. Today the directory is empty,
        // so the check is a no-op and gated to avoid spurious
        // "directory not found" warnings on open builds.
        #[cfg(feature = "enterprise")]
        {
            let ch_enterprise_path = std::path::Path::new("./clickhouse-enterprise");
            if ch_enterprise_path.exists()
                && std::fs::read_dir(ch_enterprise_path)
                    .map(|mut it| it.any(|e| {
                        e.ok()
                            .and_then(|d| d.file_name().to_str().map(str::to_string))
                            .map(|name| name.ends_with(".sql"))
                            .unwrap_or(false)
                    }))
                    .unwrap_or(false)
            {
                ch_migrator
                    .check_schema_up_to_date(ch_enterprise_path)
                    .await
                    .map_err(|e| DualPoolError::SchemaBehind(e.to_string()))?;
            }
        }
        tracing::info!("ClickHouse schema version OK");

        // Re-detect cluster state. DualPool::new() runs before this check, so
        // is_clustered may reflect the pre-distributed-tables view; the
        // pre-deploy migrator creates distributed tables and we need a
        // post-create read for the runtime pool.
        dual_pool
            .refresh_cluster_state(&dual_config.clickhouse_database)
            .await;

        tracing::info!("DualPool initialized - using ClickHouse for log storage");
        let mut state = Self::new_with_dual_pool(dual_pool, config);

        // Swap the in-process presence tracker + marketplace coverage cache
        // for Redis-backed versions so cross-replica state is consistent.
        // Dragonfly is deployed alongside the API in prod; both fall back
        // to their disabled/in-memory variants if Redis is unreachable.
        //
        // - PresenceTracker — see NAN-420.
        // - MarketplaceCoverageCache (NAN-609) — without it, every fresh
        //   browser tab on every replica re-runs the ~10s coverage SQL.
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            if !redis_url.is_empty() {
                #[cfg(feature = "enterprise")]
                {
                    state.presence_tracker = std::sync::Arc::new(
                        nanosiem_enterprise::PresenceTracker::try_with_redis_url(&redis_url).await,
                    );
                }
                state.marketplace_coverage_cache = std::sync::Arc::new(
                    nanosiem_core::marketplace::MarketplaceCoverageCache::try_with_redis_url(
                        &redis_url,
                    )
                    .await,
                );
                // NAN-702: same Dragonfly powers the panel-query result cache
                // so dashboard refreshes hit the same compressed responses the
                // search HTTP handler caches.
                state.search_result_cache =
                    nanosiem_search::cache::SearchResultCache::connect(&redis_url).await;
                tracing::info!(redis_url = %redis_url, "Case presence tracker + marketplace coverage cache + panel result cache initialized with Redis URL");

                // NAN-682: wire the same Dragonfly into the JWT JTI denylist
                // so logout-driven revocations propagate across API replicas.
                // Both `token_service` and the AuthService's internal copy
                // share the local DashMap denylist already; here we additionally
                // share the Redis handle so cross-pod revocation works.
                match nanosiem_core::auth::token::redis_denylist_from_url(&redis_url).await {
                    Ok(denylist) => {
                        state.token_service.set_redis(denylist.clone());
                        state.auth_service.token_service().set_redis(denylist);
                        tracing::info!("JWT JTI denylist initialized with Redis (cross-pod revocation enabled)");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to initialize Redis JTI denylist; falling back to per-pod denylist");
                    }
                }
            }
        } else {
            tracing::info!(
                "REDIS_URL not set — case presence tracker is in-memory only, marketplace coverage cache is disabled, and JWT JTI denylist is per-pod (single-node mode)"
            );
        }

        Ok(state)
    }
}
