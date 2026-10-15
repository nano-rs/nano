// SPDX-License-Identifier: AGPL-3.0-or-later

use super::get_vector_config_dir;
use super::{AppState, TaskRegistry};

use nanosiem_core::audit::{AuditEmitter, AuditQueryService};
use nanosiem_core::auth::source_scope_resolver::SourceScopeResolver;
#[cfg(feature = "enterprise")]
use nanosiem_core::auth::TenantMembershipResolver;
use nanosiem_core::auth::{OidcRepository, OidcService};
use nanosiem_core::db::repository::SourceScopeRepository;
use nanosiem_core::db::{ClickHouseMigrator, DualPool, DualPoolConfig, DualPoolError};
use nanosiem_core::detection::{MaterializedViewGenerator, SignalProcessor, SignalProcessorConfig};
use nanosiem_core::enrichment::{EnrichmentRepository, EnrichmentService, LakeIpContextClient};
use nanosiem_core::identity::{
    IdentityRepository, IdentitySyncService, LakeIdentityClient, LeanIdentityDirectoryClient,
};
use nanosiem_core::inputlookup::{InputLookupConfig, InputLookupService};
use nanosiem_core::lookup::LookupService;
use nanosiem_core::onboarding::OnboardingRepository;
use nanosiem_core::prevalence::PrevalenceService;
use nanosiem_core::search::RedisJobStore;
use nanosiem_core::tuning::{NotificationService, TuningRepository};
use nanosiem_core::{
    generate_node_id, DetectionService, DiskPressureConfig, DiskPressureService, FeedService,
    IpAllowlistService, LogSourceService, LogTelemetryService, ParserService,
    QueryLibraryRepository, SearchService, SourceConfigService,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::cases::ShadowInvestigationService;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::{
    AgentConfigRegistry, MelodJobRepository, MelodService, MelodSessionRepository,
    WizardSessionRepository,
};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::risk::RiskAnalyticsService;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::ApiConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostgresMigrationAuthority {
    Runtime,
    ExternalJob,
}

impl PostgresMigrationAuthority {
    fn from_values(authority: Option<&str>, deployment_mode: Option<&str>) -> Result<Self, String> {
        match authority {
            None | Some("") | Some("runtime") => Ok(Self::Runtime),
            Some("external_job") if deployment_mode == Some("enterprise_shared") => {
                Ok(Self::ExternalJob)
            }
            Some("external_job") => Err(
                "NANOSIEM_POSTGRES_MIGRATION_AUTHORITY=external_job requires DEPLOYMENT_MODE=enterprise_shared"
                    .to_string(),
            ),
            Some(other) => Err(format!(
                "invalid NANOSIEM_POSTGRES_MIGRATION_AUTHORITY value: {other}"
            )),
        }
    }

    fn from_env() -> Result<Self, String> {
        let authority = std::env::var("NANOSIEM_POSTGRES_MIGRATION_AUTHORITY").ok();
        let deployment_mode = std::env::var("DEPLOYMENT_MODE").ok();
        Self::from_values(authority.as_deref(), deployment_mode.as_deref())
    }
}

#[cfg(test)]
mod postgres_migration_authority_tests {
    use super::PostgresMigrationAuthority;

    #[cfg(feature = "enterprise")]
    #[test]
    fn external_job_is_scoped_to_enterprise_shared() {
        assert_eq!(
            PostgresMigrationAuthority::from_values(
                Some("external_job"),
                Some("enterprise_shared")
            )
            .unwrap(),
            PostgresMigrationAuthority::ExternalJob
        );
        assert!(
            PostgresMigrationAuthority::from_values(Some("external_job"), Some("enterprise"))
                .is_err()
        );
    }

    #[test]
    fn runtime_is_the_only_default_authority() {
        assert_eq!(
            PostgresMigrationAuthority::from_values(None, None).unwrap(),
            PostgresMigrationAuthority::Runtime
        );
        assert!(PostgresMigrationAuthority::from_values(Some("skip"), None).is_err());
    }
}

impl AppState {
    /// Create a new application state with DualPool (ClickHouse + PostgreSQL)
    ///
    /// Both pools are required:
    /// - ClickHouse is used for log storage and queries
    /// - PostgreSQL is used for metadata, configuration, and AI-related data
    ///
    /// `schema_profile` is resolved once by the caller (NAN-2361) and shared by
    /// every service and request handler; it is never rebuilt per request.
    ///
    /// Requirements: 1.1, 1.2
    pub async fn new_with_dual_pool(
        dual_pool: DualPool,
        config: ApiConfig,
        schema_profile: Arc<dyn nanosiem_core::schema::SchemaProfile>,
    ) -> Self {
        let pg_pool = dual_pool.postgres().clone();

        let enrichment_repo = EnrichmentRepository::new(pg_pool.clone());
        // Legacy deployments retain the ClickHouse IP_TRIE dictionary. The
        // canonical lake lane serves the same IPinfo Lite fields directly from
        // a memory-mapped immutable MMDB generation, so lookups and stats do not
        // depend on ClickHouse availability. The saved operator URL can remain
        // CSV; the lake sync derives IPinfo's official MMDB sibling.
        let mut enrichment_service = EnrichmentService::with_defaults(enrichment_repo.clone())
            .with_clickhouse(dual_pool.clickhouse().clone());
        if config.canonical_lake_ocsf {
            let source_enabled = enrichment_repo
                .get_source("ipinfo_lite")
                .await
                .map(|source| source.enabled)
                .unwrap_or(false);
            let mmdb_path = std::env::var("NANO_IPINFO_MMDB_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("data/enrichment/ipinfo_lite.mmdb"));
            enrichment_service = enrichment_service
                // This stable file is application-owned and every writer
                // validates a complete candidate before atomic publication.
                // A launch-time digest would become stale after the first
                // successful online/air-gap rotation and make restarts fail.
                // Bronze alone may enforce an optional bootstrap digest before
                // it consumes an externally pre-provisioned first generation.
                .with_ipinfo_mmdb(mmdb_path, None, source_enabled)
                .unwrap_or_else(|error| panic!("invalid IPinfo MMDB serving snapshot: {error}"));
            if std::env::var("DEPLOYMENT_MODE").as_deref() == Ok("enterprise_shared") {
                enrichment_service = enrichment_service.with_request_ip_context(
                    nanosiem_core::enrichment::lake_ip_context::LakeIpContextResolver::new(
                        std::env::var_os("NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE")
                            .map(PathBuf::from),
                    ),
                );
            } else {
                enrichment_service = enrichment_service.with_lake_ip_context(
                    LakeIpContextClient::from_env().unwrap_or_else(|error| {
                        panic!("invalid lake custom IP context configuration: {error}")
                    }),
                );
            }
        }

        // Create identity sync service. Provider config/credentials/sync status
        // remain in PostgreSQL. The directory payload follows the selected data
        // plane: see `default_identity_storage_backend`.
        let identity_backend = std::env::var("IDENTITY_STORAGE_BACKEND").unwrap_or_else(|_| {
            default_identity_storage_backend(
                nanosiem_core::schema::log_query_backend_is_lake(),
                nanosiem_core::search::lake_cell::trusted_local_from_env(),
            )
            .to_string()
        });
        let identity_repo = match identity_backend.to_ascii_lowercase().as_str() {
            "postgres" => IdentityRepository::new(pg_pool.clone()),
            "lake" => IdentityRepository::new_with_lake(
                pg_pool.clone(),
                LakeIdentityClient::from_env()
                    .unwrap_or_else(|error| panic!("invalid lake identity configuration: {error}")),
            ),
            "lean_directory" => IdentityRepository::new_with_lean_directory(
                pg_pool.clone(),
                LeanIdentityDirectoryClient::from_env().unwrap_or_else(|error| {
                    panic!("invalid lean identity directory configuration: {error}")
                }),
            ),
            "clickhouse" => IdentityRepository::new_with_clickhouse(
                pg_pool.clone(),
                dual_pool.clickhouse().clone(),
            ),
            other => {
                panic!(
                    "IDENTITY_STORAGE_BACKEND must be lean_directory, lake, clickhouse, or postgres; got {other}"
                );
            }
        };
        // NAN-1151: the identity-sync scheduler runs in this service, so the
        // enrichment-lane client is built from this process's env
        // (VECTOR_INGEST_URL / VECTOR_AUTH_TOKEN — provisioned in api.yaml +
        // docker-compose + the dev script).
        let identity_service = Arc::new(IdentitySyncService::new(
            identity_repo,
            nanosiem_core::enrichment::EnrichmentLaneClient::from_env(),
        ));

        // Create lookup service for search enrichment. NAN-1581: lookup row data
        // follows LOOKUP_STORAGE_BACKEND. An unset flag uses PostgreSQL in the
        // primary lake lane and ClickHouse in legacy deployments; the registry
        // always stays in Postgres. The backfill remains available for legacy
        // ClickHouse lookup deployments.
        let lookup_service = LookupService::with_backend(
            nanosiem_core::lookup::LookupStorageBackend::from_env(),
            pg_pool.clone(),
            dual_pool.clickhouse().clone(),
        );
        // NAN-1581: the lookup MANAGEMENT handlers (create/upload/rows) must use
        // this same flag-aware instance so LOOKUP_STORAGE_BACKEND applies. Clone
        // it now (cheap — Arc inside) for AppState before `lookup_service` is
        // moved into `search_service` below.
        let lookup_service_for_state = lookup_service.clone();

        // Create prevalence service for search enrichment (uses ClickHouse).
        // P1 audit: build via `with_database_config` so this long-lived instance
        // (shared into SearchService + DetectionService below) honors the
        // persisted admin config at boot instead of the hardcoded defaults
        // (rarity_threshold=3, all tracking on). Otherwise detection `is_rare`
        // and search `prevalence_score` ignore the admin config until restart.
        // NAN-2361 wave-4: hosted-shared prevalence is per-tenant (lake
        // worker registry: rarity threshold / snapshots per assignment) and
        // `system_settings` is a deployment-global table the CONTROL login
        // holds nothing on (boot logged "permission denied for table
        // system_settings"); the tenant page answers a platform verdict. Skip
        // the global load there instead of warning on every boot.
        #[cfg(feature = "enterprise")]
        let shared_profile = config.deployment_mode.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_profile = false;
        let prevalence_service = if shared_profile {
            PrevalenceService::with_config(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
                nanosiem_core::prevalence::PrevalenceConfig::default(),
            )
        } else {
            PrevalenceService::with_database_config(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
                &pg_pool,
            )
            .await
        };
        // Keep a Clone-shared handle for AppState so the settings PUT handler can
        // hot-reload config in-process. Clone shares the Arc<RwLock<config>>, so
        // updating this handle updates the search + detection copies too.
        let prevalence_service_for_state = prevalence_service.clone();

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
            auth_enabled,
        ) = Self::init_auth_services(pg_pool.clone(), &config);

        // Keep both the pool sockets and the revocation load on this runtime.
        // A temporary runtime can leave pooled sockets bound to a destroyed IO
        // driver; joining its thread also blocks single-worker API executors.
        // Await completion before exposing AppState, preserving startup order.
        match nanosiem_core::auth::token::load_revoked_tokens(
            &pg_pool,
            &token_service.revoked_jtis_handle(),
        )
        .await
        {
            Ok(count) if count > 0 => {
                tracing::info!(count, "Loaded persisted token revocations from database");
            }
            Err(error) => {
                tracing::warn!(%error, "Failed to load persisted token revocations (table may not exist yet)");
            }
            _ => {}
        }

        // NAN-2181: read handle for the local-password toggle. AuthService holds
        // its own copy for enforcement; this one serves the public
        // /api/auth/methods probe and the admin settings handlers.
        let local_auth_settings =
            nanosiem_core::settings::local_auth::LocalAuthSettings::new(pg_pool.clone());

        // Create OIDC repository and service
        let oidc_repo = OidcRepository::new(pg_pool.clone());
        let oidc_service = Arc::new(OidcService::new(
            oidc_repo.clone(),
            user_repo.clone(),
            group_repo.clone(),
        ));

        // Create notification service for tuning alerts
        let notification_service = Arc::new(NotificationService::new(pg_pool.clone()));

        // Create tuning repository for proposal management
        let tuning_repository = Arc::new(TuningRepository::new(pg_pool.clone()));

        // Create detection service with prevalence support (needed for materialized views).
        // The active schema profile (UDM default | OCSF, from NANO_SCHEMA_PROFILE)
        // is threaded through BOTH halves of the scheduled detection path: the
        // internal SearchService (rule query targets the profile's logs table and
        // resolves fields under the active schema) and entity extraction
        // (auto-detect grouping/scoring uses the profile's entity-extraction
        // order). NAN-1241 Phase 5.
        // NAN-1546: wire the webhook service so scheduled detection alerts
        // actually fire webhooks. Before this, `with_webhook_service` had zero
        // callers and `webhook_service` was always `None`, so real alerts fired
        // nothing — only the manual "Send Test" path worked. The scheduler
        // reuses this exact instance (schedulers.rs), so this is the single
        // wiring point for the scheduled path. Uses the same env-derived
        // encryption as the settings handler (decrypts headers/HMAC secrets).
        let detection_service = DetectionService::with_dual_pool_prevalence_and_profile(
            &dual_pool,
            lookup_service.clone(),
            prevalence_service.clone(),
            schema_profile.clone(),
        )
        .with_webhook_service(nanosiem_core::webhooks::WebhookService::new(
            nanosiem_core::webhooks::WebhookRepository::new(pg_pool.clone()),
        ));

        // Create materialized view generator for real-time detection rules.
        // Uses admin client for DDL operations (CREATE/DROP MATERIALIZED VIEW).
        // The profile parameterizes DDL field-name validation + risk-entity
        // auto-detection; the generated MV body itself stays UDM-shaped (real-time
        // MV on OCSF is a Phase 5+ follow-up — see materialized_view.rs).
        let mv_generator = MaterializedViewGenerator::new(dual_pool.clickhouse_admin().clone())
            .with_profile(schema_profile.clone());

        // Create audit emitter and query service for ClickHouse audit logging
        let audit_emitter = Arc::new(AuditEmitter::new(dual_pool.clone()));
        let audit_query_service = AuditQueryService::new(dual_pool.clone());

        // Create inputlookup service for URL-based enrichment. The internal
        // lookup layer is wired so `| inputlookup <internal_table>` reads the
        // CH/PG-backed lookup table directly (NAN-1581 Phase 5).
        let inputlookup_service = InputLookupService::new(InputLookupConfig::default())
            .with_lookup_service(Arc::new(lookup_service.clone()));

        // Create search service and add inputlookup. The active schema profile
        // (UDM default | OCSF, from NANO_SCHEMA_PROFILE) selects the FROM logs
        // table and is injected into the SQL generator so default-view
        // projection / field resolution follow the active schema (NAN-1241).
        let mut search_service = SearchService::with_dual_pool_lookup_and_prevalence_and_profile(
            &dual_pool,
            lookup_service,
            prevalence_service,
            schema_profile.clone(),
        );
        search_service.set_inputlookup_service(inputlookup_service);

        // Wire the enterprise `CloudRiskProvider` impl onto the search service
        // so cloud overview / dossier surfaces render risk badges. Open-core
        // builds keep the default `NoopCloudRiskProvider` (empty risk data).
        // NAN-873: the bridge impl shipped with NAN-744 Phase 2.5 but neither
        // the `impl CloudRiskProvider for RiskAnalyticsService` nor this setter
        // call ever landed, so production silently returned noop risk data.
        #[cfg(feature = "enterprise")]
        let risk_service = if config.deployment_mode.is_enterprise_shared() {
            // Shared risk data routes remain closed until the complete risk
            // vertical resolves a per-request TrustedTenantContext. Do not
            // initialize the legacy NANO_LAKE_TENANT_ID-pinned client in this
            // process: doing so would make one tenant ambient for every API
            // request even though the provider itself is not installed.
            RiskAnalyticsService::with_dual_pool_without_lake(&dual_pool)
        } else {
            RiskAnalyticsService::with_dual_pool(&dual_pool)
        };
        #[cfg(feature = "enterprise")]
        if !config.deployment_mode.is_enterprise_shared() {
            // The legacy risk repository is deployment-global. Shared mode
            // keeps the provider at NoopCloudRiskProvider until the complete
            // risk vertical uses signed tenant transactions and per-tenant
            // lake identities.
            search_service.set_cloud_risk(Arc::new(risk_service.clone()));
        }

        // Create melod_service Arc (initialized as None, reloaded later in reload_melod_service).
        // Open-core build skips the meloD handles entirely; shadow_investigation
        // wires NoopAiClient and the engine falls back to its non-AI path.
        #[cfg(feature = "enterprise")]
        let melod_service: Arc<RwLock<Option<Arc<MelodService>>>> = Arc::new(RwLock::new(None));

        // Agent config registry (initialized as None, populated in reload_melod_service)
        #[cfg(feature = "enterprise")]
        let agent_config_registry: Arc<RwLock<Option<Arc<AgentConfigRegistry>>>> =
            Arc::new(RwLock::new(None));

        // Stable per-pod identity for cross-pod claim coordination (detection
        // scheduler, and NAN-1492 re-triage debounce). Computed here (ahead of
        // the shadow-investigation wiring that now consumes it) and stored on
        // AppState below.
        let node_id = generate_node_id();

        // Create shadow investigation service for auto-triage on new case creation.
        // Phase 3.2 (NAN-744): cases lifted to enterprise — the whole shadow
        // investigation hook only wires up in enterprise builds. Open-core
        // builds default to `NoopShadowInvestigationHook` on signal_processor /
        // detection_service.
        #[cfg(feature = "enterprise")]
        let shadow_investigation_hook: Arc<
            dyn nanosiem_core::extensions::ShadowInvestigationHook,
        > = if config.deployment_mode.is_enterprise_shared() {
            // The legacy service captures process-global Search/AI and starts
            // constructor-time recovery work. Shared may install only a future
            // exact-tenant runtime, so even construction is fail-closed here.
            Arc::new(nanosiem_core::extensions::NoopShadowInvestigationHook)
        } else {
            let shadow_ai_client: Arc<dyn nanosiem_core::extensions::AiClient> =
                Arc::new(nanosiem_enterprise::melod::MelodAiClientBridge::live(
                    melod_service.clone(),
                    agent_config_registry.clone(),
                ));
            let svc = Arc::new(ShadowInvestigationService::new(
                pg_pool.clone(),
                search_service.clone(),
                shadow_ai_client,
                3, // max 3 concurrent investigations
            ));
            let sweep = svc.clone();
            tokio::spawn(async move {
                sweep.resume_interrupted().await;
                sweep.sweep_due_coordination().await;
            });
            svc
        };

        // Build the case-grouping hook for enterprise builds. NAN-744 Phase 2.3
        // added the `CaseGroupingHook` trait surface on detection_service /
        // signal_processor, but the AppState wire-up was
        // never written — so saturn fired alerts but never created cases
        // (case_id stayed NULL). NAN-872 restores the wiring. Open-core
        // builds keep `NoopCaseGroupingHook` on all three services.
        #[cfg(feature = "enterprise")]
        let case_grouping_hook: Arc<dyn nanosiem_core::extensions::CaseGroupingHook> =
            if config.deployment_mode.is_enterprise_shared() {
                Arc::new(nanosiem_core::extensions::NoopCaseGroupingHook)
            } else {
                nanosiem_enterprise::cases::case_grouping_hook(
                    pg_pool.clone(),
                    dual_pool.clone(),
                    shadow_investigation_hook.clone(),
                )
            };

        // Create signal processor; in enterprise also wire shadow investigation
        // and case grouping.
        let signal_processor = {
            // NAN-1741 A2: wire the webhook service so real-time (materialized-
            // view) detection alerts actually fire webhooks — previously the
            // SignalProcessor had no webhook wiring, so MV-produced alerts
            // created a row but never notified. Webhooks are a core feature (not
            // enterprise-gated), so this is wired unconditionally, mirroring the
            // scheduled `detection_service` wiring above.
            let sp = SignalProcessor::new(dual_pool.clone(), SignalProcessorConfig::default())
                .with_webhook_service(nanosiem_core::webhooks::WebhookService::new(
                    nanosiem_core::webhooks::WebhookRepository::new(pg_pool.clone()),
                ));
            #[cfg(feature = "enterprise")]
            let sp = sp
                .with_shadow_investigation(shadow_investigation_hook.clone())
                .with_case_grouping(case_grouping_hook.clone());
            Arc::new(sp)
        };

        // Wire shadow investigation and case grouping into detection service
        // (enterprise only).
        #[cfg(feature = "enterprise")]
        let detection_service = detection_service
            .with_shadow_investigation(shadow_investigation_hook.clone())
            .with_case_grouping(case_grouping_hook.clone());

        // Trait-object form of the shadow hook stored on AppState so handler-
        // built CaseService instances can wire it up (NAN-1059 re-triage on
        // alert add). Enterprise hands over the live service; open-core uses
        // the no-op so the cases handlers can call into it unconditionally.
        #[cfg(not(feature = "enterprise"))]
        let shadow_investigation_hook: Arc<
            dyn nanosiem_core::extensions::ShadowInvestigationHook,
        > = Arc::new(nanosiem_core::extensions::NoopShadowInvestigationHook);

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

        #[cfg(feature = "enterprise")]
        let (case_events_tx, _) = tokio::sync::broadcast::channel(256);

        // NAN-948: wire `SourceConfigService::update_dynamic_router` to
        // the same deploy lock that `ParserService`'s inner
        // `VectorConfigManager` uses. Without this, the two services'
        // read-mutate-write of `_router.toml` can interleave and the
        // later writer clobbers the earlier one's changes.
        let vector_config_dir = get_vector_config_dir();
        let parser_service =
            ParserService::with_vector_config_dir(pg_pool.clone(), &vector_config_dir);
        let source_config_service =
            SourceConfigService::with_vector_config_dir(pg_pool.clone(), &vector_config_dir)
                .with_deploy_lock(parser_service.deploy_lock());

        // NAN-2297: taken before the struct literal below moves `parser_service`.
        let shared_vector_config = parser_service.vector_config();
        let vector_config_publisher = Arc::new(nanosiem_core::VectorConfigPublisher::new(
            pg_pool.clone(),
            &vector_config_dir,
            node_id.clone(),
        ));

        // Per-source RBAC scoping (NAN-1799). The repo backs the source-scopes
        // admin handlers (restricted registry + group grants); the resolver
        // computes a user's deny-set ScopeSet from that registry + their
        // grants, FAIL-CLOSED on PG unavailability, and is called by the auth
        // middleware. Both share the same PG pool as the other RBAC repos.
        // Mutations through the repo must call `resolver.invalidate()`.
        let source_scope_repo = SourceScopeRepository::new(pg_pool.clone());
        let source_scope_resolver = SourceScopeResolver::new(pg_pool.clone());

        #[cfg(feature = "enterprise")]
        let tenant_ai_rls_runtime = if config.deployment_mode.is_enterprise_shared() {
            match nanosiem_enterprise::melod::TenantAiRlsRuntime::connect_startup().await {
                Ok(runtime) => Some(Arc::new(runtime)),
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "enterprise-shared AI RLS runtime unavailable; shared pivt remains closed"
                    );
                    None
                }
            }
        } else {
            None
        };

        #[cfg(feature = "enterprise")]
        let tenant_case_notebook_service = tenant_ai_rls_runtime.as_ref().map(|runtime| {
            runtime.tenant_case_notebook_service(TenantMembershipResolver::new(pg_pool.clone()))
        });
        #[cfg(feature = "enterprise")]
        let melod_session_repo = tenant_ai_rls_runtime
            .as_ref()
            .map(|runtime| runtime.melod_session_repository(pg_pool.clone()))
            .unwrap_or_else(|| MelodSessionRepository::new(pg_pool.clone()));
        #[cfg(feature = "enterprise")]
        let melod_job_repo = tenant_ai_rls_runtime
            .as_ref()
            .map(|runtime| runtime.melod_job_repository(pg_pool.clone()))
            .unwrap_or_else(|| MelodJobRepository::new(pg_pool.clone()));

        #[cfg(feature = "enterprise")]
        let tenant_webhook_runtime = if config.deployment_mode.is_enterprise_shared() {
            match tenant_ai_rls_runtime.as_ref() {
                Some(rls) => match nanosiem_enterprise::webhooks_shared_runtime::TenantWebhookRuntime::connect_startup(
                    pg_pool.clone(), Arc::clone(rls), node_id.clone(),
                ) {
                    Ok(runtime) => Some(Arc::new(runtime)),
                    Err(error) => {
                        tracing::error!(error = %error, "enterprise-shared tenant webhook runner unavailable; deliveries stay queued");
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };
        // NAN-2361 wave 5: tenant lookup ingestion runner (jobs binary) and the
        // per-tenant custom-enrichment sandbox executor (API pod ships Deno).
        #[cfg(feature = "enterprise")]
        let tenant_lookup_ingestion_runtime = if config.deployment_mode.is_enterprise_shared() {
            match tenant_ai_rls_runtime.as_ref() {
                Some(rls) => match nanosiem_enterprise::lookup_ingestion_shared_runtime::TenantLookupIngestionRuntime::connect_startup(
                    pg_pool.clone(), Arc::clone(rls), node_id.clone(),
                ) {
                    Ok(runtime) => Some(Arc::new(runtime)),
                    Err(error) => {
                        tracing::error!(error = %error, "enterprise-shared lookup ingestion runner unavailable; scheduled lookup feeds will not run");
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };
        #[cfg(feature = "enterprise")]
        let tenant_custom_enrichment_executor = if config.deployment_mode.is_enterprise_shared() {
            Some(Arc::new(nanosiem_enterprise::custom_enrichment::TenantCustomEnrichmentExecutor::from_env()))
        } else {
            None
        };
        // NAN-2361 wave 6: scheduled custom-enrichment runs (jobs binary).
        #[cfg(feature = "enterprise")]
        let mut tenant_custom_enrichment_runtime: Option<Arc<nanosiem_enterprise::custom_enrichment_shared_runtime::TenantCustomEnrichmentRuntime>> = None;
        // NAN-2361 wave 6: the erasure runner defers tenants whose cell render
        // has no `lake_erasure_execute`; it needs the registry loaded below.
        #[cfg(feature = "enterprise")]
        let mut erasure_cell_registry: Option<Arc<nanosiem_core::search::SharedLakeWorkerRegistry>> = None;
        // NAN-2361 wave 4: per-tenant identity directory sync (jobs binary).
        #[cfg(feature = "enterprise")]
        let mut tenant_identity_sync_runtime: Option<Arc<nanosiem_enterprise::identity_shared_runtime::TenantIdentitySyncRuntime>> = None;
        // NAN-2361 wave 5: shadow investigation for alert-derived cases (jobs binary).
        #[cfg(feature = "enterprise")]
        let mut tenant_shadow_investigation_runtime: Option<Arc<nanosiem_enterprise::shadow_investigation_shared_runtime::TenantShadowInvestigationRuntime>> = None;
        // NAN-2361 wave 7: background AI triage of new tenant alerts (jobs binary).
        #[cfg(feature = "enterprise")]
        let mut tenant_alert_triage_runtime: Option<Arc<nanosiem_enterprise::alert_triage_shared_runtime::TenantAlertTriageRuntime>> = None;
        // NAN-2361 wave 8: scheduled tenant SIEM-health reports (jobs binary).
        #[cfg(feature = "enterprise")]
        let mut tenant_siem_health_runtime: Option<Arc<nanosiem_enterprise::siem_health_shared_runtime::TenantSiemHealthRuntime>> = None;
        // NAN-3196: shared feed-staleness monitor (leader-only, jobs binary).
        #[cfg(feature = "enterprise")]
        let mut tenant_feed_staleness_runtime: Option<Arc<nanosiem_enterprise::feed_staleness_shared_runtime::TenantFeedStalenessRuntime>> = None;
        // NAN-2361 wave 4: platform erasure runner. Its own execute-only DSN;
        // absent on a cluster whose bootstrap has not yet created the runner login.
        #[cfg(feature = "enterprise")]
        let erasure_runtime_base: Option<nanosiem_enterprise::erasure_shared_runtime::TenantErasureRuntime> =
            if config.deployment_mode.is_enterprise_shared() {
                match nanosiem_enterprise::erasure_shared_runtime::TenantErasureRuntime::connect_startup(node_id.clone()).await {
                    Ok(runtime) => Some(runtime),
                    // The DSN is mounted on the jobs Deployment only; the API
                    // process legitimately runs without it.
                    Err(nanosiem_enterprise::erasure_shared_runtime::TenantErasureRuntimeStartupError::MissingSetting(_)) => None,
                    Err(error) => {
                        tracing::error!(error = %error, "enterprise-shared erasure runner unavailable; erasure requests stay pending");
                        None
                    }
                }
            } else {
                None
            };
        #[cfg(feature = "enterprise")]
        let (tenant_search_runtime_resolver, tenant_detection_runtime, tenant_report_runtime) = if config
            .deployment_mode
            .is_enterprise_shared()
        {
            let registry = nanosiem_core::search::SharedLakeWorkerRegistry::from_env();
            let redis_url = std::env::var("REDIS_URL")
                .ok()
                .filter(|value| !value.trim().is_empty());
            match (registry, redis_url) {
                // NAN-3531 N2a: the live config directory or the N1 FILES list.
                (Ok(registry), _) if nanosiem_core::search::hosted_producer_reload::HostedProducerSource::configured_in_env() => {
                    let registry = Arc::new(registry);
                    match nanosiem_enterprise::melod::HostedTenantSearchJobStoreFactory::connect_startup(&registry).await {
                        Ok(factory) => {
                            // NAN-3020: lean tenants' ingest counters come from
                            // their query[T] part rollups through this registry.
                            nanosiem_core::enterprise_shared_lean_ingest::install(Arc::clone(&registry));
                            let job_stores: Arc<dyn nanosiem_enterprise::melod::TenantSearchJobStoreFactory> = Arc::new(factory);
                            let tenant_search = Some(Arc::new(attach_tenant_search_rls_runtime(
                                nanosiem_enterprise::melod::TenantSearchRuntimeResolver::new(
                                    pg_pool.clone(), search_service.clone(), Arc::clone(&registry), Arc::clone(&job_stores),
                                ),
                                tenant_ai_rls_runtime.as_ref(),
                            )));
                            let tenant_reports = build_tenant_report_runtime(
                                &pg_pool, tenant_ai_rls_runtime.as_ref(), &search_service, Arc::clone(&registry), Arc::clone(&job_stores), &node_id, agent_config_registry.clone(),
                            );
                            if let Some(rls) = tenant_ai_rls_runtime.as_ref() {
                                match nanosiem_enterprise::identity_shared_runtime::TenantIdentitySyncRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), search_service.clone(), Arc::clone(&registry), Arc::clone(&job_stores),
                                ) {
                                    Ok(runtime) => tenant_identity_sync_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared tenant identity sync runtime unavailable"),
                                }
                                erasure_cell_registry = Some(Arc::clone(&registry));
                                match nanosiem_enterprise::siem_health_shared_runtime::TenantSiemHealthRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), node_id.clone(),
                                ) {
                                    Ok(runtime) => tenant_siem_health_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared SIEM-health runner unavailable"),
                                }
                                match nanosiem_enterprise::feed_staleness_shared_runtime::TenantFeedStalenessRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls),
                                ) {
                                    Ok(runtime) => tenant_feed_staleness_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared feed-staleness monitor unavailable"),
                                }
                                if let Some(executor) = tenant_custom_enrichment_executor.as_ref() {
                                    match nanosiem_enterprise::custom_enrichment_shared_runtime::TenantCustomEnrichmentRuntime::connect_startup(
                                        pg_pool.clone(), Arc::clone(rls), Arc::clone(&registry), Arc::clone(executor), node_id.clone(),
                                    ) {
                                        Ok(runtime) => tenant_custom_enrichment_runtime = Some(Arc::new(runtime)),
                                        Err(error) => tracing::error!(error = %error, "enterprise-shared custom enrichment runner unavailable"),
                                    }
                                }
                                match nanosiem_enterprise::shadow_investigation_shared_runtime::TenantShadowInvestigationRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), search_service.clone(), Arc::clone(&registry), Arc::clone(&job_stores), agent_config_registry.clone(),
                                ) {
                                    Ok(runtime) => tenant_shadow_investigation_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared shadow investigation runtime unavailable"),
                                }
                                match nanosiem_enterprise::alert_triage_shared_runtime::TenantAlertTriageRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), Arc::clone(&registry), agent_config_registry.clone(),
                                ) {
                                    Ok(runtime) => tenant_alert_triage_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared alert triage runtime unavailable"),
                                }
                            }
                            let tenant_detection = match nanosiem_enterprise::detection_shared_runtime::TenantDetectionRuntimeLoop::connect_startup(
                                pg_pool.clone(), search_service.clone(), registry, job_stores,
                            ).await {
                                Ok(runtime) => Some(Arc::new(runtime)),
                                Err(error) => {
                                    tracing::error!(error = %error, "hosted detection runtime unavailable; shared detection scheduler remains closed");
                                    None
                                }
                            };
                            (tenant_search, tenant_detection, tenant_reports)
                        }
                        Err(error) => {
                            tracing::error!(error = %error, "hosted Search coordinator unavailable; shared runtimes remain closed without fallback");
                            (None, None, None)
                        }
                    }
                }
                (Ok(registry), Some(redis_url)) => {
                    match nanosiem_enterprise::melod::RedisTenantSearchJobStoreFactory::connect_startup(
                        &redis_url,
                    )
                    .await
                    {
                        Ok(job_stores) => {
                            let registry = Arc::new(registry);
                            let job_stores: Arc<
                                dyn nanosiem_enterprise::melod::TenantSearchJobStoreFactory,
                            > = Arc::new(job_stores);
                            let tenant_search = Some(Arc::new(attach_tenant_search_rls_runtime(
                                nanosiem_enterprise::melod::TenantSearchRuntimeResolver::new(
                                    pg_pool.clone(),
                                    search_service.clone(),
                                    Arc::clone(&registry),
                                    Arc::clone(&job_stores),
                                ),
                                tenant_ai_rls_runtime.as_ref(),
                            )));
                            let tenant_reports = build_tenant_report_runtime(
                                &pg_pool, tenant_ai_rls_runtime.as_ref(), &search_service, Arc::clone(&registry), Arc::clone(&job_stores), &node_id, agent_config_registry.clone(),
                            );
                            if let Some(rls) = tenant_ai_rls_runtime.as_ref() {
                                match nanosiem_enterprise::identity_shared_runtime::TenantIdentitySyncRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), search_service.clone(), Arc::clone(&registry), Arc::clone(&job_stores),
                                ) {
                                    Ok(runtime) => tenant_identity_sync_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared tenant identity sync runtime unavailable"),
                                }
                                erasure_cell_registry = Some(Arc::clone(&registry));
                                match nanosiem_enterprise::siem_health_shared_runtime::TenantSiemHealthRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), node_id.clone(),
                                ) {
                                    Ok(runtime) => tenant_siem_health_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared SIEM-health runner unavailable"),
                                }
                                match nanosiem_enterprise::feed_staleness_shared_runtime::TenantFeedStalenessRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls),
                                ) {
                                    Ok(runtime) => tenant_feed_staleness_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared feed-staleness monitor unavailable"),
                                }
                                if let Some(executor) = tenant_custom_enrichment_executor.as_ref() {
                                    match nanosiem_enterprise::custom_enrichment_shared_runtime::TenantCustomEnrichmentRuntime::connect_startup(
                                        pg_pool.clone(), Arc::clone(rls), Arc::clone(&registry), Arc::clone(executor), node_id.clone(),
                                    ) {
                                        Ok(runtime) => tenant_custom_enrichment_runtime = Some(Arc::new(runtime)),
                                        Err(error) => tracing::error!(error = %error, "enterprise-shared custom enrichment runner unavailable"),
                                    }
                                }
                                match nanosiem_enterprise::shadow_investigation_shared_runtime::TenantShadowInvestigationRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), search_service.clone(), Arc::clone(&registry), Arc::clone(&job_stores), agent_config_registry.clone(),
                                ) {
                                    Ok(runtime) => tenant_shadow_investigation_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared shadow investigation runtime unavailable"),
                                }
                                match nanosiem_enterprise::alert_triage_shared_runtime::TenantAlertTriageRuntime::connect_startup(
                                    pg_pool.clone(), Arc::clone(rls), Arc::clone(&registry), agent_config_registry.clone(),
                                ) {
                                    Ok(runtime) => tenant_alert_triage_runtime = Some(Arc::new(runtime)),
                                    Err(error) => tracing::error!(error = %error, "enterprise-shared alert triage runtime unavailable"),
                                }
                            }
                            let tenant_detection = match nanosiem_enterprise::detection_shared_runtime::TenantDetectionRuntimeLoop::connect_startup(
                                pg_pool.clone(),
                                search_service.clone(),
                                registry,
                                job_stores,
                            )
                            .await
                            {
                                Ok(runtime) => Some(Arc::new(runtime)),
                                Err(error) => {
                                    tracing::error!(
                                        error = %error,
                                        "enterprise-shared detection runtime unavailable; shared detection scheduler remains closed"
                                    );
                                    None
                                }
                            };
                            (tenant_search, tenant_detection, tenant_reports)
                        }
                        Err(error) => {
                            tracing::error!(
                                error = %error,
                                "enterprise-shared Search job-store factory unavailable; pivt and detection runtimes remain closed"
                            );
                            (None, None, None)
                        }
                    }
                }
                (Err(error), _) => {
                    tracing::error!(
                        error = %error,
                        "enterprise-shared Search worker registry unavailable; pivt and detection runtimes remain closed"
                    );
                    (None, None, None)
                }
                (_, None) => {
                    tracing::error!(
                        "enterprise-shared Search requires Redis; pivt and detection runtimes remain closed"
                    );
                    (None, None, None)
                }
            }
        } else {
            (None, None, None)
        };
        #[cfg(feature = "enterprise")]
        let tenant_erasure_runtime = erasure_runtime_base.map(|runtime| {
            Arc::new(match erasure_cell_registry.clone() {
                Some(registry) => runtime.with_cell_registry(registry),
                None => runtime,
            })
        });
        // NAN-2361 wave 8: platform readiness attestor (jobs binary; the API pod
        // has no signing key and skips it). 9012850: on its own execute-only
        // login (NANOSIEM_SHARED_READINESS_ATTESTOR_DATABASE_URL), never the
        // shared control pool.
        #[cfg(feature = "enterprise")]
        let tenant_platform_readiness_attestor = if config.deployment_mode.is_enterprise_shared() {
            match nanosiem_enterprise::platform_readiness_shared_runtime::TenantPlatformReadinessAttestor::connect_startup(
                erasure_cell_registry.clone(), node_id.clone(),
            ).await {
                Ok(runtime) => Some(Arc::new(runtime)),
                Err(nanosiem_enterprise::platform_readiness_shared_runtime::TenantPlatformReadinessStartupError::MissingSetting(_)) => None,
                Err(error) => {
                    tracing::error!(error = %error, "enterprise-shared platform readiness attestor unavailable");
                    None
                }
            }
        } else {
            None
        };
        // NAN-2361 wave 5: queued export runner (jobs binary); needs the tenant
        // search resolver, so it is built after the shared runtime tuple.
        #[cfg(feature = "enterprise")]
        let tenant_export_runtime = match (
            config.deployment_mode.is_enterprise_shared(),
            tenant_ai_rls_runtime.as_ref(),
            tenant_search_runtime_resolver.as_ref(),
        ) {
            (true, Some(rls), Some(resolver)) => {
                match nanosiem_enterprise::exports_shared_runtime::TenantExportRuntime::connect_startup(
                    pg_pool.clone(), Arc::clone(rls), Arc::clone(resolver), node_id.clone(),
                ) {
                    Ok(runtime) => Some(Arc::new(runtime)),
                    Err(error) => {
                        tracing::error!(error = %error, "enterprise-shared export runner unavailable; queued exports will not run");
                        None
                    }
                }
            }
            _ => None,
        };

        Self {
            // Services using DualPool for ClickHouse log queries
            search_service,
            detection_service,
            // NAN-1581: flag-aware lookup service shared with the management
            // handlers so create/upload/row ops follow LOOKUP_STORAGE_BACKEND.
            lookup_service: lookup_service_for_state,
            feed_service: FeedService::with_dual_pool(&dual_pool),

            // Services using PostgreSQL only (or with optional ClickHouse for stats)
            distributed_scheduler: Arc::new(RwLock::new(None)),
            node_id,
            enrichment: Arc::new(RwLock::new(enrichment_service)),
            parser_service,
            // NAN-2297: share ParserService's config manager, so all three
            // writers to the Vector config tree (parsers, log sources, source
            // configs) serialize on ONE deploy mutex. Building a second manager
            // here gave log-source publishes a private lock while they staged
            // into the same directory.
            log_source_service: LogSourceService::with_dual_pool_and_vector_config(
                &dual_pool,
                shared_vector_config,
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
            vector_config_publisher,
            #[cfg(feature = "enterprise")]
            melod_service,
            // Risk service needs DualPool for time-windowed queries (findings are in ClickHouse)
            // Same instance is also wired into search_service as a CloudRiskProvider above (NAN-873).
            #[cfg(feature = "enterprise")]
            risk_service,
            query_library: QueryLibraryRepository::new(pg_pool.clone()),

            // Store both pools
            #[cfg(feature = "enterprise")]
            melod_job_repo,
            #[cfg(feature = "enterprise")]
            wizard_session_repo: WizardSessionRepository::new(pg_pool.clone()),
            #[cfg(feature = "enterprise")]
            melod_session_repo,
            #[cfg(feature = "enterprise")]
            tenant_search_runtime_resolver,
            #[cfg(feature = "enterprise")]
            tenant_ai_rls_runtime,
            #[cfg(feature = "enterprise")]
            tenant_case_notebook_service,
            #[cfg(feature = "enterprise")]
            tenant_detection_runtime,
            #[cfg(feature = "enterprise")]
            tenant_report_runtime,
            #[cfg(feature = "enterprise")]
            tenant_webhook_runtime,
            #[cfg(feature = "enterprise")]
            tenant_identity_sync_runtime,
            #[cfg(feature = "enterprise")]
            tenant_erasure_runtime,
            #[cfg(feature = "enterprise")]
            tenant_shadow_investigation_runtime,
            #[cfg(feature = "enterprise")]
            tenant_alert_triage_runtime,
            #[cfg(feature = "enterprise")]
            tenant_siem_health_runtime,
            #[cfg(feature = "enterprise")]
            tenant_feed_staleness_runtime,
            #[cfg(feature = "enterprise")]
            tenant_platform_readiness_attestor,
            #[cfg(feature = "enterprise")]
            tenant_lookup_ingestion_runtime,
            #[cfg(feature = "enterprise")]
            tenant_export_runtime,
            #[cfg(feature = "enterprise")]
            tenant_custom_enrichment_executor,
            #[cfg(feature = "enterprise")]
            tenant_custom_enrichment_runtime,
            ip_allowlist_service: Arc::new(IpAllowlistService::new(pg_pool.clone())),
            ingest_token_service: Arc::new(nanosiem_core::ingest_tokens::IngestTokenService::new(
                pg_pool.clone(),
                nanosiem_core::reports::COMPATIBILITY_TENANT_ID,
            )),
            onboarding_repo: OnboardingRepository::new(pg_pool.clone()),
            pool: pg_pool,
            dual_pool,
            materialized_view_generator: Arc::new(mv_generator),
            config: Arc::new(config),
            // Stamp the manifest identity the profile was built from so a later
            // generation promotion is detectable (drift on /health/detailed) and
            // adoptable (the refresh loop in `main.rs`) instead of silently
            // leaving the process pinned to a dead generation.
            schema_profile: super::SharedSchemaProfile::with_manifest(
                schema_profile,
                super::schema_profile::resolve_pinned_manifest(),
            ),

            // Auth services
            auth_service,
            local_auth_settings,
            token_service,
            api_key_service,
            session_service,
            permission_service,
            user_repo,
            group_repo,
            role_repo,
            source_scope_repo,
            source_scope_resolver,
            oidc_repo,
            oidc_service,
            auth_enabled,
            notification_service,
            tuning_repository,
            task_registry: TaskRegistry::default(),
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
            #[cfg(feature = "enterprise")]
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
            rule_test_admission: Arc::new(nanosiem_core::RuleTestAdmission::local()),
            shadow_investigation_hook,
            // P1 audit: shared prevalence handle for in-process config hot-reload
            // (settings PUT handler → live search/detection consumers).
            prevalence_service: prevalence_service_for_state,
        }
    }

    /// Try to create application state with DualPool from environment
    ///
    /// PostgreSQL is always required. Legacy mode also requires ClickHouse and
    /// preserves its fail-fast boot checks; canonical lake mode uses only the
    /// PostgreSQL control plane and the lake query service.
    ///
    /// Requirements: 1.1, 1.2, 1.3, 1.5
    pub async fn try_with_dual_pool(config: ApiConfig) -> Result<Self, DualPoolError> {
        // NAN-2361: resolve the active schema profile once, before any pool is
        // opened. In canonical lake mode this parses the tenant source manifest,
        // which used to happen inside request handlers. Fail closed: a manifest
        // we cannot read or trust must refuse to boot rather than serve an empty
        // field inventory (the field universe gates query validation).
        let schema_profile = config.try_schema_profile().map_err(|error| {
            DualPoolError::ConfigError(format!("schema profile unavailable: {error}"))
        })?;

        // Try to load DualPool configuration from environment
        let mut dual_config = DualPoolConfig::from_env()?;
        // As in search, the statement itself detects a dead socket and fails
        // closed. Avoid an extra network ping on every pooled checkout.
        if std::env::var_os("PG_TEST_BEFORE_ACQUIRE").is_none() {
            dual_config.pg_test_before_acquire = false;
        }

        // NAN-3491: logs live in the lake. The pool is PostgreSQL control-plane
        // state only and never connects to a ClickHouse process.
        let mut dual_pool =
            DualPool::new_lake_control_plane_with_min_connections(&dual_config, 2).await?;

        let pg_pool: &sqlx::PgPool = dual_pool.postgres();
        match PostgresMigrationAuthority::from_env().map_err(DualPoolError::ConfigError)? {
            PostgresMigrationAuthority::Runtime => {
                // The helper handles fresh-init detection, snapshot apply, and
                // legacy-history backfill (NAN-749) in addition to the
                // canonical sqlx::migrate!() pass. Enterprise overlay stays
                // gated below because nanosiem-core does not see the
                // enterprise feature flag.
                nanosiem_core::db::run_postgres_migrations(pg_pool)
                    .await
                    .map_err(|e| {
                        DualPoolError::PostgresConnectionError(format!("Migration failed: {}", e))
                    })?;
                #[cfg(feature = "enterprise")]
                {
                    tracing::info!("Running enterprise PostgreSQL overlay migrations...");
                    let mut overlay_migrator = sqlx::migrate!("../migrations/postgres-enterprise");
                    overlay_migrator.set_ignore_missing(true);
                    overlay_migrator.run(pg_pool).await.map_err(|e| {
                        DualPoolError::PostgresConnectionError(format!(
                            "Enterprise overlay migration failed: {}",
                            e
                        ))
                    })?;
                    tracing::info!("Enterprise PostgreSQL overlay complete");
                }
            }
            PostgresMigrationAuthority::ExternalJob => {
                // hosted-shared uses distinct least-privilege runtime
                // roles. Its digest-pinned pre-rollout Job is the only DDL
                // authority; granting CREATE merely so `migrate!()` can issue
                // `CREATE TABLE IF NOT EXISTS _sqlx_migrations` would break the
                // database isolation contract.
                tracing::info!("PostgreSQL migrations are owned by the external pre-rollout Job");
            }
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

        if !config.canonical_lake_ocsf {
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
                        .map(|mut it| {
                            it.any(|e| {
                                e.ok()
                                    .and_then(|d| d.file_name().to_str().map(str::to_string))
                                    .map(|name| name.ends_with(".sql"))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                {
                    ch_migrator
                        .check_schema_up_to_date(ch_enterprise_path)
                        .await
                        .map_err(|e| DualPoolError::SchemaBehind(e.to_string()))?;
                }
            }
            tracing::info!("ClickHouse schema version OK");

            // OCSF Phase 3b (NAN-1241): fail-fast validation that the ACTIVE schema
            // profile's logs table actually carries the columns the profile must
            // query (its PREWHERE set + `timestamp`). This is the schema analog of
            // the DualPool/schema-version fail-fast (NAN-800): an OCSF profile
            // pointed at a UDM table (or vice versa) must error here rather than
            // silently return empty results at query time.
            //
            // For UDM this is a no-op in practice — `nanosiem.logs` (already verified
            // current above) carries every required column, so a healthy UDM deploy
            // passes unconditionally and its boot behavior is unchanged.
            //
            // The probe is a plain `SELECT … FROM system.columns`; if it can't run
            // (transient CH read error mid-boot) we log and continue rather than fail
            // boot on transport flakiness — matching how other boot CH checks degrade.
            // A genuine table/column mismatch IS a hard boot failure.
            //
            // Phase 3b TODO (persistence DEFERRED): the scoping (§2.4) also calls for
            // persisting the active `SchemaId` in `system_settings` so a later boot
            // with a *different* `NANO_SCHEMA_PROFILE` against the same data can fail
            // fast on the mismatch. `system_settings` is a wide single-row
            // (`id='default'`) table with sqlx COMPILE-TIME-checked queries, not a
            // generic key/value store — recording the schema there needs a new
            // migration adding (e.g.) an `active_schema_profile text` column plus a
            // `query!`-checked read/write, which is out of scope to invent under this
            // phase's time budget (repo scar: never edit applied migrations; pick the
            // next number from the highest; verify columns exist). The boot DESCRIBE
            // probe above already catches the dangerous case (an OCSF profile against
            // a UDM table fails fast on missing columns), and `/api/schema/fields`
            // reports the active schema for the frontend — so the persistence row is
            // an introspection/audit nicety, deferred to a follow-up.
            {
                // In the canonical lake lane the active query profile describes the
                // Iceberg/Parquet event table, while ClickHouse remains temporarily
                // connected for unmigrated metadata surfaces under its historical
                // OCSF layout. Validate that auxiliary CH table with the CH profile;
                // validating it against strict lake columns would conflate two
                // different storage contracts and prevent API/jobs from booting.
                let profile = if config.canonical_lake_ocsf {
                    nanosiem_core::schema::profile_for_id(config.schema_id)
                } else {
                    schema_profile.clone()
                };
                // Resolve the LOCAL table (where columns physically live in cluster
                // mode), through the same tenant-aware registry SearchService uses.
                let key = match profile.id() {
                    nanosiem_core::schema::SchemaId::Ocsf => "ocsf_logs",
                    // Spans are a per-query dataset, never the tenant log schema
                    // (NAN-1555); UDM default keeps this unreachable arm total.
                    nanosiem_core::schema::SchemaId::Udm
                    | nanosiem_core::schema::SchemaId::Spans
                    | nanosiem_core::schema::SchemaId::Metrics
                    | nanosiem_core::schema::SchemaId::Risk => "logs",
                };
                let local_table = dual_pool.table_names().local(key);
                match nanosiem_core::schema::validate_active_schema_table(
                    dual_pool.clickhouse(),
                    profile.as_ref(),
                    &local_table,
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(
                            schema = ?profile.id(),
                            table = %local_table,
                            "Active schema profile table validated"
                        );
                    }
                    Err(nanosiem_core::schema::SchemaValidationError::ProbeFailed {
                        table,
                        message,
                    }) => {
                        tracing::warn!(
                            table = %table,
                            error = %message,
                            "Schema profile table validation probe could not run; skipping (CH read error mid-boot)"
                        );
                    }
                    Err(e) => {
                        // TableMissing / MissingColumns — a real misconfiguration.
                        return Err(DualPoolError::SchemaBehind(e.to_string()));
                    }
                }
            }

            // Re-detect cluster state. DualPool::new() runs before this check, so
            // is_clustered may reflect the pre-distributed-tables view; the
            // pre-deploy migrator creates distributed tables and we need a
            // post-create read for the runtime pool.
            dual_pool
                .refresh_cluster_state(&dual_config.clickhouse_database)
                .await;
        } else {
            tracing::info!(
                "Skipping ClickHouse migrations, schema probes, and cluster detection in canonical lake mode"
            );
        }

        if config.canonical_lake_ocsf {
            tracing::info!(
                "Canonical OCSF lake backend active; inert compatibility handles retain no ClickHouse runtime dependency"
            );
        } else {
            tracing::info!("DualPool initialized - using ClickHouse for log storage");
        }
        let mut state = Self::new_with_dual_pool(dual_pool, config, schema_profile).await;

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
                state.rule_test_admission = std::sync::Arc::new(
                    nanosiem_core::RuleTestAdmission::try_with_redis_url(&redis_url).await,
                );
                if let Some(redis_store) = RedisJobStore::connect(&redis_url).await {
                    // Product endpoints hosted by the API (for example a
                    // long-running Prevalence export) must enqueue into the
                    // same durable queue consumed by the isolated lake runner,
                    // not a per-process in-memory registry.
                    state.search_service.set_job_store(Arc::new(redis_store));
                    tracing::info!("API product-job store initialized with Redis");
                } else {
                    tracing::warn!(
                        "API product-job store could not connect to Redis; durable product escalation remains single-process"
                    );
                }
                tracing::info!(
                    "Cross-replica caches and rule-test admission initialized with Redis"
                );

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
                "REDIS_URL not set — distributed caches are disabled and rule-test admission is local (single-node mode)"
            );
        }

        Ok(state)
    }
}

/// NAN-2361 wave-3: the API-side Search runtime resolver reads the tenant
/// worker-assignment ledger through the signed RLS runtime (the ledger is a
/// runtime-only read-registry table). Without one the resolver stays
/// constructed but fails closed on every resolution.
#[cfg(feature = "enterprise")]
fn attach_tenant_search_rls_runtime(
    resolver: nanosiem_enterprise::melod::TenantSearchRuntimeResolver,
    rls: Option<&Arc<nanosiem_enterprise::melod::TenantAiRlsRuntime>>,
) -> nanosiem_enterprise::melod::TenantSearchRuntimeResolver {
    match rls {
        Some(rls) => resolver.with_tenant_runtime(Arc::clone(rls)),
        None => {
            tracing::error!(
                "enterprise-shared Search runtime resolver has no signed RLS runtime; tenant Search runtimes remain closed"
            );
            resolver
        }
    }
}

/// NAN-2361: the private tenant report runner shares the detection loop's
/// attested worker registry and job-store factory plus the signed RLS
/// runtime. Absent when any input is missing; tenant report runs then fail
/// closed while the CRUD/read surfaces stay available.
#[cfg(feature = "enterprise")]
fn build_tenant_report_runtime(
    pg_pool: &sqlx::PgPool,
    rls: Option<&Arc<nanosiem_enterprise::melod::TenantAiRlsRuntime>>,
    search_service: &SearchService,
    registry: Arc<nanosiem_core::search::SharedLakeWorkerRegistry>,
    job_stores: Arc<dyn nanosiem_enterprise::melod::TenantSearchJobStoreFactory>,
    node_id: &str,
    agent_registry: Arc<tokio::sync::RwLock<Option<Arc<nanosiem_enterprise::melod::AgentConfigRegistry>>>>,
) -> Option<Arc<nanosiem_enterprise::reports_shared_runtime::TenantReportRuntime>> {
    let Some(rls) = rls else {
        tracing::error!("enterprise-shared report runner has no signed RLS runtime; tenant report runs remain closed");
        return None;
    };
    match nanosiem_enterprise::reports_shared_runtime::TenantReportRuntime::connect_startup(
        pg_pool.clone(),
        Arc::clone(rls),
        search_service.clone(),
        registry,
        job_stores,
        node_id.to_string(),
        agent_registry,
    ) {
        Ok(runtime) => Some(Arc::new(runtime)),
        Err(error) => {
            tracing::error!(error = %error, "enterprise-shared report runner unavailable; tenant report runs remain closed");
            None
        }
    }
}

/// The identity directory store when `IDENTITY_STORAGE_BACKEND` is unset
/// (NAN-3492, NAN-3767). A trusted-local lean install reads its directory
/// from the lean enrichment coordinator's tenant snapshot through the
/// dedicated cell's `query[T]` (`/v1/identity/directory/*`); PostgreSQL keeps
/// provider and feed state only. Other lake deployments keep the
/// coordinator-backed directory; ClickHouse remains only on the retiring
/// legacy backend. `postgres`, `lake` and `clickhouse` stay selectable.
fn default_identity_storage_backend(lake: bool, trusted_local: bool) -> &'static str {
    match (lake, trusted_local) {
        (true, true) => "lean_directory",
        (true, false) => "lake",
        (false, _) => "clickhouse",
    }
}

#[cfg(test)]
mod identity_backend_default_tests {
    use super::default_identity_storage_backend;

    #[test]
    fn trusted_local_lake_reads_the_lean_identity_directory() {
        assert_eq!(default_identity_storage_backend(true, true), "lean_directory");
        assert_eq!(default_identity_storage_backend(true, false), "lake");
        assert_eq!(default_identity_storage_backend(false, false), "clickhouse");
        assert_eq!(default_identity_storage_backend(false, true), "clickhouse");
    }
}
