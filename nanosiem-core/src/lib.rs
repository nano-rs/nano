// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM Core Library
//!
//! Core functionality for NanoSIEM including:
//! - Database models and connection management
//! - Unified Data Model (UDM) types and field normalization
//! - Query parsing and SQL generation
//! - Log ingestion and parsing
//! - Search execution service
//! - Detection engine logic
//! - IP enrichment (geolocation, ASN)
//! - Parser management
//! - meloD AI assistant integration
//! - System settings (retention, storage)
//! - File upload and lookup table management
//! - Scheduled data fetch jobs
//! - Authentication and role-based access control (RBAC)
//! - Cryptographic utilities for secure credential storage
//! - AI-powered agent enrichment for alert triage
//! - Unified audit logging to ClickHouse

pub mod ai_provider;
pub mod allocator_trim;
pub mod app_features;
#[cfg(feature = "enterprise")]
pub mod ai_budget_model;
// Air-gapped signed bundle format + Ed25519 verification (NAN-1201) — enterprise
// only. Gated to match the api-side `#[cfg(feature = "enterprise")] pub mod airgap;`
// so the open edition excludes the source, and the open-core mirror can strip the
// `nanosiem-core/src/airgap` directory outright (tools/sync-to-nano-mirror.sh).
#[cfg(feature = "enterprise")]
pub mod airgap;
pub mod audit;
pub mod auth;
pub mod baseline;
pub mod branding;
#[cfg(feature = "enterprise")]
pub mod cloudflare_r2_convergence_adapter;
#[cfg(feature = "enterprise")]
pub mod cloudflare_r2_production;
pub mod r2_prefix_guard;
pub mod lake_part_writer_key;
pub(crate) mod config_safety;
pub mod config_secrets;
pub mod content_catalog_defaults;
pub mod crypto;
pub mod csv_safe;
pub mod flock_guard;
pub mod redis_transport;
pub mod db;
pub mod demo;
pub mod detection;
pub mod detection_code_target;
pub mod enrichment;
pub mod internal_domains;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_activation;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_activation_receipts;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_automation_keys;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_convergence_worker;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_runtime_database;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_feature_flags;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_ingest;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_iceberg_catalog_authority;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_membership_acceptance;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_outbox_expedite;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_provisioning;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_source_mode;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_parser_roll;
/// NAN-3361: region RLS context key rotation (`rls-context-keys:region-rotate`).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_region_rls_key;
/// NAN-3512: per-tenant monthly AI allowance (`tenant-ai-allowance:set`).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_tenant_ai_allowance;
/// NAN-3825: tenant member management from the private control plane
/// (`tenant-members:list` / `tenant-members:manage`, MSSP partners).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_operator_members;
/// NAN-3843: operator-issued tenant automation keys (`automation-keys:issue`).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_operator_automation_keys;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_risk_publisher;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment_coordinator;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_consumption;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_runtime_assignments;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_assignment_generation;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lake_pipeline_alerts;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lean_audit_delivery;
/// NAN-3762: lean per-tenant enrichment coverage snapshot (marketplace hero).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lean_coverage;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lean_ingest;
/// NAN-3207: lean per-(source, segment) counts from the part rollups.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lean_segments;
/// NAN-3207: per-source health series and segment-drop detection.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_segment_health;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_parser_rollout_observation;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_platform_ai_provider;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_platform_readiness;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2_credential_rotation;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2_owner_recovery;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2_writer_authority;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_writer_registry_gc;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2_delete_authority;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2_copy_registration;
// Search's query-time retention authority is open (`query_retention_authority`);
// only the owner-plane selection service is hosted (NAN-3861).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_retention_policy;
/// Query-time tenant retention authority read by Search admission (NAN-3861).
pub mod query_retention_authority;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_detection_authoring;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_alert_reads;
/// Hosted-shared app-shell reads (NAN-2361): plan-derived license/tier plus
/// the transaction-scoped notification, onboarding, activity and health reads.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_app_shell;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_app_shell_activity;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_app_shell_notifications;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_app_shell_onboarding;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_app_shell_system_health;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_reports;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_alert_triage;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_observability;
/// Hosted-shared tenant IAM (NAN-2361): members, roles catalogue, sessions,
/// own preferences through the 9000300 SECURITY DEFINER capabilities.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_iam;
/// Hosted-shared tenant IAM extras (NAN-2361 wave 5): tenant custom roles,
/// groups and existing-identity invitations (9000700 / 9000702).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_iam_extras;
/// Hosted-shared case queues and queue routing rules (NAN-2361 wave 5,
/// 9000701) on the tenant transaction.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_queues;
/// Hosted-shared tenant settings (NAN-2361): tenant-stored sections,
/// plan-derived answers, platform-managed verdicts, tenant feedback.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_settings;
/// Hosted-shared outbound notification channels (NAN-2361): tenant webhook
/// CRUD, the transactional delivery ledger, tenant deep links.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_webhooks;

/// Hosted-shared source visibility (NAN-2361 wave 8): group-based
/// restrictions on `metadata.log_source`, per-member exceptions, the
/// effective deny set, and the explicit bypass values (detection runtime /
/// runners, case-scoped evidence reads).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_source_visibility;
/// Hosted-shared settings pages (NAN-2361 wave 3): risk / case-grouping /
/// health-monitoring sections, AI usage, source scopes, SIEM-health
/// suppressions, storage facts and the data-subject erasure ledger.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_settings_pages;
/// Hosted-shared SIEM health reports (NAN-2361): tenant-observable lake
/// facts scored inside the signed transaction.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_siem_health;
/// Hosted-shared feed-staleness monitoring (NAN-3196): per-source stale
/// episodes, tenant inbox notifications and audit, from the lake counters.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_feed_staleness;
/// Hosted-shared SIEM health schedule ledger (NAN-2361 wave 8): the
/// claim / lease / outcome fence the tenant SIEM-health runner drives.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_siem_health_schedule;
/// Hosted-shared platform erasure runner core (NAN-2361 wave 4): claims the
/// 9000422 ledger through the runner's execute-only capabilities and drives
/// each request to completion on the tenant lake.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_erasure_runtime;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_melod;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_case_writes;
/// Hosted-shared alert → case grouping (NAN-2361 wave 4): the tenant
/// detection substrate's grouping hook, run inside the alert-publish
/// transaction.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_case_grouping;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_case_reads;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_notebook_reads;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_notebook_writes;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_case_extras;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_incidents;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_artifacts;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_notebook_extras;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_member_activation;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_detection_lifecycle;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_dashboards;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_dashboards_saved_searches;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_dashboards_query_library;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_dashboards_search_history;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_search_extras;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_tenant_credential;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_detection_dashboard;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_detection_editor;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_detection_execution;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_hunt_recon;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_playbook_execution;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_shadow_investigation;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_background_ai_purposes;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_retro_hunt;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_mitre;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_rule_repositories;
#[cfg(feature = "enterprise")]
pub mod repository_sync_lease;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_sources;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_pipe;
/// Tenant parser rollout requests, samples and platform base offers (NAN-2607).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_parser_rollouts;
/// A tenant moving onto the zero-parser base keeps every source the old base
/// parsed: catalog parsers are installed and published for them (NAN-2977).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_parser_carry_forward;
/// Hosted tenants follow the platform catalog mirror (NAN-2975).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_catalog_follow;
/// Hosted-shared durable export jobs (NAN-2361 wave 5).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_exports;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_sources_parsers;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_sources_credentials;
/// Hosted-shared tenant cloud PULL sources (NAN-3288 / NAN-3370): strict
/// request shape, validators, server-side ExternalId / service-account
/// derivation and the RLS-scoped store.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_pull_sources;

/// Hosted-shared enrichment area (NAN-2361): lookup tables, custom
/// enrichments, identity directory, typed capability verdicts.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment_lookups;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_ioc_lists;
/// Search-side tenant lookup adapter (NAN-2361 wave 5): `LookupStore` over
/// the signed tenant transaction so nPL `lookup` / `inputlookup` / `ioc in
/// lookup()` read the tenant closure.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lookup_store;
/// Tenant lookup-ingestion ledger (NAN-2361 wave 5, migration 9000660):
/// sealed header values, claim/lease protocol, run ledger, payload -> rows.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lookup_ingestion;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment_custom;
/// Tenant custom-enrichment schedule ledger (NAN-2361 wave 6, migration
/// 9000781): claim/lease protocol for the scheduled tenant runner.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment_schedule;
/// Tenant custom-enrichment execution substrate (NAN-2361 wave 5): enable,
/// run ledger, tenant credential resolution, 9000092 artifact ledger link.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment_execution;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_enrichment_identity;
/// Hosted-shared entity risk (NAN-2361): clear boundaries, tenant decay /
/// notable configuration, publisher-assignment verdict and the entity-context
/// alert / case joins inside the signed tenant transaction.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_risk;
/// Hosted-shared identity directory sync (NAN-2361): the tenant-scoped
/// derivation of `shared_identity_users` from the tenant's lake
/// events plus the tenant `identity_sync` settings section.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_identity_sync;
/// One-time export of that table into the tenant's R2 identity store (NAN-3501).
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_identity_export;

// NAN-2361 wave 2: hunting / tuning / playbooks / marketplace / remaining
// rules+alerts routes. Shared credential lock first, then one module per area.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_product_credential;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_hunting;
/// Platform-hosted hunts runner core for shared tenants (NAN-3076): the
/// per-tenant claim gate and the deterministic seed-query sweep pass.
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_hosted_hunts;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_playbooks;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_playbook_repositories;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_tuning;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_auto_tuning;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_marketplace;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_marketplace_repos;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_rules_alerts_remainder;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_region;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_security;
/// Tenant-aware cache / idempotency key scope (NAN-3861).
pub mod security_tenant_scope;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_worker_build_context;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_worker_binding_receipt;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_worker_release;
#[cfg(all(feature = "enterprise", unix))]
pub mod enterprise_shared_worker_release_runtime;
pub mod entity_extraction;
/// Pure alert → case grouping evaluation shared by the dedicated
/// `CaseService` and the hosted-shared tenant grouping hook (NAN-2361).
pub mod case_grouping;
pub mod extensions;
pub mod feeds;
pub mod gdpr;
pub mod health;
pub mod hunts;
pub mod identity;
pub mod ingestion;
/// Sender configuration templates for the hosted ingest endpoint (NAN-2592).
pub mod ingest_sender_templates;
/// Named, revocable per-sender ingest tokens for dedicated deployments (NAN-3770).
pub mod ingest_tokens;
pub mod inputlookup;
/// Read-only status of OCSF bucket-drop sources (NAN-3807).
pub mod landing_sources;
pub mod ip_allowlist;
pub mod lake_http;
pub mod leader;
// Enterprise-only: license / phone-home machinery is stripped from the open
// edition entirely (NAN-1193), not merely runtime-disabled.
#[cfg(feature = "enterprise")]
pub mod license;
pub mod log_sources;
pub mod log_telemetry;
pub mod lookup;
pub mod marketplace;
pub mod mitre;
pub mod models;
pub mod namespace;
pub mod observability;
pub mod onboarding;
pub mod parser_repository;
pub mod parsers;
pub mod playbook_repository;
pub mod playbooks;
pub mod prevalence;
pub mod query;
pub mod query_library;
pub mod reports;
pub mod risk;
pub mod rule_repository;
pub mod scheduler;
pub mod schema;
pub mod search;
pub mod settings;
pub mod process_supervision;
pub mod shutdown;
pub mod siem_health;
pub mod source_configs;
pub mod sql_hygiene;
pub mod system_health;
pub mod telemetry;
pub mod tenant_db;
/// NAN-3361: the mounted region RLS key, its boot check and expiry monitor.
pub mod rls_context_key_env;
pub mod tenant_entitlements;
pub mod platform_enrichment;
pub mod timezone;
pub mod tuning;
pub mod typeid;
pub mod udm;
pub mod udm_context;
pub mod upload;
pub mod vector_naming;
pub mod webhooks;

pub use audit::{
    AuditEmitError,
    AuditEmitter,
    AuditEvent,
    AuditEventBuilder,
    AuditQueryError,
    AuditQueryService,
    AuditSource,
    ClickHouseAuditEntry,
    ClickHouseAuditQuery,
    ClientContext,
    APIKEY_CREATED,
    APIKEY_DELETED,
    APIKEY_DISABLED,
    APIKEY_ENABLED,
    APIKEY_RESET,
    APIKEY_UPDATED,
    CASE_CREATED,
    CASE_DELETED,
    CASE_UPDATED,
    CREDENTIAL_CREATED,
    CREDENTIAL_DELETED,
    CREDENTIAL_UPDATED,
    GDPR_ANONYMIZATION_COMPLETED,
    GDPR_ANONYMIZATION_FAILED,
    GDPR_ANONYMIZATION_STARTED,
    GDPR_ANONYMIZATION_SUBMITTED,
    GROUP_CREATED,
    GROUP_DELETED,
    GROUP_MEMBER_ADDED,
    GROUP_MEMBER_REMOVED,
    GROUP_ROLES_UPDATED,
    GROUP_UPDATED,
    INGEST_INSTALL_TOKEN_UPDATED,
    INGEST_TOKEN_CREATED,
    INGEST_TOKEN_REVOKED,
    IP_ALLOWLIST_CREATED,
    IP_ALLOWLIST_DELETED,
    IP_ALLOWLIST_UPDATED,
    LOGIN_FAILED,
    // Action constants
    LOGIN_SUCCESS,
    LOGOUT,
    OIDC_LOGIN,
    PASSWORD_CHANGED,
    PASSWORD_RESET_COMPLETE,
    PASSWORD_RESET_REQUEST,
    PROPOSAL_APPROVED,
    PROPOSAL_REJECTED,
    ROLE_CREATED,
    ROLE_DELETED,
    ROLE_UPDATED,
    RULE_CREATED,
    RULE_DELETED,
    RULE_DEMOTED,
    RULE_DUPLICATED,
    RULE_PAUSED,
    RULE_PROMOTED,
    RULE_RESUMED,
    RULE_UPDATED,
    SETTINGS_UPDATED,
    SYSTEM_INITIALIZED,
    SYSTEM_SETTINGS_UPDATED,
    TOKEN_REFRESH,
    USER_CREATED,
    USER_DELETED,
    USER_DISABLED,
    USER_ENABLED,
    USER_GROUPS_UPDATED,
    USER_LOCKED,
    USER_UNLOCKED,
    USER_UPDATED,
    VERSION_REVERTED,
};
pub use auth::{
    permissions,
    repository::{
        GroupRepository, GroupRepositoryError, RoleRepository, RoleRepositoryError,
        SessionRepository, SessionRepositoryError, UserRepository, UserRepositoryError,
    },
    types::{
        builtin_groups, builtin_roles, config_defaults, config_keys, ApiKey, ApiKeyCreated,
        AuthResponse, CreateApiKeyRequest, CreateGroupRequest, CreateOidcProviderRequest,
        CreateRoleRequest, CreateUserRequest, Group, GroupSummary, GroupWithDetails, LoginRequest,
        OidcGroupMapping, OidcProvider, PasswordResetCompletion, PasswordResetRequest, Permission,
        RefreshTokenRequest, Role, RoleSummary, RoleWithPermissions, Session, SessionResponse,
        SystemConfig, TokenClaims, TokenPair, UpdateGroupRequest, UpdateOidcProviderRequest,
        UpdateRoleRequest, UpdateUserRequest, User, UserInfo, UserStatus, UserWithGroups,
    },
};
pub use crypto::{CryptoError, EncryptedData, EncryptionService};
pub use db::{
    ArtifactRepository, ArtifactRepositoryError, DashboardRepository, DashboardRepositoryError,
    Database, DatabaseConfig, DualPool, DualPoolConfig, DualPoolError, HealthStatus,
    NotebookRepository, NotebookRepositoryError, TableNames,
};
pub use entity_extraction::{EntityExtractor, ExtractedEntity};
// Cases & incidents repositories are enterprise-only (NAN-1298). Re-exported at
// the crate root only when the `enterprise` feature is on; gated out of the open
// edition alongside the modules themselves in db/repository.rs.
#[cfg(feature = "enterprise")]
pub use db::{CaseRepository, CaseRepositoryError, IncidentRepository, IncidentRepositoryError};
pub use detection::{
    calculate_next_run_phased, generate_node_id, DailyMatchCount, DetectionError,
    DetectionService, DistributedDetectionScheduler, DistributedSchedulerConfig,
    HistoricalAnalysisResult, MaterializedViewError, MaterializedViewGenerator, RiskError,
    RiskModifier, RiskResult, RuleTestAdmission, RuleTestAdmissionError, RuleTestPermit,
    ScoreCalculator, SignalProcessor, SignalProcessorConfig, TimeBucket,
};
pub use enrichment::{
    EnrichmentError, EnrichmentRepository, EnrichmentService, IpEnrichmentResult, LogEnrichment,
};
pub use feeds::{
    Feed, FeedHealthMetrics, FeedHistoryPoint, FeedRepositoryError, FeedService, FeedServiceError,
    FeedStats, NewFeed, UpdateFeed,
};
pub use gdpr::{
    AnonymizationError, AnonymizationPreview, AnonymizationRequest, AnonymizationService,
    AnonymizationStatus, IdentifierType,
};
pub use ingestion::ParsedLog;
pub use inputlookup::{
    InputLookupConfig, InputLookupError, InputLookupFormat, InputLookupParams, InputLookupService,
    SsrfConfig, SsrfError, SsrfValidator, UrlTemplate,
};
pub use ip_allowlist::{
    CreateIpAllowlistEntry, IpAllowlistEntry, IpAllowlistScope, IpAllowlistService,
    IpAllowlistServiceError, IpAllowlistStatus, MatchedRule, TestIpRequest, TestIpResponse,
    UpdateIpAllowlistEntry,
};
pub use leader::LeaderElection;
#[cfg(feature = "enterprise")]
pub use license::{
    LicenseChecker, LicenseRepository, LicenseResponse, LicenseState, LicenseStatus,
};
pub use log_sources::{
    AiSuggestions, HealthStatus as LogSourceHealthStatus, HistoryPoint, IngestionTrend,
    ListParams as LogSourceListParams, LogSource, LogSourceCategory, LogSourceDeployment,
    LogSourceHealth, LogSourceHealthSummary, LogSourceRepository, LogSourceRepositoryError,
    LogSourceService, LogSourceServiceError, LogSourceVersion, LogSourceVersionError,
    LogSourceVersionRepository, LogSourceWithDraftStatus, NewLogSource, SourceType,
    UpdateLogSource, WizardEntry, WizardProgressEvent, WizardSession, WizardStep,
};
pub use log_telemetry::{
    BucketSize as LogTelemetryBucketSize, HourlyPoint as LogTelemetryHourlyPoint,
    LogTelemetryError, LogTelemetryRepository, LogTelemetryService,
    SourceTypeStats as LogTelemetrySourceTypeStats,
};
pub use lookup::{
    sanitize_identifier, sanitize_identifiers, BatchLookupQuery, BatchLookupResult,
    ColumnTypeOverride, LookupColumn, LookupError, LookupHistoryEntry, LookupHistoryKind,
    LookupQuery, LookupRepository, LookupRepositoryError, LookupResult, LookupRowsPage,
    LookupService, LookupTable, LookupTableCreator, LookupUsage, NewLookupTable, RuleReferenceRow,
    LOOKUP_TABLE_PREFIX, MAX_LOOKUP_TABLE_ROWS,
};
pub use marketplace::{
    CatalogFilter, CatalogListResponse, CatalogStats, ConfigureRequest, CreateMarketplaceRepo,
    CredentialRequirement, EnrichmentMarketplaceRepo,
    EnrichmentStatus as MarketplaceEnrichmentStatus, ExecutionBackend, InstallRequest,
    MarketplaceCatalogEntry, MarketplaceCategory, MarketplaceError, MarketplaceInstallService,
    MarketplaceManifest, MarketplaceRepository, MarketplaceSyncService, RepoBrowseEntry,
    RepoSyncResult, SourceType as MarketplaceSourceType, UpdateMarketplaceRepo,
};
pub use models::*;
pub use parser_repository::{
    parse_parser_yaml, NewParserRepository as NewParserRepo, ParserImport, ParserImportPreview,
    ParserImportRequest, ParserImportType, ParserImportsRepository, ParserRepository as ParserRepo,
    ParserRepositoryError, ParserRepositoryRepository as ParserRepoRepository,
    ParserRepositoryService, ParserRepositoryServiceConfig, ParserYaml, ParserYamlError,
    RepositoryParser, RepositoryParserFilter, RepositoryParsersRepository,
    SyncResult as ParserSyncResult, SyncStatus as ParserSyncStatus,
    UpdateParserRepository as UpdateParserRepo, UpstreamParserDiff,
};
pub use parsers::{
    AwsS3Credentials, CloudCredential, CloudProvider, CreateCloudCredential, CredentialRepository,
    CredentialRepositoryError, DeploymentAction, DeploymentResult, DeploymentStatus,
    GcpPubSubCredentials, KafkaCredentials, NewParser, Parser, ParserCategory, ParserDeployment,
    ParserService, ParserServiceError, ParserTestResult, PublicationOutcome, SnapshotBundle,
    UpdateCloudCredential, UpdateParser, ValidationResult, VectorConfigPublicationError,
    VectorConfigPublisher, VrlValidationResult,
};
pub use playbook_repository::{
    NewPlaybookRepository, PlaybookImport, PlaybookImportRequest, PlaybookImportResponse,
    PlaybookImportType, PlaybookImportsRepository,
    PlaybookRepoRepository as PlaybookRepositoryRepository, PlaybookRepository as PlaybookRepo,
    PlaybookRepositoryError, PlaybookRepositoryService, PlaybookRepositoryServiceConfig,
    PlaybookSyncResult, PlaybookSyncStatus, RepositoryPlaybook, RepositoryPlaybookFilter,
    RepositoryPlaybooksRepository, UpdatePlaybookRepository,
};
pub use playbooks::{
    eval_when, normalize_answer, parse_playbook, parse_step_body, parse_when_clause,
    AdaptiveSource, CreatePlaybookRequest, DangerPolicy as PlaybookDangerPolicy,
    ForkPlaybookRequest, ListPlaybooksQuery, ParsedStepTree, Playbook, PlaybookApproval,
    PlaybookCategory, PlaybookError, PlaybookFrontmatter, PlaybookListResponse, PlaybookPermission,
    PlaybookPhase, PlaybookRepository, PlaybookRun, PlaybookScope, PlaybookService, PlaybookStatus,
    PlaybookStep, PlaybookVersion, UpdatePlaybookRequest, WhenClause, WhenOp, WhenResult,
};
pub use prevalence::{
    ArtifactType, BulkPrevalenceRequest, ExportFormat, PrevalenceConfig, PrevalenceData,
    PrevalenceError, PrevalenceRepository, PrevalenceScatterData, PrevalenceScatterPoint,
    PrevalenceService, TimeWindow, MAX_BULK_ARTIFACTS,
};
pub use query::{collect_derived_fields, parse_query, ParseError, PrettyPrint, Query};
pub use query_library::{
    CategoryCount, LibraryFilter, LibraryQuery, NewLibraryQuery, QueryDifficulty,
    QueryLibraryRepository,
};
pub use reports::{
    NewReportDefinition, ReportArtifactContent, ReportArtifactMeta, ReportDefinition, ReportError,
    ReportRepository, ReportRepositoryError, ReportRun, ReportRunStatus, ReportService,
    ReportSourceType, UpdateReportDefinition,
};
pub use risk::{
    EntityActivityResponse, EntityDailyCount, EntityRiskScore, EntityRiskSummary,
    EntityRuleContribution, EntitySignalSummary, RiskAnalyticsOverview, RiskDecayConfig,
    RiskFilter, RiskLevel, RiskTimeWindow, TimeWindowedRiskScore,
};
pub use rule_repository::{
    ConversionTriageHints, CoverageAnalysis, CoverageAnalyzer, CoverageFilter, CoverageResult,
    FolderInfo, GitHubClient, GitHubClientError, ImportOutcome, ImportPreview, ImportRequest,
    ImportType, NewRuleRepository, RepositoryRule, RepositoryRuleFilter, RepositoryRulesRepository,
    RuleImport, RuleImportsRepository, RuleRepository, RuleRepositoryError,
    RuleRepositoryRepository, RuleRepositoryService, RuleRepositoryServiceConfig, SigmaDetection,
    SigmaLogsource, SigmaParseError, SigmaRule, SyncResult, SyncStatus, UpdateRuleRepository,
    UpdatedRule,
};
pub use scheduler::{
    calculate_next_run, calculate_next_runs, describe_cron, merge_auth_headers,
    redact_auth_headers, validate_cron, JobExecution, JobFilter, JobStats, JobStatus,
    NewScheduledJob, RetryPolicy, ScheduledJob, SchedulerError, SchedulerRepository,
    SchedulerRepositoryError, SchedulerService, UpdateScheduledJob,
};
pub use search::{
    HistogramBucket, LakeIdentityObservation, RawSqlRequest, SearchBackend, SearchError,
    SearchRequest, SearchResponse, SearchService, TimeRangeInput, UdmFieldQueryRequest,
    UdmQueryOperator,
};
pub use settings::{
    ai_request_cost, check_api_access, check_api_write_access, check_limit, check_model_access,
    check_sso_access, credits_for_cost_tier, generate_warnings, resolve_ai_request_cost,
    AgentUsage, AiModelTier, AiUsage, AiUsageEvent, ApiAccessLevel, DailyAiUsage, DailyUsage,
    DeveloperSettingsError, DeveloperSettingsRepository, DiskPressureConfig, DiskPressureError,
    DiskPressureLevel, DiskPressureService, DiskPressureStatus, OrganizationTier, RetentionConfig,
    RetentionError, RetentionService, SchedulerSettings, StorageStats, SystemSettings, TierError,
    TierLimitExceeded, TierLimits, TierSettings, TierStatus, TierUsage, TierWarning,
    UpdateTierLimits, AI_CREDIT_FULL, AI_CREDIT_LITE,
    ai_allowance_paused_message, next_ai_allowance_reset, AI_ALLOWANCE_PAUSED_CODE,
};
pub use source_configs::{
    DeploymentResult as SourceConfigDeploymentResult, ListParams as SourceConfigListParams,
    MatchType, NewRoutingRule, NewSourceConfiguration, RoutingRule, SourceConfigDeployment,
    SourceConfigRepository, SourceConfigRepositoryError, SourceConfigService,
    SourceConfigServiceError, SourceConfigType, SourceConfiguration, SourceConfigurationWithRules,
    UpdateRoutingRule, UpdateSourceConfiguration,
};
pub use tenant_entitlements::{
    TenantComponent, TenantComponentGrant, TenantEntitlementError, TenantEntitlementResolver,
    TenantEntitlementSnapshot, TENANT_COMPONENTS,
};
pub use tuning::{
    AlertPattern, Baseline, ComparisonMetrics, Notification, NotificationType, PatternChange,
    RuleMetrics, RuleVersion, SafetyCheck, SafetyValidation, StagingDeployment, TestResults,
    ThresholdBreach, TuningLogEntry, TuningProposal, TuningStatus, VersionChangeReason,
};
pub use upload::{
    ColumnInfo, ColumnType, FileFormat, FileParser, LookupMode, ParseError as UploadParseError,
    ParseResult as UploadParseResult, ParsedRecord, ParserConfig as UploadParserConfig,
    PreviewResult, UploadDestination, UploadError, UploadFilter, UploadRecord, UploadRepository,
    UploadRepositoryError, UploadRequest, UploadResult, UploadService, UploadStatus,
    DEFAULT_PREVIEW_ROWS, MAX_FILE_SIZE,
};

#[cfg(feature = "enterprise")]
pub mod enterprise_shared_tenant_purge_prebuild;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_uid_capability_issuer;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2_owner_observation;

pub mod request_timing;

pub mod background_queue;

#[cfg(feature = "enterprise")]
pub mod enterprise_shared_bronze_delete;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_lake_part_delete;

pub mod iceberg_export;

/// Telemetry-derived source onboarding plans (NAN-3684).
pub mod source_onboarding;
