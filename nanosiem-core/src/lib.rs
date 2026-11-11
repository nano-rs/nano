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
pub mod ai_provider_safety;
// Air-gapped signed bundle format + Ed25519 verification (NAN-1201) — enterprise
// only. Gated to match the api-side `#[cfg(feature = "enterprise")] pub mod airgap;`
// so the open edition excludes the source, and the open-core mirror can strip the
// `nanosiem-core/src/airgap` directory outright (tools/sync-to-nano-mirror.sh).
#[cfg(feature = "enterprise")]
pub mod airgap;
pub mod audit;
pub mod auth;
pub mod backup_status;
pub mod baseline;
pub(crate) mod config_safety;
pub mod config_secrets;
pub mod content_bundle;
pub mod content_catalog_defaults;
pub mod crypto;
pub mod csv_safe;
pub mod db;
pub mod demo;
pub mod deployment_posture;
pub mod detection;
pub mod detection_code_target;
pub mod enrichment;
pub mod entity_extraction;
pub mod extensions;
pub mod feeds;
pub mod gdpr;
pub mod health;
pub mod http_body;
#[cfg(feature = "enterprise")]
pub mod hunts;
pub mod identity;
/// Named, revocable per-source ingest tokens (NAN-4907, ported from NAN-3770/3806).
pub mod ingest_tokens;
pub mod ingest_watchdog;
pub mod ingestion;
pub mod inputlookup;
pub mod internal_domains;
pub mod ip_allowlist;
pub mod known_public_secrets;
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
pub mod platform_enrichment;
#[cfg(feature = "enterprise")]
pub mod playbook_repository;
#[cfg(feature = "enterprise")]
pub mod playbooks;
pub mod prevalence;
pub mod principal_gate;
pub mod process_supervision;
pub mod query;
pub mod query_library;
pub mod reports;
pub mod risk;
pub mod rule_repository;
pub mod scheduler;
pub mod schema;
pub mod search;
pub mod settings;
pub mod shutdown;
pub mod siem_health;
pub mod source_configs;
pub mod sql_hygiene;
#[cfg(test)]
#[path = "sql_interpolation_lint_tests.rs"]
mod sql_interpolation_lint_tests;
pub mod system_health;
pub mod telemetry;
pub mod text_bounds;
pub mod timezone;
pub mod tuning;
pub mod typeid;
pub mod udm;
pub mod udm_context;
pub mod upload;
pub mod vector_env;
pub mod vector_naming;
pub mod webhooks;
pub mod yaml_budget;

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
    TableNames,
};
pub use entity_extraction::{EntityExtractor, ExtractedEntity};
// Cases & incidents repositories are enterprise-only (NAN-1298). Re-exported at
// the crate root only when the `enterprise` feature is on; gated out of the open
// edition alongside the modules themselves in db/repository.rs.
#[cfg(feature = "enterprise")]
pub use db::{
    CaseRepository, CaseRepositoryError, IncidentRepository, IncidentRepositoryError,
    NotebookRepository, NotebookRepositoryError,
};
pub use detection::{
    calculate_next_run_phased, generate_node_id, DailyMatchCount, DetectionError, DetectionService,
    DistributedDetectionScheduler, DistributedSchedulerConfig, HistoricalAnalysisResult,
    MaterializedViewError, MaterializedViewGenerator, RiskError, RiskModifier, RiskResult,
    RuleTestAdmission, RuleTestAdmissionError, RuleTestPermit, ScoreCalculator, SignalProcessor,
    SignalProcessorConfig, TimeBucket,
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
#[cfg(feature = "enterprise")]
pub use playbook_repository::{
    NewPlaybookRepository, PlaybookImport, PlaybookImportRequest, PlaybookImportResponse,
    PlaybookImportType, PlaybookImportsRepository,
    PlaybookRepoRepository as PlaybookRepositoryRepository, PlaybookRepository as PlaybookRepo,
    PlaybookRepositoryError, PlaybookRepositoryService, PlaybookRepositoryServiceConfig,
    PlaybookSyncResult, PlaybookSyncStatus, RepositoryPlaybook, RepositoryPlaybookFilter,
    RepositoryPlaybooksRepository, UpdatePlaybookRepository,
};
#[cfg(feature = "enterprise")]
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
    CoverageAnalysis, CoverageAnalyzer, CoverageFilter, CoverageResult,
    FolderInfo, GitHubClient, GitHubClientError, ImportOutcome, ImportPreview, ImportRequest,
    ImportType, NewRuleRepository, RepositoryRule, RepositoryRuleFilter, RepositoryRulesRepository,
    RuleImport, RuleImportsRepository, RuleRepository, RuleRepositoryError,
    RuleRepositoryRepository, RuleRepositoryService, RuleRepositoryServiceConfig,
    SyncResult, SyncStatus, UpdateRuleRepository,
    UpdatedRule,
};
pub use scheduler::{
    calculate_next_run, calculate_next_runs, describe_cron, merge_auth_headers,
    merge_auth_headers_for_url, AuthHeadersOriginChanged,
    redact_auth_headers, validate_cron, JobExecution, JobFilter, JobStats, JobStatus,
    NewScheduledJob, RetryPolicy, ScheduledJob, SchedulerError, SchedulerRepository,
    SchedulerRepositoryError, SchedulerService, UpdateScheduledJob,
};
pub use search::{
    HistogramBucket, RawSqlRequest, SearchBackend, SearchError, SearchRequest, SearchResponse,
    SearchService, TimeRangeInput, UdmFieldQueryRequest, UdmQueryOperator,
};
pub use settings::{
    ai_request_cost, check_api_access, check_api_write_access, check_limit, check_model_access,
    check_sso_access, credits_for_cost_tier, generate_warnings, parse_capacity_gb_per_day,
    full_request_cost, resolve_ai_request_cost, AgentUsage, AiModelTier, AiUsage, AiUsageEvent, ApiAccessLevel,
    DailyAiUsage, DailyUsage, DeveloperSettingsError, DeveloperSettingsRepository,
    DiskPressureConfig, DiskPressureError, DiskPressureLevel, DiskPressureService,
    DiskPressureStatus, Entitlement, EntitlementEdition, EntitlementOperator, OrganizationTier,
    RetentionConfig, RetentionError, RetentionService, SchedulerSettings, StorageStats,
    SystemSettings, TierError, TierLimitExceeded, TierLimits, TierSettings, TierStatus, TierUsage,
    TierWarning, UpdateTierLimits, AI_CREDITS_CEILING_ENV, AI_CREDIT_FULL, AI_CREDIT_LITE, AI_CREDIT_NONE,
    CAPACITY_GB_PER_DAY_ENV,
};
pub use source_configs::{
    DeploymentResult as SourceConfigDeploymentResult, ListParams as SourceConfigListParams,
    MatchType, NewRoutingRule, NewSourceConfiguration, RoutingRule, SourceConfigDeployment,
    SourceConfigRepository, SourceConfigRepositoryError, SourceConfigService,
    SourceConfigServiceError, SourceConfigType, SourceConfiguration, SourceConfigurationWithRules,
    UpdateRoutingRule, UpdateSourceConfiguration,
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
