// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search Engine for NanoSIEM
//!
//! This module provides:
//! - Search execution service for running piped queries
//! - Field statistics calculation
//! - UDM field querying across sources
//! - Support for both PostgreSQL and ClickHouse backends
//! - Query tracking for cancellation support
//! - Async job support for long-running queries

pub mod admission;
pub mod classification;
/// NAN-3222: audit of searches naming a source the caller cannot see.
pub mod denied_source_audit;
mod config;
mod evaluator;
mod execution;
pub mod field_usage;
pub mod field_utils;
pub mod job_coordinator_client;
pub mod job_coordinator_config;
#[cfg(feature = "enterprise")]
pub mod hosted_producer_reload;
pub mod job_control_store;
pub mod job_coordinator_transport;
pub mod job_envelope;
pub mod job_runner_store;
pub mod job_signing;
pub mod jobs;
pub mod keyword_sidecar;
mod lake;
pub mod lake_cell;
pub mod lake_debug;
/// NAN-3020: query[T] reads behind the lean tenant ingest counters.
pub mod lean_ingest_fetch;
/// NAN-3243: lean-lake tenants' `lake_otel_ingest` (lean mode) routes.
pub mod lean_otel_routes;
mod otel_lake;
mod processing;
pub mod query_processing;
mod query_tracking;
/// NAN-2361 wave 5: request-actor task-local + spawn inheritance.
pub mod request_actor;
pub mod service;
/// NAN-3245: full-event rows are the event's populated fields, not the schema.
pub mod sparse_event;
pub mod streaming;
pub mod settled_reuse;
pub mod tenant;
mod types;
/// NAN-3282: per-request and process-wide product-view memory budgets.
pub mod view_memory;

pub use admission::{
    AdmissionConfig, AdmissionController, AdmissionError, AdmissionLane, AdmissionPermit,
    AdmissionStats, ClickHouseQuerySettings, QueryPriority,
};
pub use config::{SearchBackend, SearchConfig};
// NAN-2001: `inject_audit_filter` retired — the audit gate is enforced by the
// ClickHouse `nanosiem_rawsql_noaudit` row policy, not by AST rewriting.
pub use execution::validate_sql_query;
// NAN-1389: exposed for the lookup pre-check PG integration suite
pub use job_signing::{
    DurableJobSignedRecord, DurableJobSigningError, DurableJobSigningKey,
    DurableJobSigningMasterKey,
};
pub use jobs::{
    AdminSearchJobSummary, AsyncSearchResponse, DurableCloudEventsSummaryQueries,
    DurableJobStoreError, DurableLakeGenerationPin, DurableLakeTask, DurableQueryResourceClass,
    DurableResultRetentionProof, DurableSearchCredentialAuthority, DurableSearchJobAuthority,
    DurableSearchJobClaim, InMemoryJobStore, RedisJobStore, SearchJob, SearchJobBackend,
    SearchJobProgress, SearchJobRegistry, SearchJobResultPage, SearchJobResultRef,
    SearchJobResultSummary, SearchJobStatus, SearchJobStatusResponse, SearchJobStore,
    SearchJobSummary, MAX_DURABLE_POST_PAGE_ROWS, MAX_DURABLE_POST_QUERY_BYTES,
};
pub use lake::{
    lake_rollup_field_is_enrichment_sensitive, LAKE_COUNT_ROLLUP_FIELDS,
    LakeBackend, LakeDetectionPlan, LakeDetectionRerunWindow, LakeIdentityObservation, LakeIdentityResolution,
    OwnedLakeBackend, EVENT_SCAN_SOURCE_PREFIX,
    SharedLakeOtelIngestAssignment, SharedLakeWorkerAssignment, SharedLakeWorkerRegistry,
};
pub use lake_cell::{LakeCellRoute, LakeCellRouteSource, LakeCellRoutes};
pub use lean_otel_routes::{LeanOtelRouteSource, LeanOtelRoutes};
pub use processing::validate_lookup_tables;
/// The Nano-side row evaluator, exported for contract tests that prove a
/// gated query row by row (NAN-2361 wave 8 source visibility).
pub use processing::post_processing::condition::evaluate_condition_on_json;
pub use query_tracking::QueryTracker;
pub use service::asset_dossier::{
    AssetActivityTimeline, AssetAuthSummary, AssetDnsSummary, AssetDossier, AssetFilesSummary,
    AssetIdentity, AssetLogSource, AssetNetworkSummary, AssetProcessesSummary, AuthRecent, DnsTop,
    FileRecent, NetworkDest, NetworkRareCountry, ProcessRare, ProcessTop, ProductViewProgress,
};
pub use service::cloud_dossier::{
    CloudDossier, CloudDossierActionRow, CloudDossierAssumeChain, CloudDossierAssumeHop,
    CloudDossierAuthPosture, CloudDossierErrorCode, CloudDossierErrorRate,
    CloudDossierFacetFilters, CloudDossierFacetItem, CloudDossierFacets, CloudDossierIdentity,
    CloudDossierIp, CloudDossierKeyAction, CloudDossierPosturePrincipal, CloudDossierRegion,
    CloudDossierResource, CloudDossierRisk, CloudDossierRiskFactor, CloudDossierStreamEvent,
    CloudDossierTimeline, CloudDossierTimelineLane, CloudDossierTimelineMarker,
    CloudDossierUserAgent,
};
pub use service::cloud_overview::{
    CloudOverview, CloudOverviewAccount, CloudOverviewAnomaly, CloudOverviewChange,
    CloudOverviewHeader, CloudOverviewOpenAlerts, CloudOverviewPrincipal,
    CloudOverviewProviderBreakdown, CloudOverviewServiceHealth, CloudOverviewTimeline,
    CloudOverviewTimelineLane, CloudOverviewTimelineMarker,
};
pub use service::{
    run_lake_baseline, CloudDossierAccumulator, LakeAssetCardRead, LakeAssetCards, LakeBaselineOutcome, LakeBaselinePlan,
    LAKE_BASELINE_BUDGET_EXHAUSTED,
    FieldStatsResult, FieldValuesResult, LakeCellDetectHeadProbe, LakeCellDetectionCommitter, RawSqlAuditAccess, SearchHistogramResult, SearchService,
};
pub use service::lean_prevalence::{
    lean_prevalence_row, LeanPrevalenceJob, LeanPrevalencePurpose, LEAN_PREVALENCE_EXPORT_MAX_ROWS,
    LEAN_PREVALENCE_RARE_REUSE_MS,
};
pub use streaming::{is_query_streamable, SearchStreamEvent, StreamingChunk};
pub use tenant::{SearchTenantError, SearchTenantScope, ServingGenerationKey};
pub(crate) use types::SearchExecutionLimits;
pub use types::{
    cold_scan_too_large_message, parse_clickhouse_error, AssetEventFilters, AssetFacets, AssetPagination, CloudEventFilters,
    CloudFacets, CloudUserActivity, CloudUserSessionSummary, DisplayType, EntityCrossReference,
    EventCompleteness, FieldInfo, HotTailPartialCoverage, HotTailSlowPathCoverage, FieldStatistics, FieldValueInfo, HistogramBucket,
    ProductViewCursor, QueryWarningOutput, RawSqlRequest, RetroFeedCandidate, RetroHuntHit,
    RetroIndicatorSummary, RetroListRow, RetroPivotRow, RetroRequest, RetroResponse,
    RetroTopEntity, RetroVerdict, SearchError, SearchRequest, SearchResponse, TimeRangeInput,
    UdmFieldQueryRequest, UdmQueryOperator,
};

pub use service::lateral::{run_lake_lateral_job, validate_lake_lateral_job};
