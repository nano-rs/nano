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
mod config;
mod evaluator;
mod execution;
pub mod field_utils;
pub mod jobs;
mod processing;
pub mod query_processing;
mod query_tracking;
pub mod service;
pub mod streaming;
mod types;

pub use admission::{
    AdmissionConfig, AdmissionController, AdmissionError, AdmissionPermit, AdmissionStats,
    ClickHouseQuerySettings, QueryPriority,
};
pub use config::{SearchBackend, SearchConfig};
pub use execution::{inject_audit_filter, validate_sql_query};
// NAN-1389: exposed for the lookup pre-check PG integration suite
pub use processing::validate_lookup_tables;
pub use jobs::{
    AdminSearchJobSummary, AsyncSearchResponse, InMemoryJobStore, RedisJobStore, SearchJob,
    SearchJobProgress, SearchJobRegistry, SearchJobStatus, SearchJobStatusResponse, SearchJobStore,
    SearchJobSummary,
};
pub use query_tracking::QueryTracker;
pub use service::asset_dossier::{
    AssetActivityTimeline, AssetAuthSummary, AssetDnsSummary, AssetDossier, AssetFilesSummary,
    AssetIdentity, AssetLogSource, AssetNetworkSummary, AssetProcessesSummary, AuthRecent, DnsTop,
    FileRecent, NetworkDest, NetworkRareCountry, ProcessRare, ProcessTop,
};
pub use service::cloud_overview::{
    CloudOverview, CloudOverviewAccount, CloudOverviewAnomaly, CloudOverviewChange,
    CloudOverviewHeader, CloudOverviewOpenAlerts, CloudOverviewPrincipal,
    CloudOverviewProviderBreakdown, CloudOverviewServiceHealth, CloudOverviewTimeline,
    CloudOverviewTimelineLane, CloudOverviewTimelineMarker,
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
pub use service::SearchService;
pub use streaming::{is_query_streamable, SearchStreamEvent, StreamingChunk};
pub use types::{
    parse_clickhouse_error, AssetEventFilters, AssetFacets, AssetPagination, CloudEventFilters,
    CloudFacets, CloudUserActivity, CloudUserSessionSummary, DisplayType, EntityCrossReference,
    FieldInfo, FieldStatistics, FieldValueInfo, HistogramBucket, QueryWarningOutput, RawSqlRequest,
    RetroFeedCandidate, RetroHuntHit, RetroIndicatorSummary, RetroListRow, RetroPivotRow,
    RetroRequest, RetroResponse, RetroTopEntity, RetroVerdict, SearchError, SearchRequest,
    SearchResponse, TimeRangeInput, UdmFieldQueryRequest, UdmQueryOperator,
};
pub(crate) use types::SearchExecutionLimits;
