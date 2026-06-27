// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search handlers for the Search Service
//!
//! Handles search queries, saved searches, field statistics, and asset artifacts.
//! Queries are executed against ClickHouse with lookup enrichment from PostgreSQL.
//!
//! Requirements: 3.1, 3.2, 3.3

mod asset_dossier;
mod assets;
mod cloud_dossier;
mod cloud_overview;
mod health;
pub(crate) mod identity;
mod otel;
mod retro;
mod saved_searches;
mod search;
mod search_jobs;
mod streaming;

use nanosiem_core::{
    SearchResponse,
    search::{AdminSearchJobSummary, AdmissionStats, QueryPriority, SearchJobSummary},
};
use serde::Serialize;
use utoipa::OpenApi;

use crate::error::ErrorResponse;

// Re-export all handler functions
pub use asset_dossier::get_asset_dossier;
pub use assets::{
    get_asset_artifacts, get_asset_events, get_asset_true_time_range, get_cloud_entity_pivot,
    get_cloud_events, get_cloud_user_timeline,
};
pub use cloud_dossier::get_cloud_dossier;
pub use cloud_overview::get_cloud_overview;
pub use health::{health, ready};
pub use identity::resolve_identity;
pub use otel::{
    get_metric_timeseries, get_rum_summary, get_service_detail, get_trace, list_infra_hosts,
    list_metric_names, list_metric_tags, list_services, list_traces,
};
pub use retro::retro;
pub use saved_searches::{
    create_saved_search, delete_saved_search, get_saved_search, list_my_saved_searches,
    list_saved_searches, list_shared_searches, share_saved_search, update_saved_search,
};
pub use search::{
    cancel_search, explain, fetch_log, field_stats_for_query, field_values, prevalence_artifacts,
    search, search_sql,
};
pub use search_jobs::{
    admin_cancel_search_job, admin_get_stats, admin_list_search_jobs, cancel_search_job,
    get_search_job, list_search_jobs,
};
pub use streaming::search_stream;

// Re-export types used in OpenAPI schema registration
pub use asset_dossier::AssetDossierRequest;
pub use cloud_dossier::CloudDossierRequest;
pub use cloud_overview::CloudOverviewRequest;
pub use assets::{
    ArtifactOccurrence, ArtifactPrevalence, AssetArtifactsRequest, AssetArtifactsResponse,
    AssetEventsRequest, AssetEventsResponse, AssetTrueTimeRangeRequest, AssetTrueTimeRangeResponse,
    CloudEntityPivotRequest, CloudEntityPivotResponse, CloudEventsRequest, CloudEventsResponse,
    CloudUserTimelineRequest, CloudUserTimelineResponse,
};
pub use health::{HealthResponse, ReadyResponse};
pub use identity::IdentityResolveResponse;
pub use otel::{
    InfraHostsResponse, ListTracesResponse, MetricFilterInput, MetricNamesResponse, MetricSeries,
    MetricTagsResponse, MetricTimeseriesRequest, MetricTimeseriesResponse, RumSummaryResponse,
    ServiceDetailResponse, ServicesOverviewResponse, TraceResponse,
};
pub use search::{
    CancelSearchResponse, ExplainRequest, ExplainResponse, FetchLogRequest, FetchLogResponse,
    FieldStatsRequest, FieldStatsResponse, FieldValuesRequest, FieldValuesResponse,
};
pub use search_jobs::{AdminSearchJobsResponse, CancelJobResponse};

/// Response wrapper for search that can be either sync or async
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum SearchResultResponse {
    Sync(SearchResponse),
    Async(nanosiem_core::search::AsyncSearchResponse),
}

// ============================================================================
// OpenAPI Sub-Doc
// ============================================================================

/// OpenAPI sub-document for all search service handlers
#[derive(OpenApi)]
#[openapi(
    paths(
        search::search,
        streaming::search_stream,
        search::cancel_search,
        search::search_sql,
        search::explain,
        search::fetch_log,
        search::prevalence_artifacts,
        search::field_stats_for_query,
        search::field_values,
        saved_searches::list_saved_searches,
        saved_searches::list_shared_searches,
        saved_searches::list_my_saved_searches,
        saved_searches::get_saved_search,
        saved_searches::create_saved_search,
        saved_searches::update_saved_search,
        saved_searches::delete_saved_search,
        saved_searches::share_saved_search,
        health::health,
        health::ready,
        retro::retro,
        assets::get_asset_events,
        assets::get_cloud_events,
        assets::get_cloud_user_timeline,
        assets::get_cloud_entity_pivot,
        assets::get_asset_true_time_range,
        assets::get_asset_artifacts,
        asset_dossier::get_asset_dossier,
        cloud_overview::get_cloud_overview,
        cloud_dossier::get_cloud_dossier,
        search_jobs::get_search_job,
        search_jobs::cancel_search_job,
        search_jobs::list_search_jobs,
        search_jobs::admin_list_search_jobs,
        search_jobs::admin_get_stats,
        search_jobs::admin_cancel_search_job,
        identity::resolve_identity,
        otel::get_trace,
        otel::get_metric_timeseries,
        otel::list_traces,
        otel::list_metric_names,
        otel::list_metric_tags,
        otel::list_services,
        otel::get_service_detail,
        otel::list_infra_hosts,
        otel::get_rum_summary,
    ),
    components(schemas(
        SearchResultResponse,
        CancelSearchResponse,
        ExplainRequest,
        ExplainResponse,
        FetchLogRequest,
        FetchLogResponse,
        FieldValuesRequest,
        FieldValuesResponse,
        FieldStatsRequest,
        FieldStatsResponse,
        HealthResponse,
        ReadyResponse,
        nanosiem_core::search::RetroRequest,
        nanosiem_core::search::RetroResponse,
        nanosiem_core::search::RetroIndicatorSummary,
        nanosiem_core::search::RetroListRow,
        nanosiem_core::search::RetroPivotRow,
        nanosiem_core::search::RetroTopEntity,
        nanosiem_core::search::RetroVerdict,
        AssetEventsRequest,
        AssetEventsResponse,
        CloudEventsRequest,
        CloudEventsResponse,
        nanosiem_core::search::CloudFacets,
        nanosiem_core::search::CloudEventFilters,
        CloudUserTimelineRequest,
        CloudUserTimelineResponse,
        nanosiem_core::search::CloudUserSessionSummary,
        CloudEntityPivotRequest,
        CloudEntityPivotResponse,
        nanosiem_core::search::EntityCrossReference,
        nanosiem_core::search::CloudUserActivity,
        AssetTrueTimeRangeRequest,
        AssetTrueTimeRangeResponse,
        AssetArtifactsRequest,
        AssetArtifactsResponse,
        ArtifactOccurrence,
        ArtifactPrevalence,
        AssetDossierRequest,
        nanosiem_core::search::AssetDossier,
        CloudDossierRequest,
        nanosiem_core::search::CloudDossier,
        nanosiem_core::search::CloudDossierIdentity,
        nanosiem_core::search::CloudDossierUserAgent,
        nanosiem_core::search::CloudDossierIp,
        nanosiem_core::search::CloudDossierRisk,
        nanosiem_core::search::CloudDossierRiskFactor,
        nanosiem_core::search::CloudDossierFacets,
        nanosiem_core::search::CloudDossierFacetItem,
        nanosiem_core::search::CloudDossierAssumeChain,
        nanosiem_core::search::CloudDossierAssumeHop,
        nanosiem_core::search::CloudDossierKeyAction,
        nanosiem_core::search::CloudDossierTimeline,
        nanosiem_core::search::CloudDossierTimelineLane,
        nanosiem_core::search::CloudDossierTimelineMarker,
        nanosiem_core::search::CloudDossierRegion,
        nanosiem_core::search::CloudDossierActionRow,
        nanosiem_core::search::CloudDossierResource,
        nanosiem_core::search::CloudDossierAuthPosture,
        nanosiem_core::search::CloudDossierPosturePrincipal,
        nanosiem_core::search::CloudDossierErrorCode,
        nanosiem_core::search::CloudDossierErrorRate,
        nanosiem_core::search::CloudDossierStreamEvent,
        CloudOverviewRequest,
        nanosiem_core::search::CloudOverview,
        nanosiem_core::search::CloudOverviewHeader,
        nanosiem_core::search::CloudOverviewProviderBreakdown,
        nanosiem_core::search::CloudOverviewOpenAlerts,
        nanosiem_core::search::CloudOverviewAccount,
        nanosiem_core::search::CloudOverviewPrincipal,
        nanosiem_core::search::CloudOverviewTimeline,
        nanosiem_core::search::CloudOverviewTimelineLane,
        nanosiem_core::search::CloudOverviewTimelineMarker,
        nanosiem_core::search::CloudOverviewAnomaly,
        nanosiem_core::search::CloudOverviewServiceHealth,
        nanosiem_core::search::CloudOverviewChange,
        nanosiem_core::search::AssetIdentity,
        nanosiem_core::search::AssetLogSource,
        nanosiem_core::search::AssetActivityTimeline,
        nanosiem_core::search::AssetProcessesSummary,
        nanosiem_core::search::ProcessTop,
        nanosiem_core::search::ProcessRare,
        nanosiem_core::search::AssetNetworkSummary,
        nanosiem_core::search::NetworkDest,
        nanosiem_core::search::NetworkRareCountry,
        nanosiem_core::search::AssetAuthSummary,
        nanosiem_core::search::AuthRecent,
        nanosiem_core::search::AssetFilesSummary,
        nanosiem_core::search::FileRecent,
        nanosiem_core::search::AssetDnsSummary,
        nanosiem_core::search::DnsTop,
        CancelJobResponse,
        SearchJobSummary,
        AdminSearchJobSummary,
        AdminSearchJobsResponse,
        AdmissionStats,
        QueryPriority,
        IdentityResolveResponse,
        TraceResponse,
        MetricTimeseriesRequest,
        MetricFilterInput,
        MetricSeries,
        MetricTimeseriesResponse,
        MetricTagsResponse,
        ListTracesResponse,
        MetricNamesResponse,
        ServicesOverviewResponse,
        ServiceDetailResponse,
        InfraHostsResponse,
        RumSummaryResponse,
        ErrorResponse,
    ))
)]
pub struct SearchApiDoc;

// Metrics are served via Prometheus at /metrics endpoint
// See metrics.rs for the implementation
