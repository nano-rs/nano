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
mod prevalence;
mod retro;
mod saved_searches;
mod search;
pub(crate) use search::lake_debug_middleware;
mod search_jobs;
pub mod tree_page;
pub use tree_page::get_tree_page;
mod streaming;

// Fail-closed authorization contract for these handlers (NAN-2030): unit-tests
// the shared gate and source-scans every handler for a search:execute decision.
#[cfg(test)]
mod authz_guard;

// NAN-2361 wave 8: the shared lake's source-visibility contract — one row
// filter on `metadata.log_source`, OTLP datasets gated by route slug, the
// explicit detection-runtime / case-scoped bypasses.
#[cfg(test)]
mod source_visibility_contract;

use nanosiem_core::{
    search::{AdminSearchJobSummary, AdmissionStats, QueryPriority, SearchJobSummary},
    SearchResponse,
};
use serde::Serialize;
use utoipa::OpenApi;

use crate::error::ErrorResponse;

/// Shared `search:execute` capability gate for the search microservice
/// (NAN-2028 / NAN-2030). Authentication (a valid token) is NOT authorization:
/// `auth_middleware` only proves *who* the caller is, so every handler that
/// reads log or OTEL data MUST call this as its first statement to prove the
/// caller *may* search. Consolidated here (it was duplicated in `search.rs` and
/// `assets.rs`) so there is exactly one gate — and `authz_guard.rs` can assert,
/// at test time, that every data handler performs it.
///
/// The source-scope deny-set (`search::effective_scope`) is NOT a substitute: it
/// defaults OPEN, so an unscoped key denies nothing but `audit`. Source scope
/// narrows *which* sources an already-authorized caller sees; it never decides
/// *whether* the caller may search at all.
pub(crate) fn require_search_execute(
    auth: &crate::AuthContext,
) -> Result<(), crate::error::SearchError> {
    if auth
        .claims
        .has_permission(nanosiem_core::auth::permissions::SEARCH_EXECUTE)
    {
        Ok(())
    } else {
        Err(crate::error::SearchError::Forbidden(
            "This operation requires the search:execute permission".to_string(),
        ))
    }
}

/// Revalidate the complete enterprise-shared credential, membership,
/// entitlement, and source-scope authority immediately before releasing data
/// or a durable job handle. Dedicated/open-core requests are a no-op.
pub(crate) async fn require_current_shared_authority(
    state: &crate::SearchState,
    auth: &crate::AuthContext,
) -> Result<(), crate::error::SearchError> {
    // Reuse only this request's admitted proof, up to its original TTL.
    // Streaming loops call revalidate_shared_context directly and
    // retain their uncached checks before subsequent chunks.
    if crate::auth_cache::current(auth) { return Ok(()); }
    crate::middleware::revalidate_shared_context(&state.auth_state, auth)
        .await.into_result()
}

/// The search runtime for an Asset / Cloud product-view companion request
/// (NAN-3059). Dedicated deployments keep their historical singleton. An
/// enterprise-shared request is served ONLY by its own lean-lake cell view:
/// that view is structurally pinned to the authenticated tenant (no
/// ClickHouse, metadata, lookup, AI or cloud-risk singleton survives in it),
/// every product-view read goes through the tenant's `query[T]` with the
/// caller's source deny-set, and prevalence reads the cell's own partials. A
/// gen1 view is refused rather than admitted by default.
pub(crate) fn product_view_search(
    state: &crate::SearchState,
    auth: &crate::AuthContext,
) -> Result<std::sync::Arc<nanosiem_core::search::SearchService>, crate::error::SearchError> {
    let view = state.search_for_auth(auth)?;
    if crate::is_shared_scope(auth.tenant_scope) {
        if !view.serves_lake_cell()
            || view.assigned_tenant_id().is_none()
            || view.assigned_tenant_id() != auth.tenant_scope.tenant_id()
        {
            return Err(crate::error::SearchError::ServiceUnavailable(
                "this product view is served for enterprise-shared tenants only on their \
                 lean-lake cell"
                    .to_string(),
            ));
        }
    }
    Ok(view)
}

/// Require the tenant's explicit prevalence plan component for shared-only
/// prevalence reads. Dedicated/open deployments retain their historical
/// edition/RBAC behavior; this bit is meaningful only with a server-resolved
/// shared tenant scope.
pub(crate) fn require_shared_prevalence_component(
    auth: &crate::AuthContext,
) -> Result<(), crate::error::SearchError> {
    if !crate::is_shared_scope(auth.tenant_scope) || auth.shared_prevalence_entitled {
        return Ok(());
    }
    Err(crate::error::SearchError::Forbidden(
        "Prevalence is not enabled for this tenant".to_string(),
    ))
}

/// Reject any enterprise-shared nPL request that could escape the exact
/// tenant-pinned lake worker into a process-global dependency. Dedicated,
/// managed, open-core, and demo calls take no additional branch.
///
/// Tenant lookups (`lookup`, `inputlookup <table>`, `ioc in lookup(...)`),
/// base-search IOC feed terms and the no-op `output` are admitted (NAN-2922);
/// `| ai` is refused here because no tenant-billed AI view has been proven.
/// Surfaces that execute `| ai` use [`require_shared_npl_contract_for_view`].
pub(crate) fn require_shared_npl_contract(
    auth: &crate::AuthContext,
    query: &str,
    dataset: Option<&str>,
) -> Result<(), crate::error::SearchError> {
    shared_npl_contract(auth, query, dataset, Default::default())
}

#[cfg(feature = "enterprise")]
use nanosiem_core::search::query_processing::EnterpriseSharedQueryCapabilities as SharedQueryCapabilities;
/// Open builds never resolve a shared scope, so these capabilities are only
/// carried, never consulted.
#[cfg(not(feature = "enterprise"))]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SharedQueryCapabilities {
    tenant_storage_inputlookup: bool,
    tenant_ai_pipe: bool,
    tenant_risk_dataset: bool,
    tenant_lake_product_views: bool,
}

/// [`require_shared_npl_contract`] for a surface that runs the query on an
/// already resolved tenant view: `| ai` is admitted only when that view's AI
/// client is bound to the tenant's billing authority (NAN-2922, #4668).
pub(crate) fn require_shared_npl_contract_for_view(
    auth: &crate::AuthContext,
    query: &str,
    dataset: Option<&str>,
    view: &nanosiem_core::search::SearchService,
) -> Result<(), crate::error::SearchError> {
    shared_npl_contract(
        auth,
        query,
        dataset,
        SharedQueryCapabilities {
            tenant_storage_inputlookup: view.storage_lookup_tenant_bound()
                && view.assigned_tenant_id() == auth.tenant_scope.tenant_id(),
            tenant_ai_pipe: view.ai_pipe_tenant_bound(),
            tenant_risk_dataset: view.tenant_risk_dataset_bound()
                && view.assigned_tenant_id() == auth.tenant_scope.tenant_id(),
            tenant_lake_product_views: view.serves_lake_cell()
                && view.assigned_tenant_id().is_some()
                && view.assigned_tenant_id() == auth.tenant_scope.tenant_id(),
        },
    )
}

fn shared_npl_contract(
    auth: &crate::AuthContext,
    query: &str,
    dataset: Option<&str>,
    capabilities: SharedQueryCapabilities,
) -> Result<(), crate::error::SearchError> {
    if !crate::is_shared_scope(auth.tenant_scope) {
        return Ok(());
    }
    shared_dataset_contract(dataset, capabilities)?;
    let parsed = nanosiem_core::query::parse_query(query)
        .map_err(|error| crate::error::SearchError::BadRequest(error.to_string()))?;
    shared_parsed_npl_contract(auth, &parsed, capabilities)
}

/// [`require_shared_npl_contract`] for a companion that executes ONLY the
/// base search of `query` (everything before the first pipe): the
/// `field-stats` and `field-values` side panels. Both strip every pipeline
/// command before they run (lake and ClickHouse alike), so a product view
/// such as `| cloud` never executes there. Checking the full text refused
/// the field panel of every `| cloud` search with a 503 ("dependency `cloud`
/// is not tenant-pinned", NAN-3093) although nothing it names would run.
/// The base search itself is still held to the full contract.
pub(crate) fn require_shared_npl_base_search_contract(
    auth: &crate::AuthContext,
    query: &str,
    dataset: Option<&str>,
) -> Result<(), crate::error::SearchError> {
    if !crate::is_shared_scope(auth.tenant_scope) {
        return Ok(());
    }
    let capabilities = Default::default();
    shared_dataset_contract(dataset, capabilities)?;
    let parsed = nanosiem_core::query::parse_query(query)
        .map_err(|error| crate::error::SearchError::BadRequest(error.to_string()))?;
    let mut base = &parsed;
    while let nanosiem_core::query::Query::Piped { source, .. } = base {
        base = source;
    }
    shared_parsed_npl_contract(auth, base, capabilities)
}

fn shared_parsed_npl_contract(
    auth: &crate::AuthContext,
    parsed: &nanosiem_core::query::Query,
    capabilities: SharedQueryCapabilities,
) -> Result<(), crate::error::SearchError> {
    if !nanosiem_core::search::query_processing::extract_prevalence_commands(parsed).is_empty() {
        require_shared_prevalence_component(auth)?;
    }
    #[cfg(feature = "enterprise")]
    {
        nanosiem_core::search::query_processing::validate_enterprise_shared_query_dependencies_with(
            parsed,
            capabilities,
        )
        .map_err(|blocked| {
            crate::error::SearchError::ServiceUnavailable(format!(
                "enterprise-shared Search dependency `{}` is not tenant-pinned: {}",
                blocked.keyword(),
                blocked.reason()
            ))
        })
    }
    // Reached only for a shared scope, which an open build never resolves.
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = capabilities;
        Ok(())
    }
}

/// The datasets an enterprise-shared tenant may select (NAN-3018). `logs`
/// is always the tenant-pinned lake. `risk` is served only on a lean-lake
/// cell view whose decay / clear state is bound to the caller's own tenant
/// (see `SearchState::bind_shared_risk_dataset`); surfaces without such a
/// view refuse it. Anything else is a caller error (400) naming what is
/// unsupported. It is never a 503, because retrying will not help.
fn shared_dataset_contract(
    dataset: Option<&str>,
    capabilities: SharedQueryCapabilities,
) -> Result<(), crate::error::SearchError> {
    let selector = dataset.unwrap_or("logs").trim().to_ascii_lowercase();
    match selector.as_str() {
        "logs" | "log" => Ok(()),
        "risk" if capabilities.tenant_risk_dataset => Ok(()),
        "risk" => Err(crate::error::SearchError::BadRequest(
            "dataset `risk` is served for enterprise-shared tenants only by search and \
             streaming search on a lean-lake cell tenant; this endpoint or tenant does not \
             support it"
                .to_string(),
        )),
        other => Err(crate::error::SearchError::BadRequest(format!(
            "dataset `{}` is not supported for enterprise-shared tenants; supported \
             datasets are `logs` and `risk` (lean-lake tenants). Detection findings and \
             alerts are in `logs` as `source_type=findings`",
            other.chars().take(64).collect::<String>()
        ))),
    }
}

pub(crate) fn reject_shared_raw_sql(
    auth: &crate::AuthContext,
) -> Result<(), crate::error::SearchError> {
    if crate::is_shared_scope(auth.tenant_scope) {
        return Err(crate::error::SearchError::ServiceUnavailable(
            "raw SQL is not available until a tenant-pinned shared executor exists".to_string(),
        ));
    }
    Ok(())
}

// Re-export all handler functions
pub use asset_dossier::get_asset_dossier;
pub use assets::{
    get_asset_artifacts, get_asset_events, get_asset_true_time_range, get_cloud_entity_pivot,
    get_cloud_events, get_cloud_user_timeline,
};
pub use cloud_dossier::get_cloud_dossier;
pub use cloud_overview::get_cloud_overview;
pub use health::{health, livez, ready};
pub use identity::resolve_identity;
pub use otel::{
    get_metric_timeseries, get_rum_summary, get_service_detail, get_service_security_signals,
    get_trace, list_infra_hosts, list_metric_names, list_metric_tags, list_services, list_traces,
};
pub use prevalence::{lean_prevalence_export, lean_rare_artifacts};
pub use retro::retro;
pub use saved_searches::{
    create_saved_search, delete_saved_search, get_saved_search, list_my_saved_searches,
    list_saved_searches, list_shared_searches, share_saved_search, update_saved_search,
};
pub use search::{
    cancel_search, explain, fetch_log, field_stats_for_query, field_values, prevalence_artifacts,
    search, search_histogram, search_sql,
};
pub use search_jobs::{
    admin_cancel_search_job, admin_get_stats, admin_list_search_jobs, cancel_search_job,
    download_search_job_result, get_search_job, get_search_job_result_page, list_search_jobs,
};
pub use streaming::search_stream;

// Re-export types used in OpenAPI schema registration
pub use asset_dossier::AssetDossierRequest;
pub use assets::{
    ArtifactOccurrence, ArtifactPrevalence, AssetArtifactsRequest, AssetArtifactsResponse,
    AssetEventsRequest, AssetEventsResponse, AssetTrueTimeRangeRequest, AssetTrueTimeRangeResponse,
    CloudEntityPivotRequest, CloudEntityPivotResponse, CloudEventsRequest, CloudEventsResponse,
    CloudUserTimelineRequest, CloudUserTimelineResponse,
};
pub use cloud_dossier::CloudDossierRequest;
pub use cloud_overview::CloudOverviewRequest;
pub use health::{HealthResponse, ReadyResponse};
pub use identity::IdentityResolveResponse;
pub use otel::{
    InfraHostsResponse, ListTracesResponse, MetricFilterInput, MetricNamesResponse, MetricSeries,
    MetricTagsResponse, MetricTimeseriesRequest, MetricTimeseriesResponse, RumSummaryResponse,
    ServiceDetailResponse, ServiceSecuritySignalsResponse, ServicesOverviewResponse, TraceResponse,
};
pub use search::{
    CancelSearchResponse, ExplainRequest, ExplainResponse, FetchLogRequest, FetchLogResponse,
    FieldStatsRequest, FieldStatsResponse, FieldValuesRequest, FieldValuesResponse,
    SearchHistogramRequest, SearchHistogramResponse,
};
pub use prevalence::{LeanPrevalenceAvailability, LeanRareArtifactsResponse};
pub use search_jobs::{AdminSearchJobsResponse, CancelJobResponse};

/// Response wrapper for search that can be either sync or async
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum SearchResultResponse {
    Sync(SearchPageResponse),
    /// A synchronous response with opt-in lake evidence.
    SyncWithDebug(SearchResponseWithDebug),
    Async(nanosiem_core::search::AsyncSearchResponse),
}

/// Paging metadata independent of a delayed exact-count companion.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SearchPageResponse {
    #[serde(flatten)]
    pub response: SearchResponse,
    /// More rows may exist. Continue with the same query and next_offset.
    pub has_more: bool,
    pub next_offset: Option<u64>,
}

impl SearchPageResponse {
    pub fn new(response: SearchResponse, request: &nanosiem_core::SearchRequest) -> Self {
        let offset = request.offset.unwrap_or(0) as u64;
        let limit = request.limit.unwrap_or(100);
        let end = offset.saturating_add(response.results.len() as u64);
        let has_more = if response.total_count_exact {
            end < response.total_count
        } else {
            response.total_count > end || (limit > 0 && response.results.len() >= limit)
        };
        Self {
            response,
            has_more,
            next_offset: has_more.then_some(offset.saturating_add(limit as u64)),
        }
    }
}

/// A search response plus the per-phase evidence asked for with the
/// `x-nano-search-debug: 1` header (callers holding `search:sql` only).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SearchResponseWithDebug {
    #[serde(flatten)]
    pub response: SearchPageResponse,
    /// `{schema, lake_calls: [{route, companion, round_trip_ms, worker_wall_s,
    /// result, planner{phases_s, time_files, fetched_files, row_groups,
    /// kept_row_groups, count_groups, ...}} | {phase, ms}], service_ms,
    /// handler_ms}`: counts and timings only.
    #[schema(value_type = Object)]
    pub debug: serde_json::Value,
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
        search::search_histogram,
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
        health::livez,
        retro::retro,
        prevalence::lean_prevalence_export,
        prevalence::lean_rare_artifacts,
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
        search_jobs::get_search_job_result_page,
        search_jobs::download_search_job_result,
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
        otel::get_service_security_signals,
        otel::list_infra_hosts,
        otel::get_rum_summary,
    ),
    components(schemas(
        SearchResultResponse,
        SearchPageResponse,
        SearchResponseWithDebug,
        CancelSearchResponse,
        ExplainRequest,
        ExplainResponse,
        FetchLogRequest,
        FetchLogResponse,
        FieldValuesRequest,
        FieldValuesResponse,
        FieldStatsRequest,
        FieldStatsResponse,
        SearchHistogramRequest,
        SearchHistogramResponse,
        HealthResponse,
        ReadyResponse,
        nanosiem_core::search::EventCompleteness,
        nanosiem_core::search::HotTailPartialCoverage,
        nanosiem_core::search::HotTailSlowPathCoverage,
        nanosiem_core::search::RetroRequest,
        retro::RetroResultResponse,
        prevalence::LeanRareArtifactsResponse,
        prevalence::LeanPrevalenceAvailability,
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
        ServiceSecuritySignalsResponse,
        InfraHostsResponse,
        RumSummaryResponse,
        ErrorResponse,
    ))
)]
pub struct SearchApiDoc;

// Metrics are served via Prometheus at /metrics endpoint
// See metrics.rs for the implementation

#[cfg(test)]
mod search_page_tests {
    use super::*;

    #[test]
    fn search_page_schema_exposes_paging() {
        use utoipa::OpenApi;
        let spec = serde_json::to_value(SearchApiDoc::openapi()).unwrap();
        let schema = &spec["components"]["schemas"]["SearchPageResponse"];
        let wire = schema.to_string();
        assert!(wire.contains("has_more"));
        assert!(wire.contains("next_offset"));
    }

    #[test]
    fn search_page_metadata() {
        for (rows, total, exact, offset, more) in [
            (100, 100, false, 0, true),
            (100, 200, false, 100, true),
            (7, 207, false, 200, false),
            (0, 200, false, 200, false),
            (100, 100, true, 0, false),
            (7, 500, true, 0, true),
            (7, 200, false, 0, true),
        ] {
            let response: SearchResponse = serde_json::from_value(serde_json::json!({
                "results": vec![serde_json::json!({}); rows], "total_count": total,
                "total_count_exact": exact, "execution_time_ms": 1, "fields": []
            }))
            .unwrap();
            let request = serde_json::from_value(serde_json::json!({
                "query": "*", "time_range": {"start": "2026-09-30T00:00:00Z", "end": "2026-09-30T01:00:00Z"},
                "offset": offset, "limit": 100
            })).unwrap();
            let page = SearchPageResponse::new(response, &request);
            assert_eq!(page.has_more, more);
            assert_eq!(page.next_offset, more.then_some(offset + 100));
            let wire = serde_json::to_value(page).unwrap();
            assert!(wire.get("results").is_some());
            assert_eq!(wire["has_more"], more);
        }
    }
}
