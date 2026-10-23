// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3088: Prevalence export and the rare-artifact list for a lean-lake
//! tenant, served from the caller's own cell view.
//!
//! Both answer from one computation, the tenant's rare artifacts over a
//! window, which aggregates every entity of the prevalence window relation.
//! On a lean tenant that is far past an interactive budget (hundreds of
//! thousands of entities per hour), so it is always a durable
//! `PrevalenceExportV1` job on the tenant's own cell, admitted over
//! `[max(retention cutoff, now - window), now]` and carrying the runner's
//! moving retention-cutoff proof (see `SearchService::enqueue_lean_prevalence_job`).
//!
//! * `GET /api/search/prevalence/export` queues the export and answers 202
//!   with the job handle. The result downloads from
//!   `GET /api/search/jobs/{job_id}/download` in the requested format.
//! * `GET /api/search/prevalence/rare` pages the caller's newest matching
//!   rare-list result (under ten minutes old) straight from its verified
//!   result pages: 200, one page read. Without one it queues the job and
//!   answers 202 with the handle and an empty page; the client polls
//!   `GET /api/search/jobs/{job_id}` and calls again with `job_id`.
//!
//! The API's `/api/prevalence/{export,rare}` redirect here for a lean tenant.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::{
    auth::permissions,
    prevalence::{PrevalenceData, TimeWindow},
    search::{
        lean_prevalence_row, AsyncSearchResponse, LeanPrevalenceJob, LeanPrevalencePurpose, SearchJob,
        SearchJobStatus, SearchService, LEAN_PREVALENCE_RARE_REUSE_MS,
    },
};
use serde::{Deserialize, Serialize};

use super::search_jobs::{map_job_store_error, require_job_retention_visible, require_retention_safe_job_surface};
use crate::error::{ErrorResponse, SearchError};
use crate::SearchState;

const MAX_RARE_PAGE: i64 = 100;
const DEFAULT_RARE_PAGE: i64 = 25;

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct LeanPrevalenceExportQuery {
    /// `1h`, `24h` (default), `7d` or `30d`.
    pub window: Option<String>,
    /// `hash`, `domain` or `ip`; omitted for every type.
    #[serde(rename = "type")]
    pub artifact_type: Option<String>,
    /// Highest host count to export (defaults to the rarity threshold).
    pub max_prevalence: Option<u64>,
    /// `csv` (default) or `json`: the download format.
    pub format: Option<String>,
    /// Accepted for API compatibility: an export is always queued.
    pub queue: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct LeanRareArtifactsQuery {
    /// `1h`, `24h` (default), `7d` or `30d`.
    pub window: Option<String>,
    /// `hash`, `domain` or `ip`; omitted for every type.
    #[serde(rename = "type")]
    pub artifact_type: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Page this rare-list job's result (from an earlier 202).
    pub job_id: Option<String>,
    /// Queue a fresh computation instead of reusing a recent one.
    pub refresh: Option<bool>,
}

/// Whether prevalence is available for this answer (the tenant capability
/// verdict shape of `/api/prevalence/*`).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LeanPrevalenceAvailability {
    pub capability: String,
    pub available: bool,
    pub reason: Option<String>,
    pub detail: Option<String>,
}

/// A rare-artifact page (the `/api/prevalence/rare` list shape) plus the
/// durable job it was read from. `job_status` other than `completed` means
/// the page is empty and the client should poll `/api/search/jobs/{job_id}`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LeanRareArtifactsResponse {
    pub artifacts: Vec<PrevalenceData>,
    pub total: u64,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
    pub availability: LeanPrevalenceAvailability,
    pub rarity_threshold: u64,
    pub job_id: String,
    pub job_status: SearchJobStatus,
    /// The rare set hit the export row cap: `total` is a floor.
    pub truncated: bool,
    /// When the job was admitted (RFC3339).
    pub computed_at: String,
}

fn parse_window(raw: Option<&str>) -> Result<TimeWindow, SearchError> {
    match raw {
        None => Ok(TimeWindow::TwentyFourHours),
        Some(raw) => TimeWindow::from_str(raw)
            .ok_or_else(|| SearchError::BadRequest("window must be 1h, 24h, 7d or 30d".to_string())),
    }
}

fn parse_type(raw: Option<&str>) -> Result<Option<String>, SearchError> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else { return Ok(None) };
    match raw.to_ascii_lowercase().as_str() {
        "hash" | "hashes" | "md5" | "sha256" => Ok(Some("hash".to_string())),
        "domain" | "domains" => Ok(Some("domain".to_string())),
        "ip" | "ips" | "ip_address" => Ok(Some("ip".to_string())),
        "all" => Ok(None),
        _ => Err(SearchError::BadRequest("type must be hash, domain or ip".to_string())),
    }
}

fn require_permission(auth: &crate::AuthContext, permission: &str) -> Result<(), SearchError> {
    if auth.claims.has_permission(permission) {
        Ok(())
    } else {
        Err(SearchError::Forbidden(format!("Missing permission: {permission}")))
    }
}

/// Only a lean-lake cell view has the durable prevalence lane; a dedicated
/// deployment keeps `/api/prevalence/*` on the API.
fn require_lean_cell(search: &SearchService) -> Result<(), SearchError> {
    if search.serves_lake_cell() {
        return Ok(());
    }
    Err(SearchError::ServiceUnavailable(
        "lean Prevalence export and rare lists are served for lean-lake tenants; this deployment serves /api/prevalence/*"
            .to_string(),
    ))
}

fn threshold() -> u64 {
    nanosiem_core::search::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD
}

/// Queue a complete Prevalence export on the caller's lake cell.
///
/// Requires `prevalence:export` and `search:execute` (the result is a search
/// job the caller downloads). Always answers 202: poll
/// `GET /api/search/jobs/{job_id}`, then download from
/// `GET /api/search/jobs/{job_id}/download`.
#[utoipa::path(
    get,
    path = "/api/search/prevalence/export",
    tag = "search",
    params(LeanPrevalenceExportQuery),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 202, description = "Export queued as a durable, retention-bound cell job", body = AsyncSearchResponse),
        (status = 400, description = "Invalid window, type or format", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing prevalence:export or search:execute, or the tenant has no prevalence component", body = ErrorResponse),
        (status = 503, description = "The tenant's lake cell job lane or retention identity is unavailable", body = ErrorResponse),
    )
)]
pub async fn lean_prevalence_export(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Query(params): Query<LeanPrevalenceExportQuery>,
) -> Result<(StatusCode, Json<AsyncSearchResponse>), SearchError> {
    super::require_search_execute(&auth)?;
    require_permission(&auth, permissions::PREVALENCE_EXPORT)?;
    super::require_shared_prevalence_component(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let format = match params.format.as_deref() {
        None | Some("csv") => "csv",
        Some("json") => "json",
        Some(_) => return Err(SearchError::BadRequest("format must be csv or json".to_string())),
    };
    let job = LeanPrevalenceJob {
        purpose: LeanPrevalencePurpose::Export,
        window: parse_window(params.window.as_deref())?,
        artifact_type: parse_type(params.artifact_type.as_deref())?,
        max_prevalence: params.max_prevalence.unwrap_or_else(threshold).min(1_000_000),
        format: format.to_string(),
    };
    let search = super::product_view_search(&state, &auth)?;
    require_lean_cell(&search)?;
    let scope = super::search::effective_scope(&auth);
    let job_id = search
        .enqueue_lean_prevalence_job(&job, &scope, auth.claims.sub, auth.durable_search_authority().as_ref())
        .await?;
    crate::metrics::record_search_query("prevalence_export_queued", 0.0, true);
    super::require_current_shared_authority(&state, &auth).await?;
    Ok((StatusCode::ACCEPTED, Json(AsyncSearchResponse { job_id, status: "queued".to_string() })))
}

/// The caller's rare-artifact list for a window, from a durable cell job.
///
/// 200 with a page when the caller has a matching result (named by `job_id`,
/// or computed in the last ten minutes); 202 with the queued job's handle and
/// an empty page otherwise. Requires `prevalence:view` and `search:execute`.
#[utoipa::path(
    get,
    path = "/api/search/prevalence/rare",
    tag = "search",
    params(LeanRareArtifactsQuery),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "A page of the rare-artifact result", body = LeanRareArtifactsResponse),
        (status = 202, description = "The rare list is being computed; poll /api/search/jobs/{job_id}", body = LeanRareArtifactsResponse),
        (status = 400, description = "Invalid window, type or job", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing prevalence:view or search:execute, or the tenant has no prevalence component", body = ErrorResponse),
        (status = 404, description = "The named job is not this caller's rare list", body = ErrorResponse),
        (status = 503, description = "The tenant's lake cell job lane, result storage or retention identity is unavailable", body = ErrorResponse),
    )
)]
pub async fn lean_rare_artifacts(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Query(params): Query<LeanRareArtifactsQuery>,
) -> Result<(StatusCode, Json<LeanRareArtifactsResponse>), SearchError> {
    super::require_search_execute(&auth)?;
    require_permission(&auth, permissions::PREVALENCE_VIEW)?;
    super::require_shared_prevalence_component(&auth)?;
    require_retention_safe_job_surface(&auth)?;
    let job = LeanPrevalenceJob {
        purpose: LeanPrevalencePurpose::Rare,
        window: parse_window(params.window.as_deref())?,
        artifact_type: parse_type(params.artifact_type.as_deref())?,
        max_prevalence: threshold(),
        format: "json".to_string(),
    };
    let limit = params.limit.unwrap_or(DEFAULT_RARE_PAGE).clamp(1, MAX_RARE_PAGE);
    let offset = params.offset.unwrap_or(0).max(0);
    if offset > nanosiem_core::search::LEAN_PREVALENCE_EXPORT_MAX_ROWS as i64 {
        return Err(SearchError::BadRequest("offset is past the rare-list result".to_string()));
    }
    let search = super::product_view_search(&state, &auth)?;
    require_lean_cell(&search)?;
    let scope = super::search::effective_scope(&auth);

    let named = params.job_id.as_deref().map(str::trim).filter(|id| !id.is_empty());
    let existing = match named {
        Some(job_id) => Some(owned_rare_job(&search, &auth, &job, job_id).await?),
        None if params.refresh.unwrap_or(false) => None,
        None => reusable_rare_job(&search, &auth, &job).await?,
    };
    let Some(existing) = existing else {
        let job_id = search
            .enqueue_lean_prevalence_job(&job, &scope, auth.claims.sub, auth.durable_search_authority().as_ref())
            .await?;
        crate::metrics::record_search_query("prevalence_rare_queued", 0.0, true);
        super::require_current_shared_authority(&state, &auth).await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(pending(job_id, SearchJobStatus::Queued, chrono::Utc::now(), limit, offset)),
        ));
    };
    match existing.status {
        SearchJobStatus::Completed => {
            let response = read_rare_page(&search, &auth, &existing, limit, offset).await?;
            super::require_current_shared_authority(&state, &auth).await?;
            Ok((StatusCode::OK, Json(response)))
        }
        SearchJobStatus::Queued | SearchJobStatus::Running => {
            super::require_current_shared_authority(&state, &auth).await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(pending(existing.id.clone(), existing.status.clone(), existing.created_at, limit, offset)),
            ))
        }
        // NAN-3286: even a failure's text is released only under live authority.
        SearchJobStatus::Failed | SearchJobStatus::Cancelled => {
            super::require_current_shared_authority(&state, &auth).await?;
            Err(SearchError::QueryError(format!(
            "rare-list job {} {}: {}",
            existing.id,
            if existing.status == SearchJobStatus::Failed { "failed" } else { "was cancelled" },
            existing.error.as_deref().unwrap_or("no detail").chars().take(400).collect::<String>(),
        )))
        }
    }
}

fn pending(
    job_id: String,
    job_status: SearchJobStatus,
    created_at: chrono::DateTime<chrono::Utc>,
    limit: i64,
    offset: i64,
) -> LeanRareArtifactsResponse {
    LeanRareArtifactsResponse {
        artifacts: Vec::new(),
        total: 0,
        limit,
        offset,
        has_more: false,
        availability: LeanPrevalenceAvailability {
            capability: "prevalence".to_string(),
            available: false,
            reason: Some("prevalence_job_pending".to_string()),
            detail: Some(format!(
                "The rare-artifact list is computing as background job {job_id}; poll /api/search/jobs/{job_id}, then call again with job_id"
            )),
        },
        rarity_threshold: threshold(),
        job_id,
        job_status,
        truncated: false,
        computed_at: created_at.to_rfc3339(),
    }
}

/// A caller-named job: it must be this caller's own rare list of exactly
/// these parameters, readable under the caller's current source scope and the
/// tenant's moving retention cutoff. Anything else is the same 404.
async fn owned_rare_job(
    search: &SearchService,
    auth: &crate::AuthContext,
    job: &LeanPrevalenceJob,
    job_id: &str,
) -> Result<SearchJob, SearchError> {
    let not_found = || SearchError::NotFound(format!("Rare-list job not found: {job_id}"));
    if job_id.len() > 128 || job_id.chars().any(char::is_control) {
        return Err(not_found());
    }
    let found = search.job_control().get_checked(job_id).await.map_err(map_job_store_error)?.ok_or_else(not_found)?;
    if !rare_job_is_readable(&found, auth, job) {
        return Err(not_found());
    }
    require_job_retention_visible(auth, &found)?;
    Ok(found)
}

/// Owner, parameters and scope: the checks every rare-list read makes before
/// touching a result (NAN-3088). Tenant isolation is structural (the job
/// store and result references are tenant-keyed) and re-checked on the
/// result reference in `read_rare_page`.
fn rare_job_is_readable(found: &SearchJob, auth: &crate::AuthContext, job: &LeanPrevalenceJob) -> bool {
    found.user_id == Some(auth.claims.sub)
        && job.matches(found)
        && found.result_visible_under(super::search::effective_scope(auth).deny_set())
        && (!crate::is_shared_scope(auth.tenant_scope) || found.tenant_id == auth.tenant_scope.tenant_id())
}

/// The caller's newest live rare-list job of these parameters from the last
/// ten minutes, if its result is still readable by them.
async fn reusable_rare_job(
    search: &SearchService,
    auth: &crate::AuthContext,
    job: &LeanPrevalenceJob,
) -> Result<Option<SearchJob>, SearchError> {
    let jobs = search.job_control().list_for_user_checked(auth.claims.sub).await.map_err(map_job_store_error)?;
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default();
    let Some(summary) = job.reusable(&jobs, now_ms, LEAN_PREVALENCE_RARE_REUSE_MS) else { return Ok(None) };
    let Some(found) = search.job_control().get_checked(&summary.job_id).await.map_err(map_job_store_error)? else {
        return Ok(None);
    };
    // A job the caller can no longer read (scope narrowed, cutoff moved past
    // it) is not reused: a fresh one is queued instead.
    if !rare_job_is_readable(&found, auth, job) || require_job_retention_visible(auth, &found).is_err() {
        return Ok(None);
    }
    Ok(Some(found))
}

/// One rare-list page from the job's verified result pages (at most two
/// result pages: `limit` is far below the result page size).
async fn read_rare_page(
    search: &SearchService,
    auth: &crate::AuthContext,
    job: &SearchJob,
    limit: i64,
    offset: i64,
) -> Result<LeanRareArtifactsResponse, SearchError> {
    let not_found = || SearchError::NotFound(format!("Rare-list job not found: {}", job.id));
    let reference = job.result_ref.as_ref().ok_or_else(not_found)?;
    reference.verify_tenant(auth.tenant_scope).map_err(|_| not_found())?;
    let (offset_rows, limit_rows) = (offset as usize, limit as usize);
    let mut artifacts = Vec::new();
    if reference.page_rows > 0 && reference.parts > 0 {
        let first = offset_rows / reference.page_rows;
        let last = (offset_rows + limit_rows - 1) / reference.page_rows;
        for page in first..=last.min(reference.parts - 1) {
            let rows = search.get_durable_job_result_page(&job.id, reference, page).await.map_err(|error| {
                tracing::error!(job_id = %job.id, page, error = %error, "rare-list result page read failed");
                SearchError::ServiceUnavailable("Durable result storage is temporarily unavailable; retry shortly".to_string())
            })?;
            let page_start = page * reference.page_rows;
            for (index, row) in rows.rows.iter().enumerate() {
                let position = page_start + index;
                if position < offset_rows || artifacts.len() >= limit_rows {
                    continue;
                }
                artifacts.push(lean_prevalence_row(row).ok_or_else(|| {
                    SearchError::InternalError("rare-list result row is malformed".to_string())
                })?);
            }
        }
    }
    let total = reference.rows;
    Ok(LeanRareArtifactsResponse {
        has_more: (offset_rows + artifacts.len()) < total as usize,
        artifacts,
        total,
        limit,
        offset,
        availability: LeanPrevalenceAvailability {
            capability: "prevalence".to_string(),
            available: true,
            reason: None,
            detail: None,
        },
        rarity_threshold: threshold(),
        job_id: job.id.clone(),
        job_status: SearchJobStatus::Completed,
        truncated: reference.has_more,
        computed_at: job.created_at.to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_closed() {
        assert!(matches!(parse_window(None), Ok(TimeWindow::TwentyFourHours)));
        assert!(matches!(parse_window(Some("30d")), Ok(TimeWindow::ThirtyDays)));
        assert!(parse_window(Some("365d")).is_err());
        assert_eq!(parse_type(Some("IPs")).unwrap().as_deref(), Some("ip"));
        assert_eq!(parse_type(Some("all")).unwrap(), None);
        assert_eq!(parse_type(None).unwrap(), None);
        assert!(parse_type(Some("process")).is_err());
    }

    #[cfg(feature = "enterprise")]
    fn shared_auth(tenant: u128, user: u128) -> crate::AuthContext {
        let mut auth = crate::AuthContext::from_jwt(nanosiem_core::auth::types::TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: uuid::Uuid::from_u128(user),
            roles: Vec::new(),
            permissions: vec![permissions::SEARCH_EXECUTE.to_string(), permissions::PREVALENCE_VIEW.to_string()],
            exp: i64::MAX,
            iat: 0,
            jti: uuid::Uuid::nil(),
            purpose: "access".to_string(),
        });
        auth.tenant_scope = nanosiem_core::search::SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(tenant));
        auth.shared_search_entitlement_revision = Some(1);
        auth.shared_prevalence_entitled = true;
        auth
    }

    #[cfg(feature = "enterprise")]
    fn rare(window: TimeWindow) -> LeanPrevalenceJob {
        LeanPrevalenceJob {
            purpose: LeanPrevalencePurpose::Rare,
            window,
            artifact_type: None,
            max_prevalence: threshold(),
            format: "json".to_string(),
        }
    }

    /// A job as the tenant's store holds it: owned by `user` in `tenant`.
    #[cfg(feature = "enterprise")]
    fn stored(tenant: u128, user: u128, job: &LeanPrevalenceJob) -> SearchJob {
        let now = chrono::Utc::now();
        let request = nanosiem_core::SearchRequest {
            query: job.query_text(),
            time_range: nanosiem_core::TimeRangeInput::new(now - chrono::Duration::hours(24), now),
            limit: Some(nanosiem_core::search::LEAN_PREVALENCE_EXPORT_MAX_ROWS),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        let mut found = SearchJob::new_for_tenant(
            nanosiem_core::search::SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(tenant)),
            "job-rare".to_string(),
            request,
            // Stamped with the owner's effective scope, as admission does.
            &super::super::search::effective_scope(&shared_auth(tenant, user)),
        );
        found.user_id = Some(uuid::Uuid::from_u128(user));
        found.task = Some(job.task());
        found
    }

    /// NAN-3088 isolation: a rare-list result is readable only by its own
    /// owner, in its own tenant, for exactly its own parameters. A job id
    /// from another tenant (even for the same user id), another member, a
    /// different window or an export never pages.
    #[cfg(feature = "enterprise")]
    #[test]
    fn a_rare_list_is_never_read_across_tenants_members_or_parameters() {
        let job = rare(TimeWindow::TwentyFourHours);
        let own = stored(0xa, 1, &job);
        assert!(rare_job_is_readable(&own, &shared_auth(0xa, 1), &job));
        // Another tenant's job, same user id and parameters.
        assert!(!rare_job_is_readable(&stored(0xb, 1, &job), &shared_auth(0xa, 1), &job));
        assert!(!rare_job_is_readable(&own, &shared_auth(0xb, 1), &job));
        // Another member of the same tenant.
        assert!(!rare_job_is_readable(&own, &shared_auth(0xa, 2), &job));
        // Another window, or an export of the same window.
        assert!(!rare_job_is_readable(&own, &shared_auth(0xa, 1), &rare(TimeWindow::SevenDays)));
        let export = LeanPrevalenceJob { purpose: LeanPrevalencePurpose::Export, ..job.clone() };
        assert!(!rare_job_is_readable(&stored(0xa, 1, &export), &shared_auth(0xa, 1), &job));
        // A caller whose source scope narrowed since the job ran.
        let mut narrowed = shared_auth(0xa, 1);
        narrowed.denied_sources = nanosiem_core::auth::ScopeSet::from_denied(std::collections::BTreeSet::from(["aws_cloudtrail".to_string()]));
        assert!(!rare_job_is_readable(&own, &narrowed, &job));
    }

    #[test]
    fn a_pending_page_names_its_job_and_is_empty() {
        let page = pending("job-1".into(), SearchJobStatus::Queued, chrono::Utc::now(), 25, 0);
        let value = serde_json::to_value(&page).unwrap();
        assert_eq!(value["artifacts"], serde_json::json!([]));
        assert_eq!(value["availability"]["available"], false);
        assert_eq!(value["availability"]["reason"], "prevalence_job_pending");
        assert_eq!(value["job_status"], "queued");
        assert_eq!(value["job_id"], "job-1");
    }
}
