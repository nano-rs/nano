// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async search job endpoints: polling, cancel, list, admin operations.

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
};
use nanosiem_core::{
    audit::{AuditEvent, AuditSource},
    auth::permissions,
    search::{
        AdminSearchJobSummary, AdmissionStats, SearchJobSummary, background::is_durable_job_id,
    },
};
use serde::{Deserialize, Serialize};

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError};

// ============================================================================
// Async Search Jobs
// ============================================================================

/// NAN-2109: composite gate for the cross-user search-job admin surface.
///
/// `settings:system` authorizes *administering* the search service; it is not a
/// substitute for the capability that governs search CONTENT. The admin
/// responses carry other principals' query text and user ids — exactly the
/// bytes `search:execute` protects on the ordinary routes (NAN-2032) — so both
/// capabilities are required (`AllOf`). Without this, a settings-only key that
/// is forbidden from listing its OWN jobs could enumerate everyone else's.
pub(super) fn require_search_admin(auth: &crate::AuthContext) -> Result<(), SearchError> {
    require_permission(auth, permissions::SETTINGS_SYSTEM)?;
    super::require_search_execute(auth)
}

/// Get the status of an async search job
///
/// Returns the job status, progress (if running), results (if completed),
/// or error message (if failed).
#[utoipa::path(
    get,
    path = "/api/search/jobs/{job_id}",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Async search job ID (sjob_… for durable background jobs)"),
        JobStatusQuery,
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Job status and optional results", body = nanosiem_core::search::SearchJobStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
        (status = 404, description = "Job not found", body = ErrorResponse),
    )
)]
pub async fn get_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
    Query(params): Query<JobStatusQuery>,
) -> Result<Json<nanosiem_core::search::SearchJobStatusResponse>, SearchError> {
    // NAN-2032: results are search output — require search:execute BEFORE the
    // ownership check, so revoking the capability revokes access to prior jobs.
    // Ownership is object-level authz, not the feature-capability gate. Admins
    // (settings:system) still bypass ownership below.
    super::require_search_execute(&auth)?;

    // NAN-4915: durable background job. Same gates (ownership unless admin,
    // NAN-2096 scope re-check, uniform 404); the inline `result` is the first
    // page of the stored rows so legacy pollers keep working, and the rest is
    // paged from `/results`.
    if is_durable_job_id(&job_id) {
        let job = super::background_jobs::load_readable_job(&state, &auth, &job_id).await?;
        let inline = state
            .background_jobs
            .inline_result(
                &job,
                params
                    .limit
                    .or(job.page_limit.map(|l| l.max(1) as u64))
                    .unwrap_or(1_000),
            )
            .await
            .map_err(SearchError::from)?;
        return Ok(Json(job.status_response(inline)));
    }

    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let job = state
        .search
        .job_store()
        .get(&job_id)
        .await
        .ok_or_else(|| SearchError::NotFound(format!("Job not found: {}", job_id)))?;

    if !is_admin && job.user_id != Some(auth.claims.sub) {
        return Err(SearchError::NotFound(format!("Job not found: {}", job_id)));
    }

    // NAN-2096: a stored result is not authorized by ownership + capability
    // alone. The rows were frozen under the deny-set the job EXECUTED with, so
    // re-decide the data-plane question against the caller's CURRENT effective
    // scope on every poll. A source restricted (or a grant revoked) after
    // submission makes the snapshot unreadable — including for an admin whose
    // own scope is narrower than the submitter's. Legacy/unstamped jobs fail
    // closed. The response is the SAME 404 a missing job returns, so this is not
    // an existence oracle. Applies to both job stores: the predicate reads the
    // stamp carried on `SearchJob`, which `InMemoryJobStore` and `RedisJobStore`
    // both populate at creation.
    if !job.result_visible_under(super::search::effective_scope(&auth).deny_set()) {
        tracing::warn!(
            job_id = %job_id,
            user_id = %auth.claims.sub,
            "Async search job hidden: caller's source scope narrowed since submission"
        );
        return Err(SearchError::NotFound(format!("Job not found: {}", job_id)));
    }

    match state.search.get_job_status(&job_id).await {
        Some(status) => Ok(Json(status)),
        None => Err(SearchError::NotFound(format!("Job not found: {}", job_id))),
    }
}

/// Query parameters for the job status route.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct JobStatusQuery {
    /// Durable jobs only: how many stored rows to inline in `result.results`
    /// when completed (default: the page size the job was submitted with, else
    /// 1000; max 10000). Page the rest with
    /// `GET /api/search/jobs/{job_id}/results`.
    pub limit: Option<u64>,
}

/// Response for cancel_search_job endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CancelJobResponse {
    /// Whether the job was found and cancelled
    pub cancelled: bool,
}

/// Cancel a running async search job
///
/// Cancels the ClickHouse query and marks the job as cancelled.
#[utoipa::path(
    delete,
    path = "/api/search/jobs/{job_id}",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Async search job ID")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Cancellation result", body = CancelJobResponse),
        (status = 400, description = "Failed to cancel", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn cancel_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelJobResponse>, SearchError> {
    // NAN-2032: require search:execute before ownership resolution (see get_search_job).
    super::require_search_execute(&auth)?;

    // NAN-2096 deliberately does NOT apply the source-scope re-check here.
    // Cancelling destroys rather than reads the result, so an owner whose scope
    // just narrowed must stay able to stop their own now-unreadable job instead
    // of leaving it running to completion.
    //
    // The `cancelled` boolean does distinguish "your hidden job existed" from
    // "no such job", but only for jobs the ownership check below already proved
    // belong to the caller — ids they hold from their own `GET
    // /api/search/jobs` list. It reveals nothing about anyone else's jobs.
    tracing::info!("Received cancel request for job_id: {}", job_id);

    // NAN-4915: durable job — owner (or admin) may cancel; same no-scope-
    // recheck rationale as above. A foreign or missing job is `false`, exactly
    // like the legacy path.
    if is_durable_job_id(&job_id) {
        let job = match super::background_jobs::load_owned_job(&state, &auth, &job_id).await {
            Ok(job) => job,
            Err(SearchError::NotFound(_)) => return Ok(Json(CancelJobResponse { cancelled: false })),
            Err(e) => return Err(e),
        };
        let cancelled = state
            .background_jobs
            .cancel(job.id)
            .await
            .map_err(SearchError::from)?;
        return Ok(Json(CancelJobResponse { cancelled }));
    }

    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let job = match state.search.job_store().get(&job_id).await {
        Some(job) => job,
        None => return Ok(Json(CancelJobResponse { cancelled: false })),
    };
    if !is_admin && job.user_id != Some(auth.claims.sub) {
        return Ok(Json(CancelJobResponse { cancelled: false }));
    }

    let cancelled = state.search.cancel_job(&job_id).await.map_err(|e| {
        tracing::error!(error = %e, job_id = %job_id, "Failed to cancel job");
        SearchError::QueryError("Failed to cancel job".to_string())
    })?;

    if cancelled {
        tracing::info!("Successfully cancelled job: {}", job_id);
    } else {
        tracing::debug!("Job not found or already completed: {}", job_id);
    }

    Ok(Json(CancelJobResponse { cancelled }))
}

// ============================================================================
// List Search Jobs (Active Searches Panel)
// ============================================================================

/// List the current user's active and recent search jobs
///
/// Returns all queued, running, and recently completed/failed jobs for the
/// authenticated user. Used by the Active Searches panel in the UI.
#[utoipa::path(
    get,
    path = "/api/search/jobs",
    tag = "search",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "List of user's search jobs", body = Vec<SearchJobSummary>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn list_search_jobs(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<Vec<SearchJobSummary>>, SearchError> {
    // NAN-2032: require search:execute before listing the caller's jobs.
    super::require_search_execute(&auth)?;

    // NAN-2096: intentionally NOT scope-filtered, unlike the admin list. Every
    // row here is the caller's OWN job and the preview is the query text they
    // themselves submitted, so nothing is disclosed that they did not author.
    // Hiding a still-running job from its owner's Active Searches panel would
    // also strand it — they could no longer see or cancel it. The result
    // payload stays protected on the poll route.
    let user_id = auth.claims.sub;
    let mut jobs = state.search.job_store().list_for_user(user_id).await;
    // NAN-4915: durable background jobs (the caller's own, newest 50) — same
    // not-scope-filtered rationale: the owner must always be able to see and
    // cancel their own running job.
    let durable = state
        .background_jobs
        .list_for_owner(user_id, 50)
        .await
        .map_err(SearchError::from)?;
    jobs.extend(durable.iter().map(|job| job.summary()));
    jobs.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
    Ok(Json(jobs))
}

// ============================================================================
// Admin Search Jobs
// ============================================================================

/// Helper to check a permission from AuthContext, returning 403 if missing
fn require_permission(auth: &crate::AuthContext, permission: &str) -> Result<(), SearchError> {
    if auth.claims.has_permission(permission) {
        Ok(())
    } else {
        Err(SearchError::Forbidden(format!(
            "Missing permission: {}",
            permission
        )))
    }
}

/// Response for admin list search jobs endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AdminSearchJobsResponse {
    /// All search jobs across all users
    pub jobs: Vec<AdminSearchJobSummary>,
    /// Admission control statistics
    pub stats: AdmissionStats,
}

/// List all search jobs across all users (admin only)
///
/// Returns all jobs in the registry plus admission control statistics.
/// Requires BOTH `settings:system` AND `search:execute` (NAN-2109) — the
/// response carries every principal's query preview and user id.
#[utoipa::path(
    get,
    path = "/api/search/admin/jobs",
    tag = "search-admin",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "All search jobs with admission stats", body = AdminSearchJobsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system AND search:execute", body = ErrorResponse),
    )
)]
pub async fn admin_list_search_jobs(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<AdminSearchJobsResponse>, SearchError> {
    require_search_admin(&auth)?;

    // NAN-2096/NAN-2109: the admin summary carries every principal's query
    // preview, which can name a source this admin may not read. Filter by the
    // admin's OWN current scope so the list can never advertise a job whose
    // result `get_search_job` would refuse them. The predicate lives inside
    // `list_all` so a future admin variant cannot omit it.
    let mut jobs = state
        .search
        .job_store()
        .list_all(super::search::effective_scope(&auth).deny_set())
        .await;
    let viewer_scope = super::search::effective_scope(&auth);
    // NAN-4915: durable jobs, filtered by the SAME predicate the read route
    // applies, so the list never advertises a job the admin could not open.
    let durable = state
        .background_jobs
        .list_recent(200)
        .await
        .map_err(SearchError::from)?;
    jobs.extend(
        durable
            .iter()
            .filter(|job| job.result_visible_under(viewer_scope.deny_set()))
            .map(|job| job.admin_summary()),
    );
    jobs.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
    let stats = match state.search.admission_controller() {
        Some(ac) => ac.stats().await,
        None => AdmissionStats {
            active_adhoc: 0,
            queued: 0,
            per_user_counts: vec![],
        },
    };

    Ok(Json(AdminSearchJobsResponse { jobs, stats }))
}

/// Get admission control statistics (admin only)
///
/// Returns current admission stats: active queries, queue depth, per-user
/// breakdown. The per-user breakdown identifies which principals are searching,
/// so this takes the same composite gate as the job list (NAN-2109).
#[utoipa::path(
    get,
    path = "/api/search/admin/stats",
    tag = "search-admin",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Admission control statistics", body = AdmissionStats),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system AND search:execute", body = ErrorResponse),
    )
)]
pub async fn admin_get_stats(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<AdmissionStats>, SearchError> {
    require_search_admin(&auth)?;

    let stats = match state.search.admission_controller() {
        Some(ac) => ac.stats().await,
        None => AdmissionStats {
            active_adhoc: 0,
            queued: 0,
            per_user_counts: vec![],
        },
    };

    Ok(Json(stats))
}

/// Cancel any user's search job (admin only)
///
/// Cancels a running or queued search job by ID. Audit logged.
/// Requires BOTH `settings:system` AND `search:execute` (NAN-2109) — this acts
/// on another principal's search.
#[utoipa::path(
    delete,
    path = "/api/search/admin/jobs/{job_id}",
    tag = "search-admin",
    params(
        ("job_id" = String, Path, description = "Search job ID to cancel")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Cancellation result", body = CancelJobResponse),
        (status = 400, description = "Failed to cancel", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system AND search:execute", body = ErrorResponse),
    )
)]
pub async fn admin_cancel_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelJobResponse>, SearchError> {
    require_search_admin(&auth)?;

    tracing::info!(
        admin_user = %auth.claims.sub,
        job_id = %job_id,
        "Admin cancelling search job"
    );

    let cancelled = if is_durable_job_id(&job_id) {
        match nanosiem_core::search::background::decode_job_id(&job_id) {
            Some(id) => state
                .background_jobs
                .cancel(id)
                .await
                .map_err(SearchError::from)?,
            None => false,
        }
    } else {
        state.search.cancel_job(&job_id).await.map_err(|e| {
            tracing::error!(error = %e, job_id = %job_id, "Failed to admin-cancel job");
            SearchError::QueryError("Failed to cancel job".to_string())
        })?
    };

    // Audit log the admin cancellation
    state.emit_audit(
        AuditEvent::builder(AuditSource::Search, "search_job_admin_cancelled")
            .actor(Some(auth.claims.sub), None)
            .resource("search_job", None, Some(job_id.clone()))
            .details(serde_json::json!({ "cancelled": cancelled }))
            .build(),
    );

    Ok(Json(CancelJobResponse { cancelled }))
}
