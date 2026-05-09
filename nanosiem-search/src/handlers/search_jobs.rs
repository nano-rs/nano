// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async search job endpoints: polling, cancel, list, admin operations.

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use nanosiem_core::{
    audit::{AuditEvent, AuditSource},
    auth::permissions,
    search::{AdminSearchJobSummary, AdmissionStats, SearchJobSummary},
};
use serde::Serialize;

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError};

// ============================================================================
// Async Search Jobs
// ============================================================================

/// Get the status of an async search job
///
/// Returns the job status, progress (if running), results (if completed),
/// or error message (if failed).
#[utoipa::path(
    get,
    path = "/api/search/jobs/{job_id}",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Async search job ID")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Job status and optional results", body = nanosiem_core::search::SearchJobStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found", body = ErrorResponse),
    )
)]
pub async fn get_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<nanosiem_core::search::SearchJobStatusResponse>, SearchError> {
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

    match state.search.get_job_status(&job_id).await {
        Some(status) => Ok(Json(status)),
        None => Err(SearchError::NotFound(format!("Job not found: {}", job_id))),
    }
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
    )
)]
pub async fn cancel_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelJobResponse>, SearchError> {
    tracing::info!("Received cancel request for job_id: {}", job_id);

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
    )
)]
pub async fn list_search_jobs(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<Vec<SearchJobSummary>>, SearchError> {
    let user_id = auth.claims.sub;
    let jobs = state.search.job_store().list_for_user(user_id).await;
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
/// Requires `settings:system` permission.
#[utoipa::path(
    get,
    path = "/api/search/admin/jobs",
    tag = "search-admin",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "All search jobs with admission stats", body = AdminSearchJobsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system", body = ErrorResponse),
    )
)]
pub async fn admin_list_search_jobs(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<AdminSearchJobsResponse>, SearchError> {
    require_permission(&auth, "settings:system")?;

    let jobs = state.search.job_store().list_all().await;
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
/// Returns current admission stats: active queries, queue depth, per-user breakdown.
/// Requires `settings:system` permission.
#[utoipa::path(
    get,
    path = "/api/search/admin/stats",
    tag = "search-admin",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Admission control statistics", body = AdmissionStats),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires settings:system", body = ErrorResponse),
    )
)]
pub async fn admin_get_stats(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
) -> Result<Json<AdmissionStats>, SearchError> {
    require_permission(&auth, "settings:system")?;

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
/// Requires `settings:system` permission.
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
        (status = 403, description = "Forbidden - requires settings:system", body = ErrorResponse),
    )
)]
pub async fn admin_cancel_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<CancelJobResponse>, SearchError> {
    require_permission(&auth, "settings:system")?;

    tracing::info!(
        admin_user = %auth.claims.sub,
        job_id = %job_id,
        "Admin cancelling search job"
    );

    let cancelled = state.search.cancel_job(&job_id).await.map_err(|e| {
        tracing::error!(error = %e, job_id = %job_id, "Failed to admin-cancel job");
        SearchError::QueryError("Failed to cancel job".to_string())
    })?;

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
