// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled Job API handlers
//!
//! Provides REST API endpoints for scheduled data fetch job management
//! including creating, listing, updating, and triggering jobs.
//!
//! Requirements: 4.1, 4.7

use axum::{
    extract::{Path, Query, State},
    Json,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::{IntoParams, ToSchema};

use nanosiem_core::{
    calculate_next_runs, describe_cron, validate_cron, JobExecution, JobFilter, JobStats,
    NewScheduledJob, ScheduledJob, SchedulerError, SchedulerService, UpdateScheduledJob,
};

use crate::{error::ApiError, state::AppState};

/// Create a new scheduled job
///
/// POST /api/scheduled-jobs
#[utoipa::path(
    post,
    path = "/api/scheduled-jobs",
    tag = "scheduler",
    request_body = NewScheduledJob,
    responses(
        (status = 200, description = "Job created successfully", body = ScheduledJob),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn create_scheduled_job(
    State(state): State<AppState>,
    Json(request): Json<NewScheduledJob>,
) -> Result<Json<ScheduledJob>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let job = scheduler_service
        .create_job(request)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(
        job_id = %job.id,
        job_name = %job.name,
        cron = %job.cron_expression,
        "Scheduled job created"
    );

    Ok(Json(job))
}

/// Query parameters for listing scheduled jobs
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListJobsQuery {
    /// Filter by enabled status
    pub enabled: Option<bool>,
    /// Filter by destination type (logs or lookup)
    pub destination_type: Option<String>,
    /// Maximum number of results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// List all scheduled jobs
///
/// GET /api/scheduled-jobs
#[utoipa::path(
    get,
    path = "/api/scheduled-jobs",
    tag = "scheduler",
    params(ListJobsQuery),
    responses(
        (status = 200, description = "Jobs retrieved successfully", body = Vec<ScheduledJob>),
    ),
    security(("api_key" = []))
)]
pub async fn list_scheduled_jobs(
    State(state): State<AppState>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<Vec<ScheduledJob>>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let filter = JobFilter {
        enabled: query.enabled,
        destination_type: query.destination_type,
        limit: query.limit,
        offset: query.offset,
    };

    let jobs = scheduler_service
        .list_jobs(&filter)
        .await
        .map_err(scheduler_error_to_api)?;

    Ok(Json(jobs))
}

/// Get a specific scheduled job by ID
///
/// GET /api/scheduled-jobs/:id
#[utoipa::path(
    get,
    path = "/api/scheduled-jobs/{id}",
    tag = "scheduler",
    params(
        ("id" = String, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job retrieved successfully", body = ScheduledJob),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_scheduled_job(
    State(state): State<AppState>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ScheduledJob>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let job = scheduler_service
        .get_job(*id)
        .await
        .map_err(scheduler_error_to_api)?;

    Ok(Json(job))
}

/// Update a scheduled job
///
/// PUT /api/scheduled-jobs/:id
#[utoipa::path(
    put,
    path = "/api/scheduled-jobs/{id}",
    tag = "scheduler",
    params(
        ("id" = String, Path, description = "Job ID")
    ),
    request_body = UpdateScheduledJob,
    responses(
        (status = 200, description = "Job updated successfully", body = ScheduledJob),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_scheduled_job(
    State(state): State<AppState>,
    Path(id): Path<TypeIdParam>,
    Json(update): Json<UpdateScheduledJob>,
) -> Result<Json<ScheduledJob>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let job = scheduler_service
        .update_job(*id, update)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(job_id = %*id, "Scheduled job updated");

    Ok(Json(job))
}

/// Delete a scheduled job
///
/// DELETE /api/scheduled-jobs/:id
#[utoipa::path(
    delete,
    path = "/api/scheduled-jobs/{id}",
    tag = "scheduler",
    params(
        ("id" = String, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job deleted successfully", body = SchedulerDeleteResponse),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_scheduled_job(
    State(state): State<AppState>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SchedulerDeleteResponse>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let deleted = scheduler_service
        .delete_job(*id)
        .await
        .map_err(scheduler_error_to_api)?;

    if !deleted {
        return Err(ApiError::NotFound(format!(
            "Scheduled job not found: {}",
            *id
        )));
    }

    info!(job_id = %*id, "Scheduled job deleted");

    Ok(Json(SchedulerDeleteResponse { success: true }))
}

/// Response for delete operations
#[derive(Debug, Serialize, ToSchema)]
pub struct SchedulerDeleteResponse {
    pub success: bool,
}

/// Manually trigger a scheduled job
///
/// POST /api/scheduled-jobs/:id/trigger
#[utoipa::path(
    post,
    path = "/api/scheduled-jobs/{id}/trigger",
    tag = "scheduler",
    params(
        ("id" = String, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job triggered successfully", body = JobExecution),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_scheduled_job(
    State(state): State<AppState>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<JobExecution>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let execution = scheduler_service
        .trigger_job(*id)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(
        job_id = %*id,
        status = ?execution.status,
        "Scheduled job triggered manually"
    );

    Ok(Json(execution))
}

/// Enable a scheduled job
///
/// POST /api/scheduled-jobs/:id/enable
#[utoipa::path(
    post,
    path = "/api/scheduled-jobs/{id}/enable",
    tag = "scheduler",
    params(
        ("id" = String, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job enabled successfully", body = ScheduledJob),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn enable_scheduled_job(
    State(state): State<AppState>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ScheduledJob>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let job = scheduler_service
        .enable_job(*id)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(job_id = %*id, "Scheduled job enabled");

    Ok(Json(job))
}

/// Disable a scheduled job
///
/// POST /api/scheduled-jobs/:id/disable
#[utoipa::path(
    post,
    path = "/api/scheduled-jobs/{id}/disable",
    tag = "scheduler",
    params(
        ("id" = String, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job disabled successfully", body = ScheduledJob),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn disable_scheduled_job(
    State(state): State<AppState>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ScheduledJob>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let job = scheduler_service
        .disable_job(*id)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(job_id = %*id, "Scheduled job disabled");

    Ok(Json(job))
}

/// Get scheduler statistics
///
/// GET /api/scheduled-jobs/stats
#[utoipa::path(
    get,
    path = "/api/scheduled-jobs/stats",
    tag = "scheduler",
    responses(
        (status = 200, description = "Stats retrieved successfully", body = JobStats),
    ),
    security(("api_key" = []))
)]
pub async fn get_scheduler_stats(
    State(state): State<AppState>,
) -> Result<Json<JobStats>, ApiError> {
    let scheduler_service = SchedulerService::new(state.pool.clone());

    let stats = scheduler_service
        .get_stats()
        .await
        .map_err(scheduler_error_to_api)?;

    Ok(Json(stats))
}

/// Request body for validating a cron expression
#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateCronRequest {
    /// Cron expression to validate
    pub expression: String,
    /// Number of next run times to return (default: 5)
    pub preview_count: Option<usize>,
}

/// Response for cron validation
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateCronResponse {
    /// Whether the expression is valid
    pub valid: bool,
    /// Human-readable description of the schedule
    pub description: Option<String>,
    /// Next scheduled run times
    pub next_runs: Vec<String>,
    /// Error message if invalid
    pub error: Option<String>,
}

/// Validate a cron expression
///
/// POST /api/scheduled-jobs/validate-cron
#[utoipa::path(
    post,
    path = "/api/scheduled-jobs/validate-cron",
    tag = "scheduler",
    request_body = ValidateCronRequest,
    responses(
        (status = 200, description = "Validation result", body = ValidateCronResponse),
    ),
    security(("api_key" = []))
)]
pub async fn validate_cron_expression(
    Json(request): Json<ValidateCronRequest>,
) -> Result<Json<ValidateCronResponse>, ApiError> {
    let preview_count = request.preview_count.unwrap_or(5);

    match validate_cron(&request.expression) {
        Ok(()) => {
            let description = describe_cron(&request.expression).ok();
            let next_runs = calculate_next_runs(&request.expression, preview_count)
                .map(|runs| runs.into_iter().map(|dt| dt.to_rfc3339()).collect())
                .unwrap_or_default();

            Ok(Json(ValidateCronResponse {
                valid: true,
                description,
                next_runs,
                error: None,
            }))
        }
        Err(e) => Ok(Json(ValidateCronResponse {
            valid: false,
            description: None,
            next_runs: vec![],
            error: Some(e.to_string()),
        })),
    }
}

/// Convert SchedulerError to ApiError
fn scheduler_error_to_api(err: SchedulerError) -> ApiError {
    match err {
        SchedulerError::NotFound(id) => {
            ApiError::NotFound(format!("Scheduled job not found: {}", id))
        }
        SchedulerError::InvalidCron(msg) => {
            ApiError::ValidationError(format!("Invalid cron expression: {}", msg))
        }
        SchedulerError::AlreadyRunning => {
            ApiError::ValidationError("Job is already running".to_string())
        }
        SchedulerError::FetchError(msg) => ApiError::InternalError(format!("Fetch error: {}", msg)),
        SchedulerError::UploadError(msg) => {
            ApiError::InternalError(format!("Upload error: {}", msg))
        }
        SchedulerError::RepositoryError(e) => ApiError::InternalError(e.to_string()),
        SchedulerError::SsrfBlocked(msg) => {
            ApiError::ValidationError(format!("URL blocked by security policy: {}", msg))
        }
    }
}

/// OpenAPI documentation for scheduler endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_scheduled_job,
        list_scheduled_jobs,
        get_scheduled_job,
        update_scheduled_job,
        delete_scheduled_job,
        trigger_scheduled_job,
        enable_scheduled_job,
        disable_scheduled_job,
        get_scheduler_stats,
        validate_cron_expression,
    ),
    components(schemas(SchedulerDeleteResponse, ValidateCronRequest, ValidateCronResponse))
)]
pub struct SchedulerApiDoc;
