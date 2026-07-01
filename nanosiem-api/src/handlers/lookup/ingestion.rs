// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup Table Ingestion API handlers
//!
//! Provides REST API endpoints for managing automated ingestion (scheduled jobs)
//! scoped to a specific lookup table. Replaces the standalone /api/scheduled-jobs routes.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use utoipa::ToSchema;

use nanosiem_core::auth::permissions;
use nanosiem_core::upload::{LookupMode, ParserConfig, UploadDestination};
use nanosiem_core::{
    calculate_next_runs, describe_cron, merge_auth_headers, redact_auth_headers, validate_cron,
    JobExecution, NewScheduledJob, ScheduledJob, SchedulerError,
    SchedulerService, SsrfError, SsrfValidator, UpdateScheduledJob,
};

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Request body for upserting lookup table ingestion config
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpsertLookupIngestionRequest {
    /// URL to fetch data from
    pub url: String,
    /// Cron expression for scheduling
    pub cron_expression: String,
    /// Optional authentication headers
    pub auth_headers: Option<HashMap<String, String>>,
    /// Parser configuration for the fetched data
    pub parser_config: ParserConfig,
    /// Retry policy (optional, uses defaults if not provided)
    pub retry_policy: Option<nanosiem_core::RetryPolicy>,
    /// Whether the job is enabled (default: true)
    pub enabled: Option<bool>,
    /// Update mode: replace or append (default: replace)
    pub mode: Option<LookupMode>,
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

/// Response for delete operations
#[derive(Debug, Serialize, ToSchema)]
pub struct IngestionDeleteResponse {
    pub success: bool,
}

/// Get ingestion config for a lookup table
///
/// GET /api/lookup-tables/{name}/ingestion
#[utoipa::path(
    get,
    path = "/api/lookup-tables/{name}/ingestion",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Ingestion config (or null)", body = Option<ScheduledJob>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_lookup_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<Option<ScheduledJob>>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_VIEW)?;

    let scheduler_service = SchedulerService::new(state.pool.clone());

    let mut job = scheduler_service
        .get_job_for_lookup_table(&name)
        .await
        .map_err(scheduler_error_to_api)?;

    // NAN-1358: never return auth-header secrets in cleartext (this endpoint is
    // readable with only lookup:view).
    if let Some(job) = job.as_mut() {
        redact_auth_headers(&mut job.auth_headers);
    }

    Ok(Json(job))
}

/// Upsert ingestion config for a lookup table
///
/// PUT /api/lookup-tables/{name}/ingestion
#[utoipa::path(
    put,
    path = "/api/lookup-tables/{name}/ingestion",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    request_body = UpsertLookupIngestionRequest,
    responses(
        (status = 200, description = "Ingestion config created or updated", body = ScheduledJob),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn upsert_lookup_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
    Json(request): Json<UpsertLookupIngestionRequest>,
) -> Result<Json<ScheduledJob>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_EDIT)?;

    validate_ingestion_url(&request.url).await?;

    let scheduler_service = SchedulerService::new(state.pool.clone());

    // Look up the table's primary_key from the registry so the destination is accurate
    let lookup_service = state.lookup_service.clone();
    let table_info = lookup_service
        .get_table(&name)
        .await
        .map_err(super::lookup_error_to_api)?;

    let destination = UploadDestination::LookupTable {
        table_name: name.clone(),
        primary_key: table_info.primary_key.clone(),
        mode: request.mode.unwrap_or_default(),
    };

    // Check if a job already exists for this lookup table
    let existing = scheduler_service
        .get_job_for_lookup_table(&name)
        .await
        .map_err(scheduler_error_to_api)?;

    // NAN-1358: resolve auth headers so a read-modify-write round-trip can't wipe
    // stored secrets. Omitted headers are preserved; the redacted placeholder
    // echoed back keeps the stored value; only real values overwrite.
    let merged_auth = merge_auth_headers(
        request.auth_headers,
        existing.as_ref().and_then(|j| j.auth_headers.as_ref()),
    );

    let mut job = if let Some(existing_job) = existing {
        // Update existing job
        let update = UpdateScheduledJob {
            url: Some(request.url),
            cron_expression: Some(request.cron_expression),
            auth_headers: merged_auth,
            destination: Some(destination),
            parser_config: Some(request.parser_config),
            retry_policy: request.retry_policy,
            enabled: request.enabled,
            ..Default::default()
        };

        scheduler_service
            .update_job(existing_job.id, update)
            .await
            .map_err(scheduler_error_to_api)?
    } else {
        // Create new job
        let new_job = NewScheduledJob {
            name: format!("{} ingestion", name),
            description: Some(format!("Automated ingestion for lookup table {}", name)),
            cron_expression: request.cron_expression,
            url: request.url,
            auth_headers: merged_auth.flatten(),
            destination,
            parser_config: request.parser_config,
            retry_policy: request.retry_policy.unwrap_or_default(),
            enabled: request.enabled.unwrap_or(true),
        };

        scheduler_service
            .create_job(new_job)
            .await
            .map_err(scheduler_error_to_api)?
    };

    info!(lookup_table = %name, job_id = %job.id, "Lookup ingestion upserted");
    // NAN-1358: don't echo the stored secrets back in the response.
    redact_auth_headers(&mut job.auth_headers);
    Ok(Json(job))
}

/// Delete ingestion config for a lookup table
///
/// DELETE /api/lookup-tables/{name}/ingestion
#[utoipa::path(
    delete,
    path = "/api/lookup-tables/{name}/ingestion",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Ingestion removed", body = IngestionDeleteResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_lookup_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<IngestionDeleteResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_EDIT)?;

    let scheduler_service = SchedulerService::new(state.pool.clone());

    let deleted = scheduler_service
        .delete_job_for_lookup_table(&name)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(lookup_table = %name, deleted, "Lookup ingestion deleted");
    Ok(Json(IngestionDeleteResponse { success: deleted }))
}

/// Trigger ingestion for a lookup table
///
/// POST /api/lookup-tables/{name}/ingestion/trigger
#[utoipa::path(
    post,
    path = "/api/lookup-tables/{name}/ingestion/trigger",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Ingestion triggered", body = JobExecution),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No ingestion config"),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_lookup_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<JobExecution>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_EDIT)?;

    let scheduler_service = SchedulerService::new(state.pool.clone());

    let execution = scheduler_service
        .trigger_job_for_lookup_table(&name)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(
        lookup_table = %name,
        status = ?execution.status,
        "Lookup ingestion triggered"
    );

    Ok(Json(execution))
}

/// Enable ingestion for a lookup table
///
/// POST /api/lookup-tables/{name}/ingestion/enable
#[utoipa::path(
    post,
    path = "/api/lookup-tables/{name}/ingestion/enable",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Ingestion enabled", body = ScheduledJob),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No ingestion config"),
    ),
    security(("api_key" = []))
)]
pub async fn enable_lookup_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<ScheduledJob>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_EDIT)?;

    let scheduler_service = SchedulerService::new(state.pool.clone());

    let existing = scheduler_service
        .get_job_for_lookup_table(&name)
        .await
        .map_err(scheduler_error_to_api)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("No ingestion config for lookup table: {}", name))
        })?;

    let mut job = scheduler_service
        .enable_job(existing.id)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(lookup_table = %name, "Lookup ingestion enabled");
    redact_auth_headers(&mut job.auth_headers);
    Ok(Json(job))
}

/// Disable ingestion for a lookup table
///
/// POST /api/lookup-tables/{name}/ingestion/disable
#[utoipa::path(
    post,
    path = "/api/lookup-tables/{name}/ingestion/disable",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name")
    ),
    responses(
        (status = 200, description = "Ingestion disabled", body = ScheduledJob),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No ingestion config"),
    ),
    security(("api_key" = []))
)]
pub async fn disable_lookup_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<ScheduledJob>, ApiError> {
    ensure_permission(&auth, permissions::LOOKUP_EDIT)?;

    let scheduler_service = SchedulerService::new(state.pool.clone());

    let existing = scheduler_service
        .get_job_for_lookup_table(&name)
        .await
        .map_err(scheduler_error_to_api)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("No ingestion config for lookup table: {}", name))
        })?;

    let mut job = scheduler_service
        .disable_job(existing.id)
        .await
        .map_err(scheduler_error_to_api)?;

    info!(lookup_table = %name, "Lookup ingestion disabled");
    redact_auth_headers(&mut job.auth_headers);
    Ok(Json(job))
}

/// Validate a cron expression
///
/// POST /api/lookup-tables/validate-cron
#[utoipa::path(
    post,
    path = "/api/lookup-tables/validate-cron",
    tag = "lookup",
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

/// Validate an ingestion URL against SSRF rules before persisting it.
///
/// Mirrors the runtime config used in `SchedulerService::fetch_and_process` so
/// a URL that would be rejected at fetch time is also rejected at upsert time
/// — the goal is fast operator feedback and avoiding dormant unsafe state.
///
/// Errors are mapped to a generic message for IP-class rejections to avoid
/// using validation responses as a DNS/internal-host oracle (matches NAN-679).
async fn validate_ingestion_url(url: &str) -> Result<(), ApiError> {
    SsrfValidator::http_allowed_validator()
        .validate_with_dns(url)
        .await
        .map(|_| ())
        .map_err(ssrf_error_to_api)
}

fn ssrf_error_to_api(err: SsrfError) -> ApiError {
    match err {
        SsrfError::InvalidUrl(msg) => {
            ApiError::ValidationError(format!("Invalid ingestion URL: {}", msg))
        }
        SsrfError::InvalidScheme(scheme) => ApiError::ValidationError(format!(
            "Ingestion URL scheme '{}' is not allowed (use http or https)",
            scheme
        )),
        SsrfError::HttpNotAllowed => {
            ApiError::ValidationError("Ingestion URL must use https".to_string())
        }
        SsrfError::MissingHostname => {
            ApiError::ValidationError("Ingestion URL is missing a hostname".to_string())
        }
        SsrfError::PrivateIpBlocked(_)
        | SsrfError::LocalhostBlocked
        | SsrfError::LinkLocalBlocked(_)
        | SsrfError::MetadataEndpointBlocked(_)
        | SsrfError::DomainBlocked(_) => ApiError::ValidationError(
            "Ingestion URL targets a host that is not allowed".to_string(),
        ),
        SsrfError::DnsResolutionFailed(host, _) => {
            ApiError::ValidationError(format!("Could not resolve ingestion URL hostname: {}", host))
        }
        SsrfError::BlockedRedirect(msg) => {
            ApiError::ValidationError(format!("Ingestion URL redirect is not allowed: {}", msg))
        }
    }
}

/// Convert SchedulerError to ApiError
fn scheduler_error_to_api(err: SchedulerError) -> ApiError {
    match err {
        SchedulerError::NotFound(id) => {
            ApiError::NotFound(format!("Ingestion config not found: {}", id))
        }
        SchedulerError::InvalidCron(msg) => {
            ApiError::ValidationError(format!("Invalid cron expression: {}", msg))
        }
        SchedulerError::AlreadyRunning => {
            ApiError::ValidationError("Ingestion is already running".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApiError;

    fn assert_validation_error(err: ApiError, needle: &str) {
        match err {
            ApiError::ValidationError(msg) => assert!(
                msg.to_lowercase().contains(&needle.to_lowercase()),
                "expected validation error containing '{}', got '{}'",
                needle,
                msg
            ),
            other => panic!("expected ValidationError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_loopback_ipv4() {
        let err = validate_ingestion_url("http://127.0.0.1:5173/api/auth/me")
            .await
            .expect_err("loopback must be rejected");
        // Generic message — must NOT leak which class of address was blocked.
        assert_validation_error(err, "not allowed");
    }

    #[tokio::test]
    async fn rejects_loopback_ipv6() {
        let err = validate_ingestion_url("http://[::1]/")
            .await
            .expect_err("ipv6 loopback must be rejected");
        assert_validation_error(err, "not allowed");
    }

    #[tokio::test]
    async fn rejects_rfc1918_addresses() {
        for url in [
            "http://10.0.0.1/feed",
            "http://172.16.0.1/feed",
            "http://192.168.1.1/feed",
        ] {
            let err = validate_ingestion_url(url)
                .await
                .err()
                .unwrap_or_else(|| panic!("expected rejection for {}", url));
            assert_validation_error(err, "not allowed");
        }
    }

    #[tokio::test]
    async fn rejects_link_local_and_metadata() {
        let err = validate_ingestion_url("http://169.254.1.1/")
            .await
            .expect_err("link-local must be rejected");
        assert_validation_error(err, "not allowed");

        let err = validate_ingestion_url("http://169.254.169.254/latest/meta-data/")
            .await
            .expect_err("metadata endpoint must be rejected");
        assert_validation_error(err, "not allowed");
    }

    #[tokio::test]
    async fn rejects_invalid_scheme() {
        let err = validate_ingestion_url("ftp://files.example.com/feed.csv")
            .await
            .expect_err("ftp must be rejected");
        assert_validation_error(err, "scheme");
    }

    #[tokio::test]
    async fn rejects_malformed_url() {
        let err = validate_ingestion_url("not a url")
            .await
            .expect_err("malformed url must be rejected");
        assert_validation_error(err, "invalid");
    }

    #[tokio::test]
    async fn ssrf_error_does_not_leak_ip_class() {
        // Defense against using validation responses as a DNS / internal-host
        // oracle: the message must not reveal whether the rejected address
        // was loopback vs RFC1918 vs link-local vs metadata.
        let messages: Vec<String> = [
            SsrfError::LocalhostBlocked,
            SsrfError::PrivateIpBlocked("10.0.0.1".parse().unwrap()),
            SsrfError::LinkLocalBlocked("169.254.1.1".parse().unwrap()),
            SsrfError::MetadataEndpointBlocked("169.254.169.254".to_string()),
            SsrfError::DomainBlocked("internal.example".to_string()),
        ]
        .into_iter()
        .map(|e| match ssrf_error_to_api(e) {
            ApiError::ValidationError(msg) => msg,
            other => panic!("expected ValidationError, got {:?}", other),
        })
        .collect();

        for window in messages.windows(2) {
            assert_eq!(
                window[0], window[1],
                "all IP-class rejections must produce the same message"
            );
        }
    }
}
