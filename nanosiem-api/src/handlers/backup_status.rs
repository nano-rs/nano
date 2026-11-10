// SPDX-License-Identifier: AGPL-3.0-or-later

//! Automatic backup status (NAN-5204). Open core.
//!
//! - `POST /api/internal/backup-status` — the `nano-backup` compose sidecar
//!   reports each scheduled attempt. Exempt from user-session auth
//!   (`middleware::auth::is_public_endpoint`), the IP allowlist and the backup
//!   mutation fence; THIS module's bearer check against
//!   `NANO_BACKUP_STATUS_TOKEN` is the only gate, so it must stay mandatory.
//!   No token provisioned → 404 (feature off, fail closed). Every nginx edge
//!   also 404s `/api/internal/`.
//! - `GET /api/system/backup-status` — the stored state plus the staleness
//!   verdict, for `settings:system` holders (banner + "Last backup" card).
//!
//! Nothing here is sent off the deployment.

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::backup_status::{
    self, BackupClickhouseData, BackupDestinationKind, BackupOutcome, BackupStatus,
    BackupStatusReport, BackupStatusRepository, STALE_AFTER_HOURS,
};
use serde::Serialize;

use crate::error::{ApiError, ErrorResponse};
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Env var holding the sidecar's shared secret (also set on `nano-backup`).
pub const BACKUP_STATUS_TOKEN_ENV: &str = "NANO_BACKUP_STATUS_TOKEN";

/// Constant-time byte comparison. Length mismatch returns early — the token
/// length is not a secret worth protecting, the token bytes are.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The configured token, `None` when unset or blank (feature disabled).
fn configured_token() -> Option<String> {
    std::env::var(BACKUP_STATUS_TOKEN_ENV)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// - Token unset/empty → 404 (feature disabled; fail closed).
/// - Header missing / not `Bearer` / mismatch → 401.
pub(crate) fn authorize_report(
    authorization: Option<&str>,
    configured: Option<&str>,
) -> Result<(), StatusCode> {
    let Some(expected) = configured else {
        return Err(StatusCode::NOT_FOUND);
    };
    let presented = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Record an automatic backup attempt
///
/// Called by the `nano-backup` sidecar after every scheduled attempt (and
/// once with `outcome: disabled` when the schedule is turned off). Bearer
/// auth with `NANO_BACKUP_STATUS_TOKEN`; 404 when that is not provisioned.
#[utoipa::path(
    post,
    path = "/api/internal/backup-status",
    tag = "system",
    request_body = BackupStatusReport,
    responses(
        (status = 204, description = "Report recorded"),
        (status = 400, description = "Invalid report", body = ErrorResponse),
        (status = 401, description = "Missing or invalid bearer (NANO_BACKUP_STATUS_TOKEN)"),
        (status = 404, description = "Backup status reporting is not configured"),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn report_backup_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    // Authenticate before parsing, so an unauthenticated caller learns
    // nothing about the body contract.
    if let Err(status) = authorize_report(authorization, configured_token().as_deref()) {
        return status.into_response();
    }
    match record(&state, &body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn record(state: &AppState, body: &[u8]) -> Result<(), ApiError> {
    let report: BackupStatusReport = serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("invalid backup status report: {e}")))?;
    let report = report
        .validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let (before, after) = BackupStatusRepository::new(state.pool.clone())
        .record(&report)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("backup status: {e}")))?;

    let enabled_changed = before.as_ref().map(|b| b.enabled) != Some(after.enabled);
    let outcome_changed = before.as_ref().and_then(|b| b.last_outcome.clone()) != after.last_outcome;
    match report.outcome {
        BackupOutcome::Failure => tracing::warn!(
            consecutive_failures = after.consecutive_failures,
            error = report.error.as_deref().unwrap_or(""),
            "automatic backup failed"
        ),
        BackupOutcome::Partial => tracing::warn!(
            warning = report.error.as_deref().unwrap_or(""),
            "automatic backup stored without part of its scope"
        ),
        _ if enabled_changed || outcome_changed => tracing::info!(
            enabled = after.enabled,
            outcome = report.outcome.as_str(),
            destination_kind = report.destination_kind.as_str(),
            "automatic backup status changed"
        ),
        _ => tracing::debug!(outcome = report.outcome.as_str(), "automatic backup reported"),
    }
    Ok(())
}

/// Stored automatic backup status plus the staleness verdict.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupStatusResponse {
    /// False when no report was ever received (all other fields null).
    pub configured: bool,
    pub enabled: Option<bool>,
    pub enabled_since: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    /// `success` or `failure`.
    pub last_outcome: Option<String>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_success_backup_id: Option<String>,
    pub last_success_size_bytes: Option<i64>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_failure_error: Option<String>,
    pub consecutive_failures: Option<i32>,
    /// `path` or `s3`.
    pub destination_kind: Option<String>,
    pub destination: Option<String>,
    /// `included` or `excluded`.
    pub clickhouse_data: Option<String>,
    pub schedule: Option<String>,
    pub keep: Option<i32>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Enabled and no successful backup within `stale_after_hours`.
    pub stale: bool,
    pub stale_after_hours: i64,
}

impl BackupStatusResponse {
    pub fn from_status(status: Option<BackupStatus>, now: DateTime<Utc>) -> Self {
        let stale = status
            .as_ref()
            .is_some_and(|s| backup_status::is_stale(s, now));
        match status {
            None => Self {
                configured: false,
                enabled: None,
                enabled_since: None,
                last_attempt_at: None,
                last_outcome: None,
                last_success_at: None,
                last_success_backup_id: None,
                last_success_size_bytes: None,
                last_failure_at: None,
                last_failure_error: None,
                consecutive_failures: None,
                destination_kind: None,
                destination: None,
                clickhouse_data: None,
                schedule: None,
                keep: None,
                next_run_at: None,
                updated_at: None,
                stale,
                stale_after_hours: STALE_AFTER_HOURS,
            },
            Some(s) => Self {
                configured: true,
                enabled: Some(s.enabled),
                enabled_since: s.enabled_since,
                last_attempt_at: s.last_attempt_at,
                last_outcome: s.last_outcome,
                last_success_at: s.last_success_at,
                last_success_backup_id: s.last_success_backup_id,
                last_success_size_bytes: s.last_success_size_bytes,
                last_failure_at: s.last_failure_at,
                last_failure_error: s.last_failure_error,
                consecutive_failures: Some(s.consecutive_failures),
                destination_kind: s.destination_kind,
                destination: s.destination,
                clickhouse_data: s.clickhouse_data,
                schedule: s.schedule,
                keep: s.keep,
                next_run_at: s.next_run_at,
                updated_at: Some(s.updated_at),
                stale,
                stale_after_hours: STALE_AFTER_HOURS,
            },
        }
    }
}

/// Automatic backup status
///
/// Latest state reported by the `nano-backup` sidecar: schedule,
/// destination, scope, last success / failure and whether the newest
/// successful backup is stale (enabled and none within 36 hours).
/// `configured: false` when automatic backups were never set up.
/// Requires `settings:system`.
#[utoipa::path(
    get,
    path = "/api/system/backup-status",
    tag = "system",
    responses(
        (status = 200, description = "Automatic backup status", body = BackupStatusResponse),
        (status = 403, description = "Missing settings:system", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_backup_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<BackupStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let status = BackupStatusRepository::new(state.pool.clone())
        .get()
        .await
        .map_err(|e| ApiError::DatabaseError(format!("backup status: {e}")))?;
    Ok(Json(BackupStatusResponse::from_status(status, Utc::now())))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(report_backup_status, get_backup_status),
    components(schemas(
        BackupStatusReport,
        BackupStatusResponse,
        BackupOutcome,
        BackupDestinationKind,
        BackupClickhouseData
    ))
)]
pub struct BackupStatusApiDoc;

#[cfg(test)]
#[path = "backup_status_tests.rs"]
mod tests;
