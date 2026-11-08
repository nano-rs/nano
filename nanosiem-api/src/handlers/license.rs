// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosted and C05 offline licence administration.

use axum::{body::Bytes, extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_enterprise::sovereign_license::{
    ClockRecoveryRequest, EntitlementError, LicenseStateView, MAX_LICENSE_BYTES,
};
use serde::Serialize;
use utoipa::OpenApi;

use crate::error::{ApiError, ErrorResponse};
use crate::license_admission::{iso, OfflineLicenseSnapshot};
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Licence status returned to the frontend. Hosted deployments populate the
/// legacy fields; sovereign/offline deployments additionally populate the C05
/// installation, revision and recovery diagnostics.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LicenseStatusResponse {
    pub state: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_ends_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub enforcement_enabled: bool,
    pub airgap: bool,
    /// `hosted`, `offline`, or `unconfigured`.
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    pub recovery_epoch: u64,
    pub recovery_required: bool,
    pub components: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

impl LicenseStatusResponse {
    fn offline(view: &LicenseStateView) -> Self {
        let allowed = api_allowed(view);
        let state = match (allowed, view.state.as_str()) {
            (false, _) => "locked",
            (true, "running" | "renewal_due") => "active",
            (true, "grace") => "grace_period",
            (true, "shut_off" | "refused") => "locked",
            (true, _) => "locked",
        };
        Self {
            state: state.into(),
            valid: allowed,
            tier: view.license_type.clone(),
            locked_reason: view
                .refusal
                .clone()
                .or_else(|| (!view.valid).then(|| view.notice.clone()).flatten())
                .or_else(|| {
                    (!view.components.iter().any(|component| component == "api"))
                        .then(|| "The licence does not include the API component.".into())
                }),
            grace_ends_at: view.grace_until.clone(),
            expires_at: view.expires_at.clone(),
            enforcement_enabled: true,
            airgap: true,
            mode: "offline".into(),
            runtime_state: Some(view.state.clone()),
            installation_id: Some(view.installation_id.clone()),
            organization_id: Some(view.organization_id.clone()),
            installation_fingerprint: Some(view.installation_fingerprint.clone()),
            license_id: view.license_id.clone(),
            license_type: view.license_type.clone(),
            revision: view.revision,
            valid_from: view.valid_from.clone(),
            recovery_epoch: view.recovery_epoch,
            recovery_required: view.recovery_required,
            components: view.components.clone(),
            notice: view.notice.clone(),
        }
    }

    fn cached_offline(snapshot: &OfflineLicenseSnapshot) -> Self {
        if let Some(view) = snapshot.c05_view() {
            return Self::offline(view);
        }
        if let Some(grace) = snapshot.legacy_grace() {
            return Self {
                state: "grace_period".into(),
                valid: true,
                tier: grace.tier.clone(),
                locked_reason: None,
                grace_ends_at: Some(iso(grace.grace_until)),
                expires_at: grace.expires_at.map(iso),
                enforcement_enabled: true,
                airgap: true,
                mode: "offline".into(),
                runtime_state: Some("legacy_upgrade_grace".into()),
                installation_id: Some(grace.identity.installation_id.clone()),
                organization_id: Some(grace.identity.organization_id.clone()),
                installation_fingerprint: Some(grace.identity.installation_fingerprint.clone()),
                license_id: None,
                license_type: Some("legacy_offline".into()),
                revision: None,
                valid_from: None,
                recovery_epoch: 0,
                recovery_required: false,
                components: Vec::new(),
                notice: snapshot.notice().map(str::to_owned),
            };
        }
        Self {
            state: "locked".into(),
            valid: false,
            tier: None,
            locked_reason: snapshot.unavailable_reason().map(str::to_owned),
            grace_ends_at: None,
            expires_at: None,
            enforcement_enabled: true,
            airgap: true,
            mode: "offline".into(),
            runtime_state: Some("refused".into()),
            installation_id: None,
            organization_id: None,
            installation_fingerprint: None,
            license_id: None,
            license_type: None,
            revision: None,
            valid_from: None,
            recovery_epoch: 0,
            recovery_required: false,
            components: Vec::new(),
            notice: None,
        }
    }
}

/// Convert the exact C05 view into the pre-existing middleware cache. The
/// cache is only an admission mirror; the PostgreSQL + ClickHouse authority
/// remains the source of truth and refreshes it every 30 seconds.
pub fn cache_status(view: &LicenseStateView) -> nanosiem_core::license::LicenseStatus {
    use nanosiem_core::license::{LicenseState, LicenseStatus};

    let allowed = api_allowed(view);
    let state = match (allowed, view.state.as_str()) {
        (false, _) => LicenseState::Locked,
        (true, "running" | "renewal_due") => LicenseState::Active,
        (true, "grace") => LicenseState::GracePeriod,
        (true, "shut_off" | "refused") => LicenseState::Locked,
        (true, _) => LicenseState::Locked,
    };
    LicenseStatus {
        state,
        valid: allowed,
        tier: view.license_type.clone(),
        locked_reason: view
            .refusal
            .clone()
            .or_else(|| (!view.valid).then(|| view.notice.clone()).flatten())
            .or_else(|| {
                (!view.components.iter().any(|component| component == "api"))
                    .then(|| "The licence does not include the API component.".into())
            }),
        grace_ends_at: parse_time(view.grace_until.as_deref()),
        // The legacy middleware locks at `expires_at`; for C05 that boundary
        // is the hard grace limit, not the beginning of production grace.
        expires_at: parse_time(view.grace_until.as_deref()),
        last_checked_at: parse_time(view.observed_at.as_deref()),
        last_heartbeat_at: None,
        offline: true,
    }
}

fn api_allowed(view: &LicenseStateView) -> bool {
    view.valid && view.components.iter().any(|component| component == "api")
}

fn parse_time(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

/// Get the cached licence status. Durable observations are performed only by
/// the single 30-second authority refresher.
#[utoipa::path(
    get,
    path = "/api/license",
    tag = "license",
    responses(
        (status = 200, description = "Licence status", body = LicenseStatusResponse),
        (status = 503, description = "Offline licence authority unavailable", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_license_status(
    State(state): State<AppState>,
) -> Result<Json<LicenseStatusResponse>, ApiError> {
    if state.config.airgap && !state.config.is_license_enabled() {
        let snapshot = state.offline_license_snapshot.read().await.clone();
        return Ok(Json(LicenseStatusResponse::cached_offline(&snapshot)));
    }

    let status = state
        .license_status
        .read()
        .await
        .effective(chrono::Utc::now());
    let enforcement_enabled = state.config.is_license_enabled();
    Ok(Json(LicenseStatusResponse {
        state: status.state.as_str().to_string(),
        valid: status.valid,
        tier: status.tier.clone(),
        locked_reason: status.locked_reason.clone(),
        grace_ends_at: status.grace_ends_at.map(|dt| dt.to_rfc3339()),
        expires_at: status.expires_at.map(|dt| dt.to_rfc3339()),
        enforcement_enabled,
        airgap: state.config.airgap,
        mode: if enforcement_enabled {
            "hosted"
        } else {
            "unconfigured"
        }
        .into(),
        runtime_state: None,
        installation_id: None,
        organization_id: None,
        installation_fingerprint: None,
        license_id: None,
        license_type: None,
        revision: None,
        valid_from: None,
        recovery_epoch: 0,
        recovery_required: false,
        components: Vec::new(),
        notice: None,
    }))
}

#[utoipa::path(
    post,
    path = "/api/license/import",
    tag = "license",
    request_body(content = String, description = "Exact signed C05 licence JSON file", content_type = "application/json"),
    responses(
        (status = 200, description = "Licence installed", body = LicenseStatusResponse),
        (status = 400, description = "Invalid licence file", body = ErrorResponse),
        (status = 403, description = "Missing settings:system permission", body = ErrorResponse),
        (status = 409, description = "Binding, revision or term refused", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn import_license(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    body: Bytes,
) -> Result<Json<LicenseStatusResponse>, ApiError> {
    ensure_offline_admin(&state, &auth)?;
    install(&state, &body).await
}

#[utoipa::path(
    post,
    path = "/api/license/renew",
    tag = "license",
    request_body(content = String, description = "Exact signed C05 renewal JSON file", content_type = "application/json"),
    responses(
        (status = 200, description = "Renewal installed", body = LicenseStatusResponse),
        (status = 400, description = "Invalid renewal file", body = ErrorResponse),
        (status = 403, description = "Missing settings:system permission", body = ErrorResponse),
        (status = 409, description = "Revision or term rollback refused", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn renew_license(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    body: Bytes,
) -> Result<Json<LicenseStatusResponse>, ApiError> {
    ensure_offline_admin(&state, &auth)?;
    install(&state, &body).await
}

async fn install(state: &AppState, body: &[u8]) -> Result<Json<LicenseStatusResponse>, ApiError> {
    if body.is_empty() || body.len() > MAX_LICENSE_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "C05 licence files must be 1 to {MAX_LICENSE_BYTES} bytes"
        )));
    }
    let view = state
        .sovereign_license
        .import(body)
        .await
        .map_err(entitlement_error)?;
    *state.license_status.write().await = cache_status(&view);
    *state.offline_license_snapshot.write().await = OfflineLicenseSnapshot::C05(view.clone());
    Ok(Json(LicenseStatusResponse::offline(&view)))
}

#[utoipa::path(
    post,
    path = "/api/license/clock-recovery/request",
    tag = "license",
    responses(
        (status = 200, description = "Public clock-recovery request", body = ClockRecoveryRequest),
        (status = 403, description = "Missing settings:system permission", body = ErrorResponse),
        (status = 409, description = "No installed licence", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_clock_recovery_request(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ClockRecoveryRequest>, ApiError> {
    ensure_offline_admin(&state, &auth)?;
    state
        .sovereign_license
        .clock_recovery_request()
        .await
        .map(Json)
        .map_err(entitlement_error)
}

#[utoipa::path(
    post,
    path = "/api/license/clock-recovery",
    tag = "license",
    request_body(content = String, description = "Exact vendor-signed clock-recovery JSON file", content_type = "application/json"),
    responses(
        (status = 200, description = "Clock floor recovered", body = LicenseStatusResponse),
        (status = 400, description = "Invalid recovery file", body = ErrorResponse),
        (status = 403, description = "Missing settings:system permission", body = ErrorResponse),
        (status = 409, description = "Recovery request mismatch or replay", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn apply_clock_recovery(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    body: Bytes,
) -> Result<Json<LicenseStatusResponse>, ApiError> {
    ensure_offline_admin(&state, &auth)?;
    let view = state
        .sovereign_license
        .recover_clock(&body)
        .await
        .map_err(entitlement_error)?;
    *state.license_status.write().await = cache_status(&view);
    *state.offline_license_snapshot.write().await = OfflineLicenseSnapshot::C05(view.clone());
    Ok(Json(LicenseStatusResponse::offline(&view)))
}

fn ensure_offline_admin(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::SETTINGS_SYSTEM)?;
    if !state.config.airgap || state.config.is_license_enabled() {
        return Err(ApiError::Conflict(
            "C05 files are accepted only by an offline AIRGAP_MODE deployment".into(),
        ));
    }
    Ok(())
}

fn entitlement_error(error: EntitlementError) -> ApiError {
    let public = error.public_reason().to_owned();
    match error {
        EntitlementError::Storage(_) => ApiError::ServiceUnavailable(public),
        EntitlementError::Conflict
        | EntitlementError::RevisionRollback
        | EntitlementError::ForeignBinding
        | EntitlementError::NotYetValid
        | EntitlementError::Expired
        | EntitlementError::RecoveryDenied
        | EntitlementError::ClockRollback
        | EntitlementError::Rollback
        | EntitlementError::Missing => ApiError::Conflict(public),
        EntitlementError::InvalidArtifact
        | EntitlementError::UntrustedSignature
        | EntitlementError::Revoked => ApiError::BadRequest(public),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_license_status,
        import_license,
        renew_license,
        create_clock_recovery_request,
        apply_clock_recovery
    ),
    components(schemas(LicenseStatusResponse, ClockRecoveryRequest, ErrorResponse))
)]
pub struct LicenseApiDoc;

#[cfg(test)]
#[path = "license_tests.rs"]
mod tests;
