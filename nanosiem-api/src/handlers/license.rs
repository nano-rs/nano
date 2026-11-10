// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosted and C05 offline licence administration.

use axum::{body::Bytes, extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_enterprise::sovereign_license::{
    verify_production, ClockRecoveryRequest, EntitlementError, EntitlementOperator,
    LicenseStateView, MAX_LICENSE_BYTES,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement: Option<LicenseEntitlementResponse>,
    /// NAN-5194: the licence server refused this deployment's token (HTTP
    /// 401/403) at the last check-in attempt. Hosted (online) mode only;
    /// omitted otherwise, and cleared by the next successful check-in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_rejected: Option<TokenRejectedResponse>,
}

/// NAN-5194: admin banner data for a rejected licence token. Never contains
/// the token.
#[derive(Debug, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct TokenRejectedResponse {
    /// HTTP status the licence server answered (401 or 403).
    pub http_status: u16,
    pub first_rejected_at: String,
    pub last_rejected_at: String,
    /// When the install locks (14 days after the last successful check-in);
    /// omitted when it never checked in successfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locks_at: Option<String>,
    pub message: String,
}

impl From<nanosiem_core::license::TokenRejectedNotice> for TokenRejectedResponse {
    fn from(notice: nanosiem_core::license::TokenRejectedNotice) -> Self {
        Self {
            http_status: notice.http_status,
            first_rejected_at: notice.first_rejected_at.to_rfc3339(),
            last_rejected_at: notice.last_rejected_at.to_rfc3339(),
            locks_at: notice.locks_at.map(|at| at.to_rfc3339()),
            message: notice.message,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LicenseEntitlementResponse {
    pub license_id: String,
    pub edition: String,
    pub operator: String,
    pub offering: String,
    pub kind: String,
    pub capacity_gb_per_day: Option<u64>,
    pub starts_at: String,
    pub expires_at: String,
    pub grace_ends_at: String,
    pub revision: u64,
    pub days_remaining: i64,
    /// Present only inside a 14/7/1/0-day warning step; omitted (never
    /// `null`) otherwise so clients do not render an empty warning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_days: Option<i64>,
}

impl LicenseEntitlementResponse {
    fn from_status(
        status: &nanosiem_core::license::LicenseStatus,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        let entitlement = status.entitlement.as_ref()?;
        Some(Self {
            license_id: entitlement.license_id.clone(),
            edition: entitlement.edition.clone(),
            operator: entitlement.operator.clone(),
            offering: entitlement.offering.clone(),
            kind: entitlement.kind.clone(),
            capacity_gb_per_day: entitlement.capacity_gb_per_day,
            starts_at: entitlement.starts_at.to_rfc3339(),
            expires_at: entitlement.expires_at.to_rfc3339(),
            grace_ends_at: entitlement.grace_ends_at.to_rfc3339(),
            revision: entitlement.revision,
            days_remaining: status.trial_days_remaining(now).unwrap_or(0),
            warning_days: status.trial_warning_days(now),
        })
    }
}

impl LicenseStatusResponse {
    fn offline(view: &LicenseStateView, airgap: bool) -> Self {
        let allowed = api_allowed(view);
        let cached = cache_status(view);
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
                .or_else(|| (!view.valid).then(|| view.notice.clone()).flatten()),
            grace_ends_at: view.grace_until.clone(),
            expires_at: view.expires_at.clone(),
            enforcement_enabled: true,
            airgap,
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
            entitlement: LicenseEntitlementResponse::from_status(&cached, Utc::now()),
            token_rejected: None,
        }
    }

    fn cached_offline(snapshot: &OfflineLicenseSnapshot, airgap: bool) -> Self {
        if let Some(view) = snapshot.c05_view() {
            return Self::offline(view, airgap);
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
                airgap,
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
                entitlement: None,
                token_rejected: None,
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
            airgap,
            mode: "unconfigured".into(),
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
            entitlement: None,
            token_rejected: None,
        }
    }
}

/// Convert the exact C05 view into the pre-existing middleware cache. The
/// cache is only an admission mirror; the PostgreSQL + ClickHouse authority
/// remains the source of truth and refreshes it every 30 seconds.
pub fn cache_status(view: &LicenseStateView) -> nanosiem_core::license::LicenseStatus {
    use nanosiem_core::license::{LicenseEntitlement, LicenseState, LicenseStatus};

    let allowed = api_allowed(view);
    let state = match (allowed, view.state.as_str()) {
        (false, _) => LicenseState::Locked,
        (true, "running" | "renewal_due") => LicenseState::Active,
        (true, "grace") => LicenseState::GracePeriod,
        (true, "shut_off" | "refused") => LicenseState::Locked,
        (true, _) => LicenseState::Locked,
    };
    let entitlement = if view.license_type.as_deref() == Some("evaluation") {
        match (
            view.license_id.as_ref(),
            view.revision,
            parse_time(view.valid_from.as_deref()),
            parse_time(view.expires_at.as_deref()),
            parse_time(view.grace_until.as_deref()),
        ) {
            (
                Some(license_id),
                Some(revision),
                Some(starts_at),
                Some(expires_at),
                Some(grace_ends_at),
            ) => Some(LicenseEntitlement {
                license_id: license_id.clone(),
                edition: "licensed".into(),
                operator: "self-run".into(),
                offering: "self-run".into(),
                kind: "trial".into(),
                capacity_gb_per_day: view.capacity_gb_per_day,
                starts_at,
                expires_at,
                grace_ends_at,
                state: match view.state.as_str() {
                    "running" | "renewal_due" => "active",
                    "grace" => "grace",
                    "shut_off" => "expired",
                    _ => "revoked",
                }
                .into(),
                days_remaining: 0,
                revision,
            }),
            _ => None,
        }
    } else {
        None
    };
    LicenseStatus {
        state,
        valid: allowed,
        tier: view.license_type.clone(),
        locked_reason: view
            .refusal
            .clone()
            .or_else(|| (!view.valid).then(|| view.notice.clone()).flatten()),
        grace_ends_at: parse_time(view.grace_until.as_deref()),
        // The legacy middleware locks at `expires_at`; for C05 that boundary
        // is the hard grace limit, not the beginning of production grace.
        expires_at: parse_time(view.grace_until.as_deref()),
        last_checked_at: parse_time(view.observed_at.as_deref()),
        last_heartbeat_at: None,
        offline: true,
        entitlement,
    }
}

fn api_allowed(view: &LicenseStateView) -> bool {
    view.valid
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
    if !state.config.is_license_enabled() {
        let snapshot = state.offline_license_snapshot.read().await.clone();
        return Ok(Json(LicenseStatusResponse::cached_offline(
            &snapshot,
            state.config.airgap,
        )));
    }

    let now = chrono::Utc::now();
    let status = state
        .license_status
        .read()
        .await
        .effective(now);
    // NAN-5194: the check-in loop runs in nanosiem-jobs, so the rejection is
    // read from the shared cached row. A read failure only hides the banner.
    let token_rejected = nanosiem_core::license::LicenseRepository::new(state.pool.clone())
        .get_token_rejected_notice()
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "Licence token rejection unavailable");
            None
        })
        .map(TokenRejectedResponse::from);
    Ok(Json(LicenseStatusResponse {
        state: status.state.as_str().to_string(),
        valid: status.valid,
        tier: status.tier.clone(),
        locked_reason: status.locked_reason.clone(),
        grace_ends_at: status.grace_ends_at.map(|dt| dt.to_rfc3339()),
        expires_at: status.expires_at.map(|dt| dt.to_rfc3339()),
        enforcement_enabled: true,
        airgap: state.config.airgap,
        mode: "hosted".into(),
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
        entitlement: LicenseEntitlementResponse::from_status(&status, now),
        token_rejected,
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
    // Read the canonical v2 fields from the same signed artifact the stateful
    // authority admits. `import` repeats signature verification and owns the
    // binding/revision/clock transition; this first pass only makes the signed
    // commercial identity available to the shared TierSettings repository.
    let verified = verify_production(body)
        .map_err(|_| ApiError::BadRequest("Invalid or untrusted C05 licence file".into()))?;
    let entitlement = nanosiem_core::Entitlement {
        edition: nanosiem_core::EntitlementEdition::Licensed,
        operator: match verified.policy.operator {
            EntitlementOperator::SelfRun => nanosiem_core::EntitlementOperator::SelfRun,
            EntitlementOperator::Hosted => nanosiem_core::EntitlementOperator::Hosted,
        },
        capacity_gb_per_day: verified
            .policy
            .capacity
            .gb_per_day
            .map(|value| value as f64),
    };
    let view = state
        .sovereign_license
        .import(body)
        .await
        .map_err(entitlement_error)?;
    nanosiem_core::TierSettings::new(state.pool.clone())
        .set_entitlement(entitlement)
        .await?;
    *state.license_status.write().await = cache_status(&view);
    *state.offline_license_snapshot.write().await = OfflineLicenseSnapshot::C05(view.clone());
    Ok(Json(LicenseStatusResponse::offline(
        &view,
        state.config.airgap,
    )))
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
    Ok(Json(LicenseStatusResponse::offline(
        &view,
        state.config.airgap,
    )))
}

fn ensure_offline_admin(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::SETTINGS_SYSTEM)?;
    // Since v2, every enterprise install without an online licence tuple is
    // admitted only by C05; requiring AIRGAP_MODE here left self-run installs
    // locked with no way to install the licence that unlocks them (NAN-5086).
    if !state.config.uses_c05_authority() {
        return Err(ApiError::Conflict(
            "C05 files are accepted only by a deployment without an online licence".into(),
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

/// NAN-5114: whether a newer nano release is available, from the last
/// successful online licence check-in. Public facts only (version, links,
/// security flag). Offline / air-gapped installs make no check-in, so they
/// always answer `update_available: false` with no latest version.
#[derive(Debug, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct UpdateStatusResponse {
    /// The version this API runs.
    pub current_version: String,
    pub update_available: bool,
    pub latest_version: Option<String>,
    /// The newest release includes security fixes; upgrading is recommended.
    pub security_release: bool,
    pub release_notes_url: Option<String>,
    pub upgrade_url: Option<String>,
}

impl UpdateStatusResponse {
    pub fn from_notice(
        current_version: &str,
        notice: Option<nanosiem_core::license::ReleaseNotice>,
    ) -> Self {
        let available = notice
            .as_ref()
            .is_some_and(|notice| notice.is_newer_than(current_version));
        match notice.filter(|_| available) {
            Some(notice) => Self {
                current_version: current_version.into(),
                update_available: true,
                latest_version: Some(notice.latest_version),
                security_release: notice.security_release,
                release_notes_url: Some(notice.release_notes_url),
                upgrade_url: Some(notice.upgrade_url),
            },
            None => Self {
                current_version: current_version.into(),
                update_available: false,
                latest_version: None,
                security_release: false,
                release_notes_url: None,
                upgrade_url: None,
            },
        }
    }
}

/// Update availability for the admin "Update available" banner (NAN-5114).
/// Exempt from the licence guard: a locked deployment must still learn that
/// an upgrade exists.
#[utoipa::path(
    get,
    path = "/api/license/update",
    tag = "license",
    responses(
        (status = 200, description = "Update availability", body = UpdateStatusResponse),
        (status = 403, description = "Requires settings:system", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_update_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<UpdateStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let notice = if state.config.is_license_enabled() {
        nanosiem_core::license::LicenseRepository::new(state.pool.clone())
            .get_release_notice()
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "Release notice unavailable");
                None
            })
    } else {
        None
    };
    Ok(Json(UpdateStatusResponse::from_notice(
        env!("CARGO_PKG_VERSION"),
        notice,
    )))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_license_status,
        get_update_status,
        import_license,
        renew_license,
        create_clock_recovery_request,
        apply_clock_recovery
    ),
    components(schemas(
        LicenseStatusResponse,
        LicenseEntitlementResponse,
        TokenRejectedResponse,
        UpdateStatusResponse,
        ClockRecoveryRequest,
        ErrorResponse
    ))
)]
pub struct LicenseApiDoc;

#[cfg(test)]
#[path = "license_tests.rs"]
mod tests;
