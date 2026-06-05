// SPDX-License-Identifier: AGPL-3.0-or-later

//! License status handler
//!
//! Returns the cached license status so the frontend can display
//! appropriate banners (grace period warning or full lockout page).

use axum::{extract::State, Json};
use serde::Serialize;
use utoipa::OpenApi;

use crate::state::AppState;

/// License status response returned to the frontend
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LicenseStatusResponse {
    /// Current license state: "active", "grace_period", or "locked"
    pub state: String,
    /// Whether the license is valid
    pub valid: bool,
    /// Organization tier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Reason for lockout (if locked)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_reason: Option<String>,
    /// When the grace period ends (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_ends_at: Option<String>,
    /// When the license expires (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Whether license enforcement is configured
    pub enforcement_enabled: bool,
    /// Whether this is an air-gapped deployment (AIRGAP_MODE on). Air-gap
    /// installs enforce a signed *offline* license and have no phone-home path,
    /// so `enforcement_enabled` (which tracks LICENSE_URL) is false even though
    /// enforcement is active. The frontend treats `airgap || enforcement_enabled`
    /// as "enforced" and routes a locked air-gap install to the offline-license
    /// import surface instead of app.nano.rs (NAN-1222).
    pub airgap: bool,
}

/// Get the current license status
#[utoipa::path(
    get,
    path = "/api/license",
    tag = "license",
    responses(
        (status = 200, description = "License status", body = LicenseStatusResponse)
    ),
    security(("api_key" = []))
)]
pub async fn get_license_status(State(state): State<AppState>) -> Json<LicenseStatusResponse> {
    // Apply read-time `expires_at` enforcement so an expired (incl. offline
    // air-gap) license reports Locked locally with no network (NAN-1206 / WS4).
    let status = state
        .license_status
        .read()
        .await
        .effective(chrono::Utc::now());
    let enforcement_enabled = state.config.is_license_enabled();

    Json(LicenseStatusResponse {
        state: status.state.as_str().to_string(),
        valid: status.valid,
        tier: status.tier.clone(),
        locked_reason: status.locked_reason.clone(),
        grace_ends_at: status.grace_ends_at.map(|dt| dt.to_rfc3339()),
        expires_at: status.expires_at.map(|dt| dt.to_rfc3339()),
        enforcement_enabled,
        airgap: state.config.airgap,
    })
}

#[derive(OpenApi)]
#[openapi(paths(get_license_status), components(schemas(LicenseStatusResponse)))]
pub struct LicenseApiDoc;
