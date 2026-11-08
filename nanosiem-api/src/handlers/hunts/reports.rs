// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit receipts for desktop-generated threat-hunt reports (NAN-2306).
//!
//! PDF bytes and branding stay on the analyst's device. These endpoints record
//! only bounded hashes and presentation metadata after a local action succeeds;
//! they do not turn a report into a server-side artifact or grant PIVT a write
//! path into hunts or cases.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, HUNT_REPORT_BRANDING_UPDATED, HUNT_REPORT_EXPORTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::ClientContext;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::service;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

#[derive(Debug, Deserialize, ToSchema)]
pub struct HuntReportExportRequest {
    pub audience: String,
    pub classification: String,
    pub lead_count: u32,
    pub pdf_sha256: String,
    pub snapshot_sha256: String,
    #[serde(default)]
    pub logo_sha256: Option<String>,
    #[serde(default)]
    pub analyst_attested: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct HuntReportBrandingRequest {
    pub company_name_set: bool,
    pub logo_present: bool,
    #[serde(default)]
    pub logo_sha256: Option<String>,
    #[serde(default)]
    pub logo_width: Option<u32>,
    #[serde(default)]
    pub logo_height: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HuntReportAuditResponse {
    pub recorded: bool,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_optional_sha(value: Option<&str>) -> Result<(), ApiError> {
    if value.is_some_and(|hash| !valid_sha256(hash)) {
        return Err(ApiError::BadRequest(
            "logo_sha256 must be a SHA-256 hex digest".into(),
        ));
    }
    Ok(())
}

/// Record a successful local threat-hunt PDF export
#[utoipa::path(
    post,
    path = "/api/hunts/{id}/report-exports",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    request_body = HuntReportExportRequest,
    responses(
        (status = 200, description = "Export audit event recorded", body = HuntReportAuditResponse),
        (status = 400, description = "Invalid export metadata"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Hunt not found"),
    ),
    security(("api_key" = []))
)]
pub async fn record_hunt_report_export(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<HuntReportExportRequest>,
) -> Result<Json<HuntReportAuditResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    if !matches!(req.audience.as_str(), "executive" | "soc" | "technical") {
        return Err(ApiError::BadRequest("invalid hunt report audience".into()));
    }
    if req.classification.trim().is_empty() || req.classification.chars().count() > 120 {
        return Err(ApiError::BadRequest(
            "classification must be between 1 and 120 characters".into(),
        ));
    }
    if req.lead_count > 25 {
        return Err(ApiError::BadRequest("lead_count may not exceed 25".into()));
    }
    if !valid_sha256(&req.pdf_sha256) || !valid_sha256(&req.snapshot_sha256) {
        return Err(ApiError::BadRequest(
            "pdf_sha256 and snapshot_sha256 must be SHA-256 hex digests".into(),
        ));
    }
    validate_optional_sha(req.logo_sha256.as_deref())?;

    let hunt = service(&state).get_hunt(*id).await?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_REPORT_EXPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt", Some(*id), Some(hunt.title))
            .client_context(&client)
            .details(serde_json::json!({
                "audience": req.audience,
                "classification": req.classification,
                "lead_count": req.lead_count,
                "pdf_sha256": req.pdf_sha256,
                "snapshot_sha256": req.snapshot_sha256,
                "logo_sha256": req.logo_sha256,
                "analyst_attested": req.analyst_attested,
            }))
            .build(),
    );
    Ok(Json(HuntReportAuditResponse { recorded: true }))
}

/// Record a local threat-hunt report branding change
#[utoipa::path(
    post,
    path = "/api/hunts/report-branding-events",
    tag = "hunts",
    request_body = HuntReportBrandingRequest,
    responses(
        (status = 200, description = "Branding audit event recorded", body = HuntReportAuditResponse),
        (status = 400, description = "Invalid branding metadata"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn record_hunt_report_branding(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<HuntReportBrandingRequest>,
) -> Result<Json<HuntReportAuditResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    validate_optional_sha(req.logo_sha256.as_deref())?;
    if req.logo_present != req.logo_sha256.is_some() {
        return Err(ApiError::BadRequest(
            "logo_present must agree with logo_sha256".into(),
        ));
    }
    if req.logo_present != (req.logo_width.is_some() && req.logo_height.is_some()) {
        return Err(ApiError::BadRequest(
            "logo dimensions must be present exactly when a logo is present".into(),
        ));
    }
    if req
        .logo_width
        .is_some_and(|value| value == 0 || value > 1200)
        || req
            .logo_height
            .is_some_and(|value| value == 0 || value > 400)
    {
        return Err(ApiError::BadRequest(
            "logo dimensions are outside the sanitized bounds".into(),
        ));
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_REPORT_BRANDING_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_report_branding", None, None)
            .client_context(&client)
            .details(serde_json::json!({
                "company_name_set": req.company_name_set,
                "logo_present": req.logo_present,
                "logo_sha256": req.logo_sha256,
                "logo_width": req.logo_width,
                "logo_height": req.logo_height,
            }))
            .build(),
    );
    Ok(Json(HuntReportAuditResponse { recorded: true }))
}

#[cfg(test)]
mod tests {
    use super::valid_sha256;

    #[test]
    fn sha256_metadata_is_exactly_hex_64() {
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
        assert!(!valid_sha256(&format!("{}g", "a".repeat(63))));
    }
}
