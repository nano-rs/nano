// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline (air-gapped) license import — WS4 / NAN-1206 (enterprise only).
//!
//! Air-gapped deployments cannot reach `api.nano.rs` for the periodic license
//! check (`nanosiem_core::license::LicenseChecker`). Instead an operator carries
//! a **signed license bundle** across the gap and uploads it here. We verify the
//! bundle's Ed25519 signature against the embedded
//! [`nanosiem_core::airgap::AIRGAP_BUNDLE_PUBLIC_KEY`], confirm it is a
//! `BundleType::License`, parse the offline license payload, reject anything
//! expired/tampered/wrong-key, then persist an **offline** license status so
//! `GET /api/license` is satisfied locally with no network call.
//!
//! ## Why offline mode can't go stale
//!
//! The staleness auto-lock lives in `LicenseChecker::check_staleness`, which is
//! only ever constructed in `nanosiem-jobs` *when `is_license_enabled()` is true*
//! — i.e. when `LICENSE_URL` / `LICENSE_TOKEN` / `NANO_DEPLOYMENT_ID` are all set.
//! An air-gapped install sets none of those, so the checker (and its 14-day
//! staleness lock) never starts and never overwrites the row we write here. We
//! additionally stamp `license_status.offline = TRUE` so any future check-in
//! path can recognise an operator-imported license and refuse to age it out for
//! lack of a network heartbeat. (`last_heartbeat_at` / `update_heartbeat_at` are
//! dead fossils — we do not touch them.)

// Enterprise-only: depends on `nanosiem_core::license` and `AppState.license_status`,
// both of which exist only under the `enterprise` feature.
#![cfg(feature = "enterprise")]

use std::io::{Cursor, Read};

use axum::{extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use nanosiem_core::airgap::{verify_bundle, BundleError, BundleType};
use nanosiem_core::auth::permissions;
use nanosiem_core::license::{LicenseState, LicenseStatus};

use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Logical name of the single payload file inside a `license` bundle.
const LICENSE_PAYLOAD_PATH: &str = "license.json";

/// Upper bound on the license payload we will buffer (bundles are tiny; this
/// guards against a malformed manifest declaring an enormous `license.json`).
const MAX_LICENSE_PAYLOAD_BYTES: u64 = 256 * 1024;

/// The offline license token carried inside the bundle's `license.json` payload.
///
/// This is the air-gap analogue of nano-main's `GET /api/license/status`
/// response. It is signed (as part of the bundle manifest's per-file checksum,
/// which is itself covered by the Ed25519 signature), so its contents are
/// trustworthy once `verify_bundle` succeeds.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct OfflineLicensePayload {
    /// Subscription tier (e.g. "starter", "business", "enterprise").
    pub tier: String,
    /// When the license expires (RFC3339). The import is rejected if this is
    /// in the past.
    pub expires_at: String,
    /// Opaque license/customer identifier, surfaced for audit/debugging.
    #[serde(default)]
    pub license_id: Option<String>,
    /// Customer/organization name, surfaced for display.
    #[serde(default)]
    pub customer: Option<String>,
}

/// Result of importing an offline license bundle.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportLicenseResponse {
    /// Always "offline" — this install is now satisfied locally with no check-in.
    pub mode: String,
    /// Resulting license state ("active").
    pub state: String,
    pub valid: bool,
    pub tier: String,
    /// License expiry (RFC3339).
    pub expires_at: String,
    /// Bundle content version from the manifest (e.g. issue date).
    pub content_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
}

/// Import a signed offline license bundle (air-gapped deployments).
///
/// POST /api/airgap/license/import
///
/// Accepts `multipart/form-data` with a single `file` field containing the
/// `.tar.gz` license bundle produced by the offline signing tool. The bundle's
/// signature is verified against the embedded public key; a wrong-key, tampered,
/// expired, or non-`license` bundle is rejected. On success the install flips
/// into **offline license mode** and `GET /api/license` reports `active` with no
/// outbound network call.
///
/// Requires: settings:system permission.
#[utoipa::path(
    post,
    path = "/api/airgap/license/import",
    tag = "airgap",
    request_body(content = inline(LicenseBundleUpload), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "License imported; install is now in offline mode", body = ImportLicenseResponse),
        (status = 400, description = "Malformed, tampered, wrong-key, wrong-type, or expired bundle"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn import_offline_license(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<ImportLicenseResponse>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    // --- 1. Read the uploaded bundle into memory (license bundles are tiny). ---
    let mut bundle_bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            bundle_bytes = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("Failed to read upload: {e}")))?
                    .to_vec(),
            );
        }
    }
    let bundle_bytes = bundle_bytes
        .ok_or_else(|| ApiError::BadRequest("No 'file' field in multipart upload".to_string()))?;

    // --- 2. Verify + parse on a blocking thread (sync gzip/tar/Ed25519 I/O). ---
    let (payload, content_version) =
        tokio::task::spawn_blocking(move || verify_and_extract(bundle_bytes))
            .await
            .map_err(|e| ApiError::InternalError(format!("license verify task failed: {e}")))??;

    // --- 3. Reject expired licenses. ---
    let expires_at = DateTime::parse_from_rfc3339(&payload.expires_at)
        .map_err(|e| {
            ApiError::BadRequest(format!("Invalid expires_at in license payload: {e}"))
        })?
        .with_timezone(&Utc);
    let now = Utc::now();
    if expires_at <= now {
        return Err(ApiError::BadRequest(format!(
            "License expired at {} (now {})",
            expires_at.to_rfc3339(),
            now.to_rfc3339()
        )));
    }

    // --- 4. Persist offline license status (PG) + update the live RwLock. ---
    let status = LicenseStatus {
        state: LicenseState::Active,
        valid: true,
        tier: Some(payload.tier.clone()),
        locked_reason: None,
        grace_ends_at: None,
        expires_at: Some(expires_at),
        // Stamp "now" so any code that inspects freshness sees a current check;
        // offline = TRUE is what actually exempts it from staleness.
        last_checked_at: Some(now),
        last_heartbeat_at: None, // dead fossil — never set.
        // This is an operator-imported air-gap license: mark it offline so the
        // (mixed-deployment) staleness aging in LicenseChecker exempts it, while
        // read-time expiry on `expires_at` still applies (NAN-1206 / WS4).
        offline: true,
    };

    persist_offline_status(&state.pool, &status)
        .await
        .map_err(|e| ApiError::DatabaseError(format!("Failed to persist license: {e}")))?;

    // Reflect immediately in the in-memory status read by GET /api/license.
    {
        let mut live = state.license_status.write().await;
        *live = status;
    }

    tracing::info!(
        tier = %payload.tier,
        expires_at = %expires_at.to_rfc3339(),
        content_version = %content_version,
        license_id = ?payload.license_id,
        "Offline license imported — install now in offline license mode"
    );

    Ok(Json(ImportLicenseResponse {
        mode: "offline".to_string(),
        state: LicenseState::Active.as_str().to_string(),
        valid: true,
        tier: payload.tier,
        expires_at: expires_at.to_rfc3339(),
        content_version,
        license_id: payload.license_id,
        customer: payload.customer,
    }))
}

/// Verify the bundle signature, enforce `bundle_type == License`, stream the
/// single `license.json` payload to EOF (which enforces its SHA-256), and parse
/// it. Runs on a blocking thread. Returns the payload + the manifest's
/// `content_version`.
fn verify_and_extract(bytes: Vec<u8>) -> Result<(OfflineLicensePayload, String), ApiError> {
    // Signature verification against the embedded public key. A wrong-key or
    // tampered manifest surfaces here as BadSignature / InvalidKey.
    let mut verified = verify_bundle(Cursor::new(bytes)).map_err(map_bundle_error)?;

    if verified.bundle_type() != BundleType::License {
        return Err(ApiError::BadRequest(format!(
            "Wrong bundle type: expected 'license', got '{}'",
            bundle_type_str(verified.bundle_type())
        )));
    }

    let content_version = verified.manifest().content_version.clone();

    // The license bundle carries exactly one payload: license.json.
    let mut payload_reader = verified
        .next_payload()
        .map_err(map_bundle_error)?
        .ok_or_else(|| {
            ApiError::BadRequest("License bundle has no payload entries".to_string())
        })?;

    if payload_reader.path() != LICENSE_PAYLOAD_PATH {
        return Err(ApiError::BadRequest(format!(
            "Unexpected license payload '{}' (expected '{}')",
            payload_reader.path(),
            LICENSE_PAYLOAD_PATH
        )));
    }
    if payload_reader.entry().bytes > MAX_LICENSE_PAYLOAD_BYTES {
        return Err(ApiError::BadRequest(format!(
            "License payload too large: {} bytes (max {})",
            payload_reader.entry().bytes,
            MAX_LICENSE_PAYLOAD_BYTES
        )));
    }

    // Read to EOF: this is what triggers the per-file SHA-256 + byte-count
    // check inside VerifiedPayload. A checksum mismatch surfaces as an
    // io::Error whose inner error downcasts to BundleError::ChecksumMismatch.
    let mut buf = Vec::with_capacity(payload_reader.entry().bytes as usize);
    payload_reader
        .read_to_end(&mut buf)
        .map_err(map_payload_io_error)?;
    // Dropping `payload_reader` here releases the &mut borrow of `verified`.
    drop(payload_reader);

    // Confirm there are no extra/undeclared trailing entries (also enforces the
    // declared payload set was exactly satisfied).
    if verified.next_payload().map_err(map_bundle_error)?.is_some() {
        return Err(ApiError::BadRequest(
            "License bundle contains unexpected extra payloads".to_string(),
        ));
    }

    let payload: OfflineLicensePayload = serde_json::from_slice(&buf)
        .map_err(|e| ApiError::BadRequest(format!("Invalid license.json payload: {e}")))?;

    Ok((payload, content_version))
}

/// Persist the offline license status to the `license_status` singleton row,
/// flagging `offline = TRUE`. We write directly (rather than via
/// `LicenseRepository::update_status`, which neither carries the `offline`
/// column nor is editable from this workstream) so the offline marker survives.
async fn persist_offline_status(
    pool: &sqlx::PgPool,
    status: &LicenseStatus,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO license_status \
            (id, status, valid, tier, locked_reason, grace_ends_at, expires_at, last_checked_at, offline, updated_at) \
         VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, TRUE, NOW()) \
         ON CONFLICT (id) DO UPDATE SET \
            status = EXCLUDED.status, \
            valid = EXCLUDED.valid, \
            tier = EXCLUDED.tier, \
            locked_reason = EXCLUDED.locked_reason, \
            grace_ends_at = EXCLUDED.grace_ends_at, \
            expires_at = EXCLUDED.expires_at, \
            last_checked_at = EXCLUDED.last_checked_at, \
            offline = TRUE, \
            updated_at = NOW()",
    )
    .bind(status.state.as_str())
    .bind(status.valid)
    .bind(&status.tier)
    .bind(&status.locked_reason)
    .bind(status.grace_ends_at)
    .bind(status.expires_at)
    .bind(status.last_checked_at)
    .execute(pool)
    .await?;
    Ok(())
}

fn bundle_type_str(t: BundleType) -> &'static str {
    match t {
        BundleType::Parsers => "parsers",
        BundleType::IpEnrichment => "ip_enrichment",
        BundleType::Ioc => "ioc",
        BundleType::License => "license",
        BundleType::Rules => "rules",
        BundleType::Playbooks => "playbooks",
    }
}

/// Map a verification-time [`BundleError`] to a client-facing [`ApiError`].
/// All trust failures (bad signature, wrong key, schema mismatch, checksum
/// mismatch) are 400s — the operator uploaded a bad artifact.
fn map_bundle_error(e: BundleError) -> ApiError {
    match e {
        BundleError::Io(msg) => {
            ApiError::BadRequest(format!("Could not read license bundle: {msg}"))
        }
        other => ApiError::BadRequest(format!("Invalid license bundle: {other}")),
    }
}

/// Map an `io::Error` raised while draining a payload back to a clean
/// [`ApiError`]. The streaming checksum failure arrives wrapped in an
/// `io::Error`; unwrap it to a `BundleError` when possible for a precise message.
fn map_payload_io_error(e: std::io::Error) -> ApiError {
    match e.into_inner().and_then(|b| b.downcast::<BundleError>().ok()) {
        Some(be) => map_bundle_error(*be),
        None => ApiError::BadRequest("Truncated or unreadable license payload".to_string()),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(import_offline_license),
    components(schemas(ImportLicenseResponse, OfflineLicensePayload, LicenseBundleUpload))
)]
pub struct AirgapLicenseApiDoc;

/// Multipart upload shape for OpenAPI (the `file` field carries the `.tar.gz`).
#[derive(ToSchema)]
#[allow(dead_code)]
pub struct LicenseBundleUpload {
    /// The signed `.tar.gz` license bundle.
    #[schema(value_type = String, format = Binary)]
    pub file: Vec<u8>,
}
