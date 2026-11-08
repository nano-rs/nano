// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential key ring operator surface (NAN-4933).
//!
//! - `GET  /api/system/credential-keys`              active key, ring keys, per-key counts
//! - `POST /api/system/credential-keys/rewrap`       run a re-wrap pass now
//! - `POST /api/system/credential-keys/{id}/retire`  retire an unreferenced old key
//!
//! All three require `settings:system`. Responses carry key ids and one-way
//! fingerprints only, never key material. The jobs leader also runs the
//! re-wrap on a schedule; the `nanosiem-jobs credential-keys ...` CLI exposes
//! the same operations without the API.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::permissions;
use nanosiem_core::crypto::rotation::{
    self, CredentialKeyRepository, KeyUsageReport, KnownKey, RewrapOutcome, RewrapRun,
    RingMember, RotationError, TargetUsage,
};
use nanosiem_core::crypto::{KeyRole, RingKeyInfo};
use serde::Serialize;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

pub const CREDENTIAL_KEYS_REWRAPPED: &str = "credential_keys_rewrapped";
pub const CREDENTIAL_KEY_RETIRED: &str = "credential_key_retired";
pub const CREDENTIAL_KEY_RETIRE_REFUSED: &str = "credential_key_retire_refused";

/// Credential key ring status.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CredentialKeyStatus {
    /// Key id every new write uses (this API process).
    pub active_key_id: String,
    /// This process's ring.
    pub ring: Vec<RingKeyInfo>,
    /// Operator-facing key policy warnings (e.g. the active key is a pre-ring
    /// key shorter than 32 bytes). Empty when the ring meets policy.
    pub warnings: Vec<String>,
    /// Whether the credential write fence refuses secret writes from sessions
    /// that declare no key (flips on at the first retirement).
    pub write_fence_enforced: bool,
    /// Every key any process has loaded, with retire state.
    pub known_keys: Vec<KnownKey>,
    /// Live scan: stored values per key id.
    pub usage: KeyUsageReport,
    /// Processes holding a ring (api / jobs nodes).
    pub members: Vec<RingMember>,
    /// Most recent re-wrap passes.
    pub recent_runs: Vec<RewrapRun>,
}

/// Result of a manual re-wrap.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CredentialKeyRewrapResponse {
    pub outcome: RewrapOutcome,
    pub usage: KeyUsageReport,
}

/// Result of a retirement.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CredentialKeyRetireResponse {
    pub key_id: String,
    pub retired: bool,
    /// The confirming scan.
    pub usage: KeyUsageReport,
}

/// `key <id> (<role>): <warning>` for every ring key carrying a warning.
pub fn ring_warnings(ring: &[RingKeyInfo]) -> Vec<String> {
    ring.iter()
        .filter_map(|k| {
            let role = match k.role {
                KeyRole::Active => "active",
                KeyRole::DecryptOnly => "decrypt-only",
                KeyRole::V2Only => "v2-only",
            };
            k.warning.as_ref().map(|w| format!("key {} ({role}): {w}", k.id))
        })
        .collect()
}

fn rotation_error(error: RotationError) -> ApiError {
    match error {
        RotationError::UnknownKey(_) => ApiError::NotFound(error.to_string()),
        RotationError::KeyActive { .. }
        | RotationError::StillReferenced { .. }
        | RotationError::Unprovable { .. }
        | RotationError::FingerprintMismatch(_)
        | RotationError::ActiveKeyRetired(_)
        | RotationError::ActiveKeyNotRegistered(_) => ApiError::Conflict(error.to_string()),
        RotationError::Database(e) => ApiError::DatabaseError(format!("credential keys: {e}")),
        RotationError::Crypto(_) => ApiError::InternalError("credential key operation failed".into()),
    }
}

/// Credential key ring status
///
/// The active key id, every key of this process's ring with its role
/// (active / decrypt-only / v2-only) and fingerprint, the retire state of
/// every key ever loaded, a live count of stored secrets per key (the
/// rotation backlog is `usage.pending_rewrap`), ring-holding processes and
/// recent re-wrap runs. Requires `settings:system`.
#[utoipa::path(
    get,
    path = "/api/system/credential-keys",
    tag = "system",
    responses(
        (status = 200, description = "Credential key ring status", body = CredentialKeyStatus),
        (status = 403, description = "Missing settings:system", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_credential_keys(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<CredentialKeyStatus>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let cipher = state.encryption_service.as_ref();
    let repo = CredentialKeyRepository::new(state.pool.clone());
    let usage = rotation::scan(&state.pool, cipher)
        .await
        .map_err(rotation_error)?;
    let ring = cipher.ring_keys();
    Ok(Json(CredentialKeyStatus {
        active_key_id: cipher.active_key_id().to_owned(),
        warnings: ring_warnings(&ring),
        write_fence_enforced: repo.fence_enforced().await.map_err(rotation_error)?,
        ring,
        known_keys: repo.known_keys().await.map_err(rotation_error)?,
        usage,
        members: repo.members().await.map_err(rotation_error)?,
        recent_runs: repo.recent_runs(10).await.map_err(rotation_error)?,
    }))
}

/// Re-wrap stored secrets onto the active key now
///
/// Re-encrypts every stored secret that is not on the active key (the jobs
/// leader also does this on a schedule), then records a confirming scan.
/// Safe to repeat and to run beside normal writes. Requires `settings:system`.
#[utoipa::path(
    post,
    path = "/api/system/credential-keys/rewrap",
    tag = "system",
    responses(
        (status = 200, description = "Re-wrap pass result", body = CredentialKeyRewrapResponse),
        (status = 403, description = "Missing settings:system", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn rewrap_credential_keys(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<CredentialKeyRewrapResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let repo = CredentialKeyRepository::new(state.pool.clone());
    let (outcome, usage) = rotation::run_pass(
        &repo,
        state.encryption_service.as_ref(),
        "manual",
        &state.node_id,
    )
    .await
    .map_err(rotation_error)?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, CREDENTIAL_KEYS_REWRAPPED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("credential_keys", None, Some(outcome.active_key_id.clone()))
            .details(serde_json::json!({
                "active_key_id": outcome.active_key_id,
                "rewrapped": outcome.rewrapped,
                "conflicts": outcome.conflicts,
                "from_key": outcome.from_key,
                "pending_rewrap": usage.pending_rewrap,
                "undecryptable": usage.undecryptable,
            }))
            .client_context(&client)
            .build(),
    );
    Ok(Json(CredentialKeyRewrapResponse { outcome, usage }))
}

/// Retire an old credential key
///
/// Refused with `409` while the key is active in any live api/jobs process,
/// while any stored secret is still encrypted under it, or when stored
/// secrets that no ring key opens make that impossible to prove. On success
/// the key is marked retired; remove it from `NANOSIEM_ENCRYPTION_KEY`
/// afterwards. Requires `settings:system`.
#[utoipa::path(
    post,
    path = "/api/system/credential-keys/{key_id}/retire",
    tag = "system",
    params(("key_id" = String, Path, description = "Ring key id")),
    responses(
        (status = 200, description = "Key retired", body = CredentialKeyRetireResponse),
        (status = 403, description = "Missing settings:system", body = ErrorResponse),
        (status = 404, description = "Unknown key id", body = ErrorResponse),
        (status = 409, description = "Key is active or still referenced", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn retire_credential_key(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(key_id): Path<String>,
) -> Result<Json<CredentialKeyRetireResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let repo = CredentialKeyRepository::new(state.pool.clone());
    let result = repo
        .retire(state.encryption_service.as_ref(), &key_id, Some(auth.user_id()))
        .await;
    let (action, details) = match &result {
        Ok(usage) => (
            CREDENTIAL_KEY_RETIRED,
            serde_json::json!({ "key_id": key_id, "scanned": usage.scanned }),
        ),
        Err(error) => (
            CREDENTIAL_KEY_RETIRE_REFUSED,
            serde_json::json!({ "key_id": key_id, "reason": error.to_string() }),
        ),
    };
    if !matches!(result, Err(RotationError::Database(_))) {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Settings, action)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("credential_keys", None, Some(key_id.clone()))
                .details(details)
                .client_context(&client)
                .build(),
        );
    }
    let usage = result.map_err(rotation_error)?;
    Ok(Json(CredentialKeyRetireResponse {
        key_id,
        retired: true,
        usage,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_credential_keys, rewrap_credential_keys, retire_credential_key),
    components(schemas(
        CredentialKeyStatus,
        CredentialKeyRewrapResponse,
        CredentialKeyRetireResponse,
        RingKeyInfo,
        KeyRole,
        KnownKey,
        KeyUsageReport,
        TargetUsage,
        RewrapOutcome,
        RingMember,
        RewrapRun
    ))
)]
pub struct CredentialKeysApiDoc;
