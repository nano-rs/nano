// SPDX-License-Identifier: AGPL-3.0-or-later

//! Internal Vector config generation delivery (NAN-1931).
//!
//! The Vector pod's config-consumer sidecar polls these endpoints to pull the
//! current published generation (manifest + files), stage it locally, and
//! reload Vector in place — replacing the ConfigMap-sync + pod-restart path.
//!
//! Trust model: in-cluster shared-secret bearer auth with a credential of its
//! own, `NANO_VECTOR_CONFIG_DELIVERY_TOKEN`, never handed to senders (security
//! review 2026-11-08, NAN-5042). It used to be `VECTOR_AUTH_TOKEN`, the
//! forwarder install token, so any forwarder could download rendered configs.
//! For v2.0.x the install token is still accepted beside it (and alone where
//! the new token is not provisioned yet), with a boot warning, a SIEM health
//! finding and a per-caller warning carrying the caller's IP, so a role-split
//! ingest host upgraded after its app host keeps receiving config; v2.1 (or
//! `NANO_VECTOR_CONFIG_DELIVERY_STRICT=true`) removes that fallback.
//! `NANO_VECTOR_CONFIG_DELIVERY=off` (single-host stacks, which deliver config
//! on a shared volume) or no credential at all disables the endpoints (404),
//! fail closed. Resolution lives in `nanosiem_core::deployment_posture`.
//! These routes are exempted from user-session auth in
//! `middleware::auth::is_public_endpoint` because the caller is a sidecar,
//! not a user; THIS module's bearer check is the only gate, so it must stay
//! mandatory. Every nginx edge also 404s `/api/internal/`.
//!
//! Path handling is delegated to `nanosiem_core::parsers::vector_config_delivery`,
//! which validates every relative path with the publisher's own write-time
//! rules and canonicalize-confines reads to the publications root.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use nanosiem_core::parsers::vector_config_delivery::{self, VectorConfigDeliveryError};

use crate::state::AppState;
use axum::{extract::ConnectInfo, Extension};
use nanosiem_core::deployment_posture::{self, VectorConfigDeliveryCredential as DeliveryCredential};
use std::net::SocketAddr;

/// Header carrying the generation number a manifest response describes.
pub const GENERATION_HEADER: &str = "x-nano-generation";

/// Constant-time byte comparison. Length mismatch returns early — the token
/// length is not a secret worth protecting, the token bytes are.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Authorize a delivery request against the configured token.
///
/// - Env token unset/empty → 404 (feature disabled; fail closed).
/// - Header missing / not `Bearer` / mismatch → 401.
pub(crate) fn authorize_delivery(
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

fn authorize(headers: &HeaderMap, peer: Option<&SocketAddr>) -> Result<(), StatusCode> {
    authorize_with(
        headers,
        peer,
        deployment_posture::vector_config_delivery_from_env(),
    )
}

/// The full delivery decision for one request against a resolved credential.
pub(crate) fn authorize_with(
    headers: &HeaderMap,
    peer: Option<&SocketAddr>,
    credential: DeliveryCredential,
) -> Result<(), StatusCode> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    match credential {
        DeliveryCredential::Disabled(_) => Err(StatusCode::NOT_FOUND),
        DeliveryCredential::Dedicated(token) => authorize_delivery(authorization, Some(&token)),
        DeliveryCredential::DedicatedOrInstallToken { dedicated, install } => {
            // v2.0.x: the dedicated token first; then the install token for a
            // consumer whose configuration predates the dedicated one (a
            // role-split ingest host with an older copied .env). Refusing it
            // would freeze parser publishes and ingest-token revocations on
            // that host. Removed in v2.1 / NANO_VECTOR_CONFIG_DELIVERY_STRICT.
            if authorize_delivery(authorization, Some(&dedicated)).is_ok() {
                return Ok(());
            }
            let result = authorize_delivery(authorization, Some(&install));
            if result.is_ok() {
                warn_legacy_install_token_caller(crate::utils::extract_client_ip(headers, peer));
            }
            result
        }
        DeliveryCredential::LegacyInstallToken(token) => {
            let result = authorize_delivery(authorization, Some(&token));
            if result.is_ok() {
                warn_legacy_install_token_caller(crate::utils::extract_client_ip(headers, peer));
            }
            result
        }
    }
}

/// How often the same caller is logged for using the install token.
const LEGACY_CALLER_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Log (at most hourly per caller) that a delivery consumer authenticated with
/// the deprecated install-token fallback, naming its IP so the operator can
/// find and update it before v2.1.
fn warn_legacy_install_token_caller(caller: Option<String>) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    static LAST_LOGGED: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let caller = caller.unwrap_or_else(|| "unknown".to_string());
    let now = Instant::now();
    let mut seen = LAST_LOGGED
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Bounded: a flood of distinct addresses cannot grow this without limit.
    if seen.len() > 1024 {
        seen.retain(|_, at| now.duration_since(*at) < LEGACY_CALLER_LOG_INTERVAL);
        if seen.len() > 1024 {
            // Still full of recent callers (forwarded-for values can vary):
            // start over rather than grow; the worst case is a repeated log line.
            seen.clear();
        }
    }
    let due = seen
        .get(&caller)
        .is_none_or(|at| now.duration_since(*at) >= LEGACY_CALLER_LOG_INTERVAL);
    if due {
        seen.insert(caller.clone(), now);
        tracing::warn!(
            caller_ip = %caller,
            "SECURITY: a Vector config consumer authenticated to /api/internal/vector-config with \
             the forwarder install token (VECTOR_AUTH_TOKEN). Give it \
             NANO_VECTOR_CONFIG_DELIVERY_TOKEN (and set the same value on nano-api); the \
             install-token fallback is removed in v2.1."
        );
    }
}

fn delivery_error_status(error: VectorConfigDeliveryError) -> StatusCode {
    match error {
        VectorConfigDeliveryError::Io(io) => {
            tracing::warn!(error = %io, "Vector config delivery read failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
        VectorConfigDeliveryError::InvalidGeneration | VectorConfigDeliveryError::InvalidPath => {
            StatusCode::BAD_REQUEST
        }
    }
}

/// Get the manifest of the newest ready generation on this API pod.
///
/// Returns the generation's `_manifest.json` verbatim plus an
/// `x-nano-generation` header. 404 while nothing is published yet.
#[utoipa::path(
    get,
    path = "/api/internal/vector-config/current/manifest",
    tag = "vector-config-delivery",
    responses(
        (status = 200, description = "Manifest of the newest ready generation (verbatim _manifest.json)", body = String, content_type = "application/json"),
        (status = 401, description = "Missing or invalid delivery bearer (NANO_VECTOR_CONFIG_DELIVERY_TOKEN)"),
        (status = 404, description = "No ready generation published, or delivery disabled (NANO_VECTOR_CONFIG_DELIVERY=off, or no delivery credential)"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_manifest(
    State(state): State<AppState>,
    // Optional so a router built without connect info (tests) still serves.
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    authorize(&headers, peer.as_ref().map(|Extension(ConnectInfo(addr))| addr))?;
    let root = state.vector_config_publisher.publications_root();
    let Some(generation) = vector_config_delivery::latest_ready_generation(&root)
        .await
        .map_err(delivery_error_status)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    let Some(manifest) = vector_config_delivery::read_manifest(&root, generation)
        .await
        .map_err(delivery_error_status)?
    else {
        // Ready marker raced a prune; the consumer just retries next poll.
        return Err(StatusCode::NOT_FOUND);
    };

    let mut response = (
        [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        manifest,
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&generation.to_string()) {
        response.headers_mut().insert(GENERATION_HEADER, value);
    }
    Ok(response)
}

/// Get one file of a ready generation by its manifest-relative path.
///
/// The path must be the exact canonical spelling the manifest uses; traversal
/// attempts are rejected with 400 before touching disk.
#[utoipa::path(
    get,
    path = "/api/internal/vector-config/generations/{generation}/files/{path}",
    tag = "vector-config-delivery",
    params(
        ("generation" = i64, Path, description = "Generation number (positive)"),
        ("path" = String, Path, description = "Manifest-relative file path, e.g. configs/http.toml"),
    ),
    responses(
        (status = 200, description = "File bytes", body = Vec<u8>, content_type = "application/octet-stream"),
        (status = 400, description = "Malformed generation or path (traversal attempts land here)"),
        (status = 401, description = "Missing or invalid delivery bearer (NANO_VECTOR_CONFIG_DELIVERY_TOKEN)"),
        (status = 404, description = "Unknown generation, generation not ready, file absent, or delivery disabled (NANO_VECTOR_CONFIG_DELIVERY=off, or no delivery credential)"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_generation_file(
    State(state): State<AppState>,
    Path((generation, path)): Path<(i64, String)>,
    // Optional so a router built without connect info (tests) still serves.
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    authorize(&headers, peer.as_ref().map(|Extension(ConnectInfo(addr))| addr))?;
    let root = state.vector_config_publisher.publications_root();
    let Some(bytes) = vector_config_delivery::read_generation_file(&root, generation, &path)
        .await
        .map_err(delivery_error_status)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )],
        bytes,
    )
        .into_response())
}

/// Get Vector's hashed ingest tokens file (NAN-4973).
///
/// The `http` token delivery (`NANO_INGEST_TOKENS_DELIVERY=http`, the Helm
/// chart): Vector runs as its own scaled Deployment with no volume shared with
/// nano-api, so each Vector pod's config consumer pulls this file and installs
/// it where `valid_tokens_file` reads it. Rendered from the database per
/// request, so every API replica returns the same bytes. The body holds
/// SHA-256 hashes only, never token values. 404 unless the delivery is `http`.
#[utoipa::path(
    get,
    path = "/api/internal/vector-config/ingest-tokens",
    tag = "vector-config-delivery",
    responses(
        (status = 200, description = "Vector valid_tokens_file content (hashes only)", body = String, content_type = "application/json"),
        (status = 401, description = "Missing or invalid delivery bearer (NANO_VECTOR_CONFIG_DELIVERY_TOKEN)"),
        (status = 404, description = "Token delivery is not `http`, or delivery disabled (NANO_VECTOR_CONFIG_DELIVERY=off, or no delivery credential)"),
        (status = 503, description = "The database could not be read; the consumer keeps its current file"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_ingest_tokens_file(
    State(state): State<AppState>,
    // Optional so a router built without connect info (tests) still serves.
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    authorize(&headers, peer.as_ref().map(|Extension(ConnectInfo(addr))| addr))?;
    match state.ingest_token_service.render_current().await {
        Ok(content) => Ok((
            [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            content,
        )
            .into_response()),
        Err(nanosiem_core::ingest_tokens::IngestTokenServiceError::DeliveryNotConfigured) => {
            Err(StatusCode::NOT_FOUND)
        }
        Err(error) => {
            tracing::warn!(%error, "ingest tokens file render failed");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_current_manifest, get_generation_file, get_ingest_tokens_file))]
pub struct VectorConfigDeliveryApiDoc;

#[cfg(test)]
mod tests;
