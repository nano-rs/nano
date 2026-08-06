// SPDX-License-Identifier: AGPL-3.0-or-later

//! Internal Vector config generation delivery (NAN-1931).
//!
//! The Vector pod's config-consumer sidecar polls these endpoints to pull the
//! current published generation (manifest + files), stage it locally, and
//! reload Vector in place — replacing the ConfigMap-sync + pod-restart path.
//!
//! Trust model: in-cluster shared-secret bearer auth using `VECTOR_AUTH_TOKEN`
//! — the same token the Vector ingest `auth_check` transform enforces and that
//! the platform already provisions to both the API and Vector pods
//! (nanosiem-secrets/vector_auth_token). No new trust material is invented.
//! When the env var is unset the endpoints are disabled (404), fail closed.
//! These routes are exempted from user-session auth in
//! `middleware::auth::is_public_endpoint` because the caller is a sidecar,
//! not a user; THIS module's bearer check is the only gate, so it must stay
//! mandatory.
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

/// Header carrying the generation number a manifest response describes.
pub const GENERATION_HEADER: &str = "x-nano-generation";

fn configured_token() -> Option<String> {
    std::env::var("VECTOR_AUTH_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

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

fn authorize(headers: &HeaderMap) -> Result<(), StatusCode> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    authorize_delivery(authorization, configured_token().as_deref())
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
        (status = 401, description = "Missing or invalid VECTOR_AUTH_TOKEN bearer"),
        (status = 404, description = "No ready generation published, or delivery disabled (no VECTOR_AUTH_TOKEN configured)"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    authorize(&headers)?;
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
        (status = 401, description = "Missing or invalid VECTOR_AUTH_TOKEN bearer"),
        (status = 404, description = "Unknown generation, generation not ready, file absent, or delivery disabled"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_generation_file(
    State(state): State<AppState>,
    Path((generation, path)): Path<(i64, String)>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    authorize(&headers)?;
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

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_current_manifest, get_generation_file))]
pub struct VectorConfigDeliveryApiDoc;

#[cfg(test)]
mod tests;
