// SPDX-License-Identifier: AGPL-3.0-or-later

//! Air-gapped parser bundle import (NAN-1204).
//!
//! The first export -> sync vertical slice of the air-gapped deployment
//! feature (NAN-1201, sync-only as of NAN-1226). A signed `.tar.gz` parser
//! bundle (built offline by the WS1 signer) is uploaded here; we verify its
//! Ed25519 signature + per-file SHA-256 checksums via
//! [`nanosiem_core::airgap::verify_bundle`], reject any bundle whose type is
//! not [`BundleType::Parsers`], then *sync* the parser YAML payloads into the
//! synthetic air-gap parser repository's catalog
//! ([`ParserRepositoryService::sync_parser_bundle`]) — the offline equivalent
//! of a GitHub repo sync. The parsers land as available-to-import; nothing is
//! imported or deployed here (no log source is created, Vector is never
//! touched). The operator imports + deploys selectively from the repositories
//! page afterward.
//!
//! Enterprise-only: air-gapped deployment is a paid capability.

#![cfg(feature = "enterprise")]

use std::io::Read;

use axum::{extract::Multipart, extract::State, Extension, Json};
use serde::Serialize;
use utoipa::ToSchema;

use nanosiem_core::airgap::{verify_bundle, BundleType};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, PARSER_REPO_SYNCED};
use nanosiem_core::auth::permissions;
use nanosiem_core::parser_repository::{BundleImportResult, ParserRepositoryService};

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Upper bound on the uploaded bundle size. Parser bundles are small (VRL +
/// YAML); the large air-gap payloads (IP enrichment MMDB) ride a different
/// streaming path. 64 MiB is generous headroom and prevents a single
/// multipart field from buffering an oversized archive into memory.
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Response for an air-gapped parser bundle sync.
#[derive(Debug, Serialize, ToSchema)]
pub struct AirgapParserImportResponse {
    /// Synthetic air-gap parser repository the bundle landed in.
    #[serde(with = "nanosiem_core::typeid::parser_repo")]
    #[schema(value_type = String)]
    pub repository_id: uuid::Uuid,
    /// Caller-defined content version from the bundle manifest.
    pub content_version: String,
    /// Number of parsers synced into the repository catalog (available to import).
    pub synced: usize,
}

/// Verify the uploaded bundle and extract its parser YAML payloads.
///
/// Fully synchronous so the non-`Send` verified-bundle reader (tar + gzip
/// state) is created and dropped without crossing an `.await` point — keeping
/// the calling handler future `Send`. Returns the manifest content version and
/// the `(path, raw_yaml)` parser definitions in manifest order.
fn verify_and_extract_parsers(
    bundle_bytes: Vec<u8>,
) -> Result<(String, Vec<(String, String)>), ApiError> {
    // Verify signature + manifest schema before touching any payload. The
    // embedded public key gates this; a tampered or unsigned bundle fails here.
    let mut bundle = verify_bundle(std::io::Cursor::new(bundle_bytes))
        .map_err(|e| ApiError::BadRequest(format!("Bundle verification failed: {e}")))?;

    // Reject any bundle that is not a parser bundle. This is the WS2 contract:
    // enrichment / IOC / license bundles route through their own handlers.
    if bundle.bundle_type() != BundleType::Parsers {
        return Err(ApiError::BadRequest(format!(
            "Expected a parsers bundle, got {:?}",
            bundle.bundle_type()
        )));
    }

    let content_version = bundle.manifest().content_version.clone();

    // Stream each declared payload to completion (which enforces its per-file
    // SHA-256), keeping the parser YAML definitions. We only treat
    // `parser.yaml` / `parser.yml` files as parser definitions — matching the
    // GitHub sync convention — but still read every payload to EOF so all
    // checksums are validated and the payload-set is confirmed complete.
    let mut parsers: Vec<(String, String)> = Vec::new();
    while let Some(mut payload) = bundle
        .next_payload()
        .map_err(|e| ApiError::BadRequest(format!("Bundle payload error: {e}")))?
    {
        let path = payload.path().to_string();
        let is_parser_yaml = path.ends_with("/parser.yaml")
            || path.ends_with("/parser.yml")
            || path == "parser.yaml"
            || path == "parser.yml";

        let mut content = String::new();
        // Reading to EOF triggers the checksum check; a mismatch surfaces as an
        // io::Error wrapping BundleError::ChecksumMismatch.
        payload
            .read_to_string(&mut content)
            .map_err(|e| ApiError::BadRequest(format!("Bundle file '{path}' invalid: {e}")))?;

        if is_parser_yaml {
            parsers.push((path, content));
        }
    }

    Ok((content_version, parsers))
}

/// Sync a signed, air-gapped parser bundle into the air-gap repo catalog.
///
/// `POST /api/airgap/parsers/import`
///
/// Accepts `multipart/form-data` with a single `file` field carrying the
/// signed `.tar.gz` bundle. Verifies signature + checksums, rejects
/// non-parser bundles, and syncs each parser into the synthetic air-gap parser
/// repository's catalog — the offline equivalent of a GitHub repo sync
/// (NAN-1226). Parsers land as available-to-import; nothing is imported or
/// deployed. The operator imports + deploys selectively from the repositories
/// page afterward.
///
/// Requires: `parser_repositories:import`.
#[utoipa::path(
    post,
    path = "/api/airgap/parsers/import",
    tag = "airgap",
    request_body(content = inline(AirgapParserImportResponse), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Bundle synced into catalog", body = AirgapParserImportResponse),
        (status = 400, description = "Bad request / malformed or unsigned bundle"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn import_parser_bundle(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    mut multipart: Multipart,
) -> Result<Json<AirgapParserImportResponse>, ApiError> {
    check_permission(&auth, permissions::PARSER_REPOSITORIES_IMPORT).map_err(|_| {
        ApiError::Forbidden("Missing permission: parser_repositories:import".to_string())
    })?;

    // Read the uploaded bundle bytes from the `file` field.
    let mut bundle_bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            let data = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(format!("Failed to read bundle: {e}")))?;
            if data.len() > MAX_BUNDLE_BYTES {
                return Err(ApiError::BadRequest(format!(
                    "Bundle exceeds maximum size of {} bytes",
                    MAX_BUNDLE_BYTES
                )));
            }
            bundle_bytes = Some(data.to_vec());
        }
    }

    let bundle_bytes = bundle_bytes
        .ok_or_else(|| ApiError::BadRequest("No bundle file provided (field 'file')".to_string()))?;

    // Verify + drain the bundle inside a scope that ends before any `.await`.
    // The verified-bundle reader (tar/gzip state) is not `Send`, so it must be
    // fully dropped before we hit an await point or the handler future won't
    // satisfy axum's `Handler` (Send) bound.
    let (content_version, parsers) = verify_and_extract_parsers(bundle_bytes)?;

    if parsers.is_empty() {
        return Err(ApiError::BadRequest(
            "Bundle contains no parser.yaml definitions".to_string(),
        ));
    }

    // Sync-only: upserts each parser into the synthetic air-gap parser
    // repository's catalog so they show as available-to-import. No log sources
    // are created and Vector is never touched — the operator imports + deploys
    // selectively from the repo page.
    let service = ParserRepositoryService::new(state.pool.clone());
    let result: BundleImportResult = service
        .sync_parser_bundle(&content_version, &parsers, Some(auth.user_id()))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_REPO_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser_repository", Some(result.repository_id), None::<String>)
            .client_context(&client)
            .details(serde_json::json!({
                "source": "airgap_bundle",
                "content_version": content_version,
                "synced": result.synced,
            }))
            .build(),
    );

    Ok(Json(AirgapParserImportResponse {
        repository_id: result.repository_id,
        content_version: result.content_version,
        synced: result.synced,
    }))
}

/// OpenAPI documentation for air-gapped parser bundle endpoints.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(import_parser_bundle),
    components(schemas(AirgapParserImportResponse))
)]
pub struct AirgapParsersApiDoc;
