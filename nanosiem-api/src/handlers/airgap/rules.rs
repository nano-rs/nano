// SPDX-License-Identifier: AGPL-3.0-or-later

//! Air-gapped rule bundle import (NAN-1220).
//!
//! A signed `.tar.gz` rule bundle (built offline by the WS1 signer) is uploaded
//! here; we verify its Ed25519 signature + per-file SHA-256 checksums via
//! [`nanosiem_core::airgap::verify_bundle`], reject any bundle whose type is not
//! [`BundleType::Rules`], then *sync* the rule payloads into the synthetic
//! air-gap rule repository's catalog
//! ([`RuleRepositoryService::sync_rule_bundle`]) — the offline equivalent of a
//! GitHub repo sync (NAN-1226). The rules land as available-to-import; nothing
//! is imported or activated here. The operator imports selectively from the
//! repositories page afterward.
//!
//! Each payload's raw bytes ARE a rule definition (nano native
//! `rule_format: "nanosiem"`), at its repo-relative path. The reader drains
//! every payload to EOF so the WS0 checksum fires.
//!
//! Enterprise-only: air-gapped deployment is a paid capability.

#![cfg(feature = "enterprise")]

use std::io::Read;

use axum::{extract::Multipart, extract::State, Extension, Json};
use serde::Serialize;
use utoipa::ToSchema;

use nanosiem_core::airgap::{verify_bundle, BundleType};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RULE_REPO_SYNCED};
use nanosiem_core::auth::permissions;
use nanosiem_core::rule_repository::RuleBundleImportResult;

use crate::handlers::rule_repositories::get_rule_repo_service;
use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Upper bound on the uploaded bundle size. Rule bundles are small (YAML/nPL);
/// 64 MiB is generous headroom and prevents a single multipart field from
/// buffering an oversized archive into memory.
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

/// Response for an air-gapped rule bundle sync.
#[derive(Debug, Serialize, ToSchema)]
pub struct AirgapRuleImportResponse {
    /// Synthetic air-gap rule repository the bundle landed in.
    #[serde(with = "nanosiem_core::typeid::rule_repo")]
    #[schema(value_type = String)]
    pub repository_id: uuid::Uuid,
    /// Caller-defined content version from the bundle manifest.
    pub content_version: String,
    /// Number of rules synced into the repository catalog (available to import).
    pub synced: usize,
}

/// Verify the uploaded bundle and extract its rule payloads.
///
/// Fully synchronous so the non-`Send` verified-bundle reader (tar + gzip
/// state) is created and dropped without crossing an `.await` point — keeping
/// the calling handler future `Send`. Returns the manifest content version and
/// the `(path, raw_content)` rule definitions in manifest order.
fn verify_and_extract_rules(
    bundle_bytes: Vec<u8>,
) -> Result<(String, Vec<(String, String)>), ApiError> {
    // Verify signature + manifest schema before touching any payload. The
    // embedded public key gates this; a tampered or unsigned bundle fails here.
    let mut bundle = verify_bundle(std::io::Cursor::new(bundle_bytes))
        .map_err(|e| ApiError::BadRequest(format!("Bundle verification failed: {e}")))?;

    // Reject any bundle that is not a rules bundle.
    if bundle.bundle_type() != BundleType::Rules {
        return Err(ApiError::BadRequest(format!(
            "Expected a rules bundle, got {:?}",
            bundle.bundle_type()
        )));
    }

    let content_version = bundle.manifest().content_version.clone();

    // Stream each declared payload to completion (which enforces its per-file
    // SHA-256). Every payload's raw bytes ARE a rule definition.
    let mut rules: Vec<(String, String)> = Vec::new();
    while let Some(mut payload) = bundle
        .next_payload()
        .map_err(|e| ApiError::BadRequest(format!("Bundle payload error: {e}")))?
    {
        let path = payload.path().to_string();
        let mut content = String::new();
        // Reading to EOF triggers the checksum check; a mismatch surfaces as an
        // io::Error wrapping BundleError::ChecksumMismatch.
        payload
            .read_to_string(&mut content)
            .map_err(|e| ApiError::BadRequest(format!("Bundle file '{path}' invalid: {e}")))?;
        rules.push((path, content));
    }

    Ok((content_version, rules))
}

/// Sync a signed, air-gapped rule bundle into the air-gap repository catalog.
///
/// `POST /api/airgap/rules/import`
///
/// Accepts `multipart/form-data` with a single `file` field carrying the signed
/// `.tar.gz` bundle. Verifies signature + checksums, rejects non-rule bundles,
/// and syncs each rule into the synthetic air-gap rule repository's catalog —
/// the offline equivalent of a GitHub repo sync (NAN-1226). Rules land as
/// available-to-import; nothing is imported or activated. The operator imports
/// selectively from the repositories page afterward.
///
/// Requires: `rule_repositories:import`.
#[utoipa::path(
    post,
    path = "/api/airgap/rules/import",
    tag = "airgap",
    request_body(content = inline(AirgapRuleImportResponse), content_type = "multipart/form-data"),
    responses(
        (status = 200, description = "Bundle synced into catalog", body = AirgapRuleImportResponse),
        (status = 400, description = "Bad request / malformed or unsigned bundle"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn import_rule_bundle(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    mut multipart: Multipart,
) -> Result<Json<AirgapRuleImportResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_IMPORT).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:import".to_string())
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
    let (content_version, rules) = verify_and_extract_rules(bundle_bytes)?;

    if rules.is_empty() {
        return Err(ApiError::BadRequest(
            "Bundle contains no rule definitions".to_string(),
        ));
    }

    // Sync-only: upserts each rule into the synthetic air-gap rule repository's
    // catalog so they show as available-to-import. No detection rules are
    // created here — the operator imports selectively from the repo page.
    let service = get_rule_repo_service(&state)?;
    let result: RuleBundleImportResult = service
        .sync_rule_bundle(&content_version, &rules, Some(auth.user_id()))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_REPO_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule_repository", Some(result.repository_id), None::<String>)
            .client_context(&client)
            .details(serde_json::json!({
                "source": "airgap_bundle",
                "content_version": content_version,
                "synced": result.synced,
            }))
            .build(),
    );

    Ok(Json(AirgapRuleImportResponse {
        repository_id: result.repository_id,
        content_version: result.content_version,
        synced: result.synced,
    }))
}

/// OpenAPI documentation for air-gapped rule bundle endpoints.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(import_rule_bundle),
    components(schemas(AirgapRuleImportResponse))
)]
pub struct AirgapRulesApiDoc;
