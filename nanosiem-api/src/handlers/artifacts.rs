// SPDX-License-Identifier: AGPL-3.0-or-later

//! Artifact-analysis store handlers (NAN-1977).
//!
//! A SHARED, RBAC-scoped evidence locker for specimen-analysis reports. Any
//! holder of `artifacts:view` sees the whole collection; `artifacts:create`
//! adds one, `artifacts:edit` writes analysis results back, `artifacts:delete`
//! removes one. We persist the REPORT (verdict, passes, IOCs, MITRE, specimen
//! text) — never raw file bytes: binaries arrive already reduced to printable
//! strings. The desktop Artifacts pane is the primary client.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Serialize;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ARTIFACT_CREATED, ARTIFACT_DELETED, ARTIFACT_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{Artifact, ArtifactRepository, ArtifactRepositoryError, ArtifactSummary};
use nanosiem_core::{NewArtifact, UpdateArtifact};

use super::AuditExt;
use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Max specimen / deobfuscated text accepted per artifact (hard app-level cap —
/// the store holds reports, not a file archive). The artifacts sub-router raises
/// the transport body limit above this (see `ARTIFACT_BODY_LIMIT` in `routes.rs`)
/// so this handler cap — not a framework 413 — is the authoritative rejection.
const MAX_SPECIMEN_BYTES: usize = 4 * 1024 * 1024;
/// Max serialized size of each structured JSON field
/// (`passes`/`iocs`/`mitre`/`static_analysis`).
const MAX_JSON_FIELD_BYTES: usize = 512 * 1024;
/// Max artifact name length.
const MAX_NAME_LENGTH: usize = 512;

/// Reject an oversized structured JSON field (defense-in-depth beneath the
/// transport body limit — a single field can't dominate the payload).
fn check_json_size(field: &str, value: &serde_json::Value) -> Result<(), ApiError> {
    if value.to_string().len() > MAX_JSON_FIELD_BYTES {
        return Err(ApiError::ValidationError(format!(
            "{field} exceeds the {MAX_JSON_FIELD_BYTES}-byte limit"
        )));
    }
    Ok(())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ArtifactResponse {
    pub artifact: Artifact,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ArtifactListResponse {
    pub artifacts: Vec<ArtifactSummary>,
}

fn map_err(e: ArtifactRepositoryError) -> ApiError {
    match e {
        ArtifactRepositoryError::NotFound(_) => {
            ApiError::NotFound("artifact not found".to_string())
        }
        ArtifactRepositoryError::DatabaseError(err) => ApiError::InternalError(err.to_string()),
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// List the shared artifact collection (summary projection, newest first).
#[utoipa::path(
    get,
    path = "/api/artifacts",
    tag = "artifacts",
    responses(
        (status = 200, description = "Artifacts listed", body = ArtifactListResponse),
        (status = 403, description = "Forbidden - missing artifacts:view permission"),
    ),
    security(("api_key" = []))
)]
pub async fn list_artifacts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ArtifactListResponse>, ApiError> {
    ensure_permission(&auth, permissions::ARTIFACTS_VIEW)?;
    let repo = ArtifactRepository::new(state.pool.clone());
    let artifacts = repo.list().await.map_err(map_err)?;
    Ok(Json(ArtifactListResponse { artifacts }))
}

/// Add an artifact to the shared collection.
#[utoipa::path(
    post,
    path = "/api/artifacts",
    tag = "artifacts",
    request_body = NewArtifact,
    responses(
        (status = 200, description = "Artifact created", body = ArtifactResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Forbidden - missing artifacts:create permission"),
    ),
    security(("api_key" = []))
)]
pub async fn create_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(mut new): Json<NewArtifact>,
) -> Result<Json<ArtifactResponse>, ApiError> {
    ensure_permission(&auth, permissions::ARTIFACTS_CREATE)?;

    new.name = new.name.trim().to_string();
    if new.name.is_empty() || new.name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::ValidationError(format!(
            "name must be 1..={MAX_NAME_LENGTH} characters"
        )));
    }
    if new.original.len() > MAX_SPECIMEN_BYTES {
        return Err(ApiError::ValidationError(format!(
            "specimen exceeds the {MAX_SPECIMEN_BYTES}-byte limit"
        )));
    }
    if let Some(ref deob) = new.deobfuscated {
        if deob.len() > MAX_SPECIMEN_BYTES {
            return Err(ApiError::ValidationError(format!(
                "deobfuscated text exceeds the {MAX_SPECIMEN_BYTES}-byte limit"
            )));
        }
    }
    check_json_size("passes", &new.passes)?;
    check_json_size("iocs", &new.iocs)?;
    check_json_size("mitre", &new.mitre)?;
    if let Some(ref v) = new.static_analysis {
        check_json_size("static_analysis", v)?;
    }

    let repo = ArtifactRepository::new(state.pool.clone());
    let artifact = repo
        .create(&new, Some(auth.user_id()))
        .await
        .map_err(map_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Artifact, ARTIFACT_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("artifact", Some(artifact.id), Some(artifact.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ArtifactResponse { artifact }))
}

/// Fetch a single artifact fully hydrated (includes the specimen text).
#[utoipa::path(
    get,
    path = "/api/artifacts/{id}",
    tag = "artifacts",
    params(("id" = String, Path, description = "Artifact ID")),
    responses(
        (status = 200, description = "Artifact", body = ArtifactResponse),
        (status = 403, description = "Forbidden - missing artifacts:view permission"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ArtifactResponse>, ApiError> {
    ensure_permission(&auth, permissions::ARTIFACTS_VIEW)?;
    let repo = ArtifactRepository::new(state.pool.clone());
    let artifact = repo.find_by_id(*id).await.map_err(map_err)?;
    Ok(Json(ArtifactResponse { artifact }))
}

/// Write analysis results (or the async sha256) back onto an artifact.
#[utoipa::path(
    put,
    path = "/api/artifacts/{id}",
    tag = "artifacts",
    params(("id" = String, Path, description = "Artifact ID")),
    request_body = UpdateArtifact,
    responses(
        (status = 200, description = "Artifact updated", body = ArtifactResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Forbidden - missing artifacts:edit permission"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(patch): Json<UpdateArtifact>,
) -> Result<Json<ArtifactResponse>, ApiError> {
    ensure_permission(&auth, permissions::ARTIFACTS_EDIT)?;

    if let Some(ref deob) = patch.deobfuscated {
        if deob.len() > MAX_SPECIMEN_BYTES {
            return Err(ApiError::ValidationError(format!(
                "deobfuscated text exceeds the {MAX_SPECIMEN_BYTES}-byte limit"
            )));
        }
    }
    if let Some(ref v) = patch.passes {
        check_json_size("passes", v)?;
    }
    if let Some(ref v) = patch.iocs {
        check_json_size("iocs", v)?;
    }
    if let Some(ref v) = patch.mitre {
        check_json_size("mitre", v)?;
    }
    if let Some(ref v) = patch.static_analysis {
        check_json_size("static_analysis", v)?;
    }

    let repo = ArtifactRepository::new(state.pool.clone());
    let artifact = repo.update(*id, &patch).await.map_err(map_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Artifact, ARTIFACT_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("artifact", Some(artifact.id), Some(artifact.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ArtifactResponse { artifact }))
}

/// Remove an artifact from the collection.
#[utoipa::path(
    delete,
    path = "/api/artifacts/{id}",
    tag = "artifacts",
    params(("id" = String, Path, description = "Artifact ID")),
    responses(
        (status = 204, description = "Artifact deleted"),
        (status = 403, description = "Forbidden - missing artifacts:delete permission"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::ARTIFACTS_DELETE)?;
    let repo = ArtifactRepository::new(state.pool.clone());

    // Load first so the audit record carries the artifact name (and to surface a
    // clean 404 before the delete).
    let existing = repo.find_by_id(*id).await.map_err(map_err)?;
    repo.delete(*id).await.map_err(map_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Artifact, ARTIFACT_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("artifact", Some(existing.id), Some(existing.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// OpenAPI
// ============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_artifacts,
        create_artifact,
        get_artifact,
        update_artifact,
        delete_artifact,
    ),
    components(schemas(
        ArtifactResponse,
        ArtifactListResponse,
        Artifact,
        ArtifactSummary,
        NewArtifact,
        UpdateArtifact,
    ))
)]
pub struct ArtifactsApiDoc;
