// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud Credentials Management handlers
//!
//! - list_credentials() / get_credential() / list_credentials_by_provider()
//! - create_credential() / update_credential() / delete_credential()
//! - rotate_credential() / list_credential_versions() / rollback_credential()
//!
//! Update no longer mutates secret material — that path lives in rotate so
//! version history is preserved.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, CREDENTIAL_CREATED, CREDENTIAL_DELETED,
    CREDENTIAL_ROLLED_BACK, CREDENTIAL_ROTATED, CREDENTIAL_UPDATED, SOURCE_CONFIG_DEPLOYED,
};
use nanosiem_core::source_configs::{CredentialRefresh, CredentialRefreshOutcome};
use nanosiem_core::parsers::{
    is_supported_credential_provider, normalize_credential_payload, validate_credential_payload,
    CloudCredential,
    CloudCredentialVersion, CreateCloudCredential, CredentialRepository,
    CredentialRepositoryError, RollbackCloudCredential, RotateCloudCredential,
    UpdateCloudCredential, SUPPORTED_CREDENTIAL_PROVIDERS,
};

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for credential endpoints
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialApiError {
    pub error: String,
    pub message: String,
}

impl CredentialApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &CredentialRepositoryError) -> (StatusCode, Self) {
        let (status, error_type) = match err {
            CredentialRepositoryError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "credential_not_found")
            }
            CredentialRepositoryError::VersionNotFound { .. } => {
                (StatusCode::NOT_FOUND, "version_not_found")
            }
            CredentialRepositoryError::DuplicateName(_) => (StatusCode::CONFLICT, "duplicate_name"),
            // NAN-4902: deleting a credential that is still referenced is a
            // conflict the caller can fix, not a server error.
            CredentialRepositoryError::InUse { .. } => (StatusCode::CONFLICT, "credential_in_use"),
            CredentialRepositoryError::InvalidProvider(_) => {
                (StatusCode::BAD_REQUEST, "invalid_provider")
            }
            CredentialRepositoryError::InvalidCredentials(_) => {
                (StatusCode::BAD_REQUEST, "invalid_credentials")
            }
            CredentialRepositoryError::EncryptionError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "encryption_error")
            }
            CredentialRepositoryError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database_error")
            }
        };

        (status, Self::new(error_type, &err.to_string()))
    }
}

fn invalid_provider() -> (StatusCode, Json<CredentialApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(CredentialApiError::new(
            "invalid_provider",
            &format!(
                "Provider must be one of: {}",
                SUPPORTED_CREDENTIAL_PROVIDERS.join(", ")
            ),
        )),
    )
}

fn forbidden() -> (StatusCode, Json<CredentialApiError>) {
    (
        StatusCode::FORBIDDEN,
        Json(CredentialApiError::new(
            "forbidden",
            "Insufficient permissions",
        )),
    )
}

/// Response wrapper for credential list
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialListResponse {
    pub credentials: Vec<CloudCredential>,
    pub total: usize,
}

/// List all cloud credentials
///
/// Returns metadata only - secrets are never exposed via API.
#[utoipa::path(
    get,
    path = "/api/credentials",
    tag = "credentials",
    responses(
        (status = 200, description = "List of credentials", body = CredentialListResponse),
        (status = 403, description = "Forbidden", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn list_credentials(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<CredentialListResponse>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:view").map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());
    let credentials = repo.list().await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = credentials.len();
    Ok(Json(CredentialListResponse { credentials, total }))
}

/// Get a single credential's metadata
#[utoipa::path(
    get,
    path = "/api/credentials/{id}",
    tag = "credentials",
    params(
        ("id" = String, Path, description = "Credential ID")
    ),
    responses(
        (status = 200, description = "Credential details", body = CloudCredential),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 404, description = "Not found", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn get_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<CloudCredential>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:view").map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());
    let credential = repo.get(*id).await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(credential))
}

/// Request to create a new cloud credential
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub provider: String,
    pub credentials: serde_json::Value,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Create a new cloud credential
#[utoipa::path(
    post,
    path = "/api/credentials",
    tag = "credentials",
    request_body = CreateCredentialRequest,
    responses(
        (status = 201, description = "Credential created", body = CloudCredential),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 400, description = "Bad request", body = CredentialApiError),
        (status = 409, description = "Conflict - duplicate name", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn create_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Json(request): Json<CreateCredentialRequest>,
) -> Result<(StatusCode, Json<CloudCredential>), (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:create").map_err(|_| forbidden())?;

    if !is_supported_credential_provider(&request.provider) {
        return Err(invalid_provider());
    }

    // Provider-specific completeness (AWS static keys or role, GCP service
    // account JSON, Event Hubs connection string or service principal, ...).
    // Kafka credentials are optional (can be unauthenticated).
    let mut request = request;
    if let Err(message) = normalize_credential_payload(&request.provider, &mut request.credentials)
        .and_then(|()| validate_credential_payload(&request.provider, &request.credentials))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CredentialApiError::new("invalid_credentials", &message)),
        ));
    }

    let cred_name = request.name.clone();
    let cred_provider = request.provider.clone();

    // NAN-2186: lift `external_id` OUT of the encrypted payload into its own
    // column. Clients send it inside `credentials` because that is where the
    // rest of the AWS auth fields live, but it must survive as readable
    // metadata — the account owner needs it to write their trust policy, and
    // `GET /api/credentials` returns no payload at all. `get_decrypted` merges
    // it back in for the config generators, so the column is the only copy.
    let mut credentials = request.credentials;
    let external_id = credentials
        .as_object_mut()
        .and_then(|m| m.remove("external_id"))
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.trim().is_empty());

    let create_req = CreateCloudCredential {
        name: request.name,
        provider: request.provider,
        credentials,
        external_id,
        description: request.description,
        region: request.region,
        environment: request.environment,
        expires_at: request.expires_at,
    };

    let repo = CredentialRepository::new(state.pool.clone());
    let credential = repo
        .create(&create_req, Some(auth.user_id()))
        .await
        .map_err(|e| {
            let (status, err) = CredentialApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Credentials, CREDENTIAL_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("credential", Some(credential.id), Some(cred_name))
            .client_context(&client)
            .details(serde_json::json!({
                "provider": cred_provider,
            }))
            .build(),
    );

    Ok((StatusCode::CREATED, Json(credential)))
}

/// Request to update a cloud credential's metadata. Note: secret material
/// can only be replaced via the `/rotate` endpoint, which preserves version
/// history.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCredentialRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Update a cloud credential's metadata
#[utoipa::path(
    put,
    path = "/api/credentials/{id}",
    tag = "credentials",
    params(
        ("id" = String, Path, description = "Credential ID")
    ),
    request_body = UpdateCredentialRequest,
    responses(
        (status = 200, description = "Credential updated", body = CloudCredential),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 404, description = "Not found", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn update_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateCredentialRequest>,
) -> Result<Json<CloudCredential>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:edit").map_err(|_| forbidden())?;

    let update_req = UpdateCloudCredential {
        name: request.name,
        description: request.description,
        region: request.region,
        environment: request.environment,
        expires_at: request.expires_at,
    };

    let repo = CredentialRepository::new(state.pool.clone());
    let credential = repo.update(*id, &update_req).await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Credentials, CREDENTIAL_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "credential",
                Some(credential.id),
                Some(credential.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(credential))
}

/// Response for delete operation
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteResponse {
    pub deleted: bool,
    #[serde(with = "nanosiem_core::typeid::cloud_credential")]
    #[schema(value_type = String)]
    pub id: Uuid,
}

/// Delete a cloud credential
#[utoipa::path(
    delete,
    path = "/api/credentials/{id}",
    tag = "credentials",
    params(
        ("id" = String, Path, description = "Credential ID")
    ),
    responses(
        (status = 200, description = "Credential deleted", body = DeleteResponse),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 404, description = "Not found", body = CredentialApiError),
        (status = 409, description = "Credential is still used by a source configuration or custom enrichment", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn delete_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:delete").map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());

    let cred_name = repo
        .get(*id)
        .await
        .map(|c| c.name)
        .unwrap_or_else(|_| "unknown".to_string());

    repo.delete(*id).await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Credentials, CREDENTIAL_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("credential", Some(*id), Some(cred_name))
            .client_context(&client)
            .build(),
    );

    Ok(Json(DeleteResponse {
        deleted: true,
        id: *id,
    }))
}

/// List credentials by provider
#[utoipa::path(
    get,
    path = "/api/credentials/provider/{provider}",
    tag = "credentials",
    params(
        ("provider" = String, Path, description = "Provider name (aws_s3, gcp_pubsub, kafka, azure_event_hubs, okta, google_workspace, slack, saas_api)")
    ),
    responses(
        (status = 200, description = "List of credentials for provider", body = CredentialListResponse),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 400, description = "Invalid provider", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn list_credentials_by_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(provider): Path<String>,
) -> Result<Json<CredentialListResponse>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:view").map_err(|_| forbidden())?;

    if !is_supported_credential_provider(&provider) {
        return Err(invalid_provider());
    }

    let repo = CredentialRepository::new(state.pool.clone());
    let credentials = repo.list_by_provider(&provider).await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = credentials.len();
    Ok(Json(CredentialListResponse { credentials, total }))
}

// ============================================================================
// Versioning — rotate / list versions / rollback
// ============================================================================

/// Request body for rotating a credential
#[derive(Debug, Deserialize, ToSchema)]
pub struct RotateCredentialRequest {
    /// Provider-specific credential JSON (encrypted before storage)
    pub credentials: serde_json::Value,
    #[serde(default)]
    pub note: Option<String>,
}

/// Response for rotate / rollback — includes the updated parent credential
/// and the newly-created version row.
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialRotationResponse {
    pub credential: CloudCredential,
    pub version: CloudCredentialVersion,
    /// NAN-4914: what happened to the deployed source configurations bound to
    /// this credential (secret-only refresh). The rotation itself always
    /// committed when this response is returned.
    pub source_refresh: SourceRefreshReport,
}

/// NAN-4914: the secret-only refresh of bound source configs after a
/// rotation or rollback.
#[derive(Debug, Serialize, ToSchema)]
pub struct SourceRefreshReport {
    /// `none` (no deployed source uses the credential), `complete` (every
    /// bound source now runs the new secret), or `partial_failure` (at least
    /// one bound source still runs the previous secret, or the bound sources
    /// could not even be listed; see `error` and `results`).
    pub status: SourceRefreshStatus,
    pub results: Vec<SourceRefreshResult>,
    /// Set when the bound sources could not be enumerated at all.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceRefreshStatus {
    None,
    Complete,
    PartialFailure,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SourceRefreshResult {
    /// `srcfg_...`
    pub source_configuration_id: String,
    pub name: String,
    /// `redeployed`, `pending_edits` (saved but undeployed edits: not
    /// redeployed, still on the previous secret until deployed),
    /// `no_deployed_snapshot` or `failed`.
    pub outcome: String,
    pub message: Option<String>,
}

pub(crate) fn source_refresh_report(
    refreshed: Result<Vec<CredentialRefresh>, String>,
) -> SourceRefreshReport {
    let results = match refreshed {
        Ok(results) => results,
        Err(error) => {
            return SourceRefreshReport { status: SourceRefreshStatus::PartialFailure, results: Vec::new(), error: Some(error) }
        }
    };
    let status = if results.is_empty() {
        SourceRefreshStatus::None
    } else if results.iter().all(|r| r.outcome == CredentialRefreshOutcome::Redeployed) {
        SourceRefreshStatus::Complete
    } else {
        SourceRefreshStatus::PartialFailure
    };
    let results = results
        .into_iter()
        .map(|r| {
            let (outcome, message) = match r.outcome {
                CredentialRefreshOutcome::Redeployed => ("redeployed", None),
                CredentialRefreshOutcome::PendingEdits => (
                    "pending_edits",
                    Some("saved edits are not deployed; deploy the source to apply the new secret".to_string()),
                ),
                CredentialRefreshOutcome::NoDeployedSnapshot => (
                    "no_deployed_snapshot",
                    Some("no deployment snapshot to refresh from; deploy the source".to_string()),
                ),
                CredentialRefreshOutcome::Failed(m) => ("failed", Some(m)),
            };
            SourceRefreshResult {
                source_configuration_id: nanosiem_core::typeid::encode("srcfg", &r.source_configuration_id),
                name: r.name,
                outcome: outcome.to_string(),
                message,
            }
        })
        .collect();
    SourceRefreshReport { status, results, error: None }
}

/// NAN-4914: secret-only refresh of every deployed source config bound to a
/// rotated or rolled-back credential (see
/// `SourceConfigService::refresh_secrets_for_credential`). Each redeploy is
/// audited as a source-config deploy carrying the triggering credential. An
/// enumeration failure is reported as `partial_failure`, never as "no bound
/// sources": the rotation itself already committed.
async fn refresh_bound_source_configs(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    credential_id: Uuid,
    previous: Option<&serde_json::Value>,
    trigger: &str,
) -> SourceRefreshReport {
    let refreshed = state
        .source_config_service
        .refresh_secrets_for_credential(credential_id, previous)
        .await
        .map_err(|error| {
            tracing::error!(%credential_id, %error, "listing source configs to refresh after credential change failed");
            format!("the bound source configurations could not be refreshed: {error}")
        });
    if let Ok(results) = &refreshed {
        for r in results {
            let redeployed = r.outcome == CredentialRefreshOutcome::Redeployed;
            state.emit_audit(
                AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_DEPLOYED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("source_config", Some(r.source_configuration_id), Some(r.name.clone()))
                    .client_context(client)
                    .details(serde_json::json!({
                        "success": redeployed,
                        "outcome": format!("{:?}", r.outcome),
                        "trigger": trigger,
                        "secret_only": true,
                        "credential_id": nanosiem_core::typeid::encode("cred", &credential_id),
                    }))
                    .build(),
            );
        }
    }
    source_refresh_report(refreshed)
}

/// Wrapper for the version list endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialVersionListResponse {
    pub versions: Vec<CloudCredentialVersion>,
    pub total: usize,
}

/// Rotate the secret material on a credential — creates a new active version
/// while preserving the prior version for rollback. Deployed source configs
/// bound to the credential are redeployed with the new secret (NAN-4914).
#[utoipa::path(
    post,
    path = "/api/credentials/{id}/rotate",
    tag = "credentials",
    params(
        ("id" = String, Path, description = "Credential ID")
    ),
    request_body = RotateCredentialRequest,
    responses(
        (status = 200, description = "Rotated", body = CredentialRotationResponse),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 404, description = "Not found", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn rotate_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<RotateCredentialRequest>,
) -> Result<Json<CredentialRotationResponse>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, permissions::CREDENTIALS_ROTATE).map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());

    // The new version must satisfy the same provider rules as a create
    // (NAN-4914: connector vendor credentials are a flat field map; a Google
    // Workspace service-account key is split into its two fields).
    let existing = repo.get(*id).await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;
    let mut request = request;
    if let Err(message) = normalize_credential_payload(&existing.provider, &mut request.credentials)
        .and_then(|()| validate_credential_payload(&existing.provider, &request.credentials))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CredentialApiError::new("invalid_credentials", &message)),
        ));
    }

    // Same lift as create: `external_id` is readable metadata, not payload.
    // A rotation may switch posture (static keys -> cross-account role), so it
    // rewrites the column rather than inheriting the previous value.
    let mut credentials = request.credentials;
    let external_id = credentials
        .as_object_mut()
        .and_then(|m| m.remove("external_id"))
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.trim().is_empty());

    let rotate_req = RotateCloudCredential {
        credentials,
        external_id,
        note: request.note.clone(),
    };

    // The payload being replaced, to recognize which values in the deployed
    // snapshots are credential material (secret-only refresh, NAN-4914).
    let previous = repo.get_decrypted(*id).await.ok();
    let (credential, version) = repo
        .rotate(*id, &rotate_req, Some(auth.user_id()))
        .await
        .map_err(|e| {
            let (status, err) = CredentialApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Credentials, CREDENTIAL_ROTATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "credential",
                Some(credential.id),
                Some(credential.name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "version": version.version_number,
                "note": request.note,
            }))
            .build(),
    );

    let source_refresh = refresh_bound_source_configs(
        &state,
        &auth,
        &client,
        credential.id,
        previous.as_ref(),
        "credential_rotated",
    )
    .await;

    Ok(Json(CredentialRotationResponse {
        credential,
        version,
        source_refresh,
    }))
}

/// List all versions for a credential, newest first
#[utoipa::path(
    get,
    path = "/api/credentials/{id}/versions",
    tag = "credentials",
    params(
        ("id" = String, Path, description = "Credential ID")
    ),
    responses(
        (status = 200, description = "Version history", body = CredentialVersionListResponse),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 404, description = "Not found", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn list_credential_versions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<CredentialVersionListResponse>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, "credentials:view").map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());
    let versions = repo.list_versions(*id).await.map_err(|e| {
        let (status, err) = CredentialApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = versions.len();
    Ok(Json(CredentialVersionListResponse { versions, total }))
}

/// Request body for rolling a credential back to a previous version
#[derive(Debug, Deserialize, ToSchema)]
pub struct RollbackCredentialRequest {
    pub version: i32,
    #[serde(default)]
    pub note: Option<String>,
}

/// Roll a credential back to a previous version — creates a new version row
/// that copies the target's payload and records `reverted_from_version`.
#[utoipa::path(
    post,
    path = "/api/credentials/{id}/rollback",
    tag = "credentials",
    params(
        ("id" = String, Path, description = "Credential ID")
    ),
    request_body = RollbackCredentialRequest,
    responses(
        (status = 200, description = "Rolled back", body = CredentialRotationResponse),
        (status = 403, description = "Forbidden", body = CredentialApiError),
        (status = 404, description = "Not found", body = CredentialApiError),
    ),
    security(("api_key" = []))
)]
pub async fn rollback_credential(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<RollbackCredentialRequest>,
) -> Result<Json<CredentialRotationResponse>, (StatusCode, Json<CredentialApiError>)> {
    check_permission(&auth, permissions::CREDENTIALS_ROTATE).map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());
    let rollback_req = RollbackCloudCredential {
        version: request.version,
        note: request.note.clone(),
    };

    // The payload being replaced, to recognize which values in the deployed
    // snapshots are credential material (secret-only refresh, NAN-4914).
    let previous = repo.get_decrypted(*id).await.ok();
    let (credential, version) = repo
        .rollback(*id, &rollback_req, Some(auth.user_id()))
        .await
        .map_err(|e| {
            let (status, err) = CredentialApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Credentials, CREDENTIAL_ROLLED_BACK)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "credential",
                Some(credential.id),
                Some(credential.name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "rolled_back_to": request.version,
                "new_version": version.version_number,
                "note": request.note,
            }))
            .build(),
    );

    let source_refresh = refresh_bound_source_configs(
        &state,
        &auth,
        &client,
        credential.id,
        previous.as_ref(),
        "credential_rolled_back",
    )
    .await;

    Ok(Json(CredentialRotationResponse {
        credential,
        version,
        source_refresh,
    }))
}

// ============================================================================
// OpenAPI Documentation
// ============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_credentials,
        get_credential,
        create_credential,
        update_credential,
        delete_credential,
        list_credentials_by_provider,
        rotate_credential,
        list_credential_versions,
        rollback_credential,
    ),
    components(schemas(
        CredentialApiError,
        CredentialListResponse,
        CreateCredentialRequest,
        UpdateCredentialRequest,
        DeleteResponse,
        RotateCredentialRequest,
        RollbackCredentialRequest,
        CredentialRotationResponse,
        SourceRefreshReport,
        SourceRefreshStatus,
        SourceRefreshResult,
        CredentialVersionListResponse,
        CloudCredentialVersion,
    ))
)]
pub struct CredentialsApiDoc;

impl CredentialsApiDoc {
    pub fn paths() -> Vec<utoipa::openapi::path::PathItem> {
        vec![]
    }

    pub fn schemas() -> Vec<(
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    )> {
        vec![]
    }
}

#[cfg(test)]
#[path = "credentials_refresh_tests.rs"]
mod refresh_tests;

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod credentials_tests;
