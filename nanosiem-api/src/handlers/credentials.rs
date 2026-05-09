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
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, CREDENTIAL_CREATED, CREDENTIAL_DELETED,
    CREDENTIAL_ROLLED_BACK, CREDENTIAL_ROTATED, CREDENTIAL_UPDATED,
};
use nanosiem_core::parsers::{
    CloudCredential, CloudCredentialVersion, CreateCloudCredential, CredentialRepository,
    CredentialRepositoryError, RollbackCloudCredential, RotateCloudCredential,
    UpdateCloudCredential,
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
            CredentialRepositoryError::InvalidProvider(_) => {
                (StatusCode::BAD_REQUEST, "invalid_provider")
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

    if request.provider != "aws_s3"
        && request.provider != "gcp_pubsub"
        && request.provider != "kafka"
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CredentialApiError::new(
                "invalid_provider",
                "Provider must be 'aws_s3', 'gcp_pubsub', or 'kafka'",
            )),
        ));
    }

    if request.provider == "aws_s3" {
        if request.credentials.get("access_key_id").is_none()
            || request.credentials.get("secret_access_key").is_none()
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(CredentialApiError::new(
                    "invalid_credentials",
                    "AWS S3 credentials must include 'access_key_id' and 'secret_access_key'",
                )),
            ));
        }
    } else if request.provider == "gcp_pubsub"
        && request.credentials.get("credentials_json").is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CredentialApiError::new(
                "invalid_credentials",
                "GCP Pub/Sub credentials must include 'credentials_json'",
            )),
        ));
    }
    // Kafka credentials are optional (can be unauthenticated)

    let cred_name = request.name.clone();
    let cred_provider = request.provider.clone();
    let create_req = CreateCloudCredential {
        name: request.name,
        provider: request.provider,
        credentials: request.credentials,
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
        ("provider" = String, Path, description = "Provider name (aws_s3, gcp_pubsub, kafka)")
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

    if provider != "aws_s3" && provider != "gcp_pubsub" && provider != "kafka" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(CredentialApiError::new(
                "invalid_provider",
                "Provider must be 'aws_s3', 'gcp_pubsub', or 'kafka'",
            )),
        ));
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
}

/// Wrapper for the version list endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialVersionListResponse {
    pub versions: Vec<CloudCredentialVersion>,
    pub total: usize,
}

/// Rotate the secret material on a credential — creates a new active version
/// while preserving the prior version for rollback. Source configs pick up
/// the new secret on their next deploy.
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
    check_permission(&auth, "credentials:rotate").map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());
    let rotate_req = RotateCloudCredential {
        credentials: request.credentials,
        note: request.note.clone(),
    };

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

    Ok(Json(CredentialRotationResponse {
        credential,
        version,
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
    check_permission(&auth, "credentials:rotate").map_err(|_| forbidden())?;

    let repo = CredentialRepository::new(state.pool.clone());
    let rollback_req = RollbackCloudCredential {
        version: request.version,
        note: request.note.clone(),
    };

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

    Ok(Json(CredentialRotationResponse {
        credential,
        version,
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
