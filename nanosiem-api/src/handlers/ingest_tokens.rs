// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3770: named, revocable per-sender ingest tokens (dedicated deployments).
//!
//! - GET  /api/ingest-tokens                          - list tokens, install-token state, bindable sources
//! - POST /api/ingest-tokens                          - issue a token bound to a source (value returned once)
//! - POST /api/ingest-tokens/{credential_id}/bind     - bind an unbound token to a source
//! - POST /api/ingest-tokens/{credential_id}/revoke   - revoke a token
//! - PUT  /api/ingest-tokens/install-token            - enable/disable or bind the install token
//!
//! NAN-3806: a token decides the source, 100% token based. Every token is
//! bound to exactly one log source at creation; every event sent with it is
//! routed to that source whatever `sourcetype` / `X-Source-Type` it declares.
//! An unbound token (a pre-NAN-3806 token migration 363 could not bind
//! unambiguously, or one whose source was deleted) is refused by Vector until
//! an admin binds it. A binding never changes: revoke and reissue instead.
//!
//! The shape follows hosted's `/api/log-sources/ingest-credentials` where it
//! applies (`credential_id`, `state`, `revocable`, `created_at`, `revoked_at`,
//! `POST …/{credential_id}/revoke`). Hosted-shared tenants do not mount these
//! routes: their credentials are verified at the edge Worker.
//!
//! The token value appears only in the create response (`Cache-Control:
//! no-store`); it is never logged, audited or readable again.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, INGEST_INSTALL_TOKEN_UPDATED, INGEST_TOKEN_BOUND,
    INGEST_TOKEN_CREATED, INGEST_TOKEN_REVOKED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::ingest_tokens::{
    BindableSource, IngestToken, IngestTokenService, IngestTokenServiceError, IngestTokenSettings,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Display name of the install-wide `VECTOR_AUTH_TOKEN`.
pub const INSTALL_TOKEN_NAME: &str = "Install token (legacy)";

/// The install-wide token's state. Its value is never returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct InstallTokenState {
    /// Always "Install token (legacy)".
    pub name: String,
    /// The admin switch. Senders are accepted only while it is enabled AND
    /// the token is bound (`state` = `active`).
    pub enabled: bool,
    /// `active` (enabled and bound), `unbound` (enabled, refused until it is
    /// bound), `disabled`, or `not_configured` (no `VECTOR_AUTH_TOKEN`).
    pub state: String,
    /// The log source every event sent with the install token lands in.
    pub source_id: Option<Uuid>,
    pub source_name: Option<String>,
    pub route_key: Option<String>,
    pub source_bound_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_by: Option<Uuid>,
}

/// `GET /api/ingest-tokens`.
#[derive(Debug, Serialize, ToSchema)]
pub struct IngestTokenList {
    /// Active first, newest first. `state` = `unbound` marks a token Vector
    /// refuses until an admin binds it to a source.
    pub tokens: Vec<IngestToken>,
    pub install_token: InstallTokenState,
    /// Log sources a token can be bound to (push-capable: HTTP, HEC, Vector;
    /// never OTLP or a pulled source).
    pub sources: Vec<BindableSource>,
}

/// `POST /api/ingest-tokens`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateIngestTokenRequest {
    /// Sender name, 1-100 characters, unique among active tokens.
    pub name: String,
    /// The log source every event sent with this token lands in (required;
    /// see `sources` in the list response). Never changes.
    pub source_id: Uuid,
}

/// `POST /api/ingest-tokens/{credential_id}/bind`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindIngestTokenRequest {
    pub source_id: Uuid,
}

/// The issued token. `token` is shown once and cannot be read again.
#[derive(Serialize, ToSchema)]
pub struct IssuedIngestToken {
    pub credential: IngestToken,
    /// The token value. Send it as `Authorization: Splunk <token>` (HEC) or
    /// `Authorization: Bearer <token>` (HTTP ingest).
    pub token: String,
}

impl std::fmt::Debug for IssuedIngestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedIngestToken")
            .field("credential", &self.credential)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `PUT /api/ingest-tokens/install-token`. At least one field.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateInstallTokenRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Binds the install token to this log source. Only while it is unbound.
    #[serde(default)]
    pub source_id: Option<Uuid>,
}

fn dedicated_only(state: &AppState) -> Result<(), ApiError> {
    #[cfg(feature = "enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        return Err(ApiError::NotFound(
            "Ingest tokens are issued through Log Sources on hosted tenants".into(),
        ));
    }
    Ok(())
}

fn service_error(error: IngestTokenServiceError) -> ApiError {
    match error {
        IngestTokenServiceError::InvalidName(message) => ApiError::BadRequest(message),
        IngestTokenServiceError::NotFound => ApiError::NotFound("Ingest token not found".into()),
        IngestTokenServiceError::AlreadyRevoked => {
            ApiError::Conflict("Ingest token is already revoked".into())
        }
        IngestTokenServiceError::InvalidSource(message) => ApiError::BadRequest(message),
        IngestTokenServiceError::AlreadyBound => ApiError::Conflict(
            "This token is already bound to a source; a binding never changes. Revoke it and issue a new token instead"
                .into(),
        ),
        IngestTokenServiceError::Repository(
            nanosiem_core::ingest_tokens::IngestTokenRepositoryError::DuplicateName(name),
        ) => ApiError::Conflict(format!(
            "An active ingest token named {name:?} already exists"
        )),
        IngestTokenServiceError::Publish { .. } => {
            tracing::error!(error = %error, "ingest token publication failed");
            ApiError::ServiceUnavailable(
                "Could not update Vector's ingest tokens file; retrying in the background".into(),
            )
        }
        IngestTokenServiceError::Repository(error) => {
            tracing::error!(%error, "ingest token storage error");
            ApiError::InternalError("Ingest token storage unavailable".into())
        }
    }
}

fn audit(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    action: &str,
    id: Option<Uuid>,
    name: Option<String>,
    details: serde_json::Value,
) {
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("ingest_token", id, name)
            .details(details)
            .client_context(client)
            .build(),
    );
}

async fn install_token_state(
    service: &IngestTokenService,
    settings: IngestTokenSettings,
) -> Result<InstallTokenState, ApiError> {
    let source = service
        .install_token_source(&settings)
        .await
        .map_err(service_error)?;
    let state = if !service.install_token_configured() {
        "not_configured"
    } else if !settings.install_token_enabled {
        "disabled"
    } else if source.is_none() {
        "unbound"
    } else {
        "active"
    };
    Ok(InstallTokenState {
        name: INSTALL_TOKEN_NAME.into(),
        enabled: settings.install_token_enabled,
        state: state.into(),
        source_id: settings.install_token_source_id,
        source_name: source.as_ref().map(|s| s.name.clone()),
        route_key: source.map(|s| s.route_key),
        source_bound_at: settings.install_token_source_bound_at,
        updated_at: settings.updated_at,
        updated_by: settings.updated_by,
    })
}

#[utoipa::path(get, path = "/api/ingest-tokens", tag = "ingest_tokens",
    responses((status = 200, body = IngestTokenList), (status = 403, description = "Forbidden"),
        (status = 404, description = "Not available on hosted tenants")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn list_ingest_tokens(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<IngestTokenList>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    dedicated_only(&state)?;
    let service = &state.ingest_token_service;
    let tokens = service.list().await.map_err(service_error)?;
    let settings = service.settings().await.map_err(service_error)?;
    let sources = service.bindable_sources().await.map_err(service_error)?;
    Ok(Json(IngestTokenList {
        tokens,
        install_token: install_token_state(service, settings).await?,
        sources,
    }))
}

#[utoipa::path(post, path = "/api/ingest-tokens", tag = "ingest_tokens",
    request_body = CreateIngestTokenRequest,
    responses((status = 201, body = IssuedIngestToken, description = "Issued; `token` is shown once"),
        (status = 400, description = "Invalid name, or the source does not exist / cannot receive pushed events"),
        (status = 403, description = "Forbidden (admins only)"),
        (status = 409, description = "An active token has this name"),
        (status = 503, description = "Vector's tokens file could not be written; nothing was issued")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn create_ingest_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateIngestTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    dedicated_only(&state)?;
    let (credential, token) = state
        .ingest_token_service
        .create(&request.name, request.source_id, Some(auth.user_id()))
        .await
        .map_err(service_error)?;
    audit(
        &state,
        &auth,
        &client,
        INGEST_TOKEN_CREATED,
        Some(credential.credential_id),
        Some(credential.name.clone()),
        serde_json::json!({
            "token_prefix": credential.token_prefix,
            "source_id": credential.source_id,
            "route_key": credential.route_key,
        }),
    );
    let mut response = (
        StatusCode::CREATED,
        Json(IssuedIngestToken { credential, token }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[utoipa::path(post, path = "/api/ingest-tokens/{credential_id}/bind", tag = "ingest_tokens",
    params(("credential_id" = Uuid, Path, description = "Credential id")),
    request_body = BindIngestTokenRequest,
    responses((status = 200, body = IngestToken, description = "Bound; Vector accepts the token within seconds"),
        (status = 400, description = "The source does not exist or cannot receive pushed events"),
        (status = 403, description = "Forbidden (admins only)"), (status = 404, description = "Not found"),
        (status = 409, description = "Already bound (bindings never change) or revoked"),
        (status = 503, description = "Bound, but Vector's tokens file update is still pending")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn bind_ingest_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(credential_id): Path<Uuid>,
    Json(request): Json<BindIngestTokenRequest>,
) -> Result<Json<IngestToken>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    dedicated_only(&state)?;
    let result = state
        .ingest_token_service
        .bind(credential_id, request.source_id, Some(auth.user_id()))
        .await;
    // A publish failure still bound the row (the reconcile retries): audit it.
    let bound = match &result {
        Ok(token) => Some((token.name.clone(), token.route_key.clone())),
        Err(IngestTokenServiceError::Publish { .. }) => Some((String::new(), None)),
        Err(_) => None,
    };
    if let Some((name, route_key)) = bound {
        audit(
            &state,
            &auth,
            &client,
            INGEST_TOKEN_BOUND,
            Some(credential_id),
            (!name.is_empty()).then_some(name),
            serde_json::json!({ "source_id": request.source_id, "route_key": route_key }),
        );
    }
    result.map(Json).map_err(service_error)
}

#[utoipa::path(post, path = "/api/ingest-tokens/{credential_id}/revoke", tag = "ingest_tokens",
    params(("credential_id" = Uuid, Path, description = "Credential id")),
    responses((status = 200, body = IngestToken), (status = 403, description = "Forbidden (admins only)"),
        (status = 404, description = "Not found"), (status = 409, description = "Already revoked"),
        (status = 503, description = "Revoked, but Vector's tokens file update is still pending")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn revoke_ingest_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<Json<IngestToken>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    dedicated_only(&state)?;
    let result = state
        .ingest_token_service
        .revoke(credential_id, Some(auth.user_id()))
        .await;
    // A publish failure still revoked the row: audit it, then report the error.
    let revoked = match &result {
        Ok(token) => Some((
            token.credential_id,
            token.name.clone(),
            token.token_prefix.clone(),
        )),
        Err(IngestTokenServiceError::Publish { .. }) => {
            Some((credential_id, String::new(), String::new()))
        }
        Err(_) => None,
    };
    if let Some((id, name, prefix)) = revoked {
        audit(
            &state,
            &auth,
            &client,
            INGEST_TOKEN_REVOKED,
            Some(id),
            (!name.is_empty()).then_some(name),
            serde_json::json!({ "token_prefix": prefix }),
        );
    }
    result.map(Json).map_err(service_error)
}

#[utoipa::path(put, path = "/api/ingest-tokens/install-token", tag = "ingest_tokens",
    request_body = UpdateInstallTokenRequest,
    responses((status = 200, body = InstallTokenState),
        (status = 400, description = "Empty request, or the source does not exist / cannot receive pushed events"),
        (status = 403, description = "Forbidden (admins only)"),
        (status = 409, description = "The install token is already bound (bindings never change)"),
        (status = 503, description = "Saved, but Vector's tokens file update is still pending")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn update_install_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateInstallTokenRequest>,
) -> Result<Json<InstallTokenState>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    dedicated_only(&state)?;
    if request.enabled.is_none() && request.source_id.is_none() {
        return Err(ApiError::BadRequest(
            "Set `enabled`, `source_id`, or both".into(),
        ));
    }
    let service = &state.ingest_token_service;
    // Bind first: enabling an unbound install token alone accepts nothing.
    if let Some(source_id) = request.source_id {
        let result = service
            .bind_install_token(source_id, Some(auth.user_id()))
            .await;
        if matches!(&result, Ok(_) | Err(IngestTokenServiceError::Publish { .. })) {
            audit(
                &state,
                &auth,
                &client,
                INGEST_INSTALL_TOKEN_UPDATED,
                None,
                Some(INSTALL_TOKEN_NAME.into()),
                serde_json::json!({ "source_id": source_id }),
            );
        }
        result.map_err(service_error)?;
    }
    if let Some(enabled) = request.enabled {
        let result = service
            .set_install_token_enabled(enabled, Some(auth.user_id()))
            .await;
        // Saved (a publish failure is retried by the reconcile): audit it.
        if matches!(&result, Ok(_) | Err(IngestTokenServiceError::Publish { .. })) {
            audit(
                &state,
                &auth,
                &client,
                INGEST_INSTALL_TOKEN_UPDATED,
                None,
                Some(INSTALL_TOKEN_NAME.into()),
                serde_json::json!({ "enabled": enabled }),
            );
        }
        result.map_err(service_error)?;
    }
    let settings = service.settings().await.map_err(service_error)?;
    Ok(Json(install_token_state(service, settings).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_ingest_tokens,
        create_ingest_token,
        bind_ingest_token,
        revoke_ingest_token,
        update_install_token
    ),
    components(schemas(
        IngestToken,
        IngestTokenList,
        InstallTokenState,
        BindableSource,
        CreateIngestTokenRequest,
        BindIngestTokenRequest,
        IssuedIngestToken,
        UpdateInstallTokenRequest
    )),
    tags((name = "ingest_tokens", description = "Named, revocable ingest tokens, each bound to one log source (dedicated deployments)"))
)]
pub struct IngestTokensApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_rejects_unknown_fields() {
        let source = Uuid::nil().to_string();
        assert!(serde_json::from_value::<CreateIngestTokenRequest>(
            serde_json::json!({"name": "fw", "source_id": source, "token": "chosen-by-caller"})
        )
        .is_err());
        assert!(serde_json::from_value::<CreateIngestTokenRequest>(
            serde_json::json!({"name": "fw", "source_id": source, "tenant_id": "x"})
        )
        .is_err());
        // Every token is bound at creation: no source, no token.
        assert!(serde_json::from_value::<CreateIngestTokenRequest>(
            serde_json::json!({"name": "fw"})
        )
        .is_err());
        // A sourcetype is never a binding.
        assert!(serde_json::from_value::<CreateIngestTokenRequest>(
            serde_json::json!({"name": "fw", "sourcetype": "apache_access"})
        )
        .is_err());
        assert!(serde_json::from_value::<CreateIngestTokenRequest>(
            serde_json::json!({"name": "fw", "source_id": source})
        )
        .is_ok());
    }

    #[test]
    fn issued_token_debug_is_redacted() {
        let issued = IssuedIngestToken {
            credential: IngestToken {
                credential_id: Uuid::nil(),
                name: "fw".into(),
                token_prefix: "nit_abcdefgh".into(),
                state: "active".into(),
                source_id: None,
                source_name: None,
                route_key: None,
                source_bound_at: None,
                request_count: 0,
                created_at: chrono::Utc::now(),
                created_by: None,
                last_used_at: None,
                revoked_at: None,
                revoked_by: None,
                revocable: true,
            },
            token: "nit_abcdefghSECRETSECRET".into(),
        };
        assert!(!format!("{issued:?}").contains("SECRET"));
    }

    #[test]
    fn listed_token_schema_has_no_secret_fields() {
        let token = IngestToken {
            credential_id: Uuid::nil(),
            name: "fw".into(),
            token_prefix: "nit_abcdefgh".into(),
            state: "active".into(),
            source_id: None,
            source_name: None,
            route_key: None,
            source_bound_at: None,
            request_count: 0,
            created_at: chrono::Utc::now(),
            created_by: None,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
            revocable: true,
        };
        let value = serde_json::to_value(&token).unwrap();
        let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        for forbidden in ["token", "value", "token_sha256", "sha256", "hash"] {
            assert!(
                !keys.iter().any(|k| k == forbidden),
                "{forbidden} in {keys:?}"
            );
        }
    }
}
