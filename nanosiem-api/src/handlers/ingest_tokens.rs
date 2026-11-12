// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4907: named, revocable per-source ingest tokens (ported from main's
//! open-core NAN-3770 / NAN-3806 / NAN-3933 handlers, single-tenant).
//!
//! - GET  /api/internal/otlp-auth                     - nginx auth_request for OTLP (credential, not session)
//! - GET  /api/ingest-tokens                          - list tokens, install-token state, bindable sources
//! - POST /api/ingest-tokens                          - issue a token bound to a source (value returned once)
//! - POST /api/ingest-tokens/{credential_id}/bind     - bind an unbound token to a source
//! - POST /api/ingest-tokens/{credential_id}/rotate   - new value, same name + source; old value revoked
//! - POST /api/ingest-tokens/{credential_id}/revoke   - revoke a token
//! - PUT  /api/ingest-tokens/install-token            - enable/disable, bind, or leave legacy multiplex mode
//!
//! A token decides the source. Every token is bound to exactly one log source
//! at creation; every event sent with it is routed to that source whatever
//! `sourcetype` / `X-Source-Type` it declares. A token whose source was
//! deleted is unbound and refused by Vector until an admin binds it. A binding
//! never changes: rotate keeps it, revoke-and-reissue moves a sender.
//!
//! The token value appears only in the create / rotate response
//! (`Cache-Control: no-store`); it is never logged, audited or readable again.

use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, INGEST_TOKEN_BOUND, INGEST_TOKEN_CREATED,
    INGEST_TOKEN_REVOKED, INGEST_TOKEN_ROTATED, INGEST_TOKEN_SETTINGS_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::ingest_tokens::{
    BindableSource, IngestToken, IngestTokenService, IngestTokenServiceError, IngestTokenSettings,
    InstallTokenMode, TokenDelivery,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

// Credential-authenticated nginx subrequest; no user session required.
#[utoipa::path(get, path = "/api/internal/otlp-auth", tag = "ingest_tokens",
    summary = "Authenticate an OTLP ingestion credential",
    description = "Requires an active source-bound ingestion Bearer credential, not a user session. No positive cache.",
    responses((status = 204, description = "Active OTLP credential; identity in X-Nano-Credential-Id, X-Nano-Source-Route and a signed, short-lived X-Nano-Identity-Assertion. Served to the nginx edge's subrequest; nginx returns 404 for direct requests"),
              (status = 401, description = "Invalid or inactive credential"),
              (status = 403, description = "Ingestion is paused (NAN-5217); the edge answers 503 with Retry-After"),
              (status = 503, description = "Credential state unavailable")),
    security(("bearer_auth" = [])))]
pub async fn authenticate_otlp(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.bytes().any(|b| b.is_ascii_whitespace()))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.ingest_token_service.authenticate_otlp(token).await {
        Ok(Some(credential)) => {
            // NAN-5217: a valid credential while ingestion is paused gets 403,
            // which the edge turns into 503 + Retry-After (an invalid one
            // still gets 401, so a paused install reveals nothing to it).
            if state.ingestion_pause.admission_paused().await {
                return crate::handlers::settings::otlp_paused_response();
            }
            let Ok(route) = HeaderValue::from_str(&credential.route) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().insert(
                "x-nano-credential-id",
                HeaderValue::from_str(&credential.id.to_string()).expect("UUID is a header value"),
            );
            response.headers_mut().insert("x-nano-source-route", route);
            // Vector trusts the identity only with this short-lived assertion
            // signed by the edge-only key, so a sender on the raw OTLP port
            // cannot forge it and a captured one expires.
            if let Some(assertion) = state.ingest_token_service.otlp_identity_assertion(&credential) {
                response.headers_mut().insert(
                    "x-nano-identity-assertion",
                    HeaderValue::from_str(&assertion).expect("digits and hex are a header value"),
                );
            }
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// Display name of the install-wide `VECTOR_AUTH_TOKEN`.
pub const INSTALL_TOKEN_NAME: &str = "Install token (legacy)";

/// The install-wide token's state. Its value is never returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct InstallTokenState {
    /// Always "Install token (legacy)".
    pub name: String,
    /// The admin switch. Disabled = refused in every mode.
    pub enabled: bool,
    /// `strict` (accepted only while bound) or `legacy_multiplex` (deprecated:
    /// routed by the sender's X-Source-Type / sourcetype).
    pub mode: InstallTokenMode,
    /// `legacy_multiplex` (accepted, routed by what the sender declares;
    /// deprecated), `active` (strict and bound), `unbound` (strict, refused
    /// until it is bound), `disabled`, `public_refused` (`VECTOR_AUTH_TOKEN`
    /// is a publicly known default, refused for ingest: NAN-5013), or
    /// `not_configured` (no `VECTOR_AUTH_TOKEN`).
    pub state: String,
    /// Whether the current state is deprecated (legacy multiplex).
    pub deprecated: bool,
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
    /// Log sources a token can be bound to (token-authenticated push lanes:
    /// HTTP, HEC, OTLP; never a pulled source or the Vector-native listener).
    pub sources: Vec<BindableSource>,
    /// How the tokens file reaches Vector. `none`: issuing, rotating and
    /// binding are refused for this deployment.
    pub delivery: TokenDelivery,
}

/// `POST /api/ingest-tokens`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateIngestTokenRequest {
    /// Sender name, 1-100 characters, unique among active tokens.
    pub name: String,
    /// The log source every event sent with this token lands in (required;
    /// see `sources` in the list response). Never changes. A log source
    /// TypeID (`ls_…`, as `/api/log-sources` returns it) or a bare UUID.
    #[serde(deserialize_with = "nanosiem_core::typeid::log_source::deserialize")]
    #[schema(value_type = String, example = "ls_01h455vb4pex5vsknk084sn02q")]
    pub source_id: Uuid,
}

/// `POST /api/ingest-tokens/{credential_id}/bind`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindIngestTokenRequest {
    /// A log source TypeID or a bare UUID.
    #[serde(deserialize_with = "nanosiem_core::typeid::log_source::deserialize")]
    #[schema(value_type = String, example = "ls_01h455vb4pex5vsknk084sn02q")]
    pub source_id: Uuid,
}

/// The issued token. `token` is shown once and cannot be read again.
#[derive(Serialize, ToSchema)]
pub struct IssuedIngestToken {
    pub credential: IngestToken,
    /// The token value. Send it as `Authorization: Splunk <token>` (HEC) or
    /// `Authorization: Bearer <token>` (HTTP ingest, OTLP through `/otlp`).
    pub token: String,
    /// On a rotation: the replaced token, now revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced: Option<IngestToken>,
    /// NAN-5285 (F7): seconds until every ingest host accepts the new token
    /// (each host pulls the token list every 2 s; Vector re-reads it every
    /// 2 s). A sender that gets 401 inside this window should retry.
    pub active_within_secs: u64,
}

/// Upper bound on a new token's propagation to every ingest host.
pub const TOKEN_ACTIVE_WITHIN_SECS: u64 = 10;

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
    /// Binds the install token to this log source (only while it is
    /// unbound). Binding also leaves legacy multiplex mode. A log source
    /// TypeID or a bare UUID.
    #[serde(default, deserialize_with = "nanosiem_core::typeid::log_source::opt::deserialize")]
    #[schema(value_type = Option<String>, example = "ls_01h455vb4pex5vsknk084sn02q")]
    pub source_id: Option<Uuid>,
    /// `strict` leaves the deprecated legacy multiplex mode (one-way; the
    /// unbound install token is then refused). `legacy_multiplex` is refused.
    #[serde(default)]
    pub mode: Option<InstallTokenMode>,
}

pub(crate) fn service_error(error: IngestTokenServiceError) -> ApiError {
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
        IngestTokenServiceError::NotRotatable => ApiError::Conflict(
            "Only an active, bound token with no rotation in progress can be rotated".into(),
        ),
        IngestTokenServiceError::DeliveryNotConfigured => ApiError::ServiceUnavailable(
            "Ingest token delivery to Vector is not configured for this deployment \
             (NANO_INGEST_TOKENS_DELIVERY); a token issued now would be refused, so none was issued"
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

/// Every ingest-token action is security-critical (NAN-4907), so the record
/// is durable before the handler responds (NAN-4954).
async fn audit(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    action: &str,
    id: Option<Uuid>,
    name: Option<String>,
    details: serde_json::Value,
) {
    state
        .emit_audit_durable(
            AuditEvent::builder(AuditSource::Settings, action)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("ingest_token", id, name)
                .details(details)
                .client_context(client)
                .build(),
        )
        .await;
}

/// The install token's state label (see [`InstallTokenState::state`]).
pub(crate) fn install_state_label(
    configured: bool,
    public: bool,
    settings: &IngestTokenSettings,
    bound: bool,
) -> &'static str {
    if !configured {
        "not_configured"
    } else if public {
        "public_refused"
    } else if !settings.install_token_enabled {
        "disabled"
    } else if settings.install_token_mode == InstallTokenMode::LegacyMultiplex {
        "legacy_multiplex"
    } else if bound {
        "active"
    } else {
        "unbound"
    }
}

async fn install_token_state(
    service: &IngestTokenService,
    settings: IngestTokenSettings,
) -> Result<InstallTokenState, ApiError> {
    let source = service
        .install_token_source(&settings)
        .await
        .map_err(service_error)?;
    let state = install_state_label(
        service.install_token_configured(),
        service.install_token_is_public(),
        &settings,
        source.is_some(),
    );
    Ok(InstallTokenState {
        name: INSTALL_TOKEN_NAME.into(),
        enabled: settings.install_token_enabled,
        mode: settings.install_token_mode,
        deprecated: state == "legacy_multiplex",
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
        (status = 404, description = "Not found")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn list_ingest_tokens(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<IngestTokenList>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    let service = &state.ingest_token_service;
    let tokens = service.list().await.map_err(service_error)?;
    let settings = service.settings().await.map_err(service_error)?;
    let sources = service.bindable_sources().await.map_err(service_error)?;
    Ok(Json(IngestTokenList {
        tokens,
        install_token: install_token_state(service, settings).await?,
        sources,
        delivery: service.delivery(),
    }))
}

#[utoipa::path(post, path = "/api/ingest-tokens", tag = "ingest_tokens",
    request_body = CreateIngestTokenRequest,
    responses((status = 201, body = IssuedIngestToken, description = "Issued; `token` is shown once"),
        (status = 400, description = "Invalid name, or the source does not exist / cannot receive pushed events"),
        (status = 403, description = "Forbidden (admins only)"),
        (status = 409, description = "An active token has this name"),
        (status = 503, description = "Vector's tokens file could not be written, or token delivery is not configured for this deployment; nothing was issued")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn create_ingest_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateIngestTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
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
    ).await;
    let mut response = (
        StatusCode::CREATED,
        Json(IssuedIngestToken {
            credential,
            token,
            replaced: None,
            active_within_secs: TOKEN_ACTIVE_WITHIN_SECS,
        }),
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
        ).await;
    }
    result.map(Json).map_err(service_error)
}

#[utoipa::path(post, path = "/api/ingest-tokens/{credential_id}/rotate", tag = "ingest_tokens",
    params(("credential_id" = Uuid, Path, description = "Credential id")),
    responses((status = 201, body = IssuedIngestToken, description = "Rotated; the new `token` is shown once and the old value is revoked"),
        (status = 403, description = "Forbidden (admins only)"), (status = 404, description = "Not found"),
        (status = 409, description = "Revoked or unbound (bind it first)"),
        (status = 503, description = "Not rotated: the replacement could not be published (the old token keeps working), or token delivery is not configured")),
    security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn rotate_ingest_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let (old, new, token) = state
        .ingest_token_service
        .rotate(credential_id, Some(auth.user_id()))
        .await
        // Two-phase rotation: any error leaves the old token active and
        // nothing rotated, so there is nothing to audit.
        .map_err(service_error)?;
    audit(
        &state,
        &auth,
        &client,
        INGEST_TOKEN_ROTATED,
        Some(new.credential_id),
        Some(new.name.clone()),
        serde_json::json!({
            "replaced_credential_id": old.credential_id,
            "replaced_token_prefix": old.token_prefix,
            "token_prefix": new.token_prefix,
            "source_id": new.source_id,
            "route_key": new.route_key,
        }),
    ).await;
    let mut response = (
        StatusCode::CREATED,
        Json(IssuedIngestToken {
            credential: new,
            token,
            replaced: Some(old),
            active_within_secs: TOKEN_ACTIVE_WITHIN_SECS,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
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
        ).await;
    }
    result.map(Json).map_err(service_error)
}

#[utoipa::path(put, path = "/api/ingest-tokens/install-token", tag = "ingest_tokens",
    request_body = UpdateInstallTokenRequest,
    responses((status = 200, body = InstallTokenState),
        (status = 400, description = "Empty request, `mode: legacy_multiplex` (one-way), or the source does not exist / cannot receive pushed events"),
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
    if request.enabled.is_none() && request.source_id.is_none() && request.mode.is_none() {
        return Err(ApiError::BadRequest(
            "Set `enabled`, `source_id`, `mode`, or a combination".into(),
        ));
    }
    if request.mode == Some(InstallTokenMode::LegacyMultiplex) {
        return Err(ApiError::BadRequest(
            "Legacy multiplex mode is deprecated and cannot be re-enabled; bind the install token to a source or issue named tokens".into(),
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
                INGEST_TOKEN_SETTINGS_UPDATED,
                None,
                Some(INSTALL_TOKEN_NAME.into()),
                serde_json::json!({ "source_id": source_id, "mode": "strict" }),
            ).await;
        }
        result.map_err(service_error)?;
    }
    if request.mode == Some(InstallTokenMode::Strict) && request.source_id.is_none() {
        let result = service.set_install_token_strict(Some(auth.user_id())).await;
        if matches!(&result, Ok(_) | Err(IngestTokenServiceError::Publish { .. })) {
            audit(
                &state,
                &auth,
                &client,
                INGEST_TOKEN_SETTINGS_UPDATED,
                None,
                Some(INSTALL_TOKEN_NAME.into()),
                serde_json::json!({ "mode": "strict" }),
            ).await;
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
                INGEST_TOKEN_SETTINGS_UPDATED,
                None,
                Some(INSTALL_TOKEN_NAME.into()),
                serde_json::json!({ "enabled": enabled }),
            ).await;
        }
        result.map_err(service_error)?;
    }
    let settings = service.settings().await.map_err(service_error)?;
    Ok(Json(install_token_state(service, settings).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        authenticate_otlp,
        list_ingest_tokens,
        create_ingest_token,
        bind_ingest_token,
        rotate_ingest_token,
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
        UpdateInstallTokenRequest,
        InstallTokenMode,
        TokenDelivery
    )),
    tags((name = "ingest_tokens", description = "Named, revocable ingest tokens, each bound to one log source"))
)]
pub struct IngestTokensApiDoc;

#[cfg(test)]
#[path = "ingest_tokens_tests.rs"]
mod tests;
