// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connect-first onboarding endpoints (NAN-4912 phase 2, open core).
//!
//! * `GET  /api/log-sources/connect-status`: per-source state ("awaiting data",
//!   "receiving, not parsed", "receiving", ...) for the list and Getting started.
//! * `GET  /api/log-sources/{id}/connect-status`: one source, plus the tokens
//!   bound to it (the Add data Connect step and the detail page).
//! * `GET  /api/log-sources/unassigned`: route keys that arrive with no log
//!   source, and unbound ingest tokens.
//! * `POST /api/log-sources/unassigned/convert`: turn an unassigned key into a
//!   draft source (and bind an unbound token) without changing any token.
//!
//! The state is read from the per-source rollup with the caller's source scope
//! (NAN-2059): `log_sources:view` authorizes a source's configuration, not the
//! data it ingested, so a denied source reads as idle and a denied key is never
//! listed as unassigned.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, INGEST_TOKEN_BOUND, LOG_SOURCE_CREATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::ingest_tokens::{IngestToken, InstallTokenMode};
use nanosiem_core::log_sources::connect::{
    claimed_route_keys, connect_statuses, convert_unassigned, unassigned_sources, ConvertError, ConnectState,
    ConvertUnassignedRequest, ConvertUnassignedResponse, LogSourceConnectStatus, SourceActivity,
    SourceActivityReader, UnassignedSource, ACTIVITY_WINDOW_HOURS,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::Serialize;
use utoipa::ToSchema;

use super::ingest_tokens::service_error;
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// `GET /api/log-sources/{id}/connect-status`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogSourceConnectDetail {
    #[serde(flatten)]
    pub status: LogSourceConnectStatus,
    /// Tokens bound to this source that are not revoked.
    pub tokens: Vec<IngestToken>,
}

/// `GET /api/log-sources/unassigned`.
#[derive(Debug, Serialize, ToSchema)]
pub struct UnassignedSourcesResponse {
    /// The window `sources` covers.
    pub window_hours: i64,
    /// Route keys that arrived with no log source claiming them, busiest first.
    pub sources: Vec<UnassignedSource>,
    /// Tokens whose source was deleted: Vector refuses them until they are
    /// bound (convert one into a source, or bind it on Ingest tokens).
    pub unbound_tokens: Vec<IngestToken>,
    /// `legacy_multiplex` explains most unassigned keys: the install token is
    /// routed by what each sender declares.
    pub install_token_mode: InstallTokenMode,
}

fn reader(state: &AppState) -> SourceActivityReader {
    let pool = state.dual_pool();
    SourceActivityReader::new(pool.clickhouse().clone(), pool.table_names())
}

fn activity_unavailable(error: String) -> ApiError {
    tracing::warn!(%error, "log source activity scan failed");
    ApiError::ServiceUnavailable("Source activity is unavailable (ClickHouse)".into())
}

/// The unassigned inventory: every key arriving, busiest first (capped).
async fn inventory_activity(state: &AppState, auth: &AuthContext) -> Result<Vec<SourceActivity>, ApiError> {
    reader(state)
        .activity(ACTIVITY_WINDOW_HOURS, &auth.effective_viewer_scope())
        .await
        .map_err(activity_unavailable)
}

/// Activity for known sources only: exactly their claimed keys, uncapped, so a
/// quiet source among many noisy unassigned keys still reads as receiving.
async fn known_activity(
    state: &AppState,
    auth: &AuthContext,
    sources: &[nanosiem_core::log_sources::LogSource],
) -> Result<Vec<SourceActivity>, ApiError> {
    let keys: Vec<String> = claimed_route_keys(sources).into_iter().collect();
    reader(state)
        .activity_for(&keys, ACTIVITY_WINDOW_HOURS, &auth.effective_viewer_scope())
        .await
        .map_err(activity_unavailable)
}

/// Admission for the unassigned inventory (codex P1-1). Unassigned keys are
/// sender-chosen `source_type` values with no registered source, so the deny
/// set cannot hide them (nothing restricted them yet): naming them with their
/// volumes is the live source inventory, gated like `/api/source-types`
/// (`ensure_source_inventory_access`) on top of `log_sources:view`.
///
/// The connect-status endpoints stay on `log_sources:view` alone: they report
/// only REGISTERED sources the caller can already list, scope-filtered like
/// `/api/log-sources/{id}/health` and `/ingestion-history` (NAN-2059).
pub(crate) fn ensure_unassigned_access(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::LOG_SOURCES_VIEW)?;
    nanosiem_api_lib::ensure_source_inventory_access(auth)
}

/// Per-source connect state for every log source.
#[utoipa::path(
    get,
    path = "/api/log-sources/connect-status",
    tag = "log_sources",
    responses(
        (status = 200, description = "Connect state per log source", body = Vec<LogSourceConnectStatus>),
        (status = 403, description = "Forbidden"),
        (status = 503, description = "ClickHouse unavailable"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_connect_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<LogSourceConnectStatus>>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    let sources = state.log_source_service.list(None).await?;
    let tokens = state.ingest_token_service.list().await.map_err(service_error)?;
    let activity = known_activity(&state, &auth, &sources).await?;
    Ok(Json(connect_statuses(&sources, &activity, &tokens)))
}

/// One log source's connect state and the tokens bound to it.
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/connect-status",
    tag = "log_sources",
    params(("id" = String, Path, description = "Log source ID")),
    responses(
        (status = 200, description = "Connect state and bound tokens", body = LogSourceConnectDetail),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 503, description = "ClickHouse unavailable"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_connect_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<LogSourceConnectDetail>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    let source = state.log_source_service.get(*id).await?;
    let tokens: Vec<IngestToken> = state
        .ingest_token_service
        .list()
        .await
        .map_err(service_error)?
        .into_iter()
        .filter(|t| t.source_id == Some(source.id) && t.state != "revoked")
        .collect();
    let activity = known_activity(&state, &auth, std::slice::from_ref(&source)).await?;
    let status = connect_statuses(std::slice::from_ref(&source), &activity, &tokens)
        .pop()
        .ok_or_else(|| ApiError::NotFound("Enrichment sources have no connect state".into()))?;
    Ok(Json(LogSourceConnectDetail { status, tokens }))
}

/// Route keys that arrive with no log source, and unbound tokens.
#[utoipa::path(
    get,
    path = "/api/log-sources/unassigned",
    tag = "log_sources",
    responses(
        (status = 200, description = "Unassigned sources", body = UnassignedSourcesResponse),
        (status = 403, description = "Forbidden: needs log_sources:view and live source-inventory access (search:execute, log_sources:create, detections:view or source_scopes:view)"),
        (status = 503, description = "ClickHouse unavailable"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_unassigned_sources(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<UnassignedSourcesResponse>, ApiError> {
    ensure_unassigned_access(&auth)?;
    let sources = state.log_source_service.list(None).await?;
    let activity = inventory_activity(&state, &auth).await?;
    let service = &state.ingest_token_service;
    let unbound_tokens = service
        .list()
        .await
        .map_err(service_error)?
        .into_iter()
        .filter(|t| t.state == "unbound")
        .collect();
    let settings = service.settings().await.map_err(service_error)?;
    Ok(Json(UnassignedSourcesResponse {
        window_hours: ACTIVITY_WINDOW_HOURS,
        sources: unassigned_sources(&sources, &activity),
        unbound_tokens,
        install_token_mode: settings.install_token_mode,
    }))
}

fn convert_error(error: ConvertError) -> ApiError {
    match error {
        ConvertError::InvalidKey(message) => ApiError::BadRequest(message),
        ConvertError::AlreadyClaimed(owner, key) => ApiError::Conflict(format!(
            "Log source {owner:?} already receives source key {key:?}"
        )),
        ConvertError::TokenNotUnbound(message) => ApiError::Conflict(message),
        ConvertError::Token(error) => service_error(error),
        ConvertError::Source(error) => error.into(),
        ConvertError::Database(error) => {
            tracing::error!(%error, "unassigned conversion lock failed");
            ApiError::ServiceUnavailable("Could not serialise the conversion; retry".into())
        }
    }
}

/// Converts an unassigned source key into a draft log source. No token value
/// changes: senders keep their configuration. Naming an unbound token binds it.
#[utoipa::path(
    post,
    path = "/api/log-sources/unassigned/convert",
    tag = "log_sources",
    request_body = ConvertUnassignedRequest,
    responses(
        (status = 200, description = "Draft source created (and token bound)", body = ConvertUnassignedResponse),
        (status = 400, description = "The key cannot name a source (unsafe characters or platform-assigned)"),
        (status = 403, description = "Forbidden: log_sources:create; binding a token also needs settings:system"),
        (status = 404, description = "Token not found"),
        (status = 409, description = "Another source already receives this key, the name is taken, or the token is not unbound"),
        (status = 503, description = "Token delivery to Vector is not configured"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn convert_unassigned_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ConvertUnassignedRequest>,
) -> Result<Json<ConvertUnassignedResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_CREATE)?;
    if request.credential_id.is_some() {
        // Binding a token is a token-management action (as on Ingest tokens).
        ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    }
    let route_key = request.route_key.trim().to_string();
    let response = convert_unassigned(
        &state.pool,
        &state.log_source_service,
        &state.ingest_token_service,
        request,
        Some(auth.user_id()),
    )
    .await
    .map_err(convert_error)?;

    let source = &response.log_source;
    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(source.id), Some(source.name.clone()))
            .details(serde_json::json!({
                "converted_from_unassigned": route_key,
                "lifecycle_status": source.lifecycle_status,
            }))
            .client_context(&client)
            .build(),
    );
    if let Some(token) = &response.bound_token {
        state.emit_audit_durable(
            AuditEvent::builder(AuditSource::Settings, INGEST_TOKEN_BOUND)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("ingest_token", Some(token.credential_id), Some(token.name.clone()))
                .details(serde_json::json!({
                    "source_id": source.id,
                    "via": "unassigned_convert",
                    "publication_pending": response.publication_pending,
                }))
                .client_context(&client)
                .build(),
        ).await;
    }
    Ok(Json(response))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_connect_status,
        get_connect_status,
        list_unassigned_sources,
        convert_unassigned_source
    ),
    components(schemas(
        LogSourceConnectStatus,
        LogSourceConnectDetail,
        ConnectState,
        UnassignedSource,
        UnassignedSourcesResponse,
        ConvertUnassignedRequest,
        ConvertUnassignedResponse
    )),
    tags((name = "log_sources", description = "Log source management"))
)]
pub struct LogSourceConnectApiDoc;

#[cfg(test)]
#[path = "log_source_connect_tests.rs"]
mod tests;
