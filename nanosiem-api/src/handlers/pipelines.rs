// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nano Pipe endpoints (NAN-4919, open core).
//!
//! A pipeline is a log source's parser written as ordered steps; it is SAVED,
//! PUBLISHED, VERSIONED and REVERTED through the existing log-source
//! endpoints (`PUT /api/log-sources/{id}`, `/publish`, `/versions`,
//! `/revert`, `/discard-draft`). These endpoints add what authoring needs:
//!
//! - `GET  /api/log-sources/{id}/pipe-capabilities` — step kinds, bounds and
//!   which features this deployment enables;
//! - `POST /api/log-sources/{id}/pipe-preview` — run a draft over ≤100 events
//!   in the isolated preview worker (off unless `NANO_PIPE_PREVIEW_ENABLED`);
//! - `POST /api/log-sources/{id}/pipe-samples` — recent stored events of the
//!   source from ClickHouse, under the caller's source scope (audited).

use axum::{
    extract::{Path, State},
    http::{header::RETRY_AFTER, HeaderValue},
    response::{IntoResponse, Response},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, PIPE_PREVIEWED, PIPE_RECENT_EVENTS_READ,
};
use nanosiem_core::auth::permissions::SEARCH_EXECUTE;
use nanosiem_core::log_sources::{pipe_route_key, LogSource, MAX_PIPE_SAMPLES};
use nanosiem_core::parsers::pipe::{
    native,
    preview::{
        PipePreviewEvent, PipePreviewRequest, PipePreviewResponse, PipePreviewSummary,
        PipePreviewTrace, MAX_EVENTS, MAX_EVENT_BYTES,
    },
    sandbox::{self, PreviewSandboxError},
    STATELESS_KINDS,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

const LOG_SOURCES_VIEW: &str = "log_sources:view";
const LOG_SOURCES_EDIT: &str = "log_sources:edit";

/// Load a source the caller may see. A source whose events the caller's
/// per-source scope denies is reported as missing (no existence oracle).
pub(crate) async fn visible_source(
    state: &AppState,
    auth: &AuthContext,
    id: uuid::Uuid,
) -> Result<LogSource, ApiError> {
    let source = state.log_source_service.get(id).await?;
    if auth
        .effective_viewer_scope()
        .deny_set()
        .contains(&pipe_route_key(&source))
    {
        return Err(ApiError::NotFound("Log source not found".into()));
    }
    Ok(source)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PipeBounds {
    pub max_steps: usize,
    pub max_preview_events: usize,
    pub max_preview_event_bytes: usize,
    pub max_lookup_rows: usize,
    pub max_lookup_bytes: usize,
    pub max_dedupe_cache: usize,
    pub max_combine_events: usize,
    pub max_combine_groups: usize,
    pub max_combine_expire_seconds: u64,
    pub max_route_branches: usize,
    pub max_split_outputs: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PipeCapabilities {
    /// Draft preview runs on this deployment (`NANO_PIPE_PREVIEW_ENABLED`).
    pub preview_enabled: bool,
    /// The preview worker lacks Linux resource limits (development host).
    pub preview_degraded_isolation: bool,
    /// Live tap of the source's Vector input is configured.
    pub live_tap_enabled: bool,
    /// Every step kind the editor may author (all preview).
    pub step_kinds: Vec<String>,
    /// Step kinds this deployment's Vector cannot run, with why: they
    /// preview, but publish refuses them.
    pub preview_only_kinds: Vec<PreviewOnlyKind>,
    pub bounds: PipeBounds,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewOnlyKind {
    pub kind: String,
    pub reason: String,
}

/// Nano Pipe capabilities for a log source
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/pipe-capabilities",
    tag = "pipelines",
    params(("id" = String, Path, description = "Log source ID")),
    responses(
        (status = 200, description = "Pipeline authoring capabilities", body = PipeCapabilities),
        (status = 403, description = "Missing log_sources:view"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn pipe_capabilities(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<PipeCapabilities>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;
    visible_source(&state, &auth, *id).await?;
    let runtime = native::runtime_transforms();
    let combine_probe = nanosiem_core::parsers::pipe::Plan {
        version: 2,
        revision: 1,
        steps: vec![nanosiem_core::parsers::pipe::Step {
            id: "combine".into(),
            name: "Combine".into(),
            kind: "combine".into(),
            enabled: true,
            condition: None,
            config: serde_json::Map::from_iter([(
                "keys".to_string(),
                serde_json::json!(["message"]),
            )]),
        }],
    };
    let preview_only_kinds = native::deployable_with(&combine_probe, &runtime)
        .err()
        .map(|reason| PreviewOnlyKind {
            kind: "combine".into(),
            reason,
        })
        .into_iter()
        .collect();
    Ok(Json(PipeCapabilities {
        preview_enabled: sandbox::enabled(),
        preview_degraded_isolation: !sandbox::full_isolation(),
        live_tap_enabled: super::pipeline_tap::tap_enabled(),
        step_kinds: STATELESS_KINDS
            .iter()
            .chain(native::KINDS.iter())
            .map(|s| s.to_string())
            .collect(),
        preview_only_kinds,
        bounds: PipeBounds {
            max_steps: 50,
            max_preview_events: MAX_EVENTS,
            max_preview_event_bytes: MAX_EVENT_BYTES,
            max_lookup_rows: 1000,
            max_lookup_bytes: native::MAX_LOOKUP_BYTES,
            max_dedupe_cache: native::MAX_DEDUPE_EVENTS,
            max_combine_events: 1000,
            max_combine_groups: native::MAX_GROUPS,
            max_combine_expire_seconds: native::MAX_EXPIRE_SEC,
            max_route_branches: 16,
            max_split_outputs: nanosiem_core::parsers::pipe::MAX_OUTPUTS,
        },
    }))
}

fn sandbox_error(error: PreviewSandboxError) -> Response {
    let retry = error.retry_after_seconds();
    let api = match error {
        PreviewSandboxError::Disabled => ApiError::ServiceUnavailable(error.to_string()),
        PreviewSandboxError::UserBusy | PreviewSandboxError::Busy => {
            ApiError::TooManyRequests(error.to_string())
        }
        PreviewSandboxError::Invalid(message) => ApiError::BadRequest(message),
        PreviewSandboxError::Deadline => ApiError::Timeout(error.to_string()),
        // One generic answer; the cause is classified in the operator log.
        _ => ApiError::ServiceUnavailable("Preview worker failed".into()),
    };
    let mut response = api.into_response();
    if let Some(seconds) = retry {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
    }
    response
}

/// Preview a draft pipeline over supplied events
///
/// Runs the draft parser (a stored plan or plain VRL; omitted = the saved
/// working copy) and extension over 1–100 events in an isolated worker
/// process. A busy worker answers 429 immediately; nothing queues.
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/pipe-preview",
    tag = "pipelines",
    params(("id" = String, Path, description = "Log source ID")),
    request_body = PipePreviewRequest,
    responses(
        (status = 200, description = "Per-event outputs, dispositions and step traces", body = PipePreviewResponse),
        (status = 400, description = "Invalid draft or events"),
        (status = 403, description = "Missing log_sources:edit"),
        (status = 404, description = "Not found"),
        (status = 429, description = "A preview is already running; retry after Retry-After"),
        (status = 503, description = "Preview disabled or the worker failed"),
    ),
    security(("api_key" = []))
)]
pub async fn pipe_preview(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(mut request): Json<PipePreviewRequest>,
) -> Result<Response, ApiError> {
    // Preview executes tenant-authored code: an authoring permission.
    ensure_permission(&auth, LOG_SOURCES_EDIT)?;
    let source = visible_source(&state, &auth, *id).await?;
    if request.parser_vrl.is_none() {
        request.parser_vrl = Some(source.parser_vrl.clone());
    }
    if request.extension_vrl.is_none() && source.extension_enabled {
        request.extension_vrl = source.extension_vrl.clone();
    }
    request.validate().map_err(ApiError::BadRequest)?;
    let response = match sandbox::preview(&request, auth.user_id()).await {
        Ok(response) => response,
        Err(error) => return Ok(sandbox_error(error)),
    };
    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, PIPE_PREVIEWED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(source.id), Some(source.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "events": request.events.len(),
                "engine": response.engine,
            }))
            .build(),
    );
    Ok(Json(response).into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PipeSamplesRequest {
    /// Number of recent events (1–100, default 20).
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PipeSamplesResponse {
    /// `{"message": <raw stored message>}` per event, newest first. Held
    /// in the browser for previews only; never persisted.
    #[schema(value_type = Vec<Object>)]
    pub events: Vec<serde_json::Value>,
}

/// Load recent stored events of a source as preview samples
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/pipe-samples",
    tag = "pipelines",
    params(("id" = String, Path, description = "Log source ID")),
    request_body = PipeSamplesRequest,
    responses(
        (status = 200, description = "Recent raw events", body = PipeSamplesResponse),
        (status = 403, description = "Missing log_sources:view or search:execute"),
        (status = 404, description = "Not found, or no recent events"),
    ),
    security(("api_key" = []))
)]
pub async fn pipe_samples(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<PipeSamplesRequest>,
) -> Result<Json<PipeSamplesResponse>, ApiError> {
    // Raw stored events: the same rule as /api/log-sources/test-live and
    // canonical search (NAN-2058).
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;
    ensure_permission(&auth, SEARCH_EXECUTE)?;
    let source = visible_source(&state, &auth, *id).await?;
    let limit = request.limit.unwrap_or(20).clamp(1, MAX_PIPE_SAMPLES);
    let events = state
        .log_source_service
        .pipe_recent_events(&source, limit, &auth.effective_viewer_scope())
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, PIPE_RECENT_EVENTS_READ)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(source.id), Some(source.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({ "events": events.len() }))
            .build(),
    );
    Ok(Json(PipeSamplesResponse { events }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(pipe_capabilities, pipe_preview, pipe_samples),
    components(schemas(
        PipeCapabilities,
        PipeBounds,
        PreviewOnlyKind,
        PipePreviewRequest,
        PipePreviewResponse,
        PipePreviewEvent,
        PipePreviewTrace,
        PipePreviewSummary,
        PipeSamplesRequest,
        PipeSamplesResponse,
    )),
    tags((name = "pipelines", description = "Nano Pipe: author, preview and tap log-source pipelines"))
)]
pub struct PipelinesApiDoc;
