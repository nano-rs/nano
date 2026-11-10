// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5217: the cluster-wide ingestion pause.
//!
//! - GET  /api/settings/ingestion/pause   - state (PostgreSQL) + ClickHouse guard
//! - POST /api/settings/ingestion/pause   - pause manually
//! - POST /api/settings/ingestion/resume  - resume (manual or automatic pause)
//! - GET  /api/internal/ingest-admission  - nginx auth_request: 204 admit, 423 paused
//!
//! The state lives in `system_settings`, so every app host reports the same
//! answer. See `nanosiem_core::settings::ingestion_pause` for how a pause is
//! enforced on every ingest path.

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, INGESTION_PAUSED, INGESTION_RESUMED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::settings::{
    IngestionGuardState, IngestionPauseError, IngestionPauseSource, IngestionPauseState,
    PAUSED_RETRY_AFTER_SECS,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Ingestion pause status.
#[derive(Debug, Serialize, ToSchema)]
pub struct IngestionPauseStatusResponse {
    /// Whether ingestion is paused, cluster-wide.
    pub paused: bool,
    /// `disk_pressure` (automatic, lifted when disk usage recovers) or
    /// `manual` (lifted only by an administrator).
    pub source: Option<IngestionPauseSource>,
    pub reason: Option<String>,
    pub paused_at: Option<chrono::DateTime<chrono::Utc>>,
    pub paused_by: Option<uuid::Uuid>,
    /// Whether ClickHouse currently refuses writes by the ingest users:
    /// `applied`, `absent` or `unknown`. While paused, `absent` means the
    /// guard is pending (the jobs leader re-applies it every check).
    pub clickhouse_guard: IngestionGuardState,
    /// The ClickHouse users the guard applies to.
    pub clickhouse_users: Vec<String>,
    /// Whether the disk-pressure monitor may pause automatically
    /// (`DISK_PRESSURE_PAUSE_INGESTION`).
    pub auto_pause_enabled: bool,
}

/// Body of `POST /api/settings/ingestion/pause`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct PauseIngestionRequest {
    /// Why ingestion is paused (shown in the UI and the audit log).
    #[serde(default)]
    pub reason: Option<String>,
}

fn unavailable(error: IngestionPauseError) -> ApiError {
    tracing::error!(%error, "ingestion pause");
    ApiError::ServiceUnavailable("Ingestion pause state is unavailable".to_string())
}

pub(crate) async fn build_status(
    state: &AppState,
    pause: IngestionPauseState,
) -> IngestionPauseStatusResponse {
    let clickhouse_guard = state.ingestion_pause.guard_state().await;
    IngestionPauseStatusResponse {
        paused: pause.paused,
        source: pause.source,
        reason: pause.reason,
        paused_at: pause.paused_at,
        paused_by: pause.paused_by,
        clickhouse_guard,
        clickhouse_users: state.ingestion_pause.guarded_users().to_vec(),
        auto_pause_enabled: state.disk_pressure_service.auto_pause_enabled(),
    }
}

/// Get the ingestion pause state
#[utoipa::path(
    get,
    path = "/api/settings/ingestion/pause",
    tag = "settings",
    responses(
        (status = 200, description = "Ingestion pause state", body = IngestionPauseStatusResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 503, description = "State unavailable", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ingestion_pause(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<IngestionPauseStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;
    let pause = state.ingestion_pause.state().await.map_err(unavailable)?;
    Ok(Json(build_status(&state, pause).await))
}

/// Pause ingestion cluster-wide
///
/// Every ingest path refuses or back-pressures within seconds: the ingest edge
/// answers HTTP/HEC/OTLP with 503 + Retry-After, ClickHouse refuses writes by
/// the ingest users (Vector holds events in its disk buffer and retries), and
/// the connector runner stops claiming feed runs. Lifted only by resume.
#[utoipa::path(
    post,
    path = "/api/settings/ingestion/pause",
    tag = "settings",
    request_body = PauseIngestionRequest,
    responses(
        (status = 200, description = "Ingestion paused", body = IngestionPauseStatusResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 503, description = "State unavailable", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn pause_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    body: Option<Json<PauseIngestionRequest>>,
) -> Result<Json<IngestionPauseStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    let request = body.map(|Json(b)| b).unwrap_or_default();
    let (pause, changed) = state
        .ingestion_pause
        .pause(
            IngestionPauseSource::Manual,
            request.reason.as_deref(),
            Some(auth.user_id()),
        )
        .await
        .map_err(unavailable)?;
    if changed {
        state
            .emit_audit_durable(
                AuditEvent::builder(AuditSource::Settings, INGESTION_PAUSED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("ingestion", None, Some("ingestion".to_string()))
                    .details(serde_json::json!({
                        "source": IngestionPauseSource::Manual.as_str(),
                        "reason": pause.reason,
                    }))
                    .client_context(&client)
                    .build(),
            )
            .await;
    }
    Ok(Json(build_status(&state, pause).await))
}

/// Resume ingestion
///
/// Lifts a manual or an automatic (disk-pressure) pause. If disk usage is
/// still at the emergency level, the disk-pressure monitor pauses again on its
/// next check.
#[utoipa::path(
    post,
    path = "/api/settings/ingestion/resume",
    tag = "settings",
    responses(
        (status = 200, description = "Ingestion resumed", body = IngestionPauseStatusResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 503, description = "State unavailable", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn resume_ingestion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<IngestionPauseStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    let (before, changed) = state.ingestion_pause.resume(false).await.map_err(unavailable)?;
    if changed {
        state
            .emit_audit_durable(
                AuditEvent::builder(AuditSource::Settings, INGESTION_RESUMED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("ingestion", None, Some("ingestion".to_string()))
                    .details(serde_json::json!({
                        "source": IngestionPauseSource::Manual.as_str(),
                        "lifted_pause_source": before.source.map(|s| s.as_str()),
                        "lifted_pause_reason": before.reason,
                    }))
                    .client_context(&client)
                    .build(),
            )
            .await;
    }
    let pause = state.ingestion_pause.state().await.map_err(unavailable)?;
    Ok(Json(build_status(&state, pause).await))
}

// nginx auth_request for every ingest location; no user session.
#[utoipa::path(
    get,
    path = "/api/internal/ingest-admission",
    tag = "settings",
    summary = "Ingest edge admission check",
    description = "Served to the nginx ingest edge's auth_request subrequest (nginx returns 404 for direct requests). 204 admits the ingest request; 423 (a status no older API answers this path with) means ingestion is paused, which the edge turns into 503 with Retry-After so senders keep the data and retry. The edge admits on any other status, so an older API during a rolling upgrade or rollback (404), an IP allowlist (403) or an outage never refuses ingestion.",
    responses(
        (status = 204, description = "Ingestion active: admit"),
        (status = 423, description = "Ingestion paused: the edge refuses with 503 + Retry-After")
    )
)]
pub async fn ingest_admission(State(state): State<AppState>) -> axum::response::Response {
    admission_response(state.ingestion_pause.admission_paused().await)
}

/// The admission answer. Paused is 423, never 403/404: the edge treats every
/// status except 2xx and 423 as "admit" (fail open), so only this explicit
/// answer can refuse ingestion.
pub fn admission_response(paused: bool) -> axum::response::Response {
    paused_response(paused, StatusCode::LOCKED)
}

/// The OTLP credential check's answer for a valid credential while paused.
/// nginx `auth_request` only distinguishes 2xx/401/403, so it is 403 there
/// (the edge maps it to 503); a pre-NAN-5217 otlp-auth never answers 403.
pub fn otlp_paused_response() -> axum::response::Response {
    paused_response(true, StatusCode::FORBIDDEN)
}

fn paused_response(paused: bool, paused_status: StatusCode) -> axum::response::Response {
    let mut response = if paused {
        paused_status.into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    };
    let headers = response.headers_mut();
    if paused {
        headers.insert("x-nano-ingestion-paused", HeaderValue::from_static("1"));
        headers.insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&PAUSED_RETRY_AFTER_SECS.to_string()).expect("digits"),
        );
    }
    // The edge caches this answer itself (a second or two); intermediaries
    // must not.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
