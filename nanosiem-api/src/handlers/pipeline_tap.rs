// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nano Pipe live tap (NAN-4919, open core):
//! `POST /api/log-sources/{id}/pipe-tap`.
//!
//! Captures events entering ONE source's pipeline slot on every configured
//! Vector relay (see `crate::pipe_tap_relay`): nano-api is the only caller of
//! each relay, and each relay is the only client of its Vector process's
//! loopback-bound API. The request blocks for the capture window (≤ 60 s),
//! merges a request-wide bounded result and returns it; nothing is persisted.
//!
//! - **Authorization:** `log_sources:view` + `search:execute` + the caller's
//!   per-source scope (raw events: the `/api/search` rule, as test-live).
//! - **Scope:** exactly the source's own `_parse` input; the component id is
//!   derived server-side, never supplied.
//! - **Redaction:** credential-named fields are removed before return.
//! - **Bounds:** 30 s / 100 events default; 60 s / 1,000 events / 64 KiB per
//!   event / 8 MiB per capture caps; Vector samples ≤ 50 events per 500 ms.
//!   One running tap per user, [`MAX_ACTIVE_TAPS`] per replica: refusals are
//!   429 + `Retry-After`.
//! - **Audit:** start and completion are audited.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use futures::stream::{self, StreamExt};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, PIPE_TAP_READ, PIPE_TAP_STARTED,
};
use nanosiem_core::auth::permissions::SEARCH_EXECUTE;
use nanosiem_core::log_sources::pipe_tap_component;
use nanosiem_core::parsers::pipe::tap::{
    self, DEFAULT_EVENTS, DEFAULT_SECONDS, MAX_CAPTURE_BYTES, RELAY_TOKEN_ENV, RELAY_URL_ENV,
    RELAY_URLS_ENV, TapCapture, TapEvent, TapRequest,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

use super::AuditExt;
use crate::middleware::{AuthContext, ensure_permission};
use crate::{error::ApiError, state::AppState};

const LOG_SOURCES_VIEW: &str = "log_sources:view";
pub const MAX_ACTIVE_TAPS: usize = 4;
const RETRY_AFTER_SECONDS: u64 = 5;
const MAX_TAP_RELAYS: usize = 32;
const MAX_CONCURRENT_RELAY_CALLS: usize = 4;

/// Whether the tap relay is configured for this nano-api.
pub fn tap_enabled() -> bool {
    let urls = relay_urls();
    !urls.is_empty()
        && urls.len() <= MAX_TAP_RELAYS
        && std::env::var(RELAY_TOKEN_ENV).is_ok_and(|v| v.len() >= tap::MIN_TOKEN_BYTES)
}

fn relay_urls() -> Vec<String> {
    let configured = std::env::var(RELAY_URLS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var(RELAY_URL_ENV).ok())
        .unwrap_or_default();
    let mut urls = Vec::new();
    for url in configured
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        if !urls.iter().any(|existing| existing == url) {
            urls.push(url.to_string());
        }
    }
    urls
}

fn active() -> &'static Mutex<HashSet<Uuid>> {
    static ACTIVE: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    ACTIVE.get_or_init(Default::default)
}

/// One running tap per user, at most [`MAX_ACTIVE_TAPS`] per replica.
/// Released on drop, including when the client disconnects.
struct TapSlot(Uuid);

impl TapSlot {
    fn acquire(user: Uuid) -> Result<Self, &'static str> {
        let mut running = active().lock().unwrap_or_else(|p| p.into_inner());
        if running.contains(&user) {
            return Err("You already have a live tap running; retry when it finishes");
        }
        if running.len() >= MAX_ACTIVE_TAPS {
            return Err("Live tap capacity is busy; retry shortly");
        }
        running.insert(user);
        Ok(Self(user))
    }
}

impl Drop for TapSlot {
    fn drop(&mut self) {
        active()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PipeTapRequest {
    /// Capture window, 1–60 s (default 30).
    pub seconds: Option<u64>,
    /// Events to capture, 1–1000 (default 100).
    pub max_events: Option<usize>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PipeTapResponse {
    /// The tapped component (the source's pipeline input).
    pub component: String,
    pub seconds: u64,
    /// Redacted events as they enter the pipeline, with input identity.
    pub events: Vec<TapEvent>,
    pub dropped_oversize: usize,
    /// `deadline`, `max_events`, `max_bytes`, `stream_closed` or
    /// `partial_failure`.
    pub ended: String,
    /// Relays that failed while other ingest nodes returned a usable capture.
    pub relay_failures: usize,
}

fn busy(message: &str) -> Response {
    let mut response = ApiError::TooManyRequests(message.into()).into_response();
    if let Ok(value) = HeaderValue::from_str(&RETRY_AFTER_SECONDS.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// Capture a live sample of events entering a source's pipeline
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/pipe-tap",
    tag = "pipelines",
    params(("id" = String, Path, description = "Log source ID")),
    request_body = PipeTapRequest,
    responses(
        (status = 200, description = "Redacted captured events", body = PipeTapResponse),
        (status = 400, description = "Invalid bounds"),
        (status = 403, description = "Missing log_sources:view or search:execute"),
        (status = 404, description = "Not found"),
        (status = 429, description = "A tap is already running; retry after Retry-After"),
        (status = 503, description = "Live tap is not configured, or Vector is unreachable"),
    ),
    security(("api_key" = []))
)]
pub async fn pipe_tap(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<PipeTapRequest>,
) -> Result<Response, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;
    ensure_permission(&auth, SEARCH_EXECUTE)?;
    let source = super::pipelines::visible_source(&state, &auth, *id).await?;
    if !tap_enabled() {
        return Err(ApiError::ServiceUnavailable(
            "Live tap is not configured on this deployment".into(),
        ));
    }
    let tap_request = TapRequest {
        component: pipe_tap_component(&source),
        seconds: request.seconds.unwrap_or(DEFAULT_SECONDS),
        max_events: request.max_events.unwrap_or(DEFAULT_EVENTS),
    };
    tap_request.validate().map_err(ApiError::BadRequest)?;
    let _slot = match TapSlot::acquire(auth.user_id()) {
        Ok(slot) => slot,
        Err(message) => return Ok(busy(message)),
    };
    let audit = |action: &'static str, details: serde_json::Value| {
        state.emit_audit(
            AuditEvent::builder(AuditSource::LogSource, action)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("log_source", Some(source.id), Some(source.name.clone()))
                .client_context(&client)
                .details(details)
                .build(),
        )
    };
    audit(
        PIPE_TAP_STARTED,
        serde_json::json!({
            "component": tap_request.component,
            "seconds": tap_request.seconds,
            "max_events": tap_request.max_events,
        }),
    );
    let (mut capture, relay_failures) = call_relays(&tap_request).await?;
    tap::redact(&mut capture).map_err(ApiError::InternalError)?;
    audit(
        PIPE_TAP_READ,
        serde_json::json!({
            "component": tap_request.component,
            "events": capture.events.len(),
            "ended": capture.ended,
            "relay_failures": relay_failures,
        }),
    );
    Ok(Json(PipeTapResponse {
        component: tap_request.component,
        seconds: tap_request.seconds,
        events: capture.events,
        dropped_oversize: capture.dropped_oversize,
        ended: capture.ended,
        relay_failures,
    })
    .into_response())
}

async fn call_one_relay(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    request: &TapRequest,
) -> Result<TapCapture, ApiError> {
    let unavailable = |_| ApiError::ServiceUnavailable("Live tap relay is unreachable".into());
    let response = client
        .post(format!("{}/v1/tap", base.trim_end_matches('/')))
        .bearer_auth(token)
        .timeout(Duration::from_secs(request.seconds + 15))
        .json(request)
        .send()
        .await
        .map_err(unavailable)?;
    match response.status().as_u16() {
        200 => {}
        429 => {
            return Err(ApiError::TooManyRequests(
                "Live tap capacity is busy; retry shortly".into(),
            ));
        }
        _ => {
            return Err(ApiError::ServiceUnavailable(
                "Live tap failed: Vector did not serve the tap".into(),
            ));
        }
    }
    // Never trust the relay's bounds: read at most the protocol maximum,
    // then re-check count and sizes after decoding.
    let capture = tap::read_relay_capture(response, request.max_events)
        .await
        .map_err(ApiError::ServiceUnavailable)?;
    Ok(capture)
}

#[derive(Default)]
struct RelayCaptureMerger {
    merged: TapCapture,
    bytes: usize,
    hit_event_bound: bool,
    hit_byte_bound: bool,
}

impl RelayCaptureMerger {
    fn push(&mut self, capture: TapCapture, max_events: usize) {
        self.merged.dropped_oversize = self
            .merged
            .dropped_oversize
            .saturating_add(capture.dropped_oversize);
        for event in capture.events {
            if self.merged.events.len() >= max_events {
                self.hit_event_bound = true;
                break;
            }
            let event_bytes =
                serde_json::to_vec(&event).map_or(MAX_CAPTURE_BYTES + 1, |body| body.len());
            if event_bytes > tap::MAX_EVENT_BYTES {
                self.merged.dropped_oversize = self.merged.dropped_oversize.saturating_add(1);
                continue;
            }
            if self.bytes.saturating_add(event_bytes) > MAX_CAPTURE_BYTES {
                self.hit_byte_bound = true;
                continue;
            }
            self.bytes += event_bytes;
            self.merged.events.push(event);
        }
    }

    fn finish(mut self, relay_failures: usize, max_events: usize) -> TapCapture {
        self.merged.ended = if self.hit_event_bound || self.merged.events.len() >= max_events {
            "max_events".into()
        } else if self.hit_byte_bound {
            "max_bytes".into()
        } else if relay_failures > 0 {
            "partial_failure".into()
        } else {
            "deadline".into()
        };
        self.merged
    }
}

async fn call_relays(request: &TapRequest) -> Result<(TapCapture, usize), ApiError> {
    let urls = relay_urls();
    if urls.is_empty() {
        return Err(ApiError::ServiceUnavailable(
            "Live tap is not configured on this deployment".into(),
        ));
    }
    if urls.len() > MAX_TAP_RELAYS {
        return Err(ApiError::ServiceUnavailable(format!(
            "Live tap is configured with more than {MAX_TAP_RELAYS} ingest relays"
        )));
    }
    let token = std::env::var(RELAY_TOKEN_ENV).unwrap_or_default();
    let client = reqwest::Client::new();
    // Each relay independently enforces its response ceiling. Keep only a
    // fixed number of those responses in flight and merge each completion
    // immediately, so memory is bounded by the request-wide capture plus
    // MAX_CONCURRENT_RELAY_CALLS relay responses rather than relay count.
    let calls = urls.into_iter().map(|base| {
        let client = client.clone();
        let token = token.clone();
        let request = request.clone();
        async move { call_one_relay(&client, &base, &token, &request).await }
    });
    let mut results = stream::iter(calls).buffer_unordered(MAX_CONCURRENT_RELAY_CALLS);
    let mut merger = RelayCaptureMerger::default();
    let mut relay_successes = 0usize;
    let mut relay_failures = 0usize;
    while let Some(result) = results.next().await {
        match result {
            Ok(capture) => {
                relay_successes += 1;
                merger.push(capture, request.max_events);
            }
            Err(_) => relay_failures += 1,
        }
    }
    if relay_successes == 0 {
        return Err(ApiError::ServiceUnavailable(
            "Live tap relays are unreachable".into(),
        ));
    }
    if relay_failures > 0 {
        tracing::warn!(
            relay_failures,
            "live tap returned a partial multi-ingest capture"
        );
    }
    Ok((
        merger.finish(relay_failures, request.max_events),
        relay_failures,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(pipe_tap),
    components(schemas(PipeTapRequest, PipeTapResponse, TapEvent))
)]
pub struct PipelineTapApiDoc;

#[cfg(test)]
mod multi_relay_tests {
    use super::*;

    fn capture(node: u64) -> TapCapture {
        TapCapture {
            events: vec![TapEvent {
                event: serde_json::json!({"node": node}),
                input: Some(format!("push:{node}")),
            }],
            dropped_oversize: 0,
            ended: "deadline".into(),
        }
    }

    #[test]
    fn merges_every_available_relay_and_reports_per_node_failure() {
        let mut merger = RelayCaptureMerger::default();
        merger.push(capture(1), 10);
        merger.push(capture(2), 10);
        let merged = merger.finish(1, 10);
        assert_eq!(merged.events.len(), 2);
        assert_eq!(merged.ended, "partial_failure");
    }

    #[test]
    fn merged_capture_keeps_the_request_wide_event_bound() {
        let mut merger = RelayCaptureMerger::default();
        merger.push(capture(1), 1);
        merger.push(capture(2), 1);
        let merged = merger.finish(0, 1);
        assert_eq!(merged.events.len(), 1);
        assert_eq!(merged.ended, "max_events");
    }

    #[test]
    fn incremental_merge_keeps_many_relays_under_the_aggregate_byte_bound() {
        let mut merger = RelayCaptureMerger::default();
        let total_events = MAX_TAP_RELAYS * 8;
        for node in 0..MAX_TAP_RELAYS {
            let event = TapEvent {
                event: serde_json::json!({
                    "node": node,
                    "message": "x".repeat(tap::MAX_EVENT_BYTES / 2),
                }),
                input: None,
            };
            merger.push(
                TapCapture {
                    events: vec![event; 8],
                    dropped_oversize: 0,
                    ended: "deadline".into(),
                },
                total_events,
            );
        }

        let merged = merger.finish(0, total_events);
        let bytes: usize = merged
            .events
            .iter()
            .map(|event| serde_json::to_vec(event).unwrap().len())
            .sum();
        assert!(bytes <= MAX_CAPTURE_BYTES);
        assert!(merged.events.len() < total_events);
        assert_eq!(merged.ended, "max_bytes");
    }
}
