// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule lifecycle operations (pause, resume, promote, demote)

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_DEMOTED, RULE_PAUSED, RULE_PROMOTED, RULE_RESUMED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{DetectionRule, RuleMode};
use serde::Deserialize;

use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Optimistic-concurrency guard for one-step rule lifecycle transitions.
///
/// The server applies the transition only when the persisted mode still
/// matches `expected_mode`. A stale retry therefore receives 409 instead of
/// advancing the rule through a second lifecycle state. Promote and demote
/// retain a temporary bodyless compatibility path. When a body is sent, all
/// lifecycle endpoints require this field.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RuleLifecycleTransitionRequest {
    pub expected_mode: RuleMode,
}

fn parse_lifecycle_transition(body: &[u8]) -> Result<Option<RuleMode>, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    #[derive(Deserialize)]
    struct LegacyCompatibleRequest {
        expected_mode: Option<RuleMode>,
    }

    let request: Option<LegacyCompatibleRequest> =
        serde_json::from_slice(body).map_err(|error| {
            ApiError::BadRequest(format!("Invalid lifecycle transition body: {error}"))
        })?;
    Ok(request.and_then(|request| request.expected_mode))
}

fn lifecycle_response_headers(legacy_bodyless: bool, replayed: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if legacy_bodyless {
        headers.insert(
            HeaderName::from_static("deprecation"),
            HeaderValue::from_static("true"),
        );
        headers.insert(
            HeaderName::from_static("warning"),
            HeaderValue::from_static(
                r#"299 nano "Bodyless lifecycle transitions are deprecated and sunset 2027-02-07; send expected_mode""#,
            ),
        );
        headers.insert(
            HeaderName::from_static("sunset"),
            HeaderValue::from_static("Sun, 07 Feb 2027 00:00:00 GMT"),
        );
    }
    if replayed {
        headers.insert(
            HeaderName::from_static("x-nano-lifecycle-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    headers
}

fn lifecycle_audit_details(from: RuleMode, to: RuleMode) -> serde_json::Value {
    serde_json::json!({
        "from": from.to_string(),
        "to": to.to_string(),
    })
}

/// Pause an active detection rule and remember its exact mode
#[utoipa::path(
    post,
    path = "/api/rules/{id}/pause",
    tag = "detections",
    description = "Pauses exactly one live or alerting rule. Send expected_mode for optimistic concurrency. Legacy bodyless requests are serialized per rule; pausing an already-paused rule is an idempotent no-op. The bodyless contract is deprecated and scheduled for removal on or after 2027-02-07.",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    request_body = Option<RuleLifecycleTransitionRequest>,
    responses(
        (status = 200, description = "Detection rule paused, or already paused", body = DetectionRule,
            headers(
                ("Deprecation" = String, description = "true only when the request omitted the legacy-optional body"),
                ("Sunset" = String, description = "Removal date for the legacy bodyless contract"),
                ("Warning" = String, description = "Migration guidance for legacy bodyless callers"),
                ("X-Nano-Lifecycle-Replayed" = String, description = "true when the bodyless request was an idempotent no-op")
            )
        ),
        (status = 400, description = "Invalid expected_mode request body", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 409, description = "Rule is not in a pausable mode", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn pause_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    body: Bytes,
) -> Result<(HeaderMap, Json<DetectionRule>), ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let expected_mode = parse_lifecycle_transition(&body)?;
    let legacy_bodyless = expected_mode.is_none();
    if legacy_bodyless {
        tracing::warn!(
            rule_id = %*id,
            "Deprecated bodyless rule pause; caller must send expected_mode"
        );
    }
    let (from_mode, rule) = state
        .detection_service
        .pause_rule(*id, expected_mode)
        .await?;

    // Clear next_run_at so the distributed scheduler stops picking it up
    if let Err(e) = state.detection_service.update_next_run_at(*id, None).await {
        tracing::warn!("Failed to clear next_run_at for paused rule: {}", e);
    }

    if let Some(from_mode) = from_mode {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Detection, RULE_PAUSED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("detection_rule", Some(*id), Some(rule.name.clone()))
                .details(lifecycle_audit_details(from_mode, rule.mode))
                .client_context(&client)
                .build(),
        );
    }

    Ok((
        lifecycle_response_headers(legacy_bodyless, from_mode.is_none()),
        Json(rule),
    ))
}

/// Resume a paused detection rule to its exact pre-pause mode
#[utoipa::path(
    post,
    path = "/api/rules/{id}/resume",
    tag = "detections",
    description = "Restores a paused rule to its persisted pre-pause mode. Send expected_mode for optimistic concurrency. Legacy bodyless requests are serialized per rule; resuming a non-paused rule is an idempotent no-op. The bodyless contract is deprecated and scheduled for removal on or after 2027-02-07.",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    request_body = Option<RuleLifecycleTransitionRequest>,
    responses(
        (status = 200, description = "Detection rule resumed to its pre-pause mode, or already non-paused", body = DetectionRule,
            headers(
                ("Deprecation" = String, description = "true only when the request omitted the legacy-optional body"),
                ("Sunset" = String, description = "Removal date for the legacy bodyless contract"),
                ("Warning" = String, description = "Migration guidance for legacy bodyless callers"),
                ("X-Nano-Lifecycle-Replayed" = String, description = "true when the bodyless request was an idempotent no-op")
            )
        ),
        (status = 400, description = "Invalid expected_mode request body", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 409, description = "Rule is not paused", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn resume_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    body: Bytes,
) -> Result<(HeaderMap, Json<DetectionRule>), ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let expected_mode = parse_lifecycle_transition(&body)?;
    let legacy_bodyless = expected_mode.is_none();
    if legacy_bodyless {
        tracing::warn!(
            rule_id = %*id,
            "Deprecated bodyless rule resume; caller must send expected_mode"
        );
    }
    let (from_mode, rule) = state
        .detection_service
        .resume_rule(*id, expected_mode)
        .await?;

    // Sync next_run_at for distributed scheduling
    state.detection_service.sync_next_run_at(&rule).await;

    if let Some(from_mode) = from_mode {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Detection, RULE_RESUMED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("detection_rule", Some(*id), Some(rule.name.clone()))
                .details(lifecycle_audit_details(from_mode, rule.mode))
                .client_context(&client)
                .build(),
        );
    }

    Ok((
        lifecycle_response_headers(legacy_bodyless, from_mode.is_none()),
        Json(rule),
    ))
}

/// Promote a rule by one lifecycle step (staging to live, or live to alerting)
#[utoipa::path(
    post,
    path = "/api/rules/{id}/promote",
    tag = "detections",
    description = "Promotes exactly one lifecycle step. Send expected_mode for optimistic concurrency. Legacy bodyless requests are serialized per rule and repeated unguarded transitions within 30 seconds return the current state. The bodyless contract is deprecated and scheduled for removal on or after 2027-02-07.",
    request_body = Option<RuleLifecycleTransitionRequest>,
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Rule promoted one step: staging to live, or live to alerting", body = DetectionRule,
            headers(
                ("Deprecation" = String, description = "true only when the request omitted the legacy-optional body"),
                ("Sunset" = String, description = "Removal date for the legacy bodyless contract"),
                ("Warning" = String, description = "Migration guidance for legacy bodyless callers"),
                ("X-Nano-Lifecycle-Replayed" = String, description = "true when an unguarded transition was suppressed inside the retry dwell")
            )
        ),
        (status = 400, description = "Invalid expected_mode request body", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 409, description = "The persisted rule mode no longer matches expected_mode, or the requested transition is invalid", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn promote_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    body: Bytes,
) -> Result<(HeaderMap, Json<DetectionRule>), ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let expected_mode = parse_lifecycle_transition(&body)?;
    let legacy_bodyless = expected_mode.is_none();
    if legacy_bodyless {
        tracing::warn!(
            rule_id = %*id,
            "Deprecated bodyless rule promotion; caller must send expected_mode"
        );
    }
    let (from_mode, rule) = state
        .detection_service
        .promote_rule(*id, expected_mode)
        .await?;

    // Sync next_run_at now that the rule is live or alerting.
    state.detection_service.sync_next_run_at(&rule).await;

    // A replay-suppressed legacy request did not perform a transition, so it
    // must not manufacture a duplicate lifecycle audit event.
    if let Some(from_mode) = from_mode {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Detection, RULE_PROMOTED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("detection_rule", Some(*id), Some(rule.name.clone()))
                .details(lifecycle_audit_details(from_mode, rule.mode))
                .client_context(&client)
                .build(),
        );
    }

    Ok((
        lifecycle_response_headers(legacy_bodyless, from_mode.is_none()),
        Json(rule),
    ))
}

/// Demote a rule by one lifecycle step (alerting to live, or live to staging)
#[utoipa::path(
    post,
    path = "/api/rules/{id}/demote",
    tag = "detections",
    description = "Demotes exactly one lifecycle step. Send expected_mode for optimistic concurrency. Legacy bodyless requests are serialized per rule and repeated unguarded transitions within 30 seconds return the current state. The bodyless contract is deprecated and scheduled for removal on or after 2027-02-07.",
    request_body = Option<RuleLifecycleTransitionRequest>,
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Rule demoted one step: alerting to live, or live to staging", body = DetectionRule,
            headers(
                ("Deprecation" = String, description = "true only when the request omitted the legacy-optional body"),
                ("Sunset" = String, description = "Removal date for the legacy bodyless contract"),
                ("Warning" = String, description = "Migration guidance for legacy bodyless callers"),
                ("X-Nano-Lifecycle-Replayed" = String, description = "true when an unguarded transition was suppressed inside the retry dwell")
            )
        ),
        (status = 400, description = "Invalid expected_mode request body", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 409, description = "The persisted rule mode no longer matches expected_mode, or the requested transition is invalid", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn demote_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    body: Bytes,
) -> Result<(HeaderMap, Json<DetectionRule>), ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let expected_mode = parse_lifecycle_transition(&body)?;
    let legacy_bodyless = expected_mode.is_none();
    if legacy_bodyless {
        tracing::warn!(
            rule_id = %*id,
            "Deprecated bodyless rule demotion; caller must send expected_mode"
        );
    }
    let (from_mode, rule) = state
        .detection_service
        .demote_rule(*id, expected_mode)
        .await?;

    // Sync next_run_at for the resulting live or staging mode.
    state.detection_service.sync_next_run_at(&rule).await;

    if let Some(from_mode) = from_mode {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Detection, RULE_DEMOTED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("detection_rule", Some(*id), Some(rule.name.clone()))
                .details(lifecycle_audit_details(from_mode, rule.mode))
                .client_context(&client)
                .build(),
        );
    }

    Ok((
        lifecycle_response_headers(legacy_bodyless, from_mode.is_none()),
        Json(rule),
    ))
}

#[cfg(test)]
mod tests {
    use super::{lifecycle_audit_details, lifecycle_response_headers, parse_lifecycle_transition};
    use nanosiem_core::RuleMode;

    #[test]
    fn lifecycle_audit_details_identify_every_transition() {
        for (from, to) in [
            (RuleMode::Staging, RuleMode::Live),
            (RuleMode::Live, RuleMode::Alerting),
            (RuleMode::Alerting, RuleMode::Live),
            (RuleMode::Live, RuleMode::Staging),
            (RuleMode::Live, RuleMode::Paused),
            (RuleMode::Alerting, RuleMode::Paused),
            (RuleMode::Paused, RuleMode::Live),
            (RuleMode::Paused, RuleMode::Alerting),
        ] {
            assert_eq!(
                lifecycle_audit_details(from, to),
                serde_json::json!({"from": from.to_string(), "to": to.to_string()})
            );
        }
    }

    #[test]
    fn lifecycle_request_accepts_legacy_empty_body_and_guarded_json() {
        assert_eq!(parse_lifecycle_transition(b"").unwrap(), None);
        assert_eq!(parse_lifecycle_transition(b"  \n").unwrap(), None);
        assert_eq!(
            parse_lifecycle_transition(br#"{"expected_mode":"live"}"#).unwrap(),
            Some(RuleMode::Live)
        );
        assert_eq!(parse_lifecycle_transition(br#"{}"#).unwrap(), None);
        assert_eq!(parse_lifecycle_transition(br#"null"#).unwrap(), None);
        assert!(parse_lifecycle_transition(br#"{"expected_mode":"bogus"}"#).is_err());
        assert!(parse_lifecycle_transition(b"{").is_err());
    }

    #[test]
    fn legacy_lifecycle_response_is_marked_deprecated() {
        let legacy = lifecycle_response_headers(true, false);
        assert_eq!(legacy.get("deprecation").unwrap(), "true");
        assert_eq!(
            legacy.get("sunset").unwrap(),
            "Sun, 07 Feb 2027 00:00:00 GMT"
        );
        assert!(legacy
            .get("warning")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("expected_mode"));
        assert!(lifecycle_response_headers(false, false).is_empty());
        assert_eq!(
            lifecycle_response_headers(true, true)
                .get("x-nano-lifecycle-replayed")
                .unwrap(),
            "true"
        );
    }
}
