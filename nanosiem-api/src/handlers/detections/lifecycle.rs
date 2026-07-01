// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule lifecycle operations (pause, resume, promote, demote)

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_DEMOTED, RULE_PAUSED, RULE_PROMOTED, RULE_RESUMED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::DetectionRule;

use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Pause a detection rule (set mode to paused)
#[utoipa::path(
    post,
    path = "/api/rules/{id}/pause",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule paused successfully", body = DetectionRule),
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
) -> Result<Json<DetectionRule>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let rule = state.detection_service.pause_rule(*id).await?;

    // Clear next_run_at so the distributed scheduler stops picking it up
    if let Err(e) = state.detection_service.update_next_run_at(*id, None).await {
        tracing::warn!("Failed to clear next_run_at for paused rule: {}", e);
    }

    // Remove from real-time evaluator
    state.realtime_evaluator.remove_rule(*id).await;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_PAUSED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(rule))
}

/// Resume a paused detection rule (set mode back to alerting)
#[utoipa::path(
    post,
    path = "/api/rules/{id}/resume",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule resumed successfully", body = DetectionRule),
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
) -> Result<Json<DetectionRule>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let rule = state.detection_service.resume_rule(*id).await?;

    // Sync next_run_at for distributed scheduling
    state.detection_service.sync_next_run_at(&rule).await;

    // Add to real-time evaluator
    if let Err(e) = state.realtime_evaluator.add_rule(&rule).await {
        tracing::warn!("Failed to add resumed rule to real-time evaluator: {}", e);
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_RESUMED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(rule))
}

/// Promote a rule from live to alerting mode
#[utoipa::path(
    post,
    path = "/api/rules/{id}/promote",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Rule promoted to alerting mode", body = DetectionRule),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn promote_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DetectionRule>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let rule = state.detection_service.promote_to_alerting(*id).await?;

    // Sync next_run_at now that rule is in alerting mode
    state.detection_service.sync_next_run_at(&rule).await;

    // Reload the rule in the real-time evaluator so it starts generating alerts
    if let Err(e) = state.realtime_evaluator.add_rule(&rule).await {
        tracing::warn!("Failed to update real-time evaluator after promote: {}", e);
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_PROMOTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(rule))
}

/// Demote a rule from alerting to live mode
#[utoipa::path(
    post,
    path = "/api/rules/{id}/demote",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Rule demoted to live mode", body = DetectionRule),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn demote_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DetectionRule>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let rule = state.detection_service.demote_to_live(*id).await?;

    // Sync next_run_at (rule is still scheduled in live mode, just no alerts)
    state.detection_service.sync_next_run_at(&rule).await;

    // Reload the rule in the real-time evaluator so it stops generating alerts
    if let Err(e) = state.realtime_evaluator.add_rule(&rule).await {
        tracing::warn!("Failed to update real-time evaluator after demote: {}", e);
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_DEMOTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(rule))
}
