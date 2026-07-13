// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto retro-hunt rule endpoints (NAN-1791).
//!
//! A retro-hunt rule is a `detection_rules` row (`kind = 'retro_hunt'`) that,
//! on its schedule, hunts newly-landed threat-intel indicators over historical
//! logs and emits hits through the standard signal processor. These endpoints
//! create/configure such rules and expose their run history; the rules
//! themselves list / open / promote / view-matches through the SAME
//! `/api/rules/*` surface as standard rules.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RULE_CREATED, RULE_UPDATED};
use nanosiem_core::auth::permissions;
use nanosiem_core::models::retro_hunt::{
    CreateRetroHuntRequest, RetroHuntConfig, RetroHuntRuleView, RetroHuntRun,
    UpdateRetroHuntConfigRequest,
};
use nanosiem_core::models::RuleMode;
use nanosiem_core::typeid::TypeIdParam;

use super::types::DetectionResponse;
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// List the IOC feed names available to a retro-hunt rule's feed picker.
#[utoipa::path(
    get,
    path = "/api/rules/retro-hunt/feeds",
    tag = "detections",
    responses(
        (status = 200, description = "Available IOC feed names", body = Vec<String>),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_retro_hunt_feeds(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<String>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;
    let feeds = state.detection_service.list_retro_hunt_feeds().await?;
    Ok(Json(feeds))
}

/// Create an auto retro-hunt rule.
///
/// Creates a `detection_rules` row (`kind = 'retro_hunt'`) plus its retro-hunt
/// config and schedules the first run. The rule then behaves like any scheduled
/// rule for listing / promotion / matches.
#[utoipa::path(
    post,
    path = "/api/rules/retro-hunt",
    tag = "detections",
    request_body = CreateRetroHuntRequest,
    responses(
        (status = 200, description = "Created retro-hunt rule", body = DetectionResponse),
        (status = 400, description = "Invalid config", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_retro_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateRetroHuntRequest>,
) -> Result<Json<DetectionResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_CREATE)?;

    // A retro-hunt rule is an active scheduled rule (default Live, or Alerting),
    // so creating it crosses the promotion boundary — gate on detections:promote
    // exactly like create_detection does for non-staging rules (NAN-1375).
    let is_active = request.mode.map(|m| m != RuleMode::Staging).unwrap_or(true);
    if is_active && !auth.has_permission(permissions::DETECTIONS_PROMOTE) {
        return Err(ApiError::Forbidden(
            "Missing permission: detections:promote".to_string(),
        ));
    }

    // Tier enforcement: retro-hunt rules count toward the detection-rule limit.
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await?;
    if tier_limits.is_enforced() {
        let rule_count = state
            .detection_service
            .list_rules()
            .await
            .map(|r| r.len() as u32)
            .unwrap_or(0);
        nanosiem_core::check_limit(
            "detection rules",
            rule_count,
            tier_limits.max_detection_rules,
            tier_limits.tier,
            "Upgrade to Starter for unlimited detection rules.",
        )?;
    }

    let (rule, _config) = state
        .detection_service
        .create_retro_hunt_rule(&request)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(rule.id), Some(rule.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "kind": "retro_hunt",
                "severity": rule.severity,
                "mode": rule.mode,
            }))
            .build(),
    );

    Ok(Json(DetectionResponse {
        rule,
        warning: None,
    }))
}

/// Get a rule's retro-hunt config + current delta state.
#[utoipa::path(
    get,
    path = "/api/rules/{id}/retro-hunt",
    tag = "detections",
    params(("id" = String, Path, description = "Rule ID")),
    responses(
        (status = 200, description = "Retro-hunt config + state", body = RetroHuntRuleView),
        (status = 404, description = "Not a retro-hunt rule", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_retro_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<RetroHuntRuleView>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;
    let view = state
        .detection_service
        .get_retro_hunt_view(*id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Retro-hunt config not found for rule".to_string()))?;
    Ok(Json(view))
}

/// Update a rule's retro-hunt config (feeds / artifact types / lookback / cap).
#[utoipa::path(
    put,
    path = "/api/rules/{id}/retro-hunt",
    tag = "detections",
    params(("id" = String, Path, description = "Rule ID")),
    request_body = UpdateRetroHuntConfigRequest,
    responses(
        (status = 200, description = "Updated retro-hunt config", body = RetroHuntConfig),
        (status = 400, description = "Invalid config", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:edit", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_retro_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateRetroHuntConfigRequest>,
) -> Result<Json<RetroHuntConfig>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;
    let config = state
        .detection_service
        .update_retro_hunt_config(*id, &request)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), None)
            .client_context(&client)
            .details(serde_json::json!({ "kind": "retro_hunt", "config_updated": true }))
            .build(),
    );

    Ok(Json(config))
}

/// List a retro-hunt rule's recent run history (indicators processed, hits,
/// truncation).
#[utoipa::path(
    get,
    path = "/api/rules/{id}/retro-hunt/runs",
    tag = "detections",
    params(("id" = String, Path, description = "Rule ID")),
    responses(
        (status = 200, description = "Recent retro-hunt runs", body = Vec<RetroHuntRun>),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_retro_hunt_runs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Vec<RetroHuntRun>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;
    let runs = state.detection_service.list_retro_hunt_runs(*id, 50).await?;
    Ok(Json(runs))
}
