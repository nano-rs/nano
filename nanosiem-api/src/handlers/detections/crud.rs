// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRUD operations for detection rules

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_CREATED, RULE_DELETED, RULE_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::models::detection_rule::{RuleMode, Severity};
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{DetectionRule, NewDetectionRule, UpdateDetectionRule};

use super::strip_comments;
use super::types::*;
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// List all detection rules
///
/// Supports filtering by:
/// - severity: Filter by severity level
/// - mode: Filter by rule mode (staging, live, alerting, paused)
/// - detection_mode: Filter by detection mode (real-time, scheduled)
///
/// Requirements: 5.5
#[utoipa::path(
    get,
    path = "/api/rules",
    tag = "detections",
    params(ListDetectionsQuery),
    responses(
        (status = 200, description = "List of detection rules", body = Vec<DetectionRule>),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_detections(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListDetectionsQuery>,
) -> Result<Json<Vec<DetectionRule>>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let mut rules = if let Some(severity) = query.severity {
        state
            .detection_service
            .list_rules_by_severity(severity)
            .await?
    } else {
        state.detection_service.list_rules().await?
    };

    // Apply mode filter if provided
    if let Some(ref mode_str) = query.mode {
        use nanosiem_core::models::detection_rule::RuleMode;
        let filter_mode = match mode_str.to_lowercase().as_str() {
            "staging" => RuleMode::Staging,
            "live" => RuleMode::Live,
            "alerting" => RuleMode::Alerting,
            "paused" => RuleMode::Paused,
            _ => {
                return Err(ApiError::ValidationError(format!(
                    "Invalid mode: {}. Must be one of: staging, live, alerting, paused",
                    mode_str
                )));
            }
        };
        rules.retain(|r| r.mode == filter_mode);
    }

    // Apply detection_mode filter if provided
    if let Some(mode_str) = query.detection_mode {
        use nanosiem_core::models::detection_rule::DetectionMode;

        // Parse detection mode from string
        let filter_mode = match mode_str.to_lowercase().as_str() {
            "real-time" | "realtime" => DetectionMode::RealTime,
            "scheduled" => DetectionMode::Scheduled,
            _ => {
                return Err(ApiError::ValidationError(format!(
                    "Invalid detection_mode: {}. Must be one of: real-time, scheduled",
                    mode_str
                )));
            }
        };

        // Filter rules by detection mode
        rules.retain(|rule| rule.detection_mode == filter_mode);
    }

    // Demo isolation: hide rules created by other demo users
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if !exclude.is_empty() {
            rules.retain(|r| !exclude.contains(&r.id));
        }
    }

    Ok(Json(rules))
}

/// Get a detection rule by ID
///
/// Returns the full detection rule including:
/// - detection_mode: Execution tier (real-time, scheduled)
/// - materialized_view_name: View name for real-time rules
///
/// Requirements: 5.5
#[utoipa::path(
    get,
    path = "/api/rules/{id}",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule details", body = DetectionRule),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DetectionRule>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let rule = state.detection_service.get_rule(*id).await?;

    // Demo isolation: block access to rules created by other demo users
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if exclude.contains(&rule.id) {
            return Err(ApiError::NotFound("Detection rule not found".to_string()));
        }
    }

    Ok(Json(rule))
}

/// Create a new detection rule
///
/// Accepts `detection_mode` field to specify execution tier:
/// - real-time: ClickHouse materialized views (10-30s latency)
/// - scheduled: Cron-based execution (continuous with */1 * * * * or custom cron)
///
/// Auto-corrects real-time rules with piped commands to scheduled mode.
///
/// Requirements: 5.1, 5.5
#[utoipa::path(
    post,
    path = "/api/rules",
    tag = "detections",
    request_body = NewDetectionRule,
    responses(
        (status = 200, description = "Detection rule created successfully", body = DetectionResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:create", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(mut request): Json<NewDetectionRule>,
) -> Result<Json<DetectionResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_CREATE)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:create".to_string()))?;

    // Tier enforcement: check detection rule limit
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

    // Strip comments from the query (// and /* */ style)
    request.query = strip_comments(&request.query);

    // Auto-populate author from logged-in user if not provided
    // Note: User name is fetched from database since JWTs no longer contain PII
    if request.author.is_none() {
        if let Ok(user) = state.user_repo.get_user_by_id(auth.user_id()).await {
            request.author = Some(user.name);
        }
    }

    // Validate risk fields (Requirements: 7.2, 8.5)
    if let Err(e) = request.validate_risk_fields() {
        return Err(ApiError::ValidationError(e.to_string()));
    }

    // Validate field constraints (case_visibility, lookback_minutes, folder)
    if let Err(e) = request.validate_fields() {
        return Err(ApiError::ValidationError(e.to_string()));
    }

    // Auto-correct real-time rules with piped commands
    use nanosiem_core::detection::materialized_view::MaterializedViewGenerator;
    use nanosiem_core::models::detection_rule::DetectionMode;

    let mut warning = None;

    tracing::info!(
        "Creating detection '{}' with detection_mode: {:?}, query has pipes: {}",
        request.name,
        request.detection_mode,
        MaterializedViewGenerator::has_piped_commands(&request.query)
    );

    if request.detection_mode == Some(DetectionMode::RealTime)
        && MaterializedViewGenerator::has_piped_commands(&request.query)
    {
        // Auto-switch to scheduled mode
        request.detection_mode = Some(DetectionMode::Scheduled);

        // Set a fast schedule if not already set (30 seconds)
        if request.schedule_cron.is_none() {
            request.schedule_cron = Some("*/30 * * * * *".to_string());
        }

        warning = Some(
            "Detection mode automatically changed from 'real-time' to 'scheduled' because the query contains piped commands (prevalence, stats, where, etc.). Real-time detections only support simple filter queries. The rule will run every 30 seconds for near-real-time detection.".to_string()
        );

        tracing::info!(
            "Auto-corrected detection mode from real-time to scheduled for rule '{}' due to piped commands",
            request.name
        );
    }

    // Create rule with mode-based routing
    let rule = state
        .detection_service
        .create_rule_with_mode(request, state.materialized_view_generator.as_ref())
        .await?;

    // Persist next_run_at for distributed scheduling
    state.detection_service.sync_next_run_at(&rule).await;

    // Add to real-time evaluator if alerting and realtime-enabled
    if rule.mode == RuleMode::Alerting && rule.realtime_enabled {
        if let Err(e) = state.realtime_evaluator.add_rule(&rule).await {
            tracing::warn!("Failed to add rule to real-time evaluator: {}", e);
        }
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(rule.id), Some(rule.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "severity": rule.severity,
                "detection_mode": rule.detection_mode,
                "mode": rule.mode,
            }))
            .build(),
    );

    // Track resource for demo session cleanup
    state.track_demo_resource(
        auth.user_id(),
        nanosiem_core::demo::DemoResourceType::Rule,
        rule.id,
    );

    tracing::info!(
        "Returning detection response for '{}' with warning: {:?}",
        rule.name,
        warning
    );

    Ok(Json(DetectionResponse { rule, warning }))
}

/// Update a detection rule
///
/// Handles detection mode transitions and updates the appropriate execution tier.
/// Auto-corrects real-time rules with piped commands to scheduled mode.
///
/// Requirements: 4.4, 5.5
#[utoipa::path(
    put,
    path = "/api/rules/{id}",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    request_body = UpdateDetectionRule,
    responses(
        (status = 200, description = "Detection rule updated successfully", body = DetectionResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:edit", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(mut request): Json<UpdateDetectionRule>,
) -> Result<Json<DetectionResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    // Fetch current rule state for audit diff
    let old_rule = state.detection_service.get_rule(*id).await?;

    // Lifecycle / weakening fields require detections:promote, matching the
    // dedicated /pause, /resume, /promote, /demote, and /bulk-update endpoints.
    // Run before the detection_mode auto-correct so the gate sees the caller's
    // original intent, not the server-rewritten request.
    if requires_promote_for_update(&old_rule, &request)
        && !auth.has_permission(permissions::DETECTIONS_PROMOTE)
    {
        return Err(ApiError::Forbidden(
            "Missing permission: detections:promote".to_string(),
        ));
    }

    // Strip comments from the query if present (// and /* */ style)
    if let Some(ref query) = request.query {
        request.query = Some(strip_comments(query));
    }

    // Validate risk fields (Requirements: 7.2, 8.5)
    if let Err(e) = request.validate_risk_fields() {
        return Err(ApiError::ValidationError(e.to_string()));
    }

    // Validate field constraints (case_visibility, lookback_minutes, folder)
    if let Err(e) = request.validate_fields() {
        return Err(ApiError::ValidationError(e.to_string()));
    }

    // Auto-correct real-time rules with piped commands
    use nanosiem_core::detection::materialized_view::MaterializedViewGenerator;
    use nanosiem_core::models::detection_rule::DetectionMode;

    let mut warning = None;

    // Check if query is being updated and contains piped commands
    if let Some(ref query) = request.query {
        if request.detection_mode == Some(DetectionMode::RealTime)
            && MaterializedViewGenerator::has_piped_commands(query)
        {
            // Auto-switch to scheduled mode
            request.detection_mode = Some(DetectionMode::Scheduled);

            // Set a fast schedule if not already set (30 seconds)
            if request.schedule_cron.is_none() {
                request.schedule_cron = Some("*/30 * * * * *".to_string());
            }

            warning = Some(
                "Detection mode automatically changed from 'real-time' to 'scheduled' because the query contains piped commands (prevalence, stats, where, etc.). Real-time detections only support simple filter queries. The rule will run every 30 seconds for near-real-time detection.".to_string()
            );

            tracing::info!(
                "Auto-corrected detection mode from real-time to scheduled for rule {} due to piped commands",
                id
            );
        }
    }

    // Update rule with mode-based routing
    let rule = state
        .detection_service
        .update_rule_with_mode(
            *id,
            request,
            state.materialized_view_generator.as_ref(),
            Some(auth.user_id()),
        )
        .await?;

    // Recompute next_run_at for distributed scheduling (sets or clears based on rule state)
    state.detection_service.sync_next_run_at(&rule).await;

    // Update in real-time evaluator (handles enabled/disabled state internally)
    // This is for legacy real-time detection
    if rule.realtime_enabled {
        if let Err(e) = state.realtime_evaluator.add_rule(&rule).await {
            tracing::warn!("Failed to update rule in real-time evaluator: {}", e);
        }
    }

    // Build audit diff: only include fields that actually changed
    let mut changes = serde_json::Map::new();
    if old_rule.name != rule.name {
        changes.insert(
            "name".into(),
            serde_json::json!({"from": old_rule.name, "to": rule.name}),
        );
    }
    if old_rule.query != rule.query {
        changes.insert(
            "query".into(),
            serde_json::json!({"from": old_rule.query, "to": rule.query}),
        );
    }
    if old_rule.severity != rule.severity {
        changes.insert(
            "severity".into(),
            serde_json::json!({"from": old_rule.severity, "to": rule.severity}),
        );
    }
    if old_rule.mode != rule.mode {
        changes.insert(
            "mode".into(),
            serde_json::json!({"from": old_rule.mode, "to": rule.mode}),
        );
    }
    if old_rule.detection_mode != rule.detection_mode {
        changes.insert(
            "detection_mode".into(),
            serde_json::json!({"from": old_rule.detection_mode, "to": rule.detection_mode}),
        );
    }
    if old_rule.schedule_cron != rule.schedule_cron {
        changes.insert(
            "schedule_cron".into(),
            serde_json::json!({"from": old_rule.schedule_cron, "to": rule.schedule_cron}),
        );
    }
    if old_rule.description != rule.description {
        changes.insert("description".into(), serde_json::json!("changed"));
    }
    if old_rule.mitre_tactics != rule.mitre_tactics {
        changes.insert(
            "mitre_tactics".into(),
            serde_json::json!({"from": old_rule.mitre_tactics, "to": rule.mitre_tactics}),
        );
    }
    if old_rule.mitre_techniques != rule.mitre_techniques {
        changes.insert(
            "mitre_techniques".into(),
            serde_json::json!({"from": old_rule.mitre_techniques, "to": rule.mitre_techniques}),
        );
    }
    if old_rule.risk_score != rule.risk_score {
        changes.insert(
            "risk_score".into(),
            serde_json::json!({"from": old_rule.risk_score, "to": rule.risk_score}),
        );
    }
    if old_rule.risk_entity_field != rule.risk_entity_field {
        changes.insert(
            "risk_entity_field".into(),
            serde_json::json!({"from": old_rule.risk_entity_field, "to": rule.risk_entity_field}),
        );
    }
    if old_rule.tags != rule.tags {
        changes.insert(
            "tags".into(),
            serde_json::json!({"from": old_rule.tags, "to": rule.tags}),
        );
    }
    if old_rule.folder != rule.folder {
        changes.insert(
            "folder".into(),
            serde_json::json!({"from": old_rule.folder, "to": rule.folder}),
        );
    }

    // Emit audit event with diff
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(rule.id), Some(rule.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "changes": changes,
            }))
            .build(),
    );

    Ok(Json(DetectionResponse { rule, warning }))
}

/// Delete a detection rule
///
/// Cleans up the appropriate execution tier before deleting the rule.
///
/// Requirements: 4.5
#[utoipa::path(
    delete,
    path = "/api/rules/{id}",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Detection rule deleted successfully", body = inline(Object)),
        (status = 403, description = "Missing permission: detections:delete", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_DELETE)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:delete".to_string()))?;

    // Get the rule name before deleting for audit
    let rule_name = state
        .detection_service
        .get_rule(*id)
        .await
        .map(|r| r.name)
        .unwrap_or_else(|_| "unknown".to_string());

    // Delete rule with mode-based cleanup (row deletion clears next_run_at)
    state
        .detection_service
        .delete_rule_with_mode(*id, state.materialized_view_generator.as_ref())
        .await?;

    // Remove from real-time evaluator (legacy real-time detection)
    state.realtime_evaluator.remove_rule(*id).await;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule_name))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({"deleted": true})))
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Informational => 0,
    }
}

/// Returns true when the request mutates a field that should be gated on
/// `detections:promote` rather than `detections:edit`. The dedicated lifecycle
/// endpoints (pause/resume/promote/demote/bulk-update) already require promote;
/// this helper enforces the same boundary on the generic update path.
fn requires_promote_for_update(old: &DetectionRule, req: &UpdateDetectionRule) -> bool {
    if let Some(new_mode) = req.mode {
        if new_mode != old.mode {
            return true;
        }
    }
    if let Some(new_dm) = req.detection_mode {
        if new_dm != old.detection_mode {
            return true;
        }
    }
    if let Some(new_rt) = req.realtime_enabled {
        if new_rt != old.realtime_enabled {
            return true;
        }
    }
    if let Some(ref new_cron) = req.schedule_cron {
        if Some(new_cron) != old.schedule_cron.as_ref() {
            return true;
        }
    }
    if let Some(new_sev) = req.severity {
        if severity_rank(new_sev) < severity_rank(old.severity) {
            return true;
        }
    }
    if let Some(new_archived) = req.archived {
        if new_archived != old.archived {
            return true;
        }
    }
    if let Some(new_lookback) = req.lookback_minutes {
        match old.lookback_minutes {
            Some(old_lookback) if new_lookback < old_lookback => return true,
            None => return true,
            _ => {}
        }
    }
    if matches!(req.auto_tuning_enabled, Some(false)) && old.auto_tuning_enabled {
        return true;
    }
    if matches!(req.auto_tuning_critical, Some(false)) && old.auto_tuning_critical {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use nanosiem_core::models::detection_rule::{AlertMode, DetectionMode};
    use uuid::Uuid;

    fn baseline_rule() -> DetectionRule {
        DetectionRule {
            id: Uuid::new_v4(),
            name: "test".into(),
            description: None,
            query: "*".into(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: Some("*/1 * * * *".into()),
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            detection_mode: DetectionMode::Scheduled,
            materialized_view_name: None,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            archived: false,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
            lookback_minutes: Some(60),
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: true,
            auto_tuning_disabled_until: None,
            case_visibility: "public".into(),
            case_assigned_group: None,
            alert_mode: AlertMode::Grouped,
            next_run_at: None,
            claimed_by: None,
            claimed_at: None,
            playbook_selector_mode: "none".into(),
            playbook_id: None,
        }
    }

    #[test]
    fn benign_edits_do_not_require_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            name: Some("renamed".into()),
            description: Some("new desc".into()),
            query: Some("error".into()),
            mitre_tactics: Some(vec!["TA0001".into()]),
            tags: Some(vec!["new-tag".into()]),
            risk_score: Some(75),
            folder: Some("network".into()),
            alert_mode: Some(AlertMode::PerEvent),
            ..Default::default()
        };
        assert!(!requires_promote_for_update(&old, &req));
    }

    #[test]
    fn severity_upgrade_does_not_require_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            severity: Some(Severity::Critical),
            ..Default::default()
        };
        assert!(!requires_promote_for_update(&old, &req));
    }

    #[test]
    fn severity_downgrade_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            severity: Some(Severity::Informational),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn mode_change_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            mode: Some(RuleMode::Live),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn mode_unchanged_does_not_require_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            mode: Some(RuleMode::Alerting),
            ..Default::default()
        };
        assert!(!requires_promote_for_update(&old, &req));
    }

    #[test]
    fn schedule_cron_change_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            schedule_cron: Some("0 0 1 1 *".into()),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn detection_mode_change_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            detection_mode: Some(DetectionMode::RealTime),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn realtime_toggle_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            realtime_enabled: Some(true),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn archive_change_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            archived: Some(true),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn lookback_reduction_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            lookback_minutes: Some(15),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn lookback_increase_does_not_require_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            lookback_minutes: Some(120),
            ..Default::default()
        };
        assert!(!requires_promote_for_update(&old, &req));
    }

    #[test]
    fn disable_auto_tuning_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            auto_tuning_enabled: Some(false),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }

    #[test]
    fn enable_auto_tuning_does_not_require_promote() {
        let mut old = baseline_rule();
        old.auto_tuning_enabled = false;
        let req = UpdateDetectionRule {
            auto_tuning_enabled: Some(true),
            ..Default::default()
        };
        assert!(!requires_promote_for_update(&old, &req));
    }

    #[test]
    fn clear_critical_flag_requires_promote() {
        let old = baseline_rule();
        let req = UpdateDetectionRule {
            auto_tuning_critical: Some(false),
            ..Default::default()
        };
        assert!(requires_promote_for_update(&old, &req));
    }
}
