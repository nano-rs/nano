// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bulk operations for detection rules

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RULES_BULK_UPDATED};
use nanosiem_core::auth::permissions;
use nanosiem_core::models::detection_rule::RuleMode;

use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request for bulk updating detection rules
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkUpdateRulesRequest {
    /// IDs of rules to update
    pub rule_ids: Vec<String>,
    /// Target mode to set for all selected rules
    pub mode: String,
}

/// Response from bulk update operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUpdateRulesResponse {
    /// Number of rules successfully updated
    pub updated: usize,
    /// Number of rules skipped (already in target mode)
    pub skipped: usize,
    /// Rules that failed to update
    pub failed: Vec<BulkRuleFailure>,
}

/// A single rule that failed during bulk update
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkRuleFailure {
    /// Rule ID that failed
    pub rule_id: String,
    /// Error message
    pub error: String,
}

/// Bulk update detection rule modes
///
/// Set the mode (staging, live, alerting, paused) for multiple rules at once.
/// Rules already in the target mode are skipped.
#[utoipa::path(
    post,
    path = "/api/rules/bulk-update",
    tag = "detections",
    request_body = BulkUpdateRulesRequest,
    responses(
        (status = 200, description = "Bulk update result", body = BulkUpdateRulesResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn bulk_update_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<BulkUpdateRulesRequest>,
) -> Result<Json<BulkUpdateRulesResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_PROMOTE)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:promote".to_string()))?;

    // Validate mode
    let target_mode = match request.mode.to_lowercase().as_str() {
        "staging" => RuleMode::Staging,
        "live" => RuleMode::Live,
        "alerting" => RuleMode::Alerting,
        "paused" => RuleMode::Paused,
        _ => {
            return Err(ApiError::ValidationError(format!(
                "Invalid mode: {}. Must be one of: staging, live, alerting, paused",
                request.mode
            )));
        }
    };

    // Limit batch size
    if request.rule_ids.len() > 500 {
        return Err(ApiError::ValidationError(
            "Maximum 500 rules per bulk update".to_string(),
        ));
    }

    let mode_str = request.mode.to_lowercase();
    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<BulkRuleFailure> = Vec::new();

    for rule_id_str in &request.rule_ids {
        let rule_id = match nanosiem_core::typeid::parse_any(rule_id_str) {
            Ok((_, id)) => id,
            Err(e) => {
                failed.push(BulkRuleFailure {
                    rule_id: rule_id_str.clone(),
                    error: format!("Invalid rule ID: {}", e),
                });
                continue;
            }
        };

        // Get current rule to check if already in target mode
        let current_rule = match state.detection_service.get_rule(rule_id).await {
            Ok(rule) => rule,
            Err(e) => {
                failed.push(BulkRuleFailure {
                    rule_id: rule_id_str.clone(),
                    error: format!("Rule not found: {}", e),
                });
                continue;
            }
        };

        if current_rule.mode == target_mode {
            skipped += 1;
            continue;
        }

        match state.detection_service.set_mode(rule_id, &mode_str).await {
            Ok(rule) => {
                // Handle scheduling side effects based on target mode
                match target_mode {
                    RuleMode::Paused | RuleMode::Staging => {
                        // Clear scheduling and remove from real-time evaluator
                        if let Err(e) = state
                            .detection_service
                            .update_next_run_at(rule_id, None)
                            .await
                        {
                            tracing::warn!(
                                "Failed to clear next_run_at for rule {}: {}",
                                rule_id,
                                e
                            );
                        }
                        state.realtime_evaluator.remove_rule(rule_id).await;
                    }
                    RuleMode::Live | RuleMode::Alerting => {
                        // Sync scheduling and update real-time evaluator
                        state.detection_service.sync_next_run_at(&rule).await;
                        if let Err(e) = state.realtime_evaluator.add_rule(&rule).await {
                            tracing::warn!(
                                "Failed to update real-time evaluator for rule {}: {}",
                                rule_id,
                                e
                            );
                        }
                    }
                }
                updated += 1;
            }
            Err(e) => {
                failed.push(BulkRuleFailure {
                    rule_id: rule_id_str.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    tracing::info!(
        "Bulk update rules: mode={}, updated={}, skipped={}, failed={}",
        mode_str,
        updated,
        skipped,
        failed.len()
    );

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULES_BULK_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .details(serde_json::json!({
                "mode": mode_str,
                "updated": updated,
                "skipped": skipped,
                "failed": failed.len(),
                "total_requested": request.rule_ids.len(),
            }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(BulkUpdateRulesResponse {
        updated,
        skipped,
        failed,
    }))
}
