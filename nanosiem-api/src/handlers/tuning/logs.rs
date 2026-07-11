// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, VERSION_REVERTED};
use nanosiem_core::auth::permissions;
use nanosiem_core::tuning::versions::{RuleVersionManager, TuningRevertPlan};
use nanosiem_core::tuning::{ProposalType, TuningLogEntry};
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::{ApprovalResponse, ListLogsQuery, RevertRequest};
use super::versions::{
    detection_mode_name, ensure_revert_permissions, map_version_error, reconcile_reverted_runtime,
    rule_mode_name, validate_revert_target,
};
use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

fn tuning_revert_audit_details(
    rule_id: Uuid,
    reverted_to_version: i32,
    result: &nanosiem_core::tuning::versions::VersionRevertResult,
    runtime_sync_error: Option<String>,
    notification_error: Option<String>,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "route": "tuning_log_revert",
        "rule_id": rule_id,
        "reverted_to_version": reverted_to_version,
        "new_version_id": result.version_id,
        "changed": result.changed,
        "replayed": result.replayed,
        "runtime_sync_pending": runtime_sync_error.is_some(),
        "runtime_sync_error": runtime_sync_error,
        "notification_error": notification_error,
        "reason": reason,
    })
}

/// GET /api/tuning/logs
///
/// List tuning log entries with optional filters.
///
/// Requirements: 8.1
#[utoipa::path(
    get,
    path = "/api/tuning/logs",
    tag = "tuning",
    params(ListLogsQuery),
    responses(
        (status = 200, description = "Logs listed successfully", body = Vec<TuningLogEntry>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn list_logs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListLogsQuery>,
) -> Result<Json<Vec<TuningLogEntry>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // List tuning logs
    let logs = if let Some(rule_id) = query.rule_id {
        // Get logs for a specific rule
        state
            .tuning_repository
            .get_logs_for_rule(rule_id)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to list logs: {}", e)))?
    } else {
        // Get recent logs across all rules
        state
            .tuning_repository
            .get_recent_logs(query.limit as i32)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to list logs: {}", e)))?
    };

    // Apply status filter if provided
    let filtered_logs = if let Some(status) = query.status {
        logs.into_iter()
            .filter(|log| log.status == status)
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect()
    } else {
        logs.into_iter()
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect()
    };

    Ok(Json(filtered_logs))
}

/// GET /api/tuning/logs/:id
///
/// Get a specific tuning log entry by ID.
///
/// Requirements: 8.1
#[utoipa::path(
    get,
    path = "/api/tuning/logs/{id}",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Log entry ID")
    ),
    responses(
        (status = 200, description = "Log entry retrieved", body = TuningLogEntry),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 404, description = "Log entry not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_log(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<TuningLogEntry>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // Get log entry by ID
    let log = state
        .tuning_repository
        .get_log_entry(*id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get log entry: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Log entry not found".to_string()))?;

    Ok(Json(log))
}

/// POST /api/tuning/logs/:id/revert
///
/// Revert a tuning by activating the previous version.
///
/// Requirements: 9.2
#[utoipa::path(
    post,
    path = "/api/tuning/logs/{id}/revert",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Log entry ID")
    ),
    request_body = RevertRequest,
    responses(
        (status = 200, description = "Tuning reverted", body = ApprovalResponse),
        (status = 400, description = "Revert reason is required"),
        (status = 403, description = "Missing permissions: detections:edit and detections:promote"),
        (status = 404, description = "Tuning log, rule, or version not found"),
        (status = 409, description = "Tuning log cannot be reverted"),
        (status = 422, description = "Target version is invalid for the rule's execution mode"),
        (status = 503, description = "Rollback committed but runtime reconciliation is pending"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn revert_tuning(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<RevertRequest>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    ensure_revert_permissions(&auth)?;

    let reason = request.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::BadRequest(
            "Revert reason is required".to_string(),
        ));
    }

    let log = state
        .tuning_repository
        .get_log_entry(*id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get tuning log: {e}")))?
        .ok_or_else(|| ApiError::NotFound("Tuning log not found".to_string()))?;
    if log.proposal.proposal_type != ProposalType::QueryTuning {
        return Err(ApiError::Conflict(
            "Only applied query-tuning logs can revert a rule version".to_string(),
        ));
    }

    let version_manager = RuleVersionManager::new(state.pool.clone());
    let plan = version_manager
        .plan_tuning_revert(log.rule_id, request.version_id, *id)
        .await
        .map_err(map_version_error)?;
    let (rule_mode, detection_mode) = match plan {
        TuningRevertPlan::Ready => {
            let (_, rule_mode, detection_mode) =
                validate_revert_target(&state, log.rule_id, request.version_id).await?;
            (rule_mode, detection_mode)
        }
        TuningRevertPlan::Replayed(_) => {
            let rule = state.detection_service.get_rule(log.rule_id).await?;
            (rule.mode, rule.detection_mode)
        }
    };

    let sync_owner = format!("{}:{}", state.node_id, Uuid::now_v7());
    let result = version_manager
        .revert_tuning_log_claimed(
            log.rule_id,
            request.version_id,
            auth.user_id(),
            *id,
            reason.to_string(),
            &sync_owner,
            rule_mode_name(rule_mode),
            detection_mode_name(detection_mode),
        )
        .await
        .map_err(map_version_error)?;
    // Persist the operator notification before any fallible ClickHouse DDL.
    // The PostgreSQL revert is already committed at this point, so a transient
    // runtime-sync 503 must not deterministically suppress this notification.
    let notification_error = if result.replayed {
        None
    } else {
        state
            .notification_service
            .notify_reverted(
                log.proposal.id,
                &log.rule_name,
                reason,
                Some(auth.user_id()),
            )
            .await
            .err()
    };
    if let Some(error) = &notification_error {
        tracing::warn!(%error, log_id = %id, "Failed to send tuning revert notification");
    }
    let sync_error = reconcile_reverted_runtime(&state, &result, log.rule_id, &sync_owner)
        .await
        .err();

    if !result.replayed {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Tuning, VERSION_REVERTED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("tuning_log", Some(*id), Some(log.rule_name.clone()))
                .client_context(&client)
                .details(tuning_revert_audit_details(
                    log.rule_id,
                    request.version_id,
                    &result,
                    sync_error.as_ref().map(ToString::to_string),
                    notification_error.as_ref().map(ToString::to_string),
                    reason,
                ))
                .build(),
        );
    }

    if let Some(error) = sync_error {
        return Err(error);
    }

    Ok(Json(ApprovalResponse {
        success: true,
        message: "Tuning reverted and auto-tuning paused for 7 days".to_string(),
        version_id: Some(result.version_id),
        outcome: Some(super::types::ApprovalOutcome::Applied),
        status: Some(nanosiem_core::tuning::TuningStatus::Reverted),
        pr_url: None,
        effective_query: None,
        runtime_sync_pending: false,
        runtime_sync_error: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::tuning::versions::VersionRevertResult;

    #[test]
    fn tuning_log_rollback_audit_is_complete() {
        let rule_id = Uuid::now_v7();
        let result = VersionRevertResult {
            version_id: 19,
            changed: true,
            replayed: false,
            runtime_sync_required: true,
            runtime_sync_claimed: true,
        };
        let details = tuning_revert_audit_details(
            rule_id,
            11,
            &result,
            Some("runtime pending".to_string()),
            Some("notification pending".to_string()),
            "false positive burst",
        );

        assert_eq!(details["route"], "tuning_log_revert");
        assert_eq!(details["rule_id"], rule_id.to_string());
        assert_eq!(details["reverted_to_version"], 11);
        assert_eq!(details["new_version_id"], 19);
        assert_eq!(details["runtime_sync_pending"], true);
        assert_eq!(details["runtime_sync_error"], "runtime pending");
        assert_eq!(details["notification_error"], "notification pending");
        assert_eq!(details["reason"], "false positive burst");
    }
}
