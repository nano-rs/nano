// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, VERSION_REVERTED};
use nanosiem_core::auth::permissions;
use nanosiem_core::models::detection_rule::{DetectionMode, RuleMode, Severity};
use nanosiem_core::tuning::versions::{
    RuleVersionManager, VersionManagerError, VersionRevertResult,
};
use nanosiem_core::tuning::RuleVersion;
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::{ApprovalResponse, RuleVersionResponse};
use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

pub(crate) fn map_version_error(error: VersionManagerError) -> ApiError {
    match error {
        VersionManagerError::RuleNotFound(_)
        | VersionManagerError::VersionNotFound(_)
        | VersionManagerError::NoActiveVersion(_)
        | VersionManagerError::TuningLogNotFound(_) => ApiError::NotFound(error.to_string()),
        VersionManagerError::InvalidVersionData(_)
        | VersionManagerError::VersionConflict(_)
        | VersionManagerError::TuningLogNotRevertible(_) => ApiError::Conflict(error.to_string()),
        VersionManagerError::DatabaseError(message) => {
            tracing::error!(%message, "Rule version operation failed");
            ApiError::InternalError("Rule version operation failed".to_string())
        }
    }
}

pub(crate) fn ensure_revert_permissions(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::DETECTIONS_EDIT)?;
    ensure_permission(auth, permissions::DETECTIONS_PROMOTE)?;
    Ok(())
}

fn version_revert_audit_details(
    route: &str,
    reverted_to_version: i32,
    result: &VersionRevertResult,
    runtime_sync_error: Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "route": route,
        "reverted_to_version": reverted_to_version,
        "new_version_id": result.version_id,
        "changed": result.changed,
        "replayed": result.replayed,
        "runtime_sync_pending": runtime_sync_error.is_some(),
        "runtime_sync_error": runtime_sync_error,
    })
}

fn parse_version_severity(value: &str) -> Result<Severity, ApiError> {
    match value {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "informational" => Ok(Severity::Informational),
        _ => Err(ApiError::Conflict(format!(
            "Version has unsupported severity: {value}"
        ))),
    }
}

pub(crate) fn rule_mode_name(mode: RuleMode) -> &'static str {
    match mode {
        RuleMode::Staging => "staging",
        RuleMode::Live => "live",
        RuleMode::Alerting => "alerting",
        RuleMode::Paused => "paused",
    }
}

pub(crate) fn detection_mode_name(mode: DetectionMode) -> &'static str {
    match mode {
        DetectionMode::RealTime => "real-time",
        DetectionMode::Scheduled => "scheduled",
    }
}

/// Validate the exact post-rollback rule before the PostgreSQL transaction.
/// In particular, real-time DDL and Alerting prevalence constraints must fail
/// before the durable state changes.
pub(crate) async fn validate_revert_target(
    state: &AppState,
    rule_id: Uuid,
    version_id: i32,
) -> Result<(RuleVersion, RuleMode, DetectionMode), ApiError> {
    let target = RuleVersionManager::new(state.pool.clone())
        .get_version(version_id)
        .await
        .map_err(map_version_error)?;
    if target.rule_id != rule_id {
        return Err(ApiError::NotFound("Version not found".to_string()));
    }

    let mut prospective = state.detection_service.get_rule(rule_id).await?;
    let parsed = nanosiem_core::parse_query(&target.query)
        .map_err(|error| ApiError::ValidationError(format!("Invalid query: {error}")))?;
    if prospective.mode == RuleMode::Alerting {
        nanosiem_core::search::query_processing::check_prevalence_pushdown_eligible(&parsed)
            .map_err(|reason| {
                ApiError::ValidationError(format!(
                    "This version cannot run in Alerting mode: {reason}"
                ))
            })?;
    }

    prospective.query = target.query.clone();
    prospective.name = target.name.clone();
    prospective.description = target.description.clone();
    prospective.severity = parse_version_severity(&target.severity)?;
    if prospective.detection_mode == DetectionMode::RealTime {
        state
            .materialized_view_generator
            .generate_view_ddl(&prospective)
            .map_err(|error| {
                ApiError::ValidationError(format!(
                    "Version is incompatible with real-time execution: {error}"
                ))
            })?;
    }

    Ok((target, prospective.mode, prospective.detection_mode))
}

/// Reconcile the ClickHouse execution plane for an atomically committed
/// real-time rollback. Failures remain durable for distributed retry.
pub(crate) async fn reconcile_reverted_runtime(
    state: &AppState,
    result: &VersionRevertResult,
    rule_id: Uuid,
    owner: &str,
) -> Result<(), ApiError> {
    if !result.runtime_sync_required {
        return Ok(());
    }
    if !result.runtime_sync_claimed {
        return Err(ApiError::ServiceUnavailable(
            "Rule rollback committed; real-time execution reconciliation is in progress"
                .to_string(),
        ));
    }

    let pending = nanosiem_core::tuning::versions::PendingRuntimeSync {
        rule_id,
        desired_version_id: result.version_id,
    };
    state
        .reconcile_rule_runtime_sync(&pending, owner)
        .await
        .map_err(|error| {
            ApiError::ServiceUnavailable(format!(
                "Rule rollback committed, but runtime reconciliation is pending: {error}"
            ))
        })
}

/// GET /api/tuning/versions/:rule_id
///
/// Get version history for a detection rule.
///
/// Requirements: 6.1
#[utoipa::path(
    get,
    path = "/api/tuning/versions/{rule_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Version history retrieved", body = Vec<RuleVersion>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn list_versions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
) -> Result<Json<Vec<RuleVersion>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let versions = RuleVersionManager::new(state.pool.clone())
        .get_version_history(*rule_id)
        .await
        .map_err(map_version_error)?;
    Ok(Json(versions))
}

/// GET /api/tuning/versions/:rule_id/:version_id
///
/// Get a specific version of a detection rule.
///
/// Requirements: 6.1
#[utoipa::path(
    get,
    path = "/api/tuning/versions/{rule_id}/{version_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID"),
        ("version_id" = i32, Path, description = "Version ID")
    ),
    responses(
        (status = 200, description = "Version retrieved successfully", body = RuleVersion),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 404, description = "Version not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_version(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((rule_id, version_id)): Path<(TypeIdParam, i32)>,
) -> Result<Json<RuleVersion>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let version = RuleVersionManager::new(state.pool.clone())
        .get_version(version_id)
        .await
        .map_err(map_version_error)?;
    if version.rule_id != *rule_id {
        return Err(ApiError::NotFound("Version not found".to_string()));
    }
    Ok(Json(version))
}

/// POST /api/tuning/versions/:rule_id/:version_id/activate
///
/// Activate a specific version of a detection rule (revert to previous version).
///
/// Requirements: 9.2
#[utoipa::path(
    post,
    path = "/api/tuning/versions/{rule_id}/{version_id}/activate",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID"),
        ("version_id" = i32, Path, description = "Version ID to activate")
    ),
    responses(
        (status = 200, description = "Version activated", body = ApprovalResponse),
        (status = 403, description = "Missing permissions: detections:edit and detections:promote"),
        (status = 404, description = "Rule or version not found"),
        (status = 409, description = "Version cannot be activated"),
        (status = 422, description = "Target version is invalid for the rule's execution mode"),
        (status = 503, description = "Rollback committed but runtime reconciliation is pending"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn activate_version(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path((rule_id, version_id)): Path<(TypeIdParam, i32)>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    ensure_revert_permissions(&auth)?;

    let (_, rule_mode, detection_mode) =
        validate_revert_target(&state, *rule_id, version_id).await?;
    let sync_owner = format!("{}:{}", state.node_id, Uuid::now_v7());
    let result = RuleVersionManager::new(state.pool.clone())
        .revert_to_version_claimed(
            *rule_id,
            version_id,
            auth.user_id(),
            &sync_owner,
            rule_mode_name(rule_mode),
            detection_mode_name(detection_mode),
        )
        .await
        .map_err(map_version_error)?;
    let sync_error = reconcile_reverted_runtime(&state, &result, *rule_id, &sync_owner)
        .await
        .err();

    state.emit_audit(
        AuditEvent::builder(AuditSource::Tuning, VERSION_REVERTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*rule_id), None)
            .client_context(&client)
            .details(version_revert_audit_details(
                "tuning_version_activate",
                version_id,
                &result,
                sync_error.as_ref().map(ToString::to_string),
            ))
            .build(),
    );

    if let Some(error) = sync_error {
        return Err(error);
    }

    Ok(Json(ApprovalResponse {
        success: true,
        message: "Rule version activated and auto-tuning paused for 7 days".to_string(),
        version_id: Some(result.version_id),
        outcome: Some(super::types::ApprovalOutcome::Applied),
        status: Some(nanosiem_core::tuning::TuningStatus::Reverted),
        pr_url: None,
        effective_query: None,
        runtime_sync_pending: false,
        runtime_sync_error: None,
    }))
}

/// GET /api/rules/:id/versions
///
/// Returns all versions for the specified rule, ordered by version number descending.
#[utoipa::path(
    get,
    path = "/api/rules/{id}/versions",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Versions retrieved", body = Vec<RuleVersionResponse>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_rule_versions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
) -> Result<Json<Vec<RuleVersionResponse>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let version_manager = RuleVersionManager::new(state.pool.clone());
    let versions = version_manager
        .get_version_history(*rule_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get versions: {}", e)))?;

    // Batch-resolve user names for created_by UUIDs
    let user_ids: Vec<Uuid> = versions
        .iter()
        .filter_map(|v| v.created_by)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let user_names: std::collections::HashMap<Uuid, String> = if !user_ids.is_empty() {
        sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM users WHERE id = ANY($1)")
            .bind(&user_ids)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to resolve user names for version history: {}", e);
                Vec::new()
            })
            .into_iter()
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    // Fallback: fetch rule author for versions where created_by is NULL
    let rule_author: Option<String> =
        sqlx::query_scalar("SELECT author FROM detection_rules WHERE id = $1")
            .bind(*rule_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let response: Vec<RuleVersionResponse> = versions
        .into_iter()
        .map(|v| {
            let created_by_name = v
                .created_by
                .and_then(|uid| user_names.get(&uid).cloned())
                .or_else(|| rule_author.clone());
            RuleVersionResponse {
                id: v.id,
                rule_id: v.rule_id,
                version_number: v.version_number,
                query: v.query,
                name: v.name,
                description: v.description,
                severity: v.severity,
                enabled: v.enabled,
                is_active: v.is_active,
                created_at: v.created_at,
                created_by: v.created_by,
                created_by_name,
                change_reason: v.change_reason,
                tuning_proposal_id: v.tuning_proposal_id,
                reverted_from_version: v.reverted_from_version,
            }
        })
        .collect();

    Ok(Json(response))
}

/// POST /api/rules/:id/versions/:version_id/revert
///
/// Revert a detection rule to a previous version.
#[utoipa::path(
    post,
    path = "/api/rules/{id}/versions/{version_id}/revert",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Detection rule ID"),
        ("version_id" = i32, Path, description = "Version ID to revert to")
    ),
    responses(
        (status = 200, description = "Rule reverted", body = serde_json::Value),
        (status = 403, description = "Missing permissions: detections:edit and detections:promote"),
        (status = 404, description = "Rule or version not found"),
        (status = 409, description = "Version cannot be reverted"),
        (status = 422, description = "Target version is invalid for the rule's execution mode"),
        (status = 503, description = "Rollback committed but runtime reconciliation is pending"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn revert_to_version(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path((rule_id, version_id)): Path<(TypeIdParam, i32)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_revert_permissions(&auth)?;

    let (_, rule_mode, detection_mode) =
        validate_revert_target(&state, *rule_id, version_id).await?;
    let sync_owner = format!("{}:{}", state.node_id, Uuid::now_v7());
    let result = RuleVersionManager::new(state.pool.clone())
        .revert_to_version_claimed(
            *rule_id,
            version_id,
            auth.user_id(),
            &sync_owner,
            rule_mode_name(rule_mode),
            detection_mode_name(detection_mode),
        )
        .await
        .map_err(map_version_error)?;
    let sync_error = reconcile_reverted_runtime(&state, &result, *rule_id, &sync_owner)
        .await
        .err();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Tuning, VERSION_REVERTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*rule_id), None)
            .client_context(&client)
            .details(version_revert_audit_details(
                "rule_version_revert",
                version_id,
                &result,
                sync_error.as_ref().map(ToString::to_string),
            ))
            .build(),
    );

    if let Some(error) = sync_error {
        return Err(error);
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Rule reverted successfully",
        "new_version_id": result.version_id,
        "changed": result.changed,
        "replayed": result.replayed
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;

    fn auth_with_permissions(values: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: values.iter().map(ToString::to_string).collect(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    #[test]
    fn version_errors_have_actionable_http_classes() {
        assert!(matches!(
            map_version_error(VersionManagerError::VersionNotFound(7)),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            map_version_error(VersionManagerError::TuningLogNotRevertible(Uuid::now_v7())),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            map_version_error(VersionManagerError::DatabaseError("down".to_string())),
            ApiError::InternalError(_)
        ));
    }

    #[test]
    fn every_rollback_route_requires_edit_and_promote_permissions() {
        assert!(ensure_revert_permissions(&auth_with_permissions(&[
            permissions::DETECTIONS_EDIT,
            permissions::DETECTIONS_PROMOTE,
        ]))
        .is_ok());
        assert!(matches!(
            ensure_revert_permissions(&auth_with_permissions(&[permissions::DETECTIONS_EDIT])),
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            ensure_revert_permissions(&auth_with_permissions(&[permissions::DETECTIONS_PROMOTE])),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn version_rollback_audit_details_cover_both_public_routes() {
        let result = VersionRevertResult {
            version_id: 42,
            changed: true,
            replayed: false,
            runtime_sync_required: true,
            runtime_sync_claimed: true,
        };
        for route in ["tuning_version_activate", "rule_version_revert"] {
            let details = version_revert_audit_details(
                route,
                7,
                &result,
                Some("ClickHouse unavailable".to_string()),
            );
            assert_eq!(details["route"], route);
            assert_eq!(details["reverted_to_version"], 7);
            assert_eq!(details["new_version_id"], 42);
            assert_eq!(details["changed"], true);
            assert_eq!(details["replayed"], false);
            assert_eq!(details["runtime_sync_pending"], true);
            assert_eq!(details["runtime_sync_error"], "ClickHouse unavailable");
        }
    }
}
