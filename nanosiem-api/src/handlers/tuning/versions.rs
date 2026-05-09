// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, VERSION_REVERTED};
use nanosiem_core::auth::permissions;
use nanosiem_core::tuning::RuleVersion;
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::{ApprovalResponse, RuleVersionResponse};
use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

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
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(_rule_id): Path<TypeIdParam>,
) -> Result<Json<Vec<RuleVersion>>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    // TODO: Implement version history retrieval
    // For now, return empty list as version manager is not yet integrated into AppState
    Ok(Json(vec![]))
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
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((_rule_id, _version_id)): Path<(TypeIdParam, i32)>,
) -> Result<Json<RuleVersion>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    // TODO: Implement version retrieval
    Err(ApiError::NotFound("Version not found".to_string()))
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
        (status = 403, description = "Missing permission: detections:edit"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn activate_version(
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((_rule_id, _version_id)): Path<(TypeIdParam, i32)>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    // TODO: Implement version activation workflow
    // 1. Retrieve version
    // 2. Validate it belongs to the specified rule
    // 3. Create new version entry marking it as a revert
    // 4. Update rule with version's query
    // 5. Create audit log entry
    // 6. Send notifications
    // 7. Set 7-day cooldown on auto-tuning

    Ok(Json(ApprovalResponse {
        success: false,
        message: "Version activation not yet implemented".to_string(),
        version_id: None,
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
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    use nanosiem_core::tuning::versions::RuleVersionManager;

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
        (status = 403, description = "Missing permission: detections:edit"),
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
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    use nanosiem_core::tuning::versions::RuleVersionManager;

    let version_manager = RuleVersionManager::new(state.pool.clone());
    let user_id = auth.user_id();

    let new_version_id = version_manager
        .revert_to_version(*rule_id, version_id, user_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to revert version: {}", e)))?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Tuning, VERSION_REVERTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*rule_id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "reverted_to_version": version_id,
                "new_version_id": new_version_id,
            }))
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Rule reverted successfully",
        "new_version_id": new_version_id
    })))
}
