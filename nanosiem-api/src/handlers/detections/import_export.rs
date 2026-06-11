// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import and export operations for detection rules

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULES_EXPORTED, RULES_IMPORTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::DetectionRule;

use super::types::*;
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Import detection rules from JSON/YAML
#[utoipa::path(
    post,
    path = "/api/rules/import",
    tag = "detections",
    request_body = ImportRulesRequest,
    responses(
        (status = 200, description = "Import results with counts and errors", body = ImportResponse),
        (status = 403, description = "Missing permission: detections:create", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn import_detections(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ImportRulesRequest>,
) -> Result<Json<ImportResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_CREATE)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:create".to_string()))?;

    let mut imported = 0;
    let mut failed = 0;
    let mut errors = Vec::new();

    // Same promote gate as POST /api/rules: without detections:promote, only
    // inert staging rules may be created (NAN-1375).
    let has_promote = auth.has_permission(permissions::DETECTIONS_PROMOTE);

    for rule in request.rules {
        if !has_promote && super::crud::requires_promote_for_create(&rule) {
            failed += 1;
            errors.push(format!(
                "Rule '{}' requires detections:promote (non-staging mode or real-time activation)",
                rule.name
            ));
            continue;
        }
        match state.detection_service.create_rule(rule).await {
            Ok(created) => {
                state.detection_service.sync_next_run_at(&created).await;
                imported += 1;
            }
            Err(e) => {
                failed += 1;
                errors.push(e.to_string());
            }
        }
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULES_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .details(serde_json::json!({
                "imported": imported,
                "failed": failed,
            }))
            .build(),
    );

    Ok(Json(ImportResponse {
        imported,
        failed,
        errors,
    }))
}

/// Export detection rules to JSON
#[utoipa::path(
    get,
    path = "/api/rules/export",
    tag = "detections",
    responses(
        (status = 200, description = "All detection rules exported as JSON", body = Vec<DetectionRule>),
        (status = 403, description = "Missing permission: detections:export", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn export_detections(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<Vec<DetectionRule>>, ApiError> {
    // M8: Require separate export permission (not just view)
    check_permission(&auth, permissions::DETECTIONS_EXPORT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:export".to_string()))?;

    let rules = state.detection_service.list_rules().await?;

    // Bulk export of the detection corpus is a defender-relevant exfil surface,
    // so emit an audit event recording who pulled how much (NAN-1365).
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULES_EXPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .details(serde_json::json!({
                "exported": rules.len(),
            }))
            .build(),
    );

    Ok(Json(rules))
}
