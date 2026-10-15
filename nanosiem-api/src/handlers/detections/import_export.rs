// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import and export operations for detection rules

use axum::{
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULES_EXPORTED, RULES_IMPORTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::detection::rule_transfer::{render_rules_export, resolve_import_rules};
use nanosiem_core::DetectionRule;

use super::types::*;
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Import detection rules: `{"rules": [...]}` or a JSON/YAML file upload
/// `{"data": "...", "format": "json"|"yaml"}`.
#[utoipa::path(
    post,
    path = "/api/rules/import",
    tag = "detections",
    request_body = ImportRulesRequest,
    responses(
        (status = 200, description = "Import results with counts and errors", body = ImportResponse),
        (status = 400, description = "Missing/ambiguous body or an unparseable rule file", body = ErrorResponse),
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
    ensure_permission(&auth, permissions::DETECTIONS_CREATE)?;
    let rules = resolve_import_rules(request.rules, request.data.as_deref(), request.format)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let mut imported = 0;
    let mut failed = 0;
    let mut errors = Vec::new();

    // Same promote gate as POST /api/rules: without detections:promote, only
    // inert staging rules may be created (NAN-1375).
    let has_promote = auth.has_permission(permissions::DETECTIONS_PROMOTE);

    for rule in rules {
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

/// Export detection rules as JSON (default) or YAML (`?format=yaml`)
#[utoipa::path(
    get,
    path = "/api/rules/export",
    tag = "detections",
    params(ExportRulesQuery),
    responses(
        (status = 200, description = "All detection rules as a JSON array, or the same list as YAML with `format=yaml`; sent as an attachment",
            content((Vec<DetectionRule> = "application/json"), (String = "application/yaml"))),
        (status = 403, description = "Missing permission: detections:export", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn export_detections(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Query(query): Query<ExportRulesQuery>,
) -> Result<Response, ApiError> {
    // M8: Require separate export permission (not just view)
    ensure_permission(&auth, permissions::DETECTIONS_EXPORT)?;

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

    let format = query.format.unwrap_or_default();
    let body = render_rules_export(&rules, format)
        .map_err(|e| ApiError::InternalError(format!("rule export failed: {e}")))?;
    Ok((
        [
            (header::CONTENT_TYPE, format.content_type().to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", format.filename()),
            ),
        ],
        body,
    )
        .into_response())
}
