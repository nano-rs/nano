// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_ALL_REMOVED, RULE_BATCH_IMPORTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{ImportOutcome, ImportRequest, RuleRepositoryError};

use super::{
    get_rule_repo_service,
    types::{
        BatchFailure, BatchImportRequest, BatchImportResponse, BatchRemoveFailure,
        BatchRemoveResponse,
    },
    AuditExt,
};
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Batch import multiple rules from a repository
#[utoipa::path(
    post,
    path = "/api/rule-repositories/{id}/rules/import-batch",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    request_body = BatchImportRequest,
    responses(
        (status = 200, description = "Batch import completed", body = BatchImportResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn batch_import_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<BatchImportRequest>,
) -> Result<Json<BatchImportResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_IMPORT).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:import".to_string())
    })?;

    if req.items.len() > 1000 {
        return Err(ApiError::BadRequest(format!(
            "Batch import limited to 1000 rules, got {}",
            req.items.len()
        )));
    }

    let service = get_rule_repo_service(&state)?;
    let repo = service.get_repository(*id).await?;

    let mv_gen = state.materialized_view_generator.as_deref();

    let mut imported = 0usize;
    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut failed = Vec::new();

    for item in req.items {
        // Build the import request for this rule
        let import_request = ImportRequest {
            import_type: nanosiem_core::ImportType::Forked,
            folder: None,
            name: None,
            severity: item.severity,
            mode: item.mode,
            custom_npl: None,
            ai_triage_hints: None,
            source_type_mappings: item.source_type_mappings,
            merge_to_single_source_type: item.merge_to_single_source_type,
        };

        match service
            .import_rule(
                *id,
                &item.path,
                import_request,
                Some(auth.user_id()),
                mv_gen,
            )
            .await
        {
            Ok((_, ImportOutcome::Created)) => {
                imported += 1;
            }
            Ok((_, ImportOutcome::Updated)) => {
                updated += 1;
            }
            Err(RuleRepositoryError::AlreadyImported { .. }) => {
                skipped += 1;
            }
            Err(e) => {
                failed.push(BatchFailure {
                    path: item.path.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    // Invalidate caches
    tracing::info!(
        "Batch import for repo {}: imported={}, updated={}, skipped={}, failed={}",
        repo.name,
        imported,
        updated,
        skipped,
        failed.len()
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_BATCH_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule_repository", Some(*id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "imported": imported,
                "updated": updated,
                "skipped": skipped,
                "failed": failed.len(),
            }))
            .build(),
    );

    Ok(Json(BatchImportResponse {
        imported,
        updated,
        skipped,
        failed,
    }))
}

/// Remove all imported rules for a repository (deletes detection rules)
#[utoipa::path(
    post,
    path = "/api/rule-repositories/{id}/rules/remove-all-imported",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "All imported rules removed", body = BatchRemoveResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn remove_all_imported(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<BatchRemoveResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_MANAGE).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:manage".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let repo = service.get_repository(*id).await?;

    // Get all imports for this repository
    let imports = service.get_imports_for_repository(*id).await?;

    let mut removed = 0usize;
    let mut failed = Vec::new();

    // Get materialized view generator for proper cleanup
    let mv_gen = state.materialized_view_generator.as_deref();

    for import in &imports {
        // Delete the detection rule (with mode-based cleanup)
        match state
            .detection_service
            .delete_rule_with_mode(import.detection_rule_id, mv_gen)
            .await
        {
            Ok(_) => {
                // Delete the import record
                if let Err(e) = service.delete_import(import.id).await {
                    tracing::warn!(
                        "Failed to delete import record {} after deleting detection rule: {}",
                        import.id,
                        e
                    );
                }
                removed += 1;
            }
            Err(e) => {
                failed.push(BatchRemoveFailure {
                    detection_rule_id: import.detection_rule_id,
                    error: e.to_string(),
                });
            }
        }
    }

    tracing::info!(
        "Batch remove for repo {}: removed={}, failed={}",
        repo.name,
        removed,
        failed.len()
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_ALL_REMOVED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule_repository", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(BatchRemoveResponse { removed, failed }))
}
