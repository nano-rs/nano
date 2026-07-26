// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_ALL_REMOVED, RULE_BATCH_IMPORTED,
};
use std::collections::HashSet;

use futures::StreamExt;
use nanosiem_core::auth::{permissions, TargetEffect};
use nanosiem_core::rule_repository::RuleImportAction;
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
use crate::handlers::repository_target_authz::{ensure_target_effects, held_target_grants};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// How many import plans to preflight concurrently. Bounded so a 1000-item
/// batch cannot open 1000 simultaneous pool connections while still cutting the
/// serial round-trip cost of the authorization preflight.
const PLAN_CONCURRENCY: usize = 16;

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
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden — missing rule_repositories:import, or the detections:create / detections:edit / detections:promote capability some item in the batch consumes"),
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
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_IMPORT)?;

    if req.items.len() > 1000 {
        return Err(ApiError::BadRequest(format!(
            "Batch import limited to 1000 rules, got {}",
            req.items.len()
        )));
    }

    let service = get_rule_repo_service(&state)?;
    let repo = service.get_repository(*id).await?;

    let mv_gen = state.materialized_view_generator.as_ref();

    // Build every item's import request up front so the authorization preflight
    // sees exactly what the execution loop will submit.
    let requests: Vec<(String, ImportRequest)> = req
        .items
        .into_iter()
        .map(|item| {
            (
                item.path,
                ImportRequest {
                    import_type: nanosiem_core::ImportType::Forked,
                    folder: None,
                    name: None,
                    severity: item.severity,
                    mode: item.mode,
                    custom_npl: None,
                    ai_triage_hints: None,
                    source_type_mappings: item.source_type_mappings,
                    merge_to_single_source_type: item.merge_to_single_source_type,
                },
            )
        })
        .collect();

    // NAN-2118: preflight the WHOLE batch before importing anything. Without
    // this, a caller lacking `detections:edit` (or `detections:promote`) could
    // still commit every item ahead of the first forbidden one. Items whose plan
    // errors are left to the execution loop — `plan_import` reads a strict subset
    // of `import_rule`'s lookups, so the same error recurs there before any write
    // and the item lands in `failed` exactly as it does today.
    let mut required_effects: Vec<TargetEffect> = Vec::new();
    // Every plan is computed against the CURRENT database, so two actionable
    // items that resolve to the same detection name are both planned against a
    // target the other is about to change: the second one really executes as an
    // update against item 1's freshly written severity/schedule/lookback. Its
    // true promotion need is therefore unknowable at preflight time (a
    // 60→120→90 lookback sequence looks like two lengthenings but the second is a
    // shortening). Fail closed on the collision — demand the FULL update
    // capability set for repeats — rather than discovering it as a 403 after
    // item 1 has already committed.
    //
    // Planned with bounded concurrency: a 1000-item batch would otherwise add
    // ~4000 sequential round trips before the first import starts. `buffered`
    // preserves input order, which the collision rule below depends on.
    let plan_futures: Vec<_> = requests
        .iter()
        .map(|(path, import_request)| service.plan_import(*id, path, import_request))
        .collect();
    let plans: Vec<_> = futures::stream::iter(plan_futures)
        .buffered(PLAN_CONCURRENCY)
        .collect()
        .await;

    let mut paths_seen: HashSet<&str> = HashSet::new();
    let mut targets_touched_in_batch: HashSet<String> = HashSet::new();
    for ((path, _), plan) in requests.iter().zip(plans) {
        // A plan that errored is deferred to the execution loop, which raises the
        // same error at the same point, before any write.
        let Ok(mut plan) = plan else { continue };

        // The SAME path repeated is not a collision: the first item creates the
        // import record, so every repeat short-circuits on `AlreadyImported`
        // before touching the detection. It consumes no target capability.
        if !paths_seen.insert(path.as_str()) {
            continue;
        }

        // Two DIFFERENT paths resolving to one detection name do collide. Both
        // plans were computed against the CURRENT database, so the second really
        // executes as an update against whatever item 1 just wrote, and its true
        // promotion need is unknowable at preflight time (a 60→120→90 lookback
        // sequence looks like two lengthenings but the second is a shortening).
        // Fail closed on the ambiguity rather than discovering it as a 403 after
        // item 1 has already committed. A Skip writes nothing, so it neither
        // claims a target nor collides.
        if plan.action != RuleImportAction::Skip
            && !targets_touched_in_batch.insert(plan.resolved_name.clone())
        {
            plan.action = RuleImportAction::Update;
            plan.requires_promote = true;
        }
        for effect in plan.required_effects() {
            if !required_effects.contains(&effect) {
                required_effects.push(effect);
            }
        }
    }
    ensure_target_effects(&auth, &required_effects)?;
    // Re-checked inside the service at each item's create/update branch.
    let grants = held_target_grants(&auth);

    let mut imported = 0usize;
    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut failed = Vec::new();

    for (path, import_request) in requests {
        match service
            .import_rule(
                *id,
                &path,
                import_request,
                Some(auth.user_id()),
                &grants,
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
            // A target-capability denial is never a per-item soft failure: the
            // preflight above should have rejected the whole request, so reaching
            // here means the outcome changed under a race. Fail the batch.
            Err(e @ RuleRepositoryError::Forbidden(_)) => {
                return Err(e.into());
            }
            Err(e) => {
                failed.push(BatchFailure {
                    path: path.clone(),
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
        (status = 403, description = "Forbidden — missing rule_repositories:manage or detections:delete"),
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
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_MANAGE)?;
    // NAN-2111: this deletes first-class detection rules. `rule_repositories:manage`
    // covers the repository row ("Create, edit, and delete rule repositories"),
    // never the linked detections — `DELETE /api/rules/{id}` requires
    // `detections:delete`. Enforced before the imports are loaded so a denied
    // caller learns nothing about how many targets exist.
    ensure_target_effects(&auth, &[TargetEffect::DetectionDelete])?;

    let service = get_rule_repo_service(&state)?;
    let repo = service.get_repository(*id).await?;

    // Get all imports for this repository
    let imports = service.get_imports_for_repository(*id).await?;

    let mut removed = 0usize;
    let mut failed = Vec::new();

    // Get materialized view generator for proper cleanup
    let mv_gen = state.materialized_view_generator.as_ref();

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
