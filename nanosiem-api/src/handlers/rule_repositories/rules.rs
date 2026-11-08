// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_CREATED, RULE_IMPORTED, RULE_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{
    ImportOutcome, ImportPreview, ImportRequest, RepositoryRule, RepositoryRuleFilter,
};
use uuid::Uuid;

use super::{
    get_rule_repo_service,
    types::{
        ImportRuleRequest, ImportRuleResponse, ListFoldersResponse, ListRulesQuery,
        RepositoryRuleResponse,
    },
    AuditExt,
};
use crate::handlers::repository_target_authz::{ensure_target_effects, held_target_grants};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List top-level folders in a repository (for folder selection before sync)
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}/folders",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Folders retrieved successfully", body = ListFoldersResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_folders(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ListFoldersResponse>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

    let service = get_rule_repo_service(&state)?;
    let folders = service.list_folders(*id).await?;

    Ok(Json(ListFoldersResponse { folders }))
}

/// List rules in a repository
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}/rules",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ListRulesQuery
    ),
    responses(
        (status = 200, description = "Rules retrieved successfully", body = Vec<RepositoryRuleResponse>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_repository_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<ListRulesQuery>,
) -> Result<Json<Vec<RepositoryRuleResponse>>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

    let service = get_rule_repo_service(&state)?;

    let filter = RepositoryRuleFilter {
        path_prefix: query.path_prefix,
        severity: query.severity,
        conversion_status: query.conversion_status,
        coverage_status: query.coverage_status,
        search: query.search,
        has_npl: query.has_npl,
        limit: query.limit,
        offset: query.offset,
    };

    let rules = service.list_rules(*id, filter).await?;

    // Get import status for all rules in this repository
    let imports = service.get_imports_for_repository(*id).await?;
    let import_map: std::collections::HashMap<Uuid, Uuid> = imports
        .into_iter()
        .map(|i| (i.repository_rule_id, i.detection_rule_id))
        .collect();

    // Enrich rules with import status
    let response: Vec<RepositoryRuleResponse> = rules
        .into_iter()
        .map(|rule| {
            let linked_detection_rule_id = import_map.get(&rule.id).copied();
            RepositoryRuleResponse {
                rule,
                is_imported: linked_detection_rule_id.is_some(),
                linked_detection_rule_id,
            }
        })
        .collect();

    Ok(Json(response))
}

/// Get a specific rule from a repository
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}/rules/by-path/{path}",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ("path" = String, Path, description = "File path")
    ),
    responses(
        (status = 200, description = "Rule retrieved successfully", body = RepositoryRule),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_repository_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
) -> Result<Json<RepositoryRule>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

    let service = get_rule_repo_service(&state)?;
    let rule = service.get_rule(*id, &path).await?;

    Ok(Json(rule))
}

/// Preview importing a rule
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}/rules/preview/{path}",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ("path" = String, Path, description = "File path")
    ),
    responses(
        (status = 200, description = "Preview generated successfully", body = ImportPreview),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn preview_import(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
) -> Result<Json<ImportPreview>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

    // NAN-2081: the preview's `available_source_types` and coverage decision come
    // from an all-time scan of live telemetry — the same inventory
    // `GET /api/source-types` gates, further narrowed by per-source RBAC. Both
    // bars apply: without the live-data capability the preview returns its
    // catalog half only, and with it the inventory is still filtered by the
    // caller's effective deny set (per-source RBAC ∪ implicit `audit` without
    // `audit:view`).
    let scope = auth.effective_viewer_scope();
    let access = live_inventory_access(&auth, &scope);

    let service = get_rule_repo_service(&state)?;
    let preview = service.preview_import(*id, &path, &access).await?;

    Ok(Json(preview))
}

/// Resolve how much of the live telemetry inventory this caller may observe.
///
/// NAN-2081: repository visibility is not a live-data capability — without an
/// inventory capability a repository viewer gets no inventory at all, and with
/// one the inventory is still filtered by their per-source RBAC scope.
///
/// NAN-2159: the admission policy is `nanosiem_api_lib::source_inventory`, the
/// same one `GET /api/source-types` applies. This function previously carried
/// its own copy that still admitted `search:view` — the gate that predated
/// NAN-2055 — which made preview an alternate route around that fix (a
/// `search:view` key refused by `/api/source-types` still got the full all-time
/// inventory here) while refusing a legitimate `search:execute` holder. Do not
/// reintroduce a local capability check: preview and `/api/source-types` must
/// never disagree about whether a principal may enumerate live sources.
pub(crate) fn live_inventory_access<'a>(
    auth: &AuthContext,
    scope: &'a nanosiem_core::auth::ScopeSet,
) -> nanosiem_core::rule_repository::LiveInventoryAccess<'a> {
    if nanosiem_api_lib::permits_source_inventory(auth) {
        nanosiem_core::rule_repository::LiveInventoryAccess::Scoped(scope)
    } else {
        nanosiem_core::rule_repository::LiveInventoryAccess::Denied
    }
}

/// Import a rule from a repository
#[utoipa::path(
    post,
    path = "/api/rule-repositories/{id}/rules/import/{path}",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ("path" = String, Path, description = "File path")
    ),
    request_body = ImportRuleRequest,
    responses(
        (status = 200, description = "Rule imported successfully", body = ImportRuleResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden — missing rule_repositories:import, or the detections:create / detections:edit / detections:promote capability the import consumes"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn import_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
    Json(req): Json<ImportRuleRequest>,
) -> Result<Json<ImportRuleResponse>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_IMPORT)?;

    let service = get_rule_repo_service(&state)?;

    // Get the repository rule to check if it needs conversion
    let repo_rule = service.get_rule(*id, &path).await?;
    let repo = service.get_repository(*id).await?;

    let import_type = match req.import_type.as_str() {
        "forked" => nanosiem_core::ImportType::Forked,
        _ => nanosiem_core::ImportType::Linked,
    };

    // NAN-2118: `rule_repositories:import` authorizes reading the catalog — it is
    // NOT a substitute for the capabilities governing the detection this import
    // materializes or rewrites. Preflight the target outcome and enforce the
    // complete policy HERE, before AI conversion, credit charging,
    // materialized-view work, or any database mutation.
    let mut import_request = ImportRequest {
        import_type,
        folder: req.folder.clone(),
        name: req.name.clone(),
        severity: req.severity.clone(),
        mode: req.mode.clone(),
        custom_npl: None,
        ai_triage_hints: None,
        source_type_mappings: req.source_type_mappings.clone(),
        merge_to_single_source_type: req.merge_to_single_source_type.clone(),
    };
    let plan = service.plan_import(*id, &path, &import_request).await?;
    ensure_target_effects(&auth, &plan.required_effects())?;
    // Re-checked inside the service at the exact create/update branch so a
    // concurrent import that flips the outcome cannot launder a missing cap.
    let grants = held_target_grants(&auth);

    // Determine the nPL query and triage hints - either custom, already converted, or convert now via AI
    let (npl_query, ai_triage_hints) = if let Some(custom) = req.custom_npl.clone() {
        // User provided custom nPL
        (Some(custom), None)
    } else if repo_rule.converted_npl.is_some() {
        // Already converted
        (None, None) // Let the service use the stored one
    } else if repo.rule_format == "sigma" {
        // Sigma → nPL conversion is an enterprise feature (depends on the
        // meloD detection agent + agent registry). Open-core users must
        // supply a custom nPL query via the `custom_npl` field, or import
        // a repo whose rules are already in NanoSIEM format.
        #[cfg(not(feature = "enterprise"))]
        {
            return Err(ApiError::BadRequest(
                "Sigma rule conversion requires the enterprise build. \
                Provide `custom_npl` or import a rule already in nPL format."
                    .to_string(),
            ));
        }
        #[cfg(feature = "enterprise")]
        {
            // Need to convert via AI — credit rate limiting
            let cost = {
                let registry_guard = state.agent_config_registry.read().await;
                match registry_guard.as_ref() {
                    Some(registry) => match registry
                        .get_agent_config(&nanosiem_enterprise::melod::AgentId::Detection)
                        .await
                    {
                        Some(config) => {
                            nanosiem_core::resolve_ai_request_cost(&state.pool, &config.model_id)
                                .await
                        }
                        None => nanosiem_core::AI_CREDIT_FULL,
                    },
                    None => nanosiem_core::AI_CREDIT_FULL,
                }
            };
            let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
            let tier_limits = tier_settings.get_tier_limits().await?;
            tier_settings
                .increment_ai_credits(cost, tier_limits.ai_credits_per_month)
                .await?;

            let melod_guard = state.melod_service.read().await;
            let melod_service = melod_guard.as_ref().ok_or_else(|| {
                ApiError::InternalError(
                    "AI service not configured - cannot convert Sigma rule".to_string(),
                )
            })?;

            let sigma_rule = nanosiem_core::rule_repository::parse_sigma(&repo_rule.raw_content)
                .map_err(|e| ApiError::BadRequest(format!("Failed to parse Sigma rule: {}", e)))?;

            // Get available source_types from the environment for smarter conversion.
            // NAN-1801: user-initiated AI conversion — enumerate with the
            // requester's per-source scope so restricted sources stay invisible.
            let available_source_types = {
                let time_range = nanosiem_core::TimeRangeInput {
                    start: chrono::Utc::now() - chrono::Duration::days(7),
                    end: chrono::Utc::now(),
                };
                let scope = auth.effective_viewer_scope();
                melod_service
                    .data_access()
                    .get_source_types(&time_range, &scope)
                    .await
                    .map(|types| types.into_iter().map(|t| t.source_type).collect::<Vec<_>>())
                    .unwrap_or_default()
            };

            let ai_client = melod_service.ai_client_arc();
            let converter = nanosiem_enterprise::melod::SigmaConverterAgent::new(
                ai_client,
                state.config.schema_profile(),
            );
            let context = nanosiem_enterprise::melod::ConversionContext {
                available_source_types,
                ..Default::default()
            };

            let result = converter
                .convert(&sigma_rule, context)
                .await
                .map_err(|e| ApiError::InternalError(format!("AI conversion failed: {}", e)))?;

            if result.npl_query.is_empty() {
                return Err(ApiError::BadRequest(
                    "AI conversion produced an empty query. Please provide a custom nPL query."
                        .to_string(),
                ));
            }

            (
                Some(result.npl_query),
                result
                    .triage_hints
                    .map(|h| nanosiem_core::ConversionTriageHints {
                        suspicious_when: h.suspicious_when,
                        context: h.context,
                    }),
            )
        }
    } else {
        // NanoSIEM format - should have query in content
        (None, None)
    };

    import_request.custom_npl = npl_query;
    import_request.ai_triage_hints = ai_triage_hints;

    let mv_gen = state.materialized_view_generator.as_ref();

    let (detection_rule_id, outcome) = service
        .import_rule(
            *id,
            &path,
            import_request,
            Some(auth.user_id()),
            &grants,
            mv_gen,
        )
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule", None, Some(path.clone()))
            .client_context(&client)
            .build(),
    );

    // NAN-2118: also emit the TARGET-resource record. `rule_imported` alone left
    // an audit blind spot — a detection appeared (or was rewritten) with no
    // rule_created/rule_updated entry naming it. Uses the canonical
    // `detection_rule` resource type + the target's own name, so repository
    // imports show up in the same audit filters as `POST /api/rules`.
    let target_action = match outcome {
        ImportOutcome::Created => RULE_CREATED,
        ImportOutcome::Updated => RULE_UPDATED,
    };
    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, target_action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "detection_rule",
                Some(detection_rule_id),
                Some(plan.resolved_name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "source": "rule_repository_import",
                "repository_id": id.to_string(),
                "repository_path": path.clone(),
            }))
            .build(),
    );

    Ok(Json(ImportRuleResponse {
        detection_rule_id,
        import_type: req.import_type,
    }))
}
