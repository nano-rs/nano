// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RULE_IMPORTED};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{ImportPreview, ImportRequest, RepositoryRule, RepositoryRuleFilter};
use uuid::Uuid;

use super::{
    get_rule_repo_service,
    types::{
        ImportRuleRequest, ImportRuleResponse, ListFoldersResponse, ListRulesQuery,
        RepositoryRuleResponse,
    },
    AuditExt,
};
use crate::middleware::{check_permission, AuthContext};
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
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

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
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

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
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

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
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let preview = service.preview_import(*id, &path).await?;

    Ok(Json(preview))
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
        (status = 403, description = "Forbidden"),
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
    check_permission(&auth, permissions::RULE_REPOSITORIES_IMPORT).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:import".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;

    // Get the repository rule to check if it needs conversion
    let repo_rule = service.get_rule(*id, &path).await?;
    let repo = service.get_repository(*id).await?;

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
                        Some(config) => nanosiem_core::ai_request_cost(&config.model_id),
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

            // Get available source_types from the environment for smarter conversion
            let available_source_types = {
                let time_range = nanosiem_core::TimeRangeInput {
                    start: chrono::Utc::now() - chrono::Duration::days(7),
                    end: chrono::Utc::now(),
                };
                melod_service
                    .data_access()
                    .get_source_types(&time_range)
                    .await
                    .map(|types| types.into_iter().map(|t| t.source_type).collect::<Vec<_>>())
                    .unwrap_or_default()
            };

            let ai_client = melod_service.ai_client_arc();
            let converter = nanosiem_enterprise::melod::SigmaConverterAgent::new(ai_client);
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

    let import_type = match req.import_type.as_str() {
        "forked" => nanosiem_core::ImportType::Forked,
        _ => nanosiem_core::ImportType::Linked,
    };

    let import_request = ImportRequest {
        import_type,
        folder: req.folder,
        name: req.name,
        severity: req.severity,
        mode: req.mode,
        custom_npl: npl_query,
        ai_triage_hints,
        source_type_mappings: req.source_type_mappings,
        merge_to_single_source_type: req.merge_to_single_source_type,
    };

    let mv_gen = state.materialized_view_generator.as_deref();

    let (detection_rule_id, _outcome) = service
        .import_rule(*id, &path, import_request, Some(auth.user_id()), mv_gen)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule", None, Some(path.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ImportRuleResponse {
        detection_rule_id,
        import_type: req.import_type,
    }))
}
