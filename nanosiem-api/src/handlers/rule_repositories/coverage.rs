// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::{CoverageAnalysis, CoverageFilter};

use super::get_rule_repo_service;
use super::types::{ConvertSigmaRequest, ConvertSigmaResponse, CoverageQuery};
#[cfg(feature = "enterprise")]
use super::types::FieldMappingResponse;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Get coverage analysis
#[utoipa::path(
    get,
    path = "/api/rule-repositories/coverage",
    tag = "rule_repositories",
    params(CoverageQuery),
    responses(
        (status = 200, description = "Coverage analysis retrieved successfully", body = CoverageAnalysis),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<CoverageQuery>,
) -> Result<Json<CoverageAnalysis>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;

    let filter = CoverageFilter {
        repository_id: query.repository_id,
        severity: query.severity,
        mitre_tactic: query.mitre_tactic,
        mitre_technique: query.mitre_technique,
    };

    let analysis = service.get_coverage_analysis(filter).await?;

    Ok(Json(analysis))
}

/// Refresh coverage data from ClickHouse
#[utoipa::path(
    post,
    path = "/api/rule-repositories/coverage/refresh",
    tag = "rule_repositories",
    responses(
        (status = 200, description = "Coverage data refreshed successfully"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn refresh_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<(), ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_SYNC).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:sync".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    service.refresh_coverage_data().await?;

    Ok(())
}

/// Convert a Sigma rule to nPL (standalone, without importing)
#[utoipa::path(
    post,
    path = "/api/sigma/convert",
    tag = "rule_repositories",
    request_body = ConvertSigmaRequest,
    responses(
        (status = 200, description = "Sigma rule converted successfully", body = ConvertSigmaResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
#[cfg(feature = "enterprise")]
pub async fn convert_sigma(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ConvertSigmaRequest>,
) -> Result<Json<ConvertSigmaResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    // AI credit rate limiting
    let cost = {
        let registry_guard = state.agent_config_registry.read().await;
        match registry_guard.as_ref() {
            Some(registry) => match registry
                .get_agent_config(&nanosiem_enterprise::melod::AgentId::Detection)
                .await
            {
                Some(config) => {
                    nanosiem_core::resolve_ai_request_cost(&state.pool, &config.model_id).await
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

    // Get the meloD service for AI conversion
    let melod_guard = state.melod_service.read().await;
    let melod_service = melod_guard
        .as_ref()
        .ok_or_else(|| ApiError::InternalError("AI service not configured".to_string()))?;

    // Parse the Sigma rule
    let sigma_rule = nanosiem_core::rule_repository::parse_sigma(&req.sigma_yaml)
        .map_err(|e| ApiError::BadRequest(format!("Failed to parse Sigma rule: {}", e)))?;

    // Get the AI client
    let ai_client = melod_service.ai_client_arc();

    // Create the converter agent
    let converter =
        nanosiem_enterprise::melod::SigmaConverterAgent::new(ai_client, state.config.schema_profile());

    // Convert
    let context = nanosiem_enterprise::melod::ConversionContext::default();
    let result = converter
        .convert(&sigma_rule, context)
        .await
        .map_err(|e| ApiError::InternalError(format!("Conversion failed: {}", e)))?;

    Ok(Json(ConvertSigmaResponse {
        npl_query: result.npl_query,
        confidence: result.confidence,
        field_mappings: result
            .field_mappings
            .into_iter()
            .map(|m| FieldMappingResponse {
                sigma_field: m.sigma_field,
                udm_field: m.udm_field,
                confidence: m.confidence,
                notes: m.notes,
            })
            .collect(),
        unmapped_fields: result.unmapped_fields,
        requires_fields: result.requires_fields,
        warnings: result.warnings,
        needs_review: result.needs_review,
    }))
}

/// Open-core stub: Sigma → nPL conversion is enterprise-only (depends on the
/// meloD detection agent). Endpoint stays registered; users must supply
/// `custom_npl` on the import endpoint instead.
#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    post,
    path = "/api/sigma/convert",
    tag = "rule_repositories",
    request_body = ConvertSigmaRequest,
    responses(
        (status = 400, description = "Enterprise-only endpoint"),
    ),
    security(("api_key" = []))
)]
pub async fn convert_sigma(
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(_req): Json<ConvertSigmaRequest>,
) -> Result<Json<ConvertSigmaResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;
    Err(ApiError::BadRequest(
        "Sigma → nPL conversion requires the enterprise build. \
        Provide `custom_npl` on the import endpoint instead."
            .to_string(),
    ))
}
