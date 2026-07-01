// SPDX-License-Identifier: AGPL-3.0-or-later

//! Agent enrichment lookup handler (Deno providers)

use axum::{extract::State, Extension, Json};
use nanosiem_core::auth::permissions;

use super::types::*;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Run on-demand agent enrichment lookup across all installed Deno providers
#[utoipa::path(
    post,
    path = "/api/enrichment/agent/lookup",
    tag = "enrichment",
    request_body = AgentLookupRequest,
    responses(
        (status = 200, description = "Agent enrichment results", body = AgentLookupResponse),
        (status = 400, description = "Invalid artifact"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn agent_lookup(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<AgentLookupRequest>,
) -> Result<Json<AgentLookupResponse>, ApiError> {
    use nanosiem_enterprise::agent_enrichment::{
        register_deno_providers, ArtifactType, ProviderRegistry,
    };
    use nanosiem_core::crypto::EncryptionService;
    use nanosiem_enterprise::custom_enrichment::sandbox::SandboxExecutor;
    use std::sync::Arc;

    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

    // Detect artifact type
    let artifact_type = if let Some(ref hint) = request.artifact_type {
        hint.parse::<ArtifactType>()
            .map_err(|e| ApiError::ValidationError(e))?
    } else {
        ArtifactType::detect(&request.artifact).ok_or_else(|| {
            ApiError::ValidationError(format!(
                "Could not detect artifact type for: {}",
                request.artifact
            ))
        })?
    };

    // Build provider registry with installed Deno providers.
    // NOTE: This rebuilds the registry per request (DB query + provider construction).
    // Acceptable for on-demand lookups; if this becomes a hot path, consider caching
    // the registry in AppState with periodic refresh.
    let mut registry = ProviderRegistry::new();
    let encryption = Arc::new(EncryptionService::from_env());
    let executor = Arc::new(SandboxExecutor::new());
    register_deno_providers(&state.pool, encryption, executor, &mut registry).await;

    // Find providers that support this artifact type
    let providers = registry.get_providers_for(artifact_type);
    if providers.is_empty() {
        return Ok(Json(AgentLookupResponse {
            artifact: request.artifact,
            artifact_type: artifact_type.as_db_str().to_string(),
            results: vec![],
        }));
    }

    // Run all matching providers concurrently
    let futures: Vec<_> = providers
        .iter()
        .map(|provider| {
            let artifact = &request.artifact;
            let provider_id = provider.id().to_string();
            async move {
                match provider.enrich(artifact, artifact_type).await {
                    Ok(result) => AgentLookupProviderResult {
                        provider_id: result.provider_id,
                        is_malicious: result.is_malicious,
                        confidence: result.confidence,
                        reputation_score: result.reputation_score,
                        categories: result.categories,
                        raw_data: result.raw_data,
                        error: None,
                    },
                    Err(e) => AgentLookupProviderResult {
                        provider_id,
                        is_malicious: false,
                        confidence: 0.0,
                        reputation_score: None,
                        categories: vec![],
                        raw_data: serde_json::Value::Null,
                        error: Some(e.to_string()),
                    },
                }
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    Ok(Json(AgentLookupResponse {
        artifact: request.artifact,
        artifact_type: artifact_type.as_db_str().to_string(),
        results,
    }))
}

/// OpenAPI doc for the agent enrichment lookup endpoint. Registered only on
/// enterprise builds in `crate::openapi::build_openapi`; the parent
/// `EnrichmentApiDoc` keeps the open IPinfo / ThreatFox / TOR surface.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(agent_lookup),
    components(schemas(
        AgentLookupRequest,
        AgentLookupResponse,
        AgentLookupProviderResult,
    ))
)]
pub struct EnrichmentAgentApiDoc;
