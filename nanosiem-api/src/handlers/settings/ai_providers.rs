// SPDX-License-Identifier: AGPL-3.0-or-later

//! Multi-provider AI configuration, models, agents, and catalog sync handlers

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, AGENT_MODEL_CONFIG_UPDATED, AI_PROVIDER_UPDATED,
    AI_PROVIDER_VALIDATED, AVAILABLE_MODEL_CREATED, AVAILABLE_MODEL_DELETED,
    AVAILABLE_MODEL_UPDATED, MODEL_CATALOG_SYNCED,
};
use nanosiem_core::ai_provider::{direct_endpoint, DirectApiStyle};
use nanosiem_core::auth::permissions;
use nanosiem_core::crypto::EncryptionService;
use nanosiem_core::inputlookup::ai_base_url_validator;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

use super::check_not_managed;
use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Version pin sent as `anthropic-version` on every Anthropic Messages probe,
/// whether that is Anthropic's public API or an operator's own endpoint.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Cheapest Claude model to prove reachability + auth with. Overridable per
/// provider via `config.test_model` — an operator's own endpoint may serve a
/// different model set.
const ANTHROPIC_TEST_MODEL: &str = "claude-haiku-4-5-20251001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AiSettingsSurface {
    Providers,
    AgentModels,
}

impl AiSettingsSurface {
    const fn permission(self) -> &'static str {
        match self {
            Self::Providers => permissions::SETTINGS_AI_PROVIDERS,
            Self::AgentModels => permissions::SETTINGS_AGENT_MODELS,
        }
    }
}

/// Keep the purpose-specific AI management capabilities live and independent.
fn require_ai_settings_surface(
    auth: &AuthContext,
    surface: AiSettingsSurface,
) -> Result<(), ApiError> {
    ensure_permission(auth, surface.permission())
}

fn require_ai_availability(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::SETTINGS_AI)
}

// ============================================================================
// Request/Response Types — Providers
// ============================================================================

/// Narrow meloD availability probe for callers with the legacy
/// non-management `settings:ai` capability.
#[derive(Debug, Serialize, ToSchema)]
pub struct AiAvailabilityResponse {
    pub connected: bool,
    pub model_available: bool,
}

/// Response for a provider's configuration
#[derive(Debug, Serialize, ToSchema)]
pub struct ProviderCredentialsResponse {
    pub provider: String,
    pub display_name: String,
    pub enabled: bool,
    pub has_credentials: bool,
    pub config: serde_json::Value,
    pub last_validated_at: Option<String>,
    pub validation_error: Option<String>,
}

/// Request to update provider credentials
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateProviderCredentialsRequest {
    /// API key for the provider. Omit (or null) to keep the stored key;
    /// send an empty string to remove the stored key (NAN-2355).
    pub api_key: Option<String>,
    /// Provider-specific configuration (region, endpoint, etc.)
    pub config: Option<serde_json::Value>,
    /// Whether to enable this provider
    pub enabled: Option<bool>,
}

// ============================================================================
// Request/Response Types — Agent Model Config
// ============================================================================

/// Response for an agent's model configuration
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentModelConfigResponse {
    pub agent_id: String,
    pub display_name: String,
    pub model_id: String,
    pub max_tokens: i32,
    pub temperature: f32,
    pub timeout_seconds: i32,
    pub enabled: bool,
    pub reasoning_effort: Option<String>,
}

/// Request to update agent model configuration
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAgentModelConfigRequest {
    pub model_id: Option<String>,
    pub max_tokens: Option<i32>,
    pub temperature: Option<f32>,
    pub timeout_seconds: Option<i32>,
    pub enabled: Option<bool>,
    pub reasoning_effort: Option<String>,
}

// ============================================================================
// Request/Response Types — Available Models
// ============================================================================

/// Response for an available model
#[derive(Debug, Serialize, ToSchema)]
pub struct AvailableModelResponse {
    pub model_id: String,
    pub provider: String,
    pub display_name: String,
    pub context_window: Option<i32>,
    pub input_price_per_million: Option<f32>,
    pub output_price_per_million: Option<f32>,
    pub supports_vision: bool,
    pub supports_function_calling: bool,
    pub deprecated: bool,
}

/// Request to create a new available model
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAvailableModelRequest {
    pub model_id: String,
    pub provider: String,
    pub display_name: String,
    pub context_window: Option<i32>,
    pub input_price_per_million: Option<f32>,
    pub output_price_per_million: Option<f32>,
    #[serde(default)]
    pub supports_vision: bool,
    #[serde(default = "default_true")]
    pub supports_function_calling: bool,
}

fn default_true() -> bool {
    true
}

/// Request to update an available model
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAvailableModelRequest {
    pub display_name: Option<String>,
    pub context_window: Option<Option<i32>>,
    pub input_price_per_million: Option<Option<f32>>,
    pub output_price_per_million: Option<Option<f32>>,
    pub supports_vision: Option<bool>,
    pub supports_function_calling: Option<bool>,
    pub deprecated: Option<bool>,
}

// ============================================================================
// Request/Response Types — Model Catalog
// ============================================================================

/// Response for model catalog sync
#[derive(Debug, Serialize, ToSchema)]
pub struct ModelCatalogSyncResponse {
    pub status: String,
    pub models_deprecated: usize,
    pub models_total: usize,
    pub commit: Option<String>,
}

/// Response for model catalog sync status
#[derive(Debug, Serialize, ToSchema)]
pub struct ModelCatalogStatusResponse {
    pub url: String,
    pub branch: String,
    pub last_synced_at: Option<String>,
    pub last_sync_status: Option<String>,
    pub last_sync_commit: Option<String>,
    pub last_sync_error: Option<String>,
}

// ============================================================================
// Provider Handlers
// ============================================================================

/// Return only whether meloD has a configured provider and selectable model.
///
/// GET /api/settings/ai-availability
#[utoipa::path(
    get,
    path = "/api/settings/ai-availability",
    tag = "settings",
    responses(
        (status = 200, description = "AI availability", body = AiAvailabilityResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ai_availability(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<AiAvailabilityResponse>, ApiError> {
    require_ai_availability(&auth)?;

    let (connected, model_available): (bool, bool) = sqlx::query_as(
        r#"
        SELECT
            EXISTS (
                SELECT 1
                FROM provider_credentials
                WHERE enabled = true
                  AND credentials_encrypted IS NOT NULL
            ) AS connected,
            EXISTS (
                SELECT 1
                FROM available_models m
                JOIN provider_credentials p ON p.provider = m.provider
                WHERE p.enabled = true
                  AND p.credentials_encrypted IS NOT NULL
                  AND m.deprecated = false
            ) AS model_available
        "#,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(AiAvailabilityResponse {
        connected,
        model_available,
    }))
}

/// List all AI provider configurations
///
/// GET /api/settings/ai-providers
#[utoipa::path(
    get,
    path = "/api/settings/ai-providers",
    tag = "settings",
    responses(
        (status = 200, description = "List of AI providers", body = Vec<ProviderCredentialsResponse>),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_ai_providers(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<ProviderCredentialsResponse>>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::Providers)?;

    let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(
        r#"
        SELECT provider, display_name, enabled,
               credentials_encrypted IS NOT NULL as has_credentials,
               config, last_validated_at, validation_error
        FROM provider_credentials
        ORDER BY provider
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    use sqlx::Row;
    let providers = rows
        .into_iter()
        .map(|row| {
            let config_val: Option<serde_json::Value> = row.get("config");
            let last_validated: Option<chrono::DateTime<chrono::Utc>> =
                row.get("last_validated_at");
            ProviderCredentialsResponse {
                provider: row.get("provider"),
                display_name: row.get("display_name"),
                enabled: row.get("enabled"),
                has_credentials: row.get("has_credentials"),
                config: config_val.unwrap_or_else(|| serde_json::json!({})),
                last_validated_at: last_validated.map(|t| t.to_rfc3339()),
                validation_error: row.get("validation_error"),
            }
        })
        .collect();

    Ok(Json(providers))
}

/// Get a specific provider's configuration
///
/// GET /api/settings/ai-providers/:provider
#[utoipa::path(
    get,
    path = "/api/settings/ai-providers/{provider}",
    tag = "settings",
    params(
        ("provider" = String, Path, description = "Provider name")
    ),
    responses(
        (status = 200, description = "Provider details", body = ProviderCredentialsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Provider not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ai_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(provider): Path<String>,
) -> Result<Json<ProviderCredentialsResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::Providers)?;

    let row = sqlx::query(
        r#"
        SELECT provider, display_name, enabled,
               credentials_encrypted IS NOT NULL as has_credentials,
               config, last_validated_at, validation_error
        FROM provider_credentials
        WHERE provider = $1
        "#,
    )
    .bind(&provider)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?
    .ok_or_else(|| ApiError::NotFound(format!("Provider '{}' not found", provider)))?;

    use sqlx::Row;
    let config_val: Option<serde_json::Value> = row.get("config");
    let last_validated: Option<chrono::DateTime<chrono::Utc>> = row.get("last_validated_at");
    Ok(Json(ProviderCredentialsResponse {
        provider: row.get("provider"),
        display_name: row.get("display_name"),
        enabled: row.get("enabled"),
        has_credentials: row.get("has_credentials"),
        config: config_val.unwrap_or_else(|| serde_json::json!({})),
        last_validated_at: last_validated.map(|t| t.to_rfc3339()),
        validation_error: row.get("validation_error"),
    }))
}

/// Update provider credentials
///
/// PUT /api/settings/ai-providers/:provider
#[utoipa::path(
    put,
    path = "/api/settings/ai-providers/{provider}",
    tag = "settings",
    params(
        ("provider" = String, Path, description = "Provider name")
    ),
    request_body = UpdateProviderCredentialsRequest,
    responses(
        (status = 200, description = "Provider updated", body = ProviderCredentialsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Provider not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_ai_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(provider): Path<String>,
    Json(request): Json<UpdateProviderCredentialsRequest>,
) -> Result<Json<ProviderCredentialsResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::Providers)?;
    check_not_managed(&state)?;

    // SSRF guard (NAN-1368): reject a loopback / private / link-local /
    // cloud-metadata base_url before it is ever persisted, so neither the
    // validate path nor runtime inference can later post to it. On-prem
    // operators opt private endpoints in via NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS.
    validate_config_base_url(request.config.as_ref()).await?;

    // NAN-2355: api_key is tri-state — absent keeps the stored key, a blank
    // string removes it, anything else replaces it. Removal also resets the
    // validation stamp, which described the key that no longer exists. Without
    // an explicit remove path, a key saved for a direct endpoint (the
    // Test-connection gate requires one) could never be evicted, and a stale
    // key poisons credential-less providers like workers-ai on the managed path.
    let clear_credentials = matches!(request.api_key.as_deref(), Some(k) if k.trim().is_empty());

    // Encrypt the API key if provided using AES-256-GCM
    let encrypted_creds: Option<Vec<u8>> = match request.api_key.as_deref() {
        Some(api_key) if !api_key.trim().is_empty() => {
            let encryption = EncryptionService::from_env();
            let creds = serde_json::json!({ "api_key": api_key });
            let encrypted = encryption
                .encrypt_json(&creds)
                .map_err(|e| ApiError::InternalError(format!("Encryption failed: {}", e)))?;
            // Store as JSON: {"ciphertext": "...", "nonce": "..."}
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "ciphertext": encrypted.ciphertext,
                    "nonce": encrypted.nonce
                }))
                .unwrap_or_default(),
            )
        }
        _ => None,
    };

    sqlx::query(
        r#"
        UPDATE provider_credentials
        SET credentials_encrypted = CASE WHEN $5 THEN NULL
                                         ELSE COALESCE($2, credentials_encrypted) END,
            last_validated_at = CASE WHEN $5 THEN NULL ELSE last_validated_at END,
            validation_error = CASE WHEN $5 THEN NULL ELSE validation_error END,
            config = COALESCE($3, config),
            enabled = COALESCE($4, enabled),
            updated_at = NOW()
        WHERE provider = $1
        "#,
    )
    .bind(&provider)
    .bind(&encrypted_creds)
    .bind(&request.config)
    .bind(&request.enabled)
    .bind(clear_credentials)
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    tracing::info!(provider = %provider, "AI provider credentials updated");

    // When enabling a provider (with credentials), auto-enable the meloD master toggle
    // and reload the AI service so it's immediately available. A credential
    // removal (blank api_key) is not an enable, even though api_key is present.
    let provider_being_enabled =
        request.enabled == Some(true) || (encrypted_creds.is_some() && request.enabled.is_none());

    if provider_being_enabled {
        // Check if the master toggle is off and auto-enable it
        let melod_enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE((SELECT enabled FROM melod_settings WHERE id = 'default'), false)",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap_or(false);

        if !melod_enabled {
            if let Err(e) =
                sqlx::query("UPDATE melod_settings SET enabled = true WHERE id = 'default'")
                    .execute(&state.pool)
                    .await
            {
                tracing::warn!(error = %e, "Failed to auto-enable meloD master toggle");
            } else {
                tracing::info!("Auto-enabled meloD master toggle (first provider enabled)");
            }
        }

        // Reload the meloD service to bootstrap credential resolver + melod_service
        match state.reload_melod_service().await {
            Ok(true) => {
                tracing::info!(provider = %provider, "MelodService reloaded after provider update");
            }
            Ok(false) => {
                tracing::debug!(provider = %provider, "MelodService not loaded after provider update");
            }
            Err(e) => {
                tracing::warn!(provider = %provider, error = %e, "Failed to reload MelodService after provider update");
            }
        }

        // Auto-migrate agents that reference models from disabled/unavailable providers.
        if let Err(e) = migrate_agents_from_unavailable_providers(&state.pool).await {
            tracing::warn!(provider = %provider, error = %e, "Failed to migrate agents to enabled provider");
        } else {
            // Reload agent configs in registry to pick up the changes
            let registry_guard = state.agent_config_registry.read().await;
            if let Some(ref registry) = *registry_guard {
                if let Err(e) = registry.load_configs().await {
                    tracing::warn!(error = %e, "Failed to reload agent configs after provider enable migration");
                }
            }
        }

        // On fresh setup, agent_model_config may be empty (migration 123 deletes
        // migration-seeded rows so catalog sync can re-seed from agent_defaults.yaml).
        // The scheduler skips its initial tick, so trigger a sync now if the table is empty.
        // Runs in a background task to avoid blocking the API response on GitHub fetch.
        let agent_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_model_config"
        )
        .fetch_one(&state.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::debug!(error = %e, "Failed to count agent_model_config rows, assuming empty");
            0
        });

        if agent_count == 0 {
            let pool = state.pool.clone();
            let registry = state.agent_config_registry.clone();
            let provider_name = provider.clone();
            tokio::spawn(async move {
                tracing::info!(provider = %provider_name, "No agent configs found — triggering model catalog sync to seed defaults");
                let sync_service = nanosiem_enterprise::melod::ModelCatalogSyncService::new(pool);
                match sync_service.sync().await {
                    Ok(result) => {
                        tracing::info!(
                            total = result.models_total,
                            "Model catalog sync completed (first provider setup)"
                        );
                        // Reload agent configs so they're available on next request
                        let registry_guard = registry.read().await;
                        if let Some(ref reg) = *registry_guard {
                            if let Err(e) = reg.load_configs().await {
                                tracing::warn!(error = %e, "Failed to reload agent configs after initial catalog sync");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Model catalog sync failed during first provider setup");
                    }
                }
            });
        }
    }

    // Invalidate cached AI clients so they pick up new credentials
    {
        let registry_guard = state.agent_config_registry.read().await;
        if let Some(ref registry) = *registry_guard {
            registry.invalidate_all_clients().await;
        }
    }

    // If provider was disabled, migrate agents using its models to a fallback
    if request.enabled == Some(false) {
        if let Err(e) = migrate_agents_from_disabled_provider(&state.pool, &provider).await {
            tracing::warn!(provider = %provider, error = %e, "Failed to migrate agents from disabled provider");
        }

        // Reload agent configs in registry to pick up the changes
        let registry_guard = state.agent_config_registry.read().await;
        if let Some(ref registry) = *registry_guard {
            if let Err(e) = registry.load_configs().await {
                tracing::warn!(error = %e, "Failed to reload agent configs after provider disable");
            }
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, AI_PROVIDER_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some(provider.to_string()))
            .client_context(&client)
            .build(),
    );

    // Return updated provider
    get_ai_provider(State(state), Extension(auth), Path(provider)).await
}

/// Migrate agents from a disabled provider to the cheapest available model
async fn migrate_agents_from_disabled_provider(
    pool: &PgPool,
    disabled_provider: &str,
) -> Result<(), sqlx::Error> {
    // Find the cheapest model from an enabled provider
    let fallback_model: Option<String> = sqlx::query_scalar(
        r#"
        SELECT m.model_id
        FROM available_models m
        JOIN provider_credentials p ON m.provider = p.provider
        WHERE p.enabled = true
        ORDER BY COALESCE(m.input_price_per_million, 999999) ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let fallback_model = match fallback_model {
        Some(m) => m,
        None => {
            tracing::warn!("No enabled providers with models available for fallback");
            return Ok(());
        }
    };

    // Update all agents using models from the disabled provider
    let provider_prefix = format!("{}/", disabled_provider);
    let result = sqlx::query(
        r#"
        UPDATE agent_model_config
        SET model_id = $1, updated_at = NOW()
        WHERE model_id LIKE $2
        "#,
    )
    .bind(&fallback_model)
    .bind(format!("{}%", provider_prefix))
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        tracing::info!(
            disabled_provider = %disabled_provider,
            fallback_model = %fallback_model,
            agents_migrated = result.rows_affected(),
            "Migrated agents from disabled provider to fallback model"
        );
    }

    Ok(())
}

/// Migrate agents that reference models from disabled (or non-existent) providers
/// to the cheapest available model from any enabled provider.
async fn migrate_agents_from_unavailable_providers(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Find the cheapest non-deprecated model from an enabled provider
    let fallback_model: Option<String> = sqlx::query_scalar(
        r#"
        SELECT m.model_id
        FROM available_models m
        JOIN provider_credentials p ON m.provider = p.provider
        WHERE p.enabled = true AND m.deprecated = false
        ORDER BY COALESCE(m.input_price_per_million, 999999) ASC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let fallback_model = match fallback_model {
        Some(m) => m,
        None => {
            tracing::debug!("No enabled providers with models available for agent migration");
            return Ok(());
        }
    };

    // Update agents whose current model belongs to a disabled (or missing) provider.
    let result = sqlx::query(
        r#"
        UPDATE agent_model_config amc
        SET model_id = $1, updated_at = NOW()
        WHERE NOT EXISTS (
            SELECT 1
            FROM available_models m
            JOIN provider_credentials p ON m.provider = p.provider AND p.enabled = true
            WHERE m.model_id = amc.model_id AND m.deprecated = false
        )
        "#,
    )
    .bind(&fallback_model)
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        tracing::info!(
            fallback_model = %fallback_model,
            agents_migrated = result.rows_affected(),
            "Migrated agents from unavailable/disabled providers to enabled provider model"
        );
    }

    Ok(())
}

/// Test provider connection
///
/// POST /api/settings/ai-providers/:provider/validate
#[utoipa::path(
    post,
    path = "/api/settings/ai-providers/{provider}/validate",
    tag = "settings",
    params(
        ("provider" = String, Path, description = "Provider name")
    ),
    responses(
        (status = 200, description = "Validation result", body = serde_json::Value),
        (status = 400, description = "No credentials", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Provider not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn validate_ai_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(provider): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use nanosiem_core::crypto::EncryptedData;

    require_ai_settings_surface(&auth, AiSettingsSurface::Providers)?;
    // Defence in depth (NAN-2231): a managed tenant can't persist a `base_url`
    // — `update_ai_provider` rejects the write — so the probe can't be aimed at
    // an arbitrary host today. Gate the probe on the same condition anyway, so
    // that stays true if provider config ever becomes settable another way.
    // Health monitoring is unaffected: it calls `test_provider_connection`
    // directly through `ApiAiProviderChecker`, not this handler.
    check_not_managed(&state)?;

    // Get credentials for this provider
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT credentials_encrypted, config FROM provider_credentials WHERE provider = $1",
    )
    .bind(&provider)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?
    .ok_or_else(|| ApiError::NotFound(format!("Provider '{}' not found", provider)))?;

    let encrypted_bytes: Option<Vec<u8>> = row.get("credentials_encrypted");
    let config: Option<serde_json::Value> = row.get("config");

    // Check if credentials exist
    let encrypted_bytes = encrypted_bytes.ok_or_else(|| {
        ApiError::BadRequest("No credentials configured for this provider".to_string())
    })?;

    // Decrypt credentials
    let encryption = EncryptionService::from_env();
    let encrypted_json: serde_json::Value = serde_json::from_slice(&encrypted_bytes)
        .map_err(|e| ApiError::InternalError(format!("Invalid encrypted data: {}", e)))?;

    let ciphertext = encrypted_json["ciphertext"]
        .as_str()
        .ok_or_else(|| ApiError::InternalError("Missing ciphertext".to_string()))?;
    let nonce = encrypted_json["nonce"]
        .as_str()
        .ok_or_else(|| ApiError::InternalError("Missing nonce".to_string()))?;

    let encrypted_data = EncryptedData {
        ciphertext: ciphertext.to_string(),
        nonce: nonce.to_string(),
    };

    let creds: serde_json::Value = encryption
        .decrypt_json(&encrypted_data)
        .map_err(|e| ApiError::InternalError(format!("Decryption failed: {}", e)))?;

    let api_key = creds["api_key"]
        .as_str()
        .ok_or_else(|| ApiError::InternalError("No API key in credentials".to_string()))?;

    // Test the provider with a real API call
    let test_result = test_provider_connection(&provider, api_key, config.as_ref()).await;

    match test_result {
        Ok(_) => {
            // Update success status
            sqlx::query(
                r#"
                UPDATE provider_credentials
                SET last_validated_at = NOW(),
                    validation_error = NULL
                WHERE provider = $1
                "#,
            )
            .bind(&provider)
            .execute(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

            // Reload the MelodService to pick up the newly validated provider
            match state.reload_melod_service().await {
                Ok(true) => {
                    tracing::info!(provider = %provider, "MelodService reloaded after provider validation");
                }
                Ok(false) => {
                    tracing::debug!(provider = %provider, "MelodService not loaded (check configuration)");
                }
                Err(e) => {
                    tracing::warn!(provider = %provider, error = %e, "Failed to reload MelodService after validation");
                }
            }

            // Invalidate cached clients so they pick up validated credentials
            {
                let registry_guard = state.agent_config_registry.read().await;
                if let Some(ref registry) = *registry_guard {
                    registry.invalidate_all_clients().await;
                }
            }

            state.emit_audit(
                AuditEvent::builder(AuditSource::Settings, AI_PROVIDER_VALIDATED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("settings", None, Some(provider.to_string()))
                    .client_context(&client)
                    .build(),
            );

            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Provider connection verified successfully"
            })))
        }
        Err(error_msg) => {
            // Update error status
            sqlx::query(
                r#"
                UPDATE provider_credentials
                SET last_validated_at = NOW(),
                    validation_error = $2
                WHERE provider = $1
                "#,
            )
            .bind(&provider)
            .bind(&error_msg)
            .execute(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

            state.emit_audit(
                AuditEvent::builder(AuditSource::Settings, AI_PROVIDER_VALIDATED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("settings", None, Some(provider.to_string()))
                    .client_context(&client)
                    .build(),
            );

            Ok(Json(serde_json::json!({
                "success": false,
                "message": error_msg
            })))
        }
    }
}

/// Adapter exposing the canonical, on-prem-`base_url`-aware provider
/// connectivity test ([`test_provider_connection`]) to the `nanosiem-core`
/// health monitor.
///
/// The health scheduler lives in `nanosiem-core` and cannot call this
/// enterprise handler directly, so it goes through the
/// [`AiProviderConnectivityChecker`](nanosiem_core::health::AiProviderConnectivityChecker)
/// trait. This removes the old hardcoded-public-host duplicate in
/// `ai_monitor.rs`, so health checks now honor an operator's on-prem endpoint
/// exactly like the "Test connection" button. (NAN-1231)
pub struct ApiAiProviderChecker;

#[async_trait::async_trait]
impl nanosiem_core::health::AiProviderConnectivityChecker for ApiAiProviderChecker {
    async fn check(
        &self,
        provider: &str,
        api_key: &str,
        config: &serde_json::Value,
    ) -> Result<(), String> {
        test_provider_connection(provider, api_key, Some(config)).await
    }
}

/// Test a provider connection by making a minimal API call
/// SSRF-guard the `base_url` carried in an AI provider config before it is
/// stored. No-op when no `base_url` is set (the provider then uses the managed
/// gateway). Returns a 400 on a blocked target (NAN-1368).
async fn validate_config_base_url(config: Option<&serde_json::Value>) -> Result<(), ApiError> {
    let base_url = config
        .and_then(|c| c.get("base_url"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(base_url) = base_url {
        ai_base_url_validator()
            .validate_with_dns(base_url.trim_end_matches('/'))
            .await
            .map_err(|e| ApiError::BadRequest(format!("Invalid AI provider base_url: {}", e)))?;
    }

    Ok(())
}

async fn test_provider_connection(
    provider: &str,
    api_key: &str,
    config: Option<&serde_json::Value>,
) -> Result<(), String> {
    // SSRF (NAN-1368): do not follow redirects. The base_url SSRF guard below
    // (and on save) only validates the initial URL, so a public endpoint that
    // 302-redirects to http://127.0.0.1 / a metadata IP would otherwise bypass
    // it. Matches the redirect posture of the webhook / enrichment clients.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();

    // NAN-1207 / NAN-2231: direct path. When the provider config carries a
    // non-empty `base_url`, the operator is pointing nano at their own
    // endpoint rather than the managed Cloudflare gateway — an on-prem
    // OpenAI-compatible server (vLLM, Ollama, LocalAI, …), or their own
    // Anthropic account for data-residency reasons. Probe that endpoint in
    // whatever wire format it speaks instead of the vendor's public API.
    //
    // Style resolution is shared with the request path (`AiGatewayClient`), so
    // a passing test proves the same URL and auth shape inference will
    // actually use.
    if let Some(endpoint) = config.and_then(|c| direct_endpoint(provider, c)) {
        let base_url = endpoint.base_url.clone();
        // SSRF guard (NAN-1368): base_url is admin-configurable and was posted
        // to directly. Reject loopback / private / link-local / cloud-metadata
        // targets before any outbound request. On-prem / air-gapped operators
        // opt private endpoints back in via NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS;
        // metadata endpoints stay blocked regardless.
        // NAN-2018: validate AND pin the client to the validated IP so a DNS
        // rebind between the check and the connect can't reach loopback /
        // private / metadata after the check passed.
        let (pinned_client, _base) = ai_base_url_validator()
            .build_pinned_client(
                &base_url,
                reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()),
            )
            .await
            .map_err(|e| format!("base_url rejected: {}", e))?;

        // `test_model` is the explicit override; `model` is what the
        // direct-endpoint card writes, and before NAN-2231 the probe ignored
        // it — so an operator who filled in "Model id" was silently tested
        // against a placeholder instead. Prefer the override, fall back to the
        // configured model, and only then to a placeholder.
        let model = config
            .and_then(|c| {
                c["test_model"]
                    .as_str()
                    .or_else(|| c["model"].as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            })
            .map(str::to_string);

        let mut req = pinned_client
            .post(endpoint.chat_url())
            .header("content-type", "application/json");

        // `model` is required by both schemas; endpoints ignore an unknown id
        // but still answer, which is enough to prove reachability + auth.
        // Default to a placeholder when the operator hasn't pinned a
        // `test_model` in config.
        //
        // The API key stays optional on both shapes — many on-prem servers run
        // open behind a network boundary.
        let body = match endpoint.style {
            DirectApiStyle::Anthropic => {
                req = req.header("anthropic-version", ANTHROPIC_VERSION);
                if !api_key.is_empty() {
                    req = req.header("x-api-key", api_key);
                }
                serde_json::json!({
                    "model": model.as_deref().unwrap_or(ANTHROPIC_TEST_MODEL),
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}]
                })
            }
            DirectApiStyle::OpenAi => {
                if !api_key.is_empty() {
                    req = req.header("Authorization", format!("Bearer {}", api_key));
                }
                serde_json::json!({
                    "model": model.as_deref().unwrap_or("default"),
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}]
                })
            }
        };

        let resp = req
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Request to direct endpoint failed: {}", e))?;

        // 2xx is a clean success. A 4xx that is NOT an auth failure (e.g. 404
        // unknown model, 422 bad model id) still proves the endpoint is
        // reachable and any supplied key was accepted, so treat it as a pass —
        // the operator can correct the model id separately. 401/403 are real
        // auth failures.
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if status.as_u16() == 401 || status.as_u16() == 403 {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Authentication failed ({}): {}", status, body));
        }
        if status.is_client_error() {
            // Reachable + authorized, just an upstream request-shape quibble.
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Direct endpoint error ({}): {}", status, body));
    }

    match provider {
        "anthropic" => {
            let resp = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", api_key)
                .header("anthropic-version", ANTHROPIC_VERSION)
                .header("content-type", "application/json")
                .json(&serde_json::json!({
                    "model": ANTHROPIC_TEST_MODEL,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}]
                }))
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if resp.status().is_success() {
                Ok(())
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(format!("API error ({}): {}", status, body))
            }
        }
        "google" => {
            let resp = client
                .post(format!(
                    "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={}",
                    api_key
                ))
                .header("content-type", "application/json")
                .json(&serde_json::json!({
                    "contents": [{"parts": [{"text": "Hi"}]}],
                    "generationConfig": {"maxOutputTokens": 10}
                }))
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if resp.status().is_success() {
                Ok(())
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(format!("API error ({}): {}", status, body))
            }
        }
        "openai" => {
            let resp = client
                .post("https://api.openai.com/v1/chat/completions")
                .header("Authorization", format!("Bearer {}", api_key))
                .header("content-type", "application/json")
                .json(&serde_json::json!({
                    "model": "gpt-5-nano",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}]
                }))
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if resp.status().is_success() {
                Ok(())
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(format!("API error ({}): {}", status, body))
            }
        }
        "azure" => {
            let api_base = config
                .and_then(|c| c["api_base"].as_str())
                .ok_or_else(|| "Azure requires api_base in config".to_string())?;
            let api_version = config
                .and_then(|c| c["api_version"].as_str())
                .unwrap_or("2024-10-21");
            let deployment = config
                .and_then(|c| c["deployment"].as_str())
                .unwrap_or("gpt-5-nano");

            let resp = client
                .post(format!(
                    "{}/openai/deployments/{}/chat/completions?api-version={}",
                    api_base, deployment, api_version
                ))
                .header("api-key", api_key)
                .header("content-type", "application/json")
                .json(&serde_json::json!({
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}]
                }))
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if resp.status().is_success() {
                Ok(())
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(format!("API error ({}): {}", status, body))
            }
        }
        "bedrock" => {
            if api_key.is_empty() {
                Err("Empty API key".to_string())
            } else {
                Ok(())
            }
        }
        // Workers AI is credential-less (NAN-1102): the per-provider key is
        // optional — auth is the Cloudflare AI Gateway's `cf-aig-authorization`.
        // Mirror the runtime path (nanosiem-enterprise ai_gateway.rs):
        // `{CLOUDFLARE_AI_GATEWAY_URL}/workers-ai/v1/chat/completions`.
        "workers-ai" => {
            let base = std::env::var("CLOUDFLARE_AI_GATEWAY_URL").map_err(|_| {
                "CLOUDFLARE_AI_GATEWAY_URL not set — Workers AI routes through the \
                 Cloudflare AI Gateway"
                    .to_string()
            })?;
            let base = base.trim_end_matches('/');
            // Config may override the probe model; default to the catalog model.
            // Strip the `workers-ai/` prefix the same way the runtime does.
            let model = config
                .and_then(|c| c["model"].as_str())
                .map(|m| m.strip_prefix("workers-ai/").unwrap_or(m))
                .unwrap_or("@cf/google/gemma-4-26b-a4b-it");

            let mut req = client
                .post(format!("{}/workers-ai/v1/chat/completions", base))
                .header("content-type", "application/json")
                .json(&serde_json::json!({
                    "model": model,
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hi"}]
                }));
            // Gateway-level auth (set when the gateway requires it).
            if let Ok(token) = std::env::var("CF_AIG_AUTH_TOKEN") {
                if !token.is_empty() {
                    req = req.header("cf-aig-authorization", format!("Bearer {}", token));
                }
            }
            // Provider key is optional for Workers AI; attach only if configured.
            if !api_key.is_empty() {
                req = req.header("Authorization", format!("Bearer {}", api_key));
            }

            let resp = req
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if resp.status().is_success() {
                Ok(())
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(format!("API error ({}): {}", status, body))
            }
        }
        _ => Err(format!("Unknown provider: {}", provider)),
    }
}

// ============================================================================
// Agent Model Config Handlers
// ============================================================================

/// List all agent model configurations
///
/// GET /api/settings/agent-models
#[utoipa::path(
    get,
    path = "/api/settings/agent-models",
    tag = "settings",
    responses(
        (status = 200, description = "List of agent configs", body = Vec<AgentModelConfigResponse>),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_agent_model_configs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<AgentModelConfigResponse>>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(
        r#"
        SELECT agent_id, display_name, model_id, max_tokens, temperature,
               timeout_seconds, enabled
        FROM agent_model_config
        ORDER BY agent_id
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    use sqlx::Row;
    let configs = rows
        .into_iter()
        .map(|row| AgentModelConfigResponse {
            agent_id: row.get("agent_id"),
            display_name: row.get("display_name"),
            model_id: row.get("model_id"),
            max_tokens: row.get("max_tokens"),
            temperature: row.get("temperature"),
            timeout_seconds: row.get("timeout_seconds"),
            enabled: row.get("enabled"),
            reasoning_effort: row.try_get("reasoning_effort").ok().flatten(),
        })
        .collect();

    Ok(Json(configs))
}

/// Get a specific agent's model configuration
///
/// GET /api/settings/agent-models/:agent_id
#[utoipa::path(
    get,
    path = "/api/settings/agent-models/{agent_id}",
    tag = "settings",
    params(
        ("agent_id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Agent config", body = AgentModelConfigResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Agent not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_agent_model_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentModelConfigResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    let row = sqlx::query(
        r#"
        SELECT agent_id, display_name, model_id, max_tokens, temperature,
               timeout_seconds, enabled
        FROM agent_model_config
        WHERE agent_id = $1
        "#,
    )
    .bind(&agent_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?
    .ok_or_else(|| ApiError::NotFound(format!("Agent '{}' not found", agent_id)))?;

    use sqlx::Row;
    Ok(Json(AgentModelConfigResponse {
        agent_id: row.get("agent_id"),
        display_name: row.get("display_name"),
        model_id: row.get("model_id"),
        max_tokens: row.get("max_tokens"),
        temperature: row.get("temperature"),
        timeout_seconds: row.get("timeout_seconds"),
        enabled: row.get("enabled"),
        reasoning_effort: row.try_get("reasoning_effort").ok().flatten(),
    }))
}

/// Update agent model configuration
///
/// PUT /api/settings/agent-models/:agent_id
#[utoipa::path(
    put,
    path = "/api/settings/agent-models/{agent_id}",
    tag = "settings",
    params(
        ("agent_id" = String, Path, description = "Agent ID")
    ),
    request_body = UpdateAgentModelConfigRequest,
    responses(
        (status = 200, description = "Agent config updated", body = AgentModelConfigResponse),
        (status = 400, description = "Invalid agent ID", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Agent not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_agent_model_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(agent_id): Path<String>,
    Json(request): Json<UpdateAgentModelConfigRequest>,
) -> Result<Json<AgentModelConfigResponse>, ApiError> {
    use nanosiem_enterprise::melod::AgentId;

    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    // Try to use the registry to update (this invalidates cache)
    let registry_guard = state.agent_config_registry.read().await;
    if let Some(ref registry) = *registry_guard {
        // Parse agent_id string to AgentId enum
        let parsed_agent_id = AgentId::from_str(&agent_id)
            .ok_or_else(|| ApiError::BadRequest(format!("Invalid agent_id: {}", agent_id)))?;

        // Get current config to fill in defaults for unspecified fields
        let current = registry.get_agent_config(&parsed_agent_id).await;
        let (model_id, max_tokens, temperature, timeout_seconds, enabled, reasoning_effort) =
            match current {
                Some(cfg) => (
                    request.model_id.clone().unwrap_or(cfg.model_id),
                    request.max_tokens.unwrap_or(cfg.max_tokens),
                    request.temperature.unwrap_or(cfg.temperature),
                    request.timeout_seconds.unwrap_or(cfg.timeout_seconds),
                    request.enabled.unwrap_or(cfg.enabled),
                    if request.reasoning_effort.is_some() {
                        request.reasoning_effort.clone()
                    } else {
                        cfg.reasoning_effort
                    },
                ),
                None => {
                    let model_id = request.model_id.clone().ok_or_else(|| {
                        ApiError::BadRequest(
                            "model_id is required when creating a new agent config".to_string(),
                        )
                    })?;
                    (
                        model_id,
                        request.max_tokens.unwrap_or(4096),
                        request.temperature.unwrap_or(0.7),
                        request.timeout_seconds.unwrap_or(120),
                        request.enabled.unwrap_or(true),
                        request.reasoning_effort.clone(),
                    )
                }
            };

        // Update via registry (this invalidates cache and reloads)
        registry
            .update_agent_config_full(
                &parsed_agent_id,
                &model_id,
                max_tokens,
                temperature,
                timeout_seconds,
                enabled,
                reasoning_effort,
            )
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        tracing::info!(agent_id = %agent_id, model = %model_id, "Agent model configuration updated via registry");
    } else {
        // Fallback: direct database update (no cache invalidation)
        sqlx::query(
            r#"
            UPDATE agent_model_config
            SET model_id = COALESCE($2, model_id),
                max_tokens = COALESCE($3, max_tokens),
                temperature = COALESCE($4, temperature),
                timeout_seconds = COALESCE($5, timeout_seconds),
                enabled = COALESCE($6, enabled),
                reasoning_effort = COALESCE($7, reasoning_effort),
                source = 'custom',
                updated_at = NOW()
            WHERE agent_id = $1
            "#,
        )
        .bind(&agent_id)
        .bind(&request.model_id)
        .bind(&request.max_tokens)
        .bind(&request.temperature)
        .bind(&request.timeout_seconds)
        .bind(&request.enabled)
        .bind(&request.reasoning_effort)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

        tracing::info!(agent_id = %agent_id, "Agent model configuration updated (no registry available)");
    }
    drop(registry_guard);

    // Reload the MelodService to pick up the new model configuration
    if let Err(e) = state.reload_melod_service().await {
        tracing::warn!(error = %e, "Failed to reload meloD service after agent config update");
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, AGENT_MODEL_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some(agent_id.to_string()))
            .client_context(&client)
            .build(),
    );

    // Return updated config
    get_agent_model_config(State(state), Extension(auth), Path(agent_id)).await
}

// ============================================================================
// Available Models Handlers
// ============================================================================

/// List all available models
///
/// GET /api/settings/available-models
#[utoipa::path(
    get,
    path = "/api/settings/available-models",
    tag = "settings",
    responses(
        (status = 200, description = "List of available models", body = Vec<AvailableModelResponse>),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_available_models(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<AvailableModelResponse>>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(
        r#"
        SELECT m.model_id, m.provider, m.display_name, m.context_window,
               m.input_price_per_million, m.output_price_per_million,
               m.supports_vision, m.supports_function_calling, m.deprecated
        FROM available_models m
        JOIN provider_credentials p ON m.provider = p.provider AND p.enabled = true
        WHERE m.deprecated = false
        ORDER BY m.provider, m.display_name
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    use sqlx::Row;
    let models = rows
        .into_iter()
        .map(|row| AvailableModelResponse {
            model_id: row.get("model_id"),
            provider: row.get("provider"),
            display_name: row.get("display_name"),
            context_window: row.get("context_window"),
            input_price_per_million: row.get("input_price_per_million"),
            output_price_per_million: row.get("output_price_per_million"),
            supports_vision: row.get("supports_vision"),
            supports_function_calling: row.get("supports_function_calling"),
            deprecated: row.get("deprecated"),
        })
        .collect();

    Ok(Json(models))
}

/// List ALL available models (including deprecated, all providers)
///
/// GET /api/settings/available-models/all
///
/// Returns every model in the catalog for the management UI.
#[utoipa::path(
    get,
    path = "/api/settings/available-models/all",
    tag = "settings",
    responses(
        (status = 200, description = "All available models", body = Vec<AvailableModelResponse>),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_all_available_models(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<AvailableModelResponse>>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(
        r#"
        SELECT model_id, provider, display_name, context_window,
               input_price_per_million, output_price_per_million,
               supports_vision, supports_function_calling, deprecated
        FROM available_models
        ORDER BY provider, display_name
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    use sqlx::Row;
    let models = rows
        .into_iter()
        .map(|row| AvailableModelResponse {
            model_id: row.get("model_id"),
            provider: row.get("provider"),
            display_name: row.get("display_name"),
            context_window: row.get("context_window"),
            input_price_per_million: row.get("input_price_per_million"),
            output_price_per_million: row.get("output_price_per_million"),
            supports_vision: row.get("supports_vision"),
            supports_function_calling: row.get("supports_function_calling"),
            deprecated: row.get("deprecated"),
        })
        .collect();

    Ok(Json(models))
}

/// Create a new available model
///
/// POST /api/settings/available-models
#[utoipa::path(
    post,
    path = "/api/settings/available-models",
    tag = "settings",
    request_body = CreateAvailableModelRequest,
    responses(
        (status = 200, description = "Model created", body = AvailableModelResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 409, description = "Model ID already exists", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_available_model(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateAvailableModelRequest>,
) -> Result<Json<AvailableModelResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    // --- Input validation & sanitization ---
    let model_id = request.model_id.trim().to_string();
    let provider = request.provider.trim().to_lowercase();
    let display_name = request.display_name.trim().to_string();

    if model_id.is_empty() {
        return Err(ApiError::ValidationError(
            "model_id is required".to_string(),
        ));
    }
    if provider.is_empty() {
        return Err(ApiError::ValidationError(
            "provider is required".to_string(),
        ));
    }
    if display_name.is_empty() {
        return Err(ApiError::ValidationError(
            "display_name is required".to_string(),
        ));
    }

    if model_id.len() > 256 {
        return Err(ApiError::ValidationError(
            "model_id must be 256 characters or fewer".to_string(),
        ));
    }
    if display_name.len() > 256 {
        return Err(ApiError::ValidationError(
            "display_name must be 256 characters or fewer".to_string(),
        ));
    }

    const VALID_PROVIDERS: &[&str] = &[
        "anthropic",
        "bedrock",
        "google",
        "openai",
        "azure",
        "workers-ai",
    ];
    if !VALID_PROVIDERS.contains(&provider.as_str()) {
        return Err(ApiError::ValidationError(format!(
            "Invalid provider '{}'. Must be one of: {}",
            provider,
            VALID_PROVIDERS.join(", ")
        )));
    }

    if model_id.chars().any(|c| c.is_control()) {
        return Err(ApiError::ValidationError(
            "model_id must not contain control characters".to_string(),
        ));
    }
    if display_name.chars().any(|c| c.is_control()) {
        return Err(ApiError::ValidationError(
            "display_name must not contain control characters".to_string(),
        ));
    }

    if !model_id.contains('/') {
        return Err(ApiError::ValidationError(
            "model_id must follow provider/model-name format (e.g., anthropic/claude-sonnet-4-5)"
                .to_string(),
        ));
    }

    if let Some(ctx) = request.context_window {
        if ctx <= 0 {
            return Err(ApiError::ValidationError(
                "context_window must be a positive integer".to_string(),
            ));
        }
    }

    if let Some(price) = request.input_price_per_million {
        if price < 0.0 {
            return Err(ApiError::ValidationError(
                "input_price_per_million must be non-negative".to_string(),
            ));
        }
    }
    if let Some(price) = request.output_price_per_million {
        if price < 0.0 {
            return Err(ApiError::ValidationError(
                "output_price_per_million must be non-negative".to_string(),
            ));
        }
    }

    // Check for duplicate
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM available_models WHERE model_id = $1)")
            .bind(&model_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

    if exists {
        return Err(ApiError::Conflict(format!(
            "Model '{}' already exists",
            model_id
        )));
    }

    sqlx::query(
        r#"
        INSERT INTO available_models (model_id, provider, display_name, context_window,
            input_price_per_million, output_price_per_million,
            supports_vision, supports_function_calling, deprecated, source)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, 'custom')
        "#,
    )
    .bind(&model_id)
    .bind(&provider)
    .bind(&display_name)
    .bind(request.context_window)
    .bind(request.input_price_per_million)
    .bind(request.output_price_per_million)
    .bind(request.supports_vision)
    .bind(request.supports_function_calling)
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    tracing::info!(model_id = %model_id, provider = %provider, "Available model created");

    // Invalidate cached AI clients so the new model is immediately available
    {
        let registry_guard = state.agent_config_registry.read().await;
        if let Some(ref registry) = *registry_guard {
            registry.invalidate_all_clients().await;
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, AVAILABLE_MODEL_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some(model_id.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(AvailableModelResponse {
        model_id,
        provider,
        display_name,
        context_window: request.context_window,
        input_price_per_million: request.input_price_per_million,
        output_price_per_million: request.output_price_per_million,
        supports_vision: request.supports_vision,
        supports_function_calling: request.supports_function_calling,
        deprecated: false,
    }))
}

/// Update an available model
///
/// PUT /api/settings/available-models/{model_id}
#[utoipa::path(
    put,
    path = "/api/settings/available-models/{model_id}",
    tag = "settings",
    params(("model_id" = String, Path, description = "Model ID")),
    request_body = UpdateAvailableModelRequest,
    responses(
        (status = 200, description = "Model updated", body = AvailableModelResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Model not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_available_model(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(model_id): Path<String>,
    Json(request): Json<UpdateAvailableModelRequest>,
) -> Result<Json<AvailableModelResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    // --- Input validation ---
    if let Some(ref dn) = request.display_name {
        let dn = dn.trim();
        if dn.is_empty() {
            return Err(ApiError::ValidationError(
                "display_name must not be empty".to_string(),
            ));
        }
        if dn.len() > 256 {
            return Err(ApiError::ValidationError(
                "display_name must be 256 characters or fewer".to_string(),
            ));
        }
        if dn.chars().any(|c| c.is_control()) {
            return Err(ApiError::ValidationError(
                "display_name must not contain control characters".to_string(),
            ));
        }
    }
    if let Some(Some(ctx)) = request.context_window {
        if ctx <= 0 {
            return Err(ApiError::ValidationError(
                "context_window must be a positive integer".to_string(),
            ));
        }
    }
    if let Some(Some(price)) = request.input_price_per_million {
        if price < 0.0 {
            return Err(ApiError::ValidationError(
                "input_price_per_million must be non-negative".to_string(),
            ));
        }
    }
    if let Some(Some(price)) = request.output_price_per_million {
        if price < 0.0 {
            return Err(ApiError::ValidationError(
                "output_price_per_million must be non-negative".to_string(),
            ));
        }
    }

    // Build dynamic UPDATE query
    let mut sets = Vec::new();
    let mut param_idx = 1u32;
    let mut binds: Vec<
        Box<
            dyn FnOnce(
                    sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
                )
                    -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>
                + Send,
        >,
    > = Vec::new();

    if let Some(ref display_name) = request.display_name {
        param_idx += 1;
        sets.push(format!("display_name = ${}", param_idx));
        let v = display_name.clone();
        binds.push(Box::new(move |q| q.bind(v)));
    }
    if let Some(ref context_window) = request.context_window {
        param_idx += 1;
        sets.push(format!("context_window = ${}", param_idx));
        let v = *context_window;
        binds.push(Box::new(move |q| q.bind(v)));
    }
    if let Some(ref input_price) = request.input_price_per_million {
        param_idx += 1;
        sets.push(format!("input_price_per_million = ${}", param_idx));
        let v = *input_price;
        binds.push(Box::new(move |q| q.bind(v)));
    }
    if let Some(ref output_price) = request.output_price_per_million {
        param_idx += 1;
        sets.push(format!("output_price_per_million = ${}", param_idx));
        let v = *output_price;
        binds.push(Box::new(move |q| q.bind(v)));
    }
    if let Some(supports_vision) = request.supports_vision {
        param_idx += 1;
        sets.push(format!("supports_vision = ${}", param_idx));
        binds.push(Box::new(move |q| q.bind(supports_vision)));
    }
    if let Some(supports_function_calling) = request.supports_function_calling {
        param_idx += 1;
        sets.push(format!("supports_function_calling = ${}", param_idx));
        binds.push(Box::new(move |q| q.bind(supports_function_calling)));
    }
    if let Some(deprecated) = request.deprecated {
        param_idx += 1;
        sets.push(format!("deprecated = ${}", param_idx));
        binds.push(Box::new(move |q| q.bind(deprecated)));
    }

    if sets.is_empty() {
        return Err(ApiError::ValidationError("No fields to update".to_string()));
    }

    let _ = param_idx; // suppress unused warning
    let sql = format!(
        "UPDATE available_models SET {} WHERE model_id = $1 RETURNING model_id, provider, display_name, context_window, input_price_per_million, output_price_per_million, supports_vision, supports_function_calling, deprecated",
        sets.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&model_id);
    for bind_fn in binds {
        query = bind_fn(query);
    }

    let row = query
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("Model '{}' not found", model_id)))?;

    use sqlx::Row;
    let model = AvailableModelResponse {
        model_id: row.get("model_id"),
        provider: row.get("provider"),
        display_name: row.get("display_name"),
        context_window: row.get("context_window"),
        input_price_per_million: row.get("input_price_per_million"),
        output_price_per_million: row.get("output_price_per_million"),
        supports_vision: row.get("supports_vision"),
        supports_function_calling: row.get("supports_function_calling"),
        deprecated: row.get("deprecated"),
    };

    tracing::info!(model_id = %model.model_id, "Available model updated");

    // Invalidate cached AI clients so changes take effect immediately
    {
        let registry_guard = state.agent_config_registry.read().await;
        if let Some(ref registry) = *registry_guard {
            registry.invalidate_all_clients().await;
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, AVAILABLE_MODEL_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some(model_id.to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(model))
}

/// Delete an available model
///
/// DELETE /api/settings/available-models/{model_id}
///
/// Returns 409 Conflict if the model is referenced by any agent model config.
#[utoipa::path(
    delete,
    path = "/api/settings/available-models/{model_id}",
    tag = "settings",
    params(("model_id" = String, Path, description = "Model ID")),
    responses(
        (status = 200, description = "Model deleted"),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 404, description = "Model not found", body = ErrorResponse),
        (status = 409, description = "Model is in use by an agent", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_available_model(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(model_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    // Fetch provider before deleting (needed for client cache invalidation)
    let provider: Option<String> =
        sqlx::query_scalar("SELECT provider FROM available_models WHERE model_id = $1")
            .bind(&model_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

    let _provider =
        provider.ok_or_else(|| ApiError::NotFound(format!("Model '{}' not found", model_id)))?;

    // Check if model is referenced by any agent
    let in_use: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_model_config WHERE model_id = $1)")
            .bind(&model_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

    if in_use {
        return Err(ApiError::Conflict(format!(
            "Cannot delete model '{}': it is assigned to one or more agents. Reassign those agents first.",
            model_id
        )));
    }

    sqlx::query("DELETE FROM available_models WHERE model_id = $1")
        .bind(&model_id)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    tracing::info!(model_id = %model_id, "Available model deleted");

    // Invalidate cached AI clients so the model removal takes effect immediately
    {
        let registry_guard = state.agent_config_registry.read().await;
        if let Some(ref registry) = *registry_guard {
            registry.invalidate_all_clients().await;
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, AVAILABLE_MODEL_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some(model_id.to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({ "deleted": true })))
}

// ============================================================================
// Model Catalog Handlers
// ============================================================================

/// Sync the model catalog from the upstream GitHub repository
///
/// POST /api/settings/model-catalog/sync
#[utoipa::path(
    post,
    path = "/api/settings/model-catalog/sync",
    tag = "settings",
    responses(
        (status = 200, description = "Sync completed", body = ModelCatalogSyncResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Sync failed", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn sync_model_catalog(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<ModelCatalogSyncResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    let service = nanosiem_enterprise::melod::ModelCatalogSyncService::new(state.pool.clone());

    let result = service.sync().await.map_err(|e| {
        tracing::warn!(error = %e, "Model catalog sync failed");
        ApiError::InternalError(format!("Model catalog sync failed: {}", e))
    })?;

    tracing::info!(
        deprecated = result.models_deprecated,
        total = result.models_total,
        "Model catalog synced"
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, MODEL_CATALOG_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("model_catalog".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ModelCatalogSyncResponse {
        status: "success".to_string(),
        models_deprecated: result.models_deprecated,
        models_total: result.models_total,
        commit: result.commit,
    }))
}

/// Get model catalog sync status
///
/// GET /api/settings/model-catalog/status
#[utoipa::path(
    get,
    path = "/api/settings/model-catalog/status",
    tag = "settings",
    responses(
        (status = 200, description = "Catalog status", body = ModelCatalogStatusResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_model_catalog_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ModelCatalogStatusResponse>, ApiError> {
    require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels)?;

    let row = sqlx::query(
        r#"
        SELECT
            COALESCE(model_catalog_url, 'https://github.com/nano-rs/models') as url,
            COALESCE(model_catalog_branch, 'main') as branch,
            model_catalog_last_synced_at,
            model_catalog_last_sync_status,
            model_catalog_last_sync_commit,
            model_catalog_last_sync_error
        FROM system_settings
        WHERE id = 'default'
        "#,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    use sqlx::Row;
    let response = match row {
        Some(r) => ModelCatalogStatusResponse {
            url: r.get("url"),
            branch: r.get("branch"),
            last_synced_at: r
                .get::<Option<chrono::DateTime<chrono::Utc>>, _>("model_catalog_last_synced_at")
                .map(|dt| dt.to_rfc3339()),
            last_sync_status: r.get("model_catalog_last_sync_status"),
            last_sync_commit: r.get("model_catalog_last_sync_commit"),
            last_sync_error: r.get("model_catalog_last_sync_error"),
        },
        None => ModelCatalogStatusResponse {
            url: "https://github.com/nano-rs/models".to_string(),
            branch: "main".to_string(),
            last_synced_at: None,
            last_sync_status: None,
            last_sync_commit: None,
            last_sync_error: None,
        },
    };

    Ok(Json(response))
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use nanosiem_core::auth::{api_key::ApiKeyInfo, types::TokenClaims};

    fn jwt_auth(permissions: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: uuid::Uuid::nil(),
            roles: Vec::new(),
            permissions: permissions
                .iter()
                .map(|permission| permission.to_string())
                .collect(),
            exp: i64::MAX,
            iat: 0,
            jti: uuid::Uuid::nil(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(permissions: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: uuid::Uuid::nil(),
            name: "test-key".to_string(),
            permissions: permissions
                .iter()
                .map(|permission| permission.to_string())
                .collect(),
            user_id: Some(uuid::Uuid::nil()),
        })
    }

    fn assert_denied(result: Result<(), ApiError>) {
        assert!(matches!(result, Err(ApiError::Forbidden(_))));
    }

    #[test]
    fn ai_settings_capability_split_is_identical_for_sessions_and_api_keys() {
        for auth in [
            jwt_auth(&[]),
            jwt_auth(&["settings:view"]),
            api_key_auth(&[]),
            api_key_auth(&["settings:view"]),
        ] {
            assert_denied(require_ai_availability(&auth));
            assert_denied(require_ai_settings_surface(
                &auth,
                AiSettingsSurface::Providers,
            ));
            assert_denied(require_ai_settings_surface(
                &auth,
                AiSettingsSurface::AgentModels,
            ));
        }

        for auth in [
            jwt_auth(&[permissions::SETTINGS_AI]),
            api_key_auth(&[permissions::SETTINGS_AI]),
        ] {
            assert!(require_ai_availability(&auth).is_ok());
            assert_denied(require_ai_settings_surface(
                &auth,
                AiSettingsSurface::Providers,
            ));
            assert_denied(require_ai_settings_surface(
                &auth,
                AiSettingsSurface::AgentModels,
            ));
        }

        for auth in [
            jwt_auth(&[permissions::SETTINGS_AI_PROVIDERS]),
            api_key_auth(&[permissions::SETTINGS_AI_PROVIDERS]),
        ] {
            assert_denied(require_ai_availability(&auth));
            assert!(require_ai_settings_surface(&auth, AiSettingsSurface::Providers).is_ok());
            assert_denied(require_ai_settings_surface(
                &auth,
                AiSettingsSurface::AgentModels,
            ));
        }

        for auth in [
            jwt_auth(&[permissions::SETTINGS_AGENT_MODELS]),
            api_key_auth(&[permissions::SETTINGS_AGENT_MODELS]),
        ] {
            assert_denied(require_ai_availability(&auth));
            assert_denied(require_ai_settings_surface(
                &auth,
                AiSettingsSurface::Providers,
            ));
            assert!(require_ai_settings_surface(&auth, AiSettingsSurface::AgentModels).is_ok());
        }
    }

    #[test]
    fn revoking_a_narrow_capability_drops_only_its_management_surface() {
        for (before_revocation, after_revocation, surface) in [
            (
                jwt_auth(&[
                    permissions::SETTINGS_AI,
                    permissions::SETTINGS_AI_PROVIDERS,
                    permissions::SETTINGS_AGENT_MODELS,
                ]),
                jwt_auth(&[permissions::SETTINGS_AI, permissions::SETTINGS_AGENT_MODELS]),
                AiSettingsSurface::Providers,
            ),
            (
                api_key_auth(&[
                    permissions::SETTINGS_AI,
                    permissions::SETTINGS_AI_PROVIDERS,
                    permissions::SETTINGS_AGENT_MODELS,
                ]),
                api_key_auth(&[permissions::SETTINGS_AI, permissions::SETTINGS_AI_PROVIDERS]),
                AiSettingsSurface::AgentModels,
            ),
        ] {
            assert!(require_ai_settings_surface(&before_revocation, surface).is_ok());
            assert_denied(require_ai_settings_surface(&after_revocation, surface));
            assert!(require_ai_availability(&after_revocation).is_ok());
        }
    }
}
