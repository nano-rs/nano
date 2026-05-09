// SPDX-License-Identifier: AGPL-3.0-or-later

// meloD AI service initialization and config polling
use super::AppState;

use nanosiem_enterprise::melod::{
    AgentConfigRegistry, AgentConfigRegistryConfig, CredentialResolver, DataAccessLayer,
    MelodService,
};
use std::sync::Arc;

impl AppState {
    /// Reload the meloD service from current configuration
    ///
    /// This allows hot-reloading the service when settings change,
    /// without requiring an API server restart.
    pub async fn reload_melod_service(&self) -> anyhow::Result<bool> {
        // Check if meloD is enabled via melod_settings table
        let melod_enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE((SELECT enabled FROM melod_settings WHERE id = 'default'), false)",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        if !melod_enabled {
            // Managed mode: auto-enable meloD when AI credentials are provided
            if self.config.deployment_mode.is_managed() {
                if std::env::var("MANAGED_AI_API_KEY").is_ok()
                    && std::env::var("MANAGED_AI_PROVIDER").is_ok()
                {
                    tracing::info!(
                        "Managed mode: meloD disabled but AI credentials present, auto-enabling"
                    );
                    sqlx::query("INSERT INTO melod_settings (id, enabled) VALUES ('default', true) ON CONFLICT (id) DO UPDATE SET enabled = true, updated_at = NOW()")
                        .execute(&self.pool)
                        .await
                        .ok();
                } else {
                    tracing::debug!("meloD is disabled in configuration");
                    let mut guard = self.melod_service.write().await;
                    *guard = None;
                    return Ok(false);
                }
            } else {
                tracing::debug!("meloD is disabled in configuration");
                let mut guard = self.melod_service.write().await;
                *guard = None;
                return Ok(false);
            }
        }

        // Get requests_per_minute from melod_settings config JSON
        let requests_per_minute: u32 = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT (config->>'requests_per_minute')::int FROM melod_settings WHERE id = 'default'",
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        .flatten()
        .map(|v| v as u32)
        .unwrap_or(60);

        // Cloudflare AI Gateway URL (required for AI features)
        let ai_gateway_url = match std::env::var("CLOUDFLARE_AI_GATEWAY_URL") {
            Ok(url) => url,
            Err(_) => {
                tracing::warn!("CLOUDFLARE_AI_GATEWAY_URL not set - AI features disabled");
                let mut guard = self.melod_service.write().await;
                *guard = None;
                return Ok(false);
            }
        };
        let cf_auth_token = std::env::var("CF_AIG_AUTH_TOKEN").ok();

        // Managed mode: auto-provision AI provider if not already configured
        if self.config.deployment_mode.is_managed() {
            if let (Ok(api_key), Ok(provider)) = (
                std::env::var("MANAGED_AI_API_KEY"),
                std::env::var("MANAGED_AI_PROVIDER"),
            ) {
                tracing::info!(provider = %provider, "Managed mode: checking AI provider auto-provision");
                // Check if already provisioned with credentials
                let already_configured: bool = sqlx::query_scalar(
                    "SELECT COUNT(*) > 0 FROM provider_credentials WHERE provider = $1 AND enabled = true AND credentials_encrypted IS NOT NULL"
                )
                .bind(&provider)
                .fetch_one(&self.pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(provider = %provider, error = %e, "Failed to check provider_credentials, assuming not configured");
                    false
                });

                if already_configured {
                    tracing::info!(provider = %provider, "Managed AI provider already configured");
                } else {
                    tracing::info!(provider = %provider, "Auto-provisioning managed AI provider");
                    let encryption = nanosiem_core::crypto::EncryptionService::from_env();
                    let creds = serde_json::json!({ "api_key": api_key });
                    match encryption.encrypt_json(&creds) {
                        Ok(encrypted) => {
                            let encrypted_bytes = serde_json::to_vec(&serde_json::json!({
                                "ciphertext": encrypted.ciphertext,
                                "nonce": encrypted.nonce
                            }))
                            .unwrap_or_default();
                            let display_name = match provider.as_str() {
                                "google" => "Google (Gemini)",
                                "anthropic" => "Anthropic (Claude)",
                                "openai" => "OpenAI",
                                _ => &provider,
                            };
                            match sqlx::query(
                                "INSERT INTO provider_credentials (provider, display_name, credentials_encrypted, enabled, created_at, updated_at) \
                                 VALUES ($1, $2, $3, true, NOW(), NOW()) \
                                 ON CONFLICT (provider) DO UPDATE SET credentials_encrypted = $3, display_name = $2, enabled = true, updated_at = NOW()"
                            )
                            .bind(&provider)
                            .bind(display_name)
                            .bind(&encrypted_bytes)
                            .execute(&self.pool)
                            .await
                            {
                                Ok(_) => tracing::info!(provider = %provider, "Auto-provisioned managed AI provider"),
                                Err(e) => tracing::error!(provider = %provider, error = %e, "Failed to auto-provision managed AI provider"),
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to encrypt managed AI key: {}", e);
                        }
                    }
                }
            } else {
                tracing::debug!("Managed mode but MANAGED_AI_API_KEY/MANAGED_AI_PROVIDER not set");
            }
        }

        // Workers AI: auto-enable when gateway is configured (no API key needed —
        // auth is handled at the Cloudflare account level via CF_AIG_AUTH_TOKEN)
        let workers_ai_exists: bool = sqlx::query_scalar(
            "SELECT COUNT(*) > 0 FROM provider_credentials WHERE provider = 'workers-ai'",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        if workers_ai_exists {
            let already_enabled: bool = sqlx::query_scalar(
                "SELECT enabled FROM provider_credentials WHERE provider = 'workers-ai'",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap_or(true);

            if !already_enabled {
                tracing::info!(
                    "Auto-enabling Workers AI provider (gateway auth, no API key required)"
                );
                sqlx::query(
                    "UPDATE provider_credentials SET enabled = true, updated_at = NOW() WHERE provider = 'workers-ai'"
                )
                .execute(&self.pool)
                .await
                .ok();
            }
        }

        // Check for enabled providers
        let enabled_providers: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM provider_credentials WHERE enabled = true")
                .fetch_one(&self.pool)
                .await
                .unwrap_or(0);

        if enabled_providers == 0 {
            tracing::info!(
                "No AI providers enabled - configure providers in Settings > AI Providers"
            );
            let mut guard = self.melod_service.write().await;
            *guard = None;
            return Ok(false);
        }

        tracing::info!(
            gateway_url = %ai_gateway_url,
            enabled_providers = enabled_providers,
            "Creating MelodService with Cloudflare AI Gateway"
        );

        // Create credential resolver (replaces LiteLLM sync service)
        let credential_resolver = Arc::new(CredentialResolver::new(self.pool.clone()));

        // Build CF AI Gateway metadata for per-org analytics
        let cf_aig_metadata = {
            let org_id = std::env::var("NANO_ORG_ID").unwrap_or_default();
            let deployment_id = std::env::var("NANO_DEPLOYMENT_ID").unwrap_or_default();
            let tier = std::env::var("NANO_TIER").unwrap_or_else(|_| "unrestricted".to_string());
            if !org_id.is_empty() || !deployment_id.is_empty() {
                Some(
                    serde_json::json!({
                        "org_id": org_id,
                        "deployment_id": deployment_id,
                        "tier": tier
                    })
                    .to_string(),
                )
            } else {
                None
            }
        };

        let registry_config = AgentConfigRegistryConfig {
            ai_gateway_url,
            cf_auth_token,
            cf_aig_metadata,
            requests_per_minute,
        };

        let registry = Arc::new(AgentConfigRegistry::new(
            self.pool.clone(),
            registry_config,
            credential_resolver,
        ));

        // Load agent configurations from database
        if let Err(e) = registry.load_configs().await {
            tracing::warn!("Failed to load agent configs, using defaults: {}", e);
        }

        // Store the registry for later use
        {
            let mut guard = self.agent_config_registry.write().await;
            *guard = Some(Arc::clone(&registry));
        }

        // Create data access layer
        let data_access = self.create_data_access_layer();

        let melod_service = match MelodService::from_registry(
            registry,
            data_access,
            self.detection_service.clone(),
        )
        .await
        {
            Ok(mut service) => {
                let failure_logger = std::sync::Arc::new(
                    nanosiem_enterprise::melod::AiFailureLogger::new(self.pool.clone()),
                );
                service.set_failure_logger(failure_logger);
                service.set_session_repository(self.melod_session_repo.clone());
                service
            }
            Err(e) => {
                tracing::error!("Failed to create MelodService: {}", e);
                let mut guard = self.melod_service.write().await;
                *guard = None;
                return Err(e.into());
            }
        };

        // Update the service
        let mut guard = self.melod_service.write().await;
        *guard = Some(Arc::new(melod_service));

        tracing::info!("meloD service initialized successfully");
        Ok(true)
    }

    /// Helper to create the data access layer
    pub fn create_data_access_layer(&self) -> DataAccessLayer {
        if let Some(dual_pool) = &self.dual_pool {
            tracing::debug!("Creating DataAccessLayer with ClickHouse support");
            DataAccessLayer::with_clickhouse_clustered(
                self.pool.clone(),
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
            )
        } else {
            tracing::debug!("Creating DataAccessLayer with PostgreSQL only (legacy mode)");
            DataAccessLayer::new(self.pool.clone())
        }
    }

    /// Start the meloD config poller for multi-pod sync
    ///
    /// Spawns a background task that polls `provider_credentials.updated_at` every 30s.
    /// When a change is detected (another pod saved new settings), invalidates
    /// credential caches and reloads agent configs.
    pub fn start_melod_config_poller(&self) -> tokio::task::JoinHandle<()> {
        let state = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            interval.tick().await; // Skip initial tick (startup already calls reload)

            let mut last_seen: Option<chrono::DateTime<chrono::Utc>> = None;

            loop {
                interval.tick().await;

                let row: Option<chrono::DateTime<chrono::Utc>> = match sqlx::query_scalar(
                    "SELECT MAX(updated_at) FROM provider_credentials WHERE enabled = true",
                )
                .fetch_one(&state.pool)
                .await
                {
                    Ok(ts) => ts,
                    Err(e) => {
                        tracing::debug!("meloD config poller: query failed: {}", e);
                        continue;
                    }
                };

                match (row, last_seen) {
                    // No enabled providers — clear service if it was set
                    (None, _) => {
                        if last_seen.is_some() {
                            tracing::info!(
                                "meloD config poller: no enabled providers, clearing service"
                            );
                            let mut guard = state.melod_service.write().await;
                            *guard = None;
                        }
                        last_seen = None;
                    }
                    // First poll with enabled providers but no service yet → reload
                    (Some(ts), None) => {
                        let needs_init = state.melod_service.read().await.is_none();
                        if needs_init {
                            tracing::info!(
                                "meloD config poller: providers found, initializing service"
                            );
                            if let Err(e) = state.reload_melod_service().await {
                                tracing::warn!("meloD config poller: reload failed: {}", e);
                            }
                        }
                        last_seen = Some(ts);
                    }
                    // Timestamp changed → another pod (or user) updated config
                    (Some(ts), Some(prev)) if ts != prev => {
                        tracing::info!("meloD config poller: config changed, reloading service");
                        if let Err(e) = state.reload_melod_service().await {
                            tracing::warn!("meloD config poller: reload failed: {}", e);
                        }
                        last_seen = Some(ts);
                    }
                    // No change in provider_credentials, but service may still
                    // need initialization (e.g., model catalog sync populated
                    // agent_models after the previous reload attempt failed)
                    _ => {
                        let needs_init = state.melod_service.read().await.is_none();
                        if needs_init {
                            tracing::info!(
                                "meloD config poller: service not initialized, retrying"
                            );
                            if let Err(e) = state.reload_melod_service().await {
                                tracing::debug!("meloD config poller: retry failed: {}", e);
                            }
                        }
                    }
                }
            }
        })
    }
}
