// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI Provider health monitoring
//!
//! Checks the health of configured AI providers by testing their connectivity.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};
use tracing::{debug, warn};

use super::types::AiProviderStatus;
use crate::crypto::EncryptionService;

/// Connectivity checker for AI providers.
///
/// The actual network probe lives behind this trait so the health monitor (in
/// `nanosiem-core`) doesn't duplicate provider-connectivity logic or hardcode
/// public vendor hostnames. The enterprise API layer injects the canonical,
/// on-prem-`base_url`-aware tester (the same one the "Test connection" button
/// uses, NAN-1207); open-core builds have no AI-provider surface and inject
/// `None`, which skips AI-provider health checks entirely. (NAN-1231)
#[async_trait]
pub trait AiProviderConnectivityChecker: Send + Sync {
    /// Probe a provider's reachability + auth. `config` is the provider's
    /// JSONB config; a non-empty `base_url` means an on-prem endpoint and the
    /// implementation MUST target it instead of the vendor's public host.
    async fn check(
        &self,
        provider: &str,
        api_key: &str,
        config: &serde_json::Value,
    ) -> Result<(), String>;
}

/// AI provider health monitor
pub struct AiMonitor {
    pool: PgPool,
    encryption: EncryptionService,
    /// Injected connectivity checker. `None` (open-core / no AI surface) means
    /// AI-provider health checks are skipped — we never report a provider as
    /// down without having tested it.
    checker: Option<Arc<dyn AiProviderConnectivityChecker>>,
    /// In `AIRGAP_MODE`, providers without an on-prem `base_url` are skipped so
    /// the monitor never beacons to a public vendor host. (NAN-1231)
    airgap: bool,
}

impl AiMonitor {
    pub fn new(
        pool: PgPool,
        checker: Option<Arc<dyn AiProviderConnectivityChecker>>,
        airgap: bool,
    ) -> Self {
        Self {
            pool,
            encryption: EncryptionService::from_env(),
            checker,
            airgap,
        }
    }

    /// Check health of all enabled AI providers
    pub async fn check_all_providers(&self) -> Vec<AiProviderStatus> {
        let mut statuses = Vec::new();

        // No connectivity checker wired (open-core build, or no AI-provider
        // surface). Nothing to probe — and we must not report providers as
        // down when we never tested them. (NAN-1231)
        let Some(checker) = self.checker.as_ref() else {
            return statuses;
        };

        // Get all enabled providers
        let providers = match self.get_enabled_providers().await {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get enabled providers: {}", e);
                return statuses;
            }
        };

        for provider in providers {
            if let Some(status) = self.check_provider(checker.as_ref(), &provider).await {
                statuses.push(status);
            }
        }

        statuses
    }

    /// Get list of enabled providers from database
    async fn get_enabled_providers(&self) -> Result<Vec<ProviderInfo>, sqlx::Error> {
        // `credentials_encrypted` is a nullable BYTEA, and some enabled
        // providers legitimately store NULL: Workers AI authenticates via the
        // same-account Cloudflare AI Gateway and needs no api_key (migration
        // 142; mirrored by credential_resolver's `workers-ai` branch). A
        // provider can also be enabled before a key is set. Either way it has
        // no api_key to connectivity-test, so skip it in SQL. This also avoids
        // `Row::get` decoding a NULL into `Vec<u8>` and panicking — that panic
        // aborted the whole nanosiem-jobs worker and crashlooped every
        // background scheduler (enrichment auto-sync, identity/parser/rule/
        // marketplace sync) (NAN-1102).
        let rows = sqlx::query(
            r#"
            SELECT provider, display_name, config, credentials_encrypted
            FROM provider_credentials
            WHERE enabled = true
              AND credentials_encrypted IS NOT NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            // Defense-in-depth: `try_get` so an unexpectedly-NULL credentials
            // column skips the row instead of panicking the health monitor.
            .filter_map(|r| {
                let credentials_encrypted: Vec<u8> =
                    r.try_get("credentials_encrypted").ok()?;
                Some(ProviderInfo {
                    provider: r.get("provider"),
                    display_name: r.get("display_name"),
                    config: r.get("config"),
                    credentials_encrypted,
                })
            })
            .collect())
    }

    /// Check health of a single provider. Returns `None` when the provider is
    /// skipped (AIRGAP_MODE with no on-prem `base_url`).
    async fn check_provider(
        &self,
        checker: &dyn AiProviderConnectivityChecker,
        provider: &ProviderInfo,
    ) -> Option<AiProviderStatus> {
        let checked_at = Utc::now();

        // Air-gap guard: a provider with no on-prem `base_url` would have its
        // connectivity test fall through to the vendor's public host. In
        // AIRGAP_MODE that's an outbound beacon, so skip it — only
        // on-prem-configured providers are probed. (NAN-1231; mirrors the
        // NAN-1228 egress gating.)
        if self.airgap && !config_has_base_url(&provider.config) {
            debug!(
                provider = %provider.provider,
                "Airgap mode: skipping AI provider health check (no on-prem base_url)"
            );
            return None;
        }

        // Decrypt credentials
        let api_key = match self.decrypt_api_key(&provider.credentials_encrypted) {
            Ok(key) => key,
            Err(e) => {
                return Some(AiProviderStatus {
                    provider_id: uuid::Uuid::nil(),
                    provider_name: provider.display_name.clone(),
                    provider_type: provider.provider.clone(),
                    is_healthy: false,
                    error_message: Some(format!("Failed to decrypt credentials: {}", e)),
                    checked_at,
                });
            }
        };

        // Test the provider connection through the injected, on-prem-aware
        // checker — NOT a hardcoded public endpoint. (NAN-1231)
        match checker
            .check(&provider.provider, &api_key, &provider.config)
            .await
        {
            Ok(()) => {
                debug!(provider = %provider.provider, "Provider health check passed");
                Some(AiProviderStatus {
                    provider_id: uuid::Uuid::nil(),
                    provider_name: provider.display_name.clone(),
                    provider_type: provider.provider.clone(),
                    is_healthy: true,
                    error_message: None,
                    checked_at,
                })
            }
            Err(error_message) => {
                warn!(provider = %provider.provider, error = %error_message, "Provider health check failed");
                Some(AiProviderStatus {
                    provider_id: uuid::Uuid::nil(),
                    provider_name: provider.display_name.clone(),
                    provider_type: provider.provider.clone(),
                    is_healthy: false,
                    error_message: Some(error_message),
                    checked_at,
                })
            }
        }
    }

    /// Decrypt the API key from encrypted credentials
    fn decrypt_api_key(&self, encrypted_bytes: &[u8]) -> Result<String, String> {
        use crate::crypto::EncryptedData;

        // The BYTEA column contains JSON: {"ciphertext": "...", "nonce": "..."}
        let encrypted_json: serde_json::Value = serde_json::from_slice(encrypted_bytes)
            .map_err(|e| format!("Invalid encrypted data format: {}", e))?;

        let ciphertext = encrypted_json["ciphertext"]
            .as_str()
            .ok_or_else(|| "Missing ciphertext".to_string())?
            .to_string();
        let nonce = encrypted_json["nonce"]
            .as_str()
            .ok_or_else(|| "Missing nonce".to_string())?
            .to_string();

        let encrypted_data = EncryptedData { ciphertext, nonce };

        let decrypted_json = self
            .encryption
            .decrypt(&encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        let creds: serde_json::Value = serde_json::from_slice(&decrypted_json)
            .map_err(|e| format!("Invalid credentials JSON: {}", e))?;

        creds
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "No api_key in credentials".to_string())
    }
}

/// Whether a provider's JSONB config carries a non-empty `base_url` — i.e. the
/// operator pointed it at an on-prem OpenAI-compatible endpoint (vLLM, Ollama,
/// LocalAI, …). Used to decide whether a provider is safe to probe in
/// AIRGAP_MODE. (NAN-1231)
fn config_has_base_url(config: &serde_json::Value) -> bool {
    config
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

struct ProviderInfo {
    provider: String,
    display_name: String,
    config: serde_json::Value,
    credentials_encrypted: Vec<u8>,
}
