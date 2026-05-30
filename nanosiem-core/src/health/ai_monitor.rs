// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI Provider health monitoring
//!
//! Checks the health of configured AI providers by testing their connectivity.

use chrono::Utc;
use sqlx::{PgPool, Row};
use tracing::{debug, warn};

use super::types::AiProviderStatus;
use crate::crypto::EncryptionService;

/// AI provider health monitor
pub struct AiMonitor {
    pool: PgPool,
    encryption: EncryptionService,
    http_client: reqwest::Client,
}

impl AiMonitor {
    pub fn new(pool: PgPool) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            pool,
            encryption: EncryptionService::from_env(),
            http_client,
        }
    }

    /// Check health of all enabled AI providers
    pub async fn check_all_providers(&self) -> Vec<AiProviderStatus> {
        let mut statuses = Vec::new();

        // Get all enabled providers
        let providers = match self.get_enabled_providers().await {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get enabled providers: {}", e);
                return statuses;
            }
        };

        for provider in providers {
            let status = self.check_provider(&provider).await;
            statuses.push(status);
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

    /// Check health of a single provider
    async fn check_provider(&self, provider: &ProviderInfo) -> AiProviderStatus {
        let checked_at = Utc::now();

        // Decrypt credentials
        let api_key = match self.decrypt_api_key(&provider.credentials_encrypted) {
            Ok(key) => key,
            Err(e) => {
                return AiProviderStatus {
                    provider_id: uuid::Uuid::nil(),
                    provider_name: provider.display_name.clone(),
                    provider_type: provider.provider.clone(),
                    is_healthy: false,
                    error_message: Some(format!("Failed to decrypt credentials: {}", e)),
                    checked_at,
                };
            }
        };

        // Test the provider connection
        match self
            .test_provider_connection(&provider.provider, &api_key, &provider.config)
            .await
        {
            Ok(()) => {
                debug!(provider = %provider.provider, "Provider health check passed");
                AiProviderStatus {
                    provider_id: uuid::Uuid::nil(),
                    provider_name: provider.display_name.clone(),
                    provider_type: provider.provider.clone(),
                    is_healthy: true,
                    error_message: None,
                    checked_at,
                }
            }
            Err(error_message) => {
                warn!(provider = %provider.provider, error = %error_message, "Provider health check failed");
                AiProviderStatus {
                    provider_id: uuid::Uuid::nil(),
                    provider_name: provider.display_name.clone(),
                    provider_type: provider.provider.clone(),
                    is_healthy: false,
                    error_message: Some(error_message),
                    checked_at,
                }
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

    /// Test a provider connection by making a minimal API call
    async fn test_provider_connection(
        &self,
        provider: &str,
        api_key: &str,
        config: &serde_json::Value,
    ) -> Result<(), String> {
        match provider {
            "anthropic" => {
                // Test Anthropic API - just check auth by listing models
                let resp = self
                    .http_client
                    .post("https://api.anthropic.com/v1/messages")
                    .header("x-api-key", api_key)
                    .header("anthropic-version", "2023-06-01")
                    .header("content-type", "application/json")
                    .json(&serde_json::json!({
                        "model": "claude-haiku-4-5-20251001",
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "test"}]
                    }))
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                if resp.status().is_success() || resp.status().as_u16() == 400 {
                    // 400 can happen due to content moderation, but auth succeeded
                    Ok(())
                } else if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                    Err("Authentication failed - invalid API key".to_string())
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    Err(format!("API error ({}): {}", status, body))
                }
            }
            "google" => {
                let resp = self
                    .http_client
                    .post(format!(
                        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={}",
                        api_key
                    ))
                    .header("content-type", "application/json")
                    .json(&serde_json::json!({
                        "contents": [{"parts": [{"text": "test"}]}],
                        "generationConfig": {"maxOutputTokens": 1}
                    }))
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                if resp.status().is_success() || resp.status().as_u16() == 400 {
                    Ok(())
                } else if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                    Err("Authentication failed - invalid API key".to_string())
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    Err(format!("API error ({}): {}", status, body))
                }
            }
            "openai" => {
                let resp = self
                    .http_client
                    .get("https://api.openai.com/v1/models")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                if resp.status().is_success() {
                    Ok(())
                } else if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                    Err("Authentication failed - invalid API key".to_string())
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    Err(format!("API error ({}): {}", status, body))
                }
            }
            "azure" => {
                let api_base = config
                    .get("api_base")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Azure requires api_base in config".to_string())?;
                let api_version = config
                    .get("api_version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2024-10-21");

                // List deployments to check auth
                let resp = self
                    .http_client
                    .get(format!(
                        "{}/openai/deployments?api-version={}",
                        api_base, api_version
                    ))
                    .header("api-key", api_key)
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                if resp.status().is_success() {
                    Ok(())
                } else if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                    Err("Authentication failed - invalid API key".to_string())
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    Err(format!("API error ({}): {}", status, body))
                }
            }
            "bedrock" => {
                // Bedrock uses AWS credentials - basic validation only
                // Full validation would require AWS SDK
                if api_key.is_empty() {
                    Err("Empty credentials".to_string())
                } else {
                    Ok(())
                }
            }
            _ => Err(format!("Unknown provider: {}", provider)),
        }
    }
}

struct ProviderInfo {
    provider: String,
    display_name: String,
    config: serde_json::Value,
    credentials_encrypted: Vec<u8>,
}
