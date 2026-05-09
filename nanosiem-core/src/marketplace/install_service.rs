// SPDX-License-Identifier: AGPL-3.0-or-later

//! Install/uninstall orchestration for marketplace enrichments
//!
//! Handles the lifecycle of installing an enrichment from the catalog:
//! - For Deno backend: creates a `custom_enrichments` row and links it
//! - For native backend: enables the underlying enrichment source
//! - For identity backend: enables the underlying identity provider
//! - Manages credential encryption/storage during install

use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use super::error::MarketplaceError;
use super::repository::MarketplaceRepository;
use super::types::*;
use crate::crypto::EncryptionService;

/// Service for installing/uninstalling enrichments from the marketplace
pub struct MarketplaceInstallService {
    repository: MarketplaceRepository,
    encryption: EncryptionService,
    pool: PgPool,
}

impl MarketplaceInstallService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: MarketplaceRepository::new(pool.clone()),
            encryption: EncryptionService::from_env(),
            pool,
        }
    }

    pub fn with_encryption(pool: PgPool, encryption: EncryptionService) -> Self {
        Self {
            repository: MarketplaceRepository::new(pool.clone()),
            encryption,
            pool,
        }
    }

    /// Install an enrichment from the catalog
    pub async fn install(
        &self,
        slug: &str,
        request: &InstallRequest,
        user_id: Uuid,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        if entry.installed {
            return Err(MarketplaceError::AlreadyInstalled(slug.to_string()));
        }

        // Check credential requirements
        let req: CredentialRequirement = entry
            .requires_credential
            .parse()
            .unwrap_or(CredentialRequirement::None);

        if req == CredentialRequirement::Required && request.credentials.is_none() {
            return Err(MarketplaceError::CredentialRequired);
        }

        // Encrypt credentials if provided
        let (ciphertext, nonce) = if let Some(ref creds) = request.credentials {
            let (ct, n) = self.encrypt_credentials(creds)?;
            (Some(ct), Some(n))
        } else {
            (None, None)
        };

        // Backend-specific install logic
        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        match backend {
            ExecutionBackend::Deno => {
                self.install_deno_enrichment(&entry, request, user_id)
                    .await?;
            }
            ExecutionBackend::Native => {
                self.install_native_enrichment(&entry).await?;
            }
            ExecutionBackend::Identity => {
                self.install_identity_enrichment(&entry).await?;
            }
        }

        // Mark as installed in catalog, storing encrypted credentials
        let updated = self
            .repository
            .set_installed(slug, true, ciphertext.as_deref(), nonce.as_deref())
            .await?;

        info!(slug = %slug, backend = %backend, "Installed enrichment from marketplace");
        Ok(updated)
    }

    /// Uninstall an enrichment
    pub async fn uninstall(&self, slug: &str) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        if !entry.installed {
            return Err(MarketplaceError::NotInstalled(slug.to_string()));
        }

        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        match backend {
            ExecutionBackend::Deno => {
                // Disable the custom enrichment
                if let Some(ce_id) = entry.custom_enrichment_id {
                    sqlx::query(
                        "UPDATE custom_enrichments SET enabled = false, status = 'draft' WHERE id = $1",
                    )
                    .bind(ce_id)
                    .execute(&self.pool)
                    .await?;
                }
            }
            ExecutionBackend::Native => {
                if let Some(ref source_id) = entry.native_source_id {
                    // Try agent_enrichment_providers first, then enrichment_sources
                    let rows = sqlx::query(
                        "UPDATE agent_enrichment_providers SET enabled = false WHERE id = $1",
                    )
                    .bind(source_id)
                    .execute(&self.pool)
                    .await?
                    .rows_affected();

                    if rows == 0 {
                        sqlx::query("UPDATE enrichment_sources SET enabled = false WHERE id = $1")
                            .bind(source_id)
                            .execute(&self.pool)
                            .await?;
                    }
                }
            }
            ExecutionBackend::Identity => {
                if let Some(ref provider_id) = entry.identity_provider_id {
                    sqlx::query("UPDATE identity_providers SET enabled = false WHERE id = $1")
                        .bind(provider_id)
                        .execute(&self.pool)
                        .await?;
                }
            }
        }

        let updated = self
            .repository
            .set_installed(slug, false, None, None)
            .await?;
        info!(slug = %slug, "Uninstalled enrichment from marketplace");
        Ok(updated)
    }

    /// Trigger data sync for an installed enrichment
    pub async fn trigger_sync(&self, slug: &str) -> Result<(), MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        if !entry.installed {
            return Err(MarketplaceError::NotInstalled(slug.to_string()));
        }

        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        match backend {
            ExecutionBackend::Deno => {
                if let Some(ce_id) = entry.custom_enrichment_id {
                    // Trigger a run via custom_enrichment_runs
                    sqlx::query(
                        r#"
                        INSERT INTO custom_enrichment_runs (id, enrichment_id, run_type, status)
                        VALUES (gen_random_uuid(), $1, 'manual', 'running')
                        "#,
                    )
                    .bind(ce_id)
                    .execute(&self.pool)
                    .await?;
                }
            }
            ExecutionBackend::Native => {
                // Native enrichments are synced via the enrichment scheduler,
                // which reads from enrichment_sources (not marketplace_catalog).
                // Set status to 'pending' which the scheduler treats as an
                // immediate sync request, bypassing auto_sync_enabled and interval checks.
                if let Some(ref source_id) = entry.native_source_id {
                    sqlx::query(
                        "UPDATE enrichment_sources SET last_sync_status = 'pending', updated_at = NOW() WHERE id = $1"
                    )
                        .bind(source_id)
                        .execute(&self.pool)
                        .await?;
                }
            }
            ExecutionBackend::Identity => {
                if let Some(ref provider_id) = entry.identity_provider_id {
                    sqlx::query(
                        "UPDATE identity_providers SET sync_status = 'pending' WHERE id = $1",
                    )
                    .bind(provider_id)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        Ok(())
    }

    /// Update an installed enrichment to the latest manifest version
    pub async fn update(&self, slug: &str) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        if !entry.installed {
            return Err(MarketplaceError::NotInstalled(slug.to_string()));
        }

        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        match backend {
            ExecutionBackend::Deno => {
                // Re-deploy code from catalog to custom_enrichments
                if let Some(ce_id) = entry.custom_enrichment_id {
                    let code = entry.code.as_deref().unwrap_or("");
                    sqlx::query(
                        r#"
                        UPDATE custom_enrichments SET
                            code = $2,
                            config = $3,
                            allowed_domains = $4,
                            updated_at = NOW()
                        WHERE id = $1
                        "#,
                    )
                    .bind(ce_id)
                    .bind(code)
                    .bind(&entry.config.0)
                    .bind(&entry.allowed_domains)
                    .execute(&self.pool)
                    .await?;
                }
            }
            ExecutionBackend::Native | ExecutionBackend::Identity => {
                // Native/identity enrichments don't have deployable code to update
            }
        }

        // Bump installed_version to match manifest_version
        let updated = self.repository.update_installed_version(slug).await?;

        info!(slug = %slug, version = updated.manifest_version, "Updated enrichment to latest version");
        Ok(updated)
    }

    /// Update credentials for an installed enrichment
    pub async fn update_credentials(
        &self,
        slug: &str,
        credentials: &serde_json::Value,
    ) -> Result<(), MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        // Encrypt and store on marketplace_catalog
        let (ciphertext, nonce) = self.encrypt_credentials(credentials)?;
        self.repository
            .update_catalog_config(slug, None, None, Some(&ciphertext), Some(&nonce))
            .await?;

        // For native enrichments, also push relevant fields to the underlying tables
        if entry.execution_backend == "native" {
            if let Some(ref source_id) = entry.native_source_id {
                // IPinfo uses download_url on enrichment_sources
                if let Some(url) = credentials.get("download_url").and_then(|v| v.as_str()) {
                    sqlx::query("UPDATE enrichment_sources SET download_url = $2, updated_at = NOW() WHERE id = $1")
                        .bind(source_id)
                        .bind(url)
                        .execute(&self.pool)
                        .await?;
                }
                // Agent providers use api_key on agent_enrichment_providers
                // The column stores JSON-encoded {"ciphertext": "...", "nonce": "..."} bytes
                if let Some(api_key) = credentials.get("API_KEY").and_then(|v| v.as_str()) {
                    let encrypted = self.encryption.encrypt(api_key.as_bytes()).map_err(|e| {
                        MarketplaceError::Internal(format!("Failed to encrypt API key: {}", e))
                    })?;
                    let json = serde_json::json!({
                        "ciphertext": encrypted.ciphertext,
                        "nonce": encrypted.nonce,
                    });
                    let encrypted_bytes = serde_json::to_vec(&json).map_err(|e| {
                        MarketplaceError::Internal(format!(
                            "Failed to serialize encrypted key: {}",
                            e
                        ))
                    })?;
                    sqlx::query("UPDATE agent_enrichment_providers SET api_key_encrypted = $2, updated_at = NOW() WHERE id = $1")
                        .bind(source_id)
                        .bind(encrypted_bytes)
                        .execute(&self.pool)
                        .await?;
                }
            }
        }

        // For identity providers, push credentials to identity_providers table
        if entry.execution_backend == "identity" {
            if let Some(ref provider_id) = entry.identity_provider_id {
                let identity_repo = crate::identity::IdentityRepository::new(self.pool.clone());
                identity_repo
                    .update_credentials(provider_id, credentials)
                    .await
                    .map_err(|e| {
                        MarketplaceError::Internal(format!(
                            "Failed to update identity credentials: {}",
                            e
                        ))
                    })?;
            }
        }

        Ok(())
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /// Encrypt credentials JSON and return (ciphertext_bytes, nonce_string)
    fn encrypt_credentials(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<(Vec<u8>, String), MarketplaceError> {
        let plaintext = serde_json::to_vec(credentials).map_err(|e| {
            MarketplaceError::Internal(format!("Failed to serialize credentials: {}", e))
        })?;
        let encrypted = self
            .encryption
            .encrypt(&plaintext)
            .map_err(|e| MarketplaceError::Internal(format!("Encryption failed: {}", e)))?;

        // Decode base64 ciphertext to raw bytes for bytea column
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted.ciphertext,
        )
        .map_err(|e| MarketplaceError::Internal(format!("Base64 decode failed: {}", e)))?;

        Ok((ciphertext_bytes, encrypted.nonce))
    }

    /// Install a Deno-backed enrichment by creating a custom_enrichments row
    async fn install_deno_enrichment(
        &self,
        entry: &MarketplaceCatalogEntry,
        request: &InstallRequest,
        user_id: Uuid,
    ) -> Result<(), MarketplaceError> {
        let code = entry.code.as_deref().unwrap_or("");
        let config = request.config.as_ref().unwrap_or(&entry.config.0);

        // Determine enrichment type from category
        let enrichment_type = match entry.category.as_str() {
            "data" => "data",
            _ => "agent",
        };

        // Get default namespace
        let namespace_id: Uuid = sqlx::query_scalar("SELECT id FROM namespaces LIMIT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| MarketplaceError::Internal(format!("No namespace found: {}", e)))?;

        // Create custom enrichment (no credential_id — creds stored on marketplace_catalog)
        let ce_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO custom_enrichments (
                namespace_id, slug, name, description, enrichment_type,
                code, config, allowed_domains,
                enabled, status, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, 'active', $9)
            ON CONFLICT (namespace_id, name) DO UPDATE SET
                code = EXCLUDED.code,
                config = EXCLUDED.config,
                allowed_domains = EXCLUDED.allowed_domains,
                enabled = true,
                status = 'active',
                updated_at = NOW()
            RETURNING id
            "#,
        )
        .bind(namespace_id)
        .bind(&entry.slug)
        .bind(&entry.name)
        .bind(&entry.description)
        .bind(enrichment_type)
        .bind(code)
        .bind(config)
        .bind(&entry.allowed_domains)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // Link custom_enrichment_id in catalog
        sqlx::query("UPDATE marketplace_catalog SET custom_enrichment_id = $2 WHERE slug = $1")
            .bind(&entry.slug)
            .bind(ce_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Install a native-backed enrichment by enabling the underlying source
    async fn install_native_enrichment(
        &self,
        entry: &MarketplaceCatalogEntry,
    ) -> Result<(), MarketplaceError> {
        if let Some(ref source_id) = entry.native_source_id {
            // Try agent_enrichment_providers first
            let rows =
                sqlx::query("UPDATE agent_enrichment_providers SET enabled = true WHERE id = $1")
                    .bind(source_id)
                    .execute(&self.pool)
                    .await?
                    .rows_affected();

            if rows == 0 {
                // Try enrichment_sources — also clear last_sync_status so the
                // scheduler picks it up for an immediate sync cycle
                let rows = sqlx::query(
                    "UPDATE enrichment_sources SET enabled = true, last_sync_status = NULL, updated_at = NOW() WHERE id = $1"
                )
                    .bind(source_id)
                    .execute(&self.pool)
                    .await?
                    .rows_affected();

                if rows == 0 {
                    warn!(
                        source_id = %source_id,
                        slug = %entry.slug,
                        "Native enrichment install: no matching row found in agent_enrichment_providers or enrichment_sources"
                    );
                    return Err(MarketplaceError::Internal(format!(
                        "No enrichment source found with id '{}'",
                        source_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Install an identity-backed enrichment by enabling the provider
    async fn install_identity_enrichment(
        &self,
        entry: &MarketplaceCatalogEntry,
    ) -> Result<(), MarketplaceError> {
        if let Some(ref provider_id) = entry.identity_provider_id {
            sqlx::query("UPDATE identity_providers SET enabled = true WHERE id = $1")
                .bind(provider_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}
