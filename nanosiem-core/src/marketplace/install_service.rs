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

        // Backend-specific install logic
        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        // Check credential requirements
        let req: CredentialRequirement = entry
            .requires_credential
            .parse()
            .unwrap_or(CredentialRequirement::None);

        // NAN-2189: a collector's credentials belong to an *instance*, not to
        // the catalog row — one operator can connect several vendor tenants,
        // each with its own token. Installing a collector only makes it
        // available to configure, so demanding credentials here would block the
        // install of every collector that needs them.
        if backend != ExecutionBackend::Collector
            && req == CredentialRequirement::Required
            && request.credentials.is_none()
        {
            return Err(MarketplaceError::CredentialRequired);
        }

        // Encrypt credentials if provided
        let (ciphertext, nonce) = if let Some(ref creds) = request.credentials {
            let (ct, n) = self.encrypt_credentials(creds)?;
            (Some(ct), Some(n))
        } else {
            (None, None)
        };

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
            ExecutionBackend::Collector => {
                // Nothing to provision. Unlike the other backends, a collector
                // has no shadow row in a subsystem table — the catalog row
                // already carries its code and manifest config, and the
                // operator creates `integration_instances` rows afterwards.
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
            ExecutionBackend::Collector => {
                // Disable every configured instance rather than deleting it:
                // an uninstall is reversible, and the instances hold the
                // operator's tenant hostnames, stream selection, and cursors.
                // Dropping those would silently restart collection from "now"
                // on reinstall, losing everything in between.
                sqlx::query(
                    "UPDATE integration_instances SET enabled = false, updated_at = NOW() WHERE catalog_id = $1",
                )
                .bind(entry.id)
                .execute(&self.pool)
                .await?;
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
            ExecutionBackend::Collector => {
                // Clearing `last_run_at` makes every enabled instance due on
                // the scheduler's next tick. Deliberately not spawning runs
                // here: a collector run is long-lived and must go through the
                // scheduler's single-flight lease, or two consumers end up on
                // the same cursor.
                sqlx::query(
                    r#"
                    UPDATE integration_instances
                       SET last_run_at = NULL, updated_at = NOW()
                     WHERE catalog_id = $1 AND enabled = true
                    "#,
                )
                .bind(entry.id)
                .execute(&self.pool)
                .await?;
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
            ExecutionBackend::Collector => {
                // The runtime reads code and manifest config straight off the
                // catalog row at run time, so repo sync has already applied the
                // update. Instances keep their credentials, config and cursors
                // across a version bump — which is the point of storing them
                // separately.
            }
        }

        // Bump installed_version to match manifest_version
        let updated = self.repository.update_installed_version(slug).await?;

        info!(slug = %slug, version = updated.manifest_version, "Updated enrichment to latest version");
        Ok(updated)
    }

    /// Update credentials for an installed enrichment.
    ///
    /// Returns early without writing if the request body contains no real
    /// credential material — i.e. every string value is empty or a masked
    /// sentinel placeholder like `***` or `••••••••`. NAN-1107: this guards
    /// against the configure flow re-POSTing the form (after an unrelated
    /// click such as Apply/Activate) with the masked-display value populated,
    /// which would otherwise re-encrypt the placeholder and silently destroy
    /// the previously saved real key. The frontend should never send those
    /// values, but pinning the contract here makes the data-loss class
    /// impossible to reintroduce via any future frontend regression.
    pub async fn update_credentials(
        &self,
        slug: &str,
        credentials: &serde_json::Value,
    ) -> Result<(), MarketplaceError> {
        if credentials_payload_is_masked_or_empty(credentials) {
            // Promoted from info! — under correct frontend operation the
            // handler skips calling us when no credentials field is in the
            // request. Reaching this branch means a frontend round-tripped
            // its stale masked-display state, which is the same upstream
            // bug class NAN-1107 was filed for. Worth a warn-level
            // breadcrumb so the next regression is loud, not silent.
            tracing::warn!(
                slug = %slug,
                "Skipping credential update — payload contains only empty values or masked placeholders (NAN-1107)"
            );
            return Ok(());
        }

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
        // NAN-2069: an install can override the catalog config, and the client
        // may well have built that override from a redacted catalog read.
        // Resolve masked keys back to the catalog's stored values so the
        // installed enrichment gets real consumer-supplied credentials rather
        // than the placeholder. With no override we use the catalog config
        // as-is; NAN-2151 deliberately strips publisher credentials at publish
        // time, so a fresh install never inherits the publisher's identity.
        let merged_config;
        let config = match request.config.as_ref() {
            Some(override_config) => {
                merged_config = crate::config_secrets::merge_config_secrets(
                    override_config.clone(),
                    Some(&entry.config.0),
                );
                &merged_config
            }
            None => &entry.config.0,
        };

        // Determine the functional enrichment type from category + config.
        // `category` alone is unreliable: the retired (NAN-1998) 'security' UI
        // grouping spanned both bulk data feeds and on-demand agent lookups,
        // which is what mislabeled the data feeds as agent (NAN-1585). Config
        // markers are the source of truth.
        let enrichment_type = infer_enrichment_type(&entry.category, config);

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

/// Characters that frontend secret fields use to render "a secret is already
/// configured" without revealing the real value. A string is considered a
/// masked placeholder when it is non-empty and consists *only* of these
/// characters. The character-class check is intentionally length-agnostic so
/// any future UI that masks by typed-length (e.g., one `•` per character)
/// still routes through the skip. Common examples actually shipped today:
/// `••••••••` (8 bullets, used by MarketplaceDrawer + ThreatFoxProvider),
/// `***`, `****`. Real credentials almost never consist solely of these
/// characters, so false-positive risk is negligible.
const MASK_CHARS: &[char] = &['*', '•', '●'];

fn is_masked_sentinel(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed.chars().all(|c| MASK_CHARS.contains(&c))
}

/// Returns true when the credentials payload contains no real material — i.e.
/// every string value is empty, whitespace-only, null, or consists only of
/// masking characters (see [`MASK_CHARS`]). Non-string, non-null values
/// (numbers, bools, nested objects) are treated as real data so legitimate
/// non-string config isn't silently dropped.
fn credentials_payload_is_masked_or_empty(credentials: &serde_json::Value) -> bool {
    let Some(obj) = credentials.as_object() else {
        // A non-object payload is unusual; let the caller's existing
        // encrypt path handle it rather than silently swallowing.
        return false;
    };

    if obj.is_empty() {
        return true;
    }

    obj.values().all(|v| match v {
        serde_json::Value::String(s) => s.trim().is_empty() || is_masked_sentinel(s),
        serde_json::Value::Null => true,
        // Non-string, non-null values count as real material.
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object_is_masked_or_empty() {
        assert!(credentials_payload_is_masked_or_empty(&json!({})));
    }

    #[test]
    fn all_empty_strings_is_masked_or_empty() {
        assert!(credentials_payload_is_masked_or_empty(
            &json!({"API_KEY": "", "OTHER": ""})
        ));
    }

    #[test]
    fn masked_sentinel_strings_count_as_empty() {
        assert!(credentials_payload_is_masked_or_empty(
            &json!({"API_KEY": "••••••••"})
        ));
        assert!(credentials_payload_is_masked_or_empty(
            &json!({"API_KEY": "***", "TOKEN": "••••••••"})
        ));
    }

    #[test]
    fn masked_sentinel_is_length_agnostic() {
        // P2 follow-up: the original enumerated-list approach would have
        // missed length variants. A 9-bullet, 13-bullet, or 32-star sentinel
        // (the kind a "mask each typed char" UI might produce) must also
        // route through the skip.
        for n in 1..=64 {
            let bullets: String = "•".repeat(n);
            let stars: String = "*".repeat(n);
            assert!(
                credentials_payload_is_masked_or_empty(&json!({"API_KEY": bullets})),
                "{} bullets should count as masked",
                n
            );
            assert!(
                credentials_payload_is_masked_or_empty(&json!({"API_KEY": stars})),
                "{} stars should count as masked",
                n
            );
        }
    }

    #[test]
    fn mixed_mask_characters_count_as_masked() {
        // Don't care which mask char a future UI picks; we'd rather skip
        // than overwrite.
        assert!(credentials_payload_is_masked_or_empty(
            &json!({"API_KEY": "•*●•*"})
        ));
    }

    #[test]
    fn real_credential_starting_with_mask_char_is_not_skipped() {
        // Avoid the false-positive where someone's real key happens to lead
        // with `*` — the trailing alphanumeric breaks the all-mask check.
        assert!(!credentials_payload_is_masked_or_empty(&json!({
            "API_KEY": "***real-value***"
        })));
    }

    #[test]
    fn null_values_count_as_empty() {
        assert!(credentials_payload_is_masked_or_empty(
            &json!({"API_KEY": null})
        ));
    }

    #[test]
    fn whitespace_only_strings_count_as_empty() {
        assert!(credentials_payload_is_masked_or_empty(
            &json!({"API_KEY": "   "})
        ));
    }

    #[test]
    fn real_credential_is_not_masked_or_empty() {
        // A 48-char abuse.ch-style key.
        assert!(!credentials_payload_is_masked_or_empty(&json!({
            "API_KEY": "e6c7e5ed3c360c53e8fc66228751af99a21c45788fea66ad"
        })));
    }

    #[test]
    fn mixed_real_and_masked_is_treated_as_real() {
        // A POST that re-sends some masked fields but also includes a real
        // new value should still write — the user provided real material.
        assert!(!credentials_payload_is_masked_or_empty(&json!({
            "API_KEY": "real-value",
            "REGION": "••••••••"
        })));
    }

    #[test]
    fn non_string_value_counts_as_real() {
        // Numeric/bool credential configs (rare, but allowed) must not be
        // silently dropped by the guard.
        assert!(!credentials_payload_is_masked_or_empty(
            &json!({"TIMEOUT_SECS": 30})
        ));
    }

    #[test]
    fn non_object_payload_does_not_skip() {
        // Defensive: a non-object body falls through to the existing
        // encrypt path rather than being silently swallowed.
        assert!(!credentials_payload_is_masked_or_empty(&json!("string-body")));
        assert!(!credentials_payload_is_masked_or_empty(&json!([1, 2, 3])));
    }
}
