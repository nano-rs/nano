// SPDX-License-Identifier: AGPL-3.0-or-later

//! Install/uninstall orchestration for marketplace enrichments
//!
//! Handles the lifecycle of installing an enrichment from the catalog:
//! - For Deno backend: creates a `custom_enrichments` row and links it
//! - For native backend: enables the underlying enrichment source
//! - For identity backend: enables the underlying identity provider
//! - Manages credential encryption/storage during install

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use super::error::MarketplaceError;
use super::repository::MarketplaceRepository;
use super::types::*;
use crate::crypto::EncryptionService;

// Install / uninstall / sync / update of the enterprise-only backends (Deno
// custom enrichments, integration collectors, agent enrichment providers). A
// child module so the open-core mirror strip removes the source, not just the
// build (NAN-5281); the `match` arms below are thin cfg-gated wiring.
#[cfg(feature = "enterprise")]
#[path = "install_service_enterprise.rs"]
mod enterprise;

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
        #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))] user_id: Uuid,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        // NAN-4959: IPinfo Lite, ThreatFox and Tor come only from nano's signed
        // platform feed bundle; no direct fetcher installs for them.
        if super::platform_feed::bundle_feed_for_slug(&entry.slug).is_some() {
            return Err(MarketplaceError::ProvidedByPlatformFeed(entry.slug));
        }

        if entry.installed {
            return Err(MarketplaceError::AlreadyInstalled(slug.to_string()));
        }

        // NAN-4946: content installs only from nano's first-party catalogs.
        if let Some(repo_id) = entry.repository_id {
            let repo = self.repository.get_repo(repo_id).await?;
            super::first_party::validate_first_party_repo_url(&repo.url)?;
        }

        // Backend-specific install logic
        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        // Open edition: refuse enterprise-only backends first — ahead of the
        // credential checks, so the caller learns the entry needs the
        // enterprise edition, and before anything is enabled or marked
        // installed, so a refusal leaves no partial install.
        #[cfg(not(feature = "enterprise"))]
        self.refuse_enterprise_only_backend(&entry, backend).await?;

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

        // Same validation the update path runs, before anything is written
        // (NAN-2343, NAN-4959).
        if let Some(ref creds) = request.credentials {
            validate_credential_values(&entry, creds)?;
        }

        // Encrypt credentials if provided. NAN-5284: a lookup's key lives in
        // the credentials store, bound to its threat-intel provider by the API
        // layer; the catalog keeps no copy.
        let (ciphertext, nonce) = if backend == ExecutionBackend::Lookup {
            (None, None)
        } else if let Some(ref creds) = request.credentials {
            let (ct, n) = self.encrypt_credentials(creds)?;
            (Some(ct), Some(n))
        } else {
            (None, None)
        };

        match backend {
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Deno => {
                self.install_deno_enrichment(&entry, request, user_id)
                    .await?;
            }
            // Refused above by `refuse_enterprise_only_backend`.
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Deno => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Custom enrichments".to_string(),
                ));
            }
            ExecutionBackend::Native => {
                self.install_native_enrichment(&entry).await?;
            }
            ExecutionBackend::Identity => {
                self.install_identity_enrichment(&entry).await?;
            }
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Collector => {
                // Nothing to provision. Unlike the other backends, a collector
                // has no shadow row in a subsystem table — the catalog row
                // already carries its code and manifest config, and the
                // operator creates `integration_instances` rows afterwards.
            }
            // Refused above by `refuse_enterprise_only_backend`.
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Collector => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Integration collectors".to_string(),
                ));
            }
            // NAN-5284: the API layer configures the threat-intel provider
            // right after this marks the entry installed (and rolls the
            // install back if that fails).
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Lookup => {}
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Lookup => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Threat-intel lookups".to_string(),
                ));
            }
        }

        // Mark as installed in catalog, storing encrypted credentials
        let updated = self
            .repository
            .set_installed(slug, true, ciphertext.as_deref(), nonce.as_deref())
            .await?;

        // NAN-2343: propagate install-time credentials into the backend's own
        // table. Without this a `download_url` typed into the install dialog
        // lived only as catalog ciphertext, leaving `enrichment_sources` with a
        // NULL URL while the UI reported the enrichment as configured.
        // Runs against `updated` so `installed`/`native_source_id` reflect the
        // row we just wrote.
        if let (Some(creds), false) = (&request.credentials, backend == ExecutionBackend::Lookup) {
            self.push_native_credentials(&updated, creds).await?;
        }

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
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Deno => self.uninstall_deno_enrichment(&entry).await?,
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Deno => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Custom enrichments".to_string(),
                ));
            }
            ExecutionBackend::Native => {
                if let Some(ref source_id) = entry.native_source_id {
                    #[cfg(feature = "enterprise")]
                    let rows = self.disable_agent_provider(source_id).await?;

                    #[cfg(not(feature = "enterprise"))]
                    let rows = 0;

                    if rows == 0 {
                        // A download URL carrying a provider token (IPinfo
                        // `?token=`) is a credential; a public default URL stays.
                        sqlx::query("UPDATE enrichment_sources SET enabled = false, download_url = CASE WHEN download_url ~* '[?&]token=' THEN NULL ELSE download_url END WHERE id = $1")
                            .bind(source_id)
                            .execute(&self.pool)
                            .await?;
                    }
                }
            }
            ExecutionBackend::Identity => {
                if let Some(ref provider_id) = entry.identity_provider_id {
                    sqlx::query("UPDATE identity_providers SET enabled = false, credentials_encrypted = NULL WHERE id = $1")
                        .bind(provider_id)
                        .execute(&self.pool)
                        .await?;
                }
            }
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Collector => self.uninstall_collector(&entry).await?,
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Collector => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Integration collectors".to_string(),
                ));
            }
            // NAN-5284: the API layer removed the threat-intel provider first.
            ExecutionBackend::Lookup => {}
        }

        let updated = self
            .repository
            .set_installed(slug, false, None, None)
            .await?;
        // NAN-4946: uninstall deletes the stored credentials (set_installed
        // keeps them by COALESCE for the install / configure paths).
        let updated = self.repository.clear_credentials(&updated.slug).await?;
        info!(slug = %slug, "Uninstalled enrichment from marketplace; credentials removed");
        Ok(updated)
    }

    /// Trigger data sync for an installed enrichment
    pub async fn trigger_sync(&self, slug: &str) -> Result<(), MarketplaceError> {
        let entry = self.repository.get_catalog_entry(slug).await?;

        if super::platform_feed::bundle_feed_for_slug(&entry.slug).is_some() {
            return Err(MarketplaceError::ProvidedByPlatformFeed(entry.slug));
        }

        if !entry.installed {
            return Err(MarketplaceError::NotInstalled(slug.to_string()));
        }

        let backend: ExecutionBackend = entry
            .execution_backend
            .parse()
            .map_err(|e: String| MarketplaceError::Internal(e))?;

        match backend {
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Deno => self.trigger_deno_sync(&entry).await?,
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Deno => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Custom enrichments".to_string(),
                ));
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
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Collector => self.trigger_collector_sync(&entry).await?,
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Collector => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Integration collectors".to_string(),
                ));
            }
            // NAN-5284: an on-demand lookup has nothing to sync.
            ExecutionBackend::Lookup => {
                return Err(MarketplaceError::Internal(
                    "on-demand threat-intel lookups have nothing to sync".to_string(),
                ));
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
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Deno => self.update_deno_enrichment(&entry).await?,
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Deno => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Custom enrichments".to_string(),
                ));
            }
            ExecutionBackend::Native | ExecutionBackend::Identity | ExecutionBackend::Lookup => {
                // Native/identity enrichments and official lookups (the spec
                // ships in the binary) have no deployable code to update.
            }
            #[cfg(feature = "enterprise")]
            ExecutionBackend::Collector => {
                // The runtime reads code and manifest config straight off the
                // catalog row at run time, so repo sync has already applied the
                // update. Instances keep their credentials, config and cursors
                // across a version bump — which is the point of storing them
                // separately.
            }
            #[cfg(not(feature = "enterprise"))]
            ExecutionBackend::Collector => {
                return Err(MarketplaceError::EnterpriseRequired(
                    "Integration collectors".to_string(),
                ));
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
        let entry = self.repository.get_catalog_entry(slug).await?;

        // Validate BEFORE anything is persisted (NAN-2343), and ahead of the
        // masked/empty shortcut so `{"download_url": ""}` is refused rather
        // than reported saved (NAN-4959: native entries take no download URL).
        validate_credential_values(&entry, credentials)?;

        // NAN-4959: a bundle-provided feed takes no credentials (no direct pull).
        if super::platform_feed::bundle_feed_for_slug(&entry.slug).is_some()
            && !credentials_payload_is_masked_or_empty(credentials)
        {
            return Err(MarketplaceError::ProvidedByPlatformFeed(entry.slug));
        }

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

        // NAN-5284: a lookup's credentials belong to its threat-intel
        // provider; the API layer routes them there and never reaches this.
        if entry.execution_backend == "lookup" {
            return Err(MarketplaceError::Internal(
                "threat-intel lookup credentials are configured on the provider".to_string(),
            ));
        }

        // Open edition: refuse before anything is persisted when the entry's
        // backend table is enterprise-only.
        #[cfg(not(feature = "enterprise"))]
        {
            let backend: ExecutionBackend = entry
                .execution_backend
                .parse()
                .map_err(|e: String| MarketplaceError::Internal(e))?;
            self.refuse_enterprise_only_backend(&entry, backend).await?;
        }

        // Encrypt and store on marketplace_catalog
        let (ciphertext, nonce) = self.encrypt_credentials(credentials)?;
        self.repository
            .update_catalog_config(slug, None, None, Some(&ciphertext), Some(&nonce))
            .await?;

        self.push_native_credentials(&entry, credentials).await?;

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

    /// Open core: the only backend table `push_native_credentials` writes
    /// (`agent_enrichment_providers`) is enterprise-only, and entries backed by
    /// it are refused up front by [`Self::refuse_enterprise_only_backend`], so
    /// there is nothing to push.
    #[cfg(not(feature = "enterprise"))]
    async fn push_native_credentials(
        &self,
        _entry: &MarketplaceCatalogEntry,
        _credentials: &serde_json::Value,
    ) -> Result<(), MarketplaceError> {
        Ok(())
    }

    /// Open core: refuse catalog entries whose backend lives in an
    /// enterprise-only table — Deno custom enrichments, integration
    /// collectors, and native entries backed by an agent enrichment provider
    /// (any native source that is not an `enrichment_sources` row). The web
    /// UI hides these entries in the open edition; this is the server-side
    /// guarantee. Called once per install / credential update, before any
    /// write.
    #[cfg(not(feature = "enterprise"))]
    async fn refuse_enterprise_only_backend(
        &self,
        entry: &MarketplaceCatalogEntry,
        backend: ExecutionBackend,
    ) -> Result<(), MarketplaceError> {
        let surface = match backend {
            ExecutionBackend::Deno => Some("Custom enrichments"),
            ExecutionBackend::Collector => Some("Integration collectors"),
            ExecutionBackend::Lookup => Some("Threat-intel lookups"),
            ExecutionBackend::Identity => None,
            ExecutionBackend::Native => match entry.native_source_id.as_deref() {
                None => None,
                Some(source_id) => {
                    let open_source: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM enrichment_sources WHERE id = $1)",
                    )
                    .bind(source_id)
                    .fetch_one(&self.pool)
                    .await?;
                    (!open_source).then_some("Agent enrichment providers")
                }
            },
        };
        match surface {
            Some(surface) => Err(MarketplaceError::EnterpriseRequired(surface.to_string())),
            None => Ok(()),
        }
    }

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

    #[cfg(not(feature = "enterprise"))]
    async fn install_native_enrichment(
        &self,
        entry: &MarketplaceCatalogEntry,
    ) -> Result<(), MarketplaceError> {
        if let Some(ref source_id) = entry.native_source_id {
            let rows = sqlx::query(
                "UPDATE enrichment_sources SET enabled = true, last_sync_status = NULL, updated_at = NOW() WHERE id = $1",
            )
            .bind(source_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
            if rows == 0 {
                return Err(MarketplaceError::Internal(format!(
                    "No enrichment source found with id '{}'",
                    source_id
                )));
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

/// Refuse credential values no backend may store.
///
/// NAN-4959: IPinfo Lite is served only from nano's signed platform feed
/// bundle, so a native entry has no bring-your-own `download_url` (an IPinfo
/// token URL). Any non-null value is refused with a 422 naming the field, so
/// no client can reintroduce one through the configure or install path; the
/// catalog entry no longer declares the field (migration 311). Null reads as
/// absent and masked sentinels keep the NAN-1107 silent no-op.
///
/// Scoped to `native` entries: `download_url` is not a reserved name, and a
/// first-party Deno or collector manifest may legitimately use it.
fn validate_credential_values(
    entry: &MarketplaceCatalogEntry,
    credentials: &serde_json::Value,
) -> Result<(), MarketplaceError> {
    if entry.execution_backend != "native" {
        return Ok(());
    }
    match credentials.get("download_url") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(s)) if is_masked_sentinel(s) => Ok(()),
        Some(_) => Err(MarketplaceError::InvalidCredential {
            field: "download_url".to_string(),
            reason: "IPinfo Lite comes from nano's signed platform feed bundle; \
                     there is no download URL to configure"
                .to_string(),
        }),
    }
}

#[cfg(test)]
mod tests;
