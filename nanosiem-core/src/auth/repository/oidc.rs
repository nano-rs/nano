// SPDX-License-Identifier: AGPL-3.0-or-later

//! OIDC Provider repository for CRUD operations
//!
//! Requirements: 3.5, 11.4

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::types::{
    CreateOidcProviderRequest, OidcGroupMapping, OidcProvider, UpdateOidcProviderRequest,
};
use crate::crypto::EncryptionService;

/// Server-side OIDC authorization transaction.
///
/// Created at `/authorize` and consumed at `/callback`. See migration 172.
#[derive(Debug, Clone)]
pub struct OidcAuthTransaction {
    pub state: String,
    pub provider_id: Uuid,
    pub nonce: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Error, Debug)]
pub enum OidcRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("OIDC provider not found: {0}")]
    NotFound(Uuid),
    #[error("OIDC provider not found by slug: {0}")]
    NotFoundBySlug(String),
    #[error("Provider slug already exists: {0}")]
    SlugExists(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Group mapping not found: {0}")]
    MappingNotFound(Uuid),
    #[error("OIDC auth transaction not found, already consumed, or expired")]
    AuthTransactionInvalid,
}

/// Repository for OIDC provider operations
#[derive(Clone)]
pub struct OidcRepository {
    pool: PgPool,
    /// AES-256-GCM encryption service for client secrets
    encryption_service: EncryptionService,
}

impl OidcRepository {
    pub fn new(pool: PgPool) -> Self {
        // Use the shared encryption service with mandatory key configuration
        let encryption_service = EncryptionService::from_env();

        Self {
            pool,
            encryption_service,
        }
    }

    /// Encrypt client secret using AES-256-GCM
    fn encrypt_secret(&self, secret: &str) -> Result<Vec<u8>, OidcRepositoryError> {
        let encrypted = self
            .encryption_service
            .encrypt(secret.as_bytes())
            .map_err(|e| OidcRepositoryError::EncryptionError(e.to_string()))?;

        // Store as JSON with nonce for proper decryption
        let stored = serde_json::json!({
            "ciphertext": encrypted.ciphertext,
            "nonce": encrypted.nonce,
        });

        serde_json::to_vec(&stored).map_err(|e| OidcRepositoryError::EncryptionError(e.to_string()))
    }

    /// Decrypt client secret using AES-256-GCM
    fn decrypt_secret(&self, encrypted: &[u8]) -> Result<String, OidcRepositoryError> {
        // Parse the stored JSON format
        let stored: serde_json::Value = serde_json::from_slice(encrypted).map_err(|e| {
            OidcRepositoryError::EncryptionError(format!("Failed to parse encrypted data: {}", e))
        })?;

        let ciphertext = stored["ciphertext"].as_str().ok_or_else(|| {
            OidcRepositoryError::EncryptionError("Missing ciphertext".to_string())
        })?;
        let nonce = stored["nonce"]
            .as_str()
            .ok_or_else(|| OidcRepositoryError::EncryptionError("Missing nonce".to_string()))?;

        let encrypted_data = crate::crypto::EncryptedData {
            ciphertext: ciphertext.to_string(),
            nonce: nonce.to_string(),
        };

        let decrypted = self
            .encryption_service
            .decrypt(&encrypted_data)
            .map_err(|e| OidcRepositoryError::EncryptionError(e.to_string()))?;

        String::from_utf8(decrypted)
            .map_err(|e| OidcRepositoryError::EncryptionError(e.to_string()))
    }

    /// List all OIDC providers
    /// Requirements: 3.5
    pub async fn list_providers(&self) -> Result<Vec<OidcProvider>, OidcRepositoryError> {
        let providers =
            sqlx::query_as::<_, OidcProvider>("SELECT * FROM oidc_providers ORDER BY name ASC")
                .fetch_all(&self.pool)
                .await?;

        Ok(providers)
    }

    /// List enabled OIDC providers (for login page)
    pub async fn list_enabled_providers(&self) -> Result<Vec<OidcProvider>, OidcRepositoryError> {
        let providers = sqlx::query_as::<_, OidcProvider>(
            "SELECT * FROM oidc_providers WHERE enabled = TRUE ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(providers)
    }

    /// Get an OIDC provider by ID
    pub async fn get_provider(&self, id: Uuid) -> Result<OidcProvider, OidcRepositoryError> {
        sqlx::query_as::<_, OidcProvider>("SELECT * FROM oidc_providers WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(OidcRepositoryError::NotFound(id))
    }

    /// Get an OIDC provider by slug
    pub async fn get_provider_by_slug(
        &self,
        slug: &str,
    ) -> Result<OidcProvider, OidcRepositoryError> {
        sqlx::query_as::<_, OidcProvider>("SELECT * FROM oidc_providers WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| OidcRepositoryError::NotFoundBySlug(slug.to_string()))
    }

    /// Get decrypted client secret for a provider
    pub async fn get_client_secret(&self, id: Uuid) -> Result<String, OidcRepositoryError> {
        let provider = self.get_provider(id).await?;
        self.decrypt_secret(&provider.client_secret_encrypted)
    }

    /// Create a new OIDC provider
    /// Requirements: 3.5, 11.4
    pub async fn create_provider(
        &self,
        request: &CreateOidcProviderRequest,
    ) -> Result<OidcProvider, OidcRepositoryError> {
        // Check if slug already exists
        let existing =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oidc_providers WHERE slug = $1")
                .bind(&request.slug)
                .fetch_one(&self.pool)
                .await?;

        if existing > 0 {
            return Err(OidcRepositoryError::SlugExists(request.slug.clone()));
        }

        // Encrypt the client secret using AES-256-GCM
        let encrypted_secret = self.encrypt_secret(&request.client_secret)?;

        // Default scopes if not provided
        let scopes = request.scopes.clone().unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]
        });

        let provider = sqlx::query_as::<_, OidcProvider>(
            r#"
            INSERT INTO oidc_providers (name, slug, issuer, client_id, client_secret_encrypted, scopes, group_claim, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
            RETURNING *
            "#
        )
        .bind(&request.name)
        .bind(&request.slug)
        .bind(&request.issuer)
        .bind(&request.client_id)
        .bind(&encrypted_secret)
        .bind(&scopes)
        .bind(&request.group_claim)
        .fetch_one(&self.pool)
        .await?;

        Ok(provider)
    }

    /// Update an OIDC provider
    /// Requirements: 11.4
    pub async fn update_provider(
        &self,
        id: Uuid,
        request: &UpdateOidcProviderRequest,
    ) -> Result<OidcProvider, OidcRepositoryError> {
        let existing = self.get_provider(id).await?;

        let name = request.name.as_ref().unwrap_or(&existing.name);
        let issuer = request.issuer.as_ref().unwrap_or(&existing.issuer);
        let client_id = request.client_id.as_ref().unwrap_or(&existing.client_id);
        let scopes = request.scopes.as_ref().unwrap_or(&existing.scopes);
        let group_claim = request.group_claim.clone().or(existing.group_claim);
        let enabled = request.enabled.unwrap_or(existing.enabled);

        // Handle client secret update
        let encrypted_secret = if let Some(ref new_secret) = request.client_secret {
            self.encrypt_secret(new_secret)?
        } else {
            existing.client_secret_encrypted
        };

        let provider = sqlx::query_as::<_, OidcProvider>(
            r#"
            UPDATE oidc_providers SET
                name = $2,
                issuer = $3,
                client_id = $4,
                client_secret_encrypted = $5,
                scopes = $6,
                group_claim = $7,
                enabled = $8,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(issuer)
        .bind(client_id)
        .bind(&encrypted_secret)
        .bind(scopes)
        .bind(&group_claim)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(provider)
    }

    /// Delete an OIDC provider
    /// Requirements: 11.4
    pub async fn delete_provider(&self, id: Uuid) -> Result<(), OidcRepositoryError> {
        let result = sqlx::query("DELETE FROM oidc_providers WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(OidcRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Enable an OIDC provider
    pub async fn enable_provider(&self, id: Uuid) -> Result<OidcProvider, OidcRepositoryError> {
        let provider = sqlx::query_as::<_, OidcProvider>(
            r#"
            UPDATE oidc_providers SET enabled = TRUE, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(OidcRepositoryError::NotFound(id))?;

        Ok(provider)
    }

    /// Disable an OIDC provider
    pub async fn disable_provider(&self, id: Uuid) -> Result<OidcProvider, OidcRepositoryError> {
        let provider = sqlx::query_as::<_, OidcProvider>(
            r#"
            UPDATE oidc_providers SET enabled = FALSE, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(OidcRepositoryError::NotFound(id))?;

        Ok(provider)
    }

    // =========================================================================
    // Group Mapping Operations
    // =========================================================================

    /// Get group mappings for a provider
    /// Requirements: 3.4
    pub async fn get_group_mappings(
        &self,
        provider_id: Uuid,
    ) -> Result<Vec<OidcGroupMapping>, OidcRepositoryError> {
        // Verify provider exists
        self.get_provider(provider_id).await?;

        let mappings = sqlx::query_as::<_, OidcGroupMapping>(
            r#"
            SELECT * FROM oidc_group_mappings
            WHERE provider_id = $1
            ORDER BY oidc_group ASC
            "#,
        )
        .bind(provider_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(mappings)
    }

    /// Set group mappings for a provider (replaces existing)
    /// Requirements: 3.4, 11.4
    pub async fn set_group_mappings(
        &self,
        provider_id: Uuid,
        mappings: &[(String, Uuid)], // (oidc_group, local_group_id)
    ) -> Result<Vec<OidcGroupMapping>, OidcRepositoryError> {
        // Verify provider exists
        self.get_provider(provider_id).await?;

        // Delete existing mappings
        sqlx::query("DELETE FROM oidc_group_mappings WHERE provider_id = $1")
            .bind(provider_id)
            .execute(&self.pool)
            .await?;

        // Insert new mappings
        for (oidc_group, local_group_id) in mappings {
            sqlx::query(
                r#"
                INSERT INTO oidc_group_mappings (provider_id, oidc_group, local_group_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (provider_id, oidc_group) DO UPDATE SET local_group_id = $3
                "#,
            )
            .bind(provider_id)
            .bind(oidc_group)
            .bind(local_group_id)
            .execute(&self.pool)
            .await?;
        }

        // Return the new mappings
        self.get_group_mappings(provider_id).await
    }

    /// Add a single group mapping
    pub async fn add_group_mapping(
        &self,
        provider_id: Uuid,
        oidc_group: &str,
        local_group_id: Uuid,
    ) -> Result<OidcGroupMapping, OidcRepositoryError> {
        // Verify provider exists
        self.get_provider(provider_id).await?;

        let mapping = sqlx::query_as::<_, OidcGroupMapping>(
            r#"
            INSERT INTO oidc_group_mappings (provider_id, oidc_group, local_group_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (provider_id, oidc_group) DO UPDATE SET local_group_id = $3
            RETURNING *
            "#,
        )
        .bind(provider_id)
        .bind(oidc_group)
        .bind(local_group_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(mapping)
    }

    /// Remove a group mapping
    pub async fn remove_group_mapping(&self, mapping_id: Uuid) -> Result<(), OidcRepositoryError> {
        let result = sqlx::query("DELETE FROM oidc_group_mappings WHERE id = $1")
            .bind(mapping_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(OidcRepositoryError::MappingNotFound(mapping_id));
        }

        Ok(())
    }

    /// Get local group IDs for OIDC groups
    /// Used during OIDC login to map user's groups
    pub async fn get_local_groups_for_oidc_groups(
        &self,
        provider_id: Uuid,
        oidc_groups: &[String],
    ) -> Result<Vec<Uuid>, OidcRepositoryError> {
        if oidc_groups.is_empty() {
            return Ok(vec![]);
        }

        let group_ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT local_group_id FROM oidc_group_mappings
            WHERE provider_id = $1 AND oidc_group = ANY($2)
            "#,
        )
        .bind(provider_id)
        .bind(oidc_groups)
        .fetch_all(&self.pool)
        .await?;

        Ok(group_ids)
    }

    /// Count OIDC providers
    pub async fn count_providers(&self) -> Result<i64, OidcRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oidc_providers")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    // ========================================================================
    // OIDC auth transactions (server-side state/nonce/code_verifier store)
    // See migration 172_oidc_auth_transactions.sql.
    // ========================================================================

    /// Persist an OIDC authorization transaction. Called at `/authorize`.
    pub async fn create_auth_transaction(
        &self,
        state: &str,
        provider_id: Uuid,
        nonce: &str,
        code_verifier: &str,
        redirect_uri: &str,
        ttl_seconds: i64,
    ) -> Result<(), OidcRepositoryError> {
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);

        sqlx::query(
            r#"
            INSERT INTO oidc_auth_transactions
                (state, provider_id, nonce, code_verifier, redirect_uri, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(state)
        .bind(provider_id)
        .bind(nonce)
        .bind(code_verifier)
        .bind(redirect_uri)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Atomically consume an OIDC authorization transaction. Called at `/callback`.
    ///
    /// Marks the row consumed in the same UPDATE that returns it, so a concurrent
    /// callback for the same `state` cannot succeed twice. The `provider_id` is
    /// part of the predicate: a callback submitted under the wrong provider slug
    /// will not consume a transaction belonging to a different provider, so a
    /// legitimate retry against the right provider can still succeed.
    /// Returns `AuthTransactionInvalid` if the row is missing, already consumed,
    /// expired, or belongs to a different provider.
    pub async fn consume_auth_transaction(
        &self,
        state: &str,
        provider_id: Uuid,
    ) -> Result<OidcAuthTransaction, OidcRepositoryError> {
        let row = sqlx::query_as::<_, OidcAuthTransactionRow>(
            r#"
            UPDATE oidc_auth_transactions
            SET consumed_at = NOW()
            WHERE state = $1
              AND provider_id = $2
              AND consumed_at IS NULL
              AND expires_at > NOW()
            RETURNING state, provider_id, nonce, code_verifier, redirect_uri,
                      expires_at, consumed_at, created_at
            "#,
        )
        .bind(state)
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(OidcRepositoryError::AuthTransactionInvalid)?;

        Ok(row.into())
    }

    /// Delete expired transactions. Safe to call periodically from a housekeeping job;
    /// returns the number of rows removed.
    pub async fn delete_expired_auth_transactions(&self) -> Result<u64, OidcRepositoryError> {
        let result = sqlx::query("DELETE FROM oidc_auth_transactions WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[derive(sqlx::FromRow)]
struct OidcAuthTransactionRow {
    state: String,
    provider_id: Uuid,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<OidcAuthTransactionRow> for OidcAuthTransaction {
    fn from(row: OidcAuthTransactionRow) -> Self {
        Self {
            state: row.state,
            provider_id: row.provider_id,
            nonce: row.nonce,
            code_verifier: row.code_verifier,
            redirect_uri: row.redirect_uri,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
            created_at: row.created_at,
        }
    }
}
