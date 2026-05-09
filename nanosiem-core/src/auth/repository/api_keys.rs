// SPDX-License-Identifier: AGPL-3.0-or-later

//! API Key repository for CRUD operations
//!
//! Requirements: 12.1, 12.4, 12.6, 12.8, 12.10

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::types::ApiKey;

#[derive(Error, Debug)]
pub enum ApiKeyRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("API key not found: {0}")]
    NotFound(Uuid),
    #[error("API key not found by hash")]
    NotFoundByHash,
    #[error("API key expired")]
    Expired,
    #[error("API key disabled")]
    Disabled,
}

/// Repository for API key operations
#[derive(Clone)]
pub struct ApiKeyRepository {
    pool: PgPool,
}

impl ApiKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new API key
    /// Requirements: 12.1
    pub async fn create_key(
        &self,
        name: &str,
        description: Option<&str>,
        key_hash: &str,
        key_prefix: &str,
        permissions: &[String],
        expires_at: Option<DateTime<Utc>>,
        rate_limit: Option<i32>,
        created_by: Option<Uuid>,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            INSERT INTO api_keys (name, description, key_hash, key_prefix, permissions, expires_at, rate_limit, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#
        )
        .bind(name)
        .bind(description)
        .bind(key_hash)
        .bind(key_prefix)
        .bind(permissions)
        .bind(expires_at)
        .bind(rate_limit)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        Ok(api_key)
    }

    /// Get an API key by its hash
    pub async fn get_key_by_hash(&self, key_hash: &str) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE key_hash = $1")
            .bind(key_hash)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ApiKeyRepositoryError::NotFoundByHash)?;

        // Check if key is disabled
        if !api_key.enabled {
            return Err(ApiKeyRepositoryError::Disabled);
        }

        // Check if key has expired
        if let Some(expires_at) = api_key.expires_at {
            if expires_at < Utc::now() {
                return Err(ApiKeyRepositoryError::Expired);
            }
        }

        Ok(api_key)
    }

    /// Get an API key by ID
    pub async fn get_key_by_id(&self, id: Uuid) -> Result<ApiKey, ApiKeyRepositoryError> {
        sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ApiKeyRepositoryError::NotFound(id))
    }

    /// Get an API key by prefix (for display/identification)
    pub async fn get_key_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<ApiKey>, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE key_prefix = $1")
            .bind(prefix)
            .fetch_optional(&self.pool)
            .await?;

        Ok(api_key)
    }

    /// List all API keys (masked - key_hash is not exposed in responses)
    /// Requirements: 12.8
    pub async fn list_keys(&self) -> Result<Vec<ApiKey>, ApiKeyRepositoryError> {
        let keys = sqlx::query_as::<_, ApiKey>(
            r#"
            SELECT * FROM api_keys
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    /// List API keys created by a specific user
    pub async fn list_keys_by_creator(
        &self,
        created_by: Uuid,
    ) -> Result<Vec<ApiKey>, ApiKeyRepositoryError> {
        let keys = sqlx::query_as::<_, ApiKey>(
            r#"
            SELECT * FROM api_keys
            WHERE created_by = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(created_by)
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    /// Delete an API key
    /// Requirements: 12.9
    pub async fn delete_key(&self, id: Uuid) -> Result<(), ApiKeyRepositoryError> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ApiKeyRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Enable or disable an API key
    /// Requirements: 12.6
    pub async fn set_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys SET enabled = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiKeyRepositoryError::NotFound(id))?;

        Ok(api_key)
    }

    /// Record API key usage (update last_used_at and last_used_ip)
    /// Requirements: 12.7
    pub async fn record_usage(
        &self,
        id: Uuid,
        ip_address: Option<&str>,
    ) -> Result<(), ApiKeyRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys SET
                last_used_at = NOW(),
                last_used_ip = COALESCE($2, last_used_ip)
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(ip_address)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiKeyRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Reset an API key (generate new hash and prefix)
    pub async fn reset_key(
        &self,
        id: Uuid,
        key_hash: &str,
        key_prefix: &str,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys SET key_hash = $2, key_prefix = $3
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(key_hash)
        .bind(key_prefix)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiKeyRepositoryError::NotFound(id))?;

        Ok(api_key)
    }

    /// Update API key permissions
    pub async fn update_permissions(
        &self,
        id: Uuid,
        permissions: &[String],
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys SET permissions = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(permissions)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiKeyRepositoryError::NotFound(id))?;

        Ok(api_key)
    }

    /// Update API key expiration
    /// Requirements: 12.4
    pub async fn update_expiration(
        &self,
        id: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys SET expires_at = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(expires_at)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiKeyRepositoryError::NotFound(id))?;

        Ok(api_key)
    }

    /// Update API key metadata (name, description, permissions, expiration, rate limit)
    pub async fn update_key(
        &self,
        id: Uuid,
        name: Option<&str>,
        description: Option<Option<&str>>,
        permissions: Option<&[String]>,
        expires_at: Option<Option<DateTime<Utc>>>,
        rate_limit: Option<Option<i32>>,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys SET
                name = COALESCE($2, name),
                description = CASE WHEN $3 THEN $4 ELSE description END,
                permissions = COALESCE($5, permissions),
                expires_at = CASE WHEN $6 THEN $7 ELSE expires_at END,
                rate_limit = CASE WHEN $8 THEN $9 ELSE rate_limit END
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(description.is_some())
        .bind(description.flatten())
        .bind(permissions)
        .bind(expires_at.is_some())
        .bind(expires_at.flatten())
        .bind(rate_limit.is_some())
        .bind(rate_limit.flatten())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiKeyRepositoryError::NotFound(id))?;

        Ok(api_key)
    }

    /// Update API key rate limit
    pub async fn update_rate_limit(
        &self,
        id: Uuid,
        rate_limit: Option<i32>,
    ) -> Result<ApiKey, ApiKeyRepositoryError> {
        let api_key = sqlx::query_as::<_, ApiKey>(
            r#"
            UPDATE api_keys SET rate_limit = $2
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(rate_limit)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiKeyRepositoryError::NotFound(id))?;

        Ok(api_key)
    }

    /// Count total API keys
    pub async fn count_keys(&self) -> Result<i64, ApiKeyRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_keys")
            .fetch_one(&self.pool)
            .await?;

        Ok(count)
    }

    /// Count enabled API keys
    pub async fn count_enabled_keys(&self) -> Result<i64, ApiKeyRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_keys WHERE enabled = TRUE")
                .fetch_one(&self.pool)
                .await?;

        Ok(count)
    }

    /// Check if an API key exists by hash
    pub async fn key_exists_by_hash(&self, key_hash: &str) -> Result<bool, ApiKeyRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_keys WHERE key_hash = $1")
                .bind(key_hash)
                .fetch_one(&self.pool)
                .await?;

        Ok(count > 0)
    }

    /// Delete expired API keys (cleanup task)
    pub async fn cleanup_expired_keys(&self) -> Result<u64, ApiKeyRepositoryError> {
        let result =
            sqlx::query("DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < NOW()")
                .execute(&self.pool)
                .await?;

        Ok(result.rows_affected())
    }
}
