// SPDX-License-Identifier: AGPL-3.0-or-later

//! API Key service for creating and validating API keys
//!
//! Requirements: 12.2, 12.3, 12.5, 12.9
//!
//! This module provides:
//! - Secure API key generation (32+ bytes, base64 encoded)
//! - API key validation with permission checking
//! - API key lifecycle management

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::Rng;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{
    password::hash_password,
    repository::{ApiKeyRepository, ApiKeyRepositoryError},
    types::{ApiKey, ApiKeyCreated, CreateApiKeyRequest},
};
use crate::db::repository::{RateLimitRepository, RateLimitRepositoryError};

/// Sliding-window length, in seconds, for the per-api-key rate limiter.
const API_KEY_RATE_LIMIT_WINDOW_SECS: f64 = 60.0;
/// Bucket category in `rate_limit_buckets` for api-key traffic.
const API_KEY_RATE_LIMIT_CATEGORY: &str = "api_key";

/// Minimum length for API keys in bytes (32 bytes = 256 bits)
/// Requirements: 12.2
pub const API_KEY_MIN_BYTES: usize = 32;

/// Prefix length for API key identification
pub const API_KEY_PREFIX_LENGTH: usize = 8;

/// API key service errors
#[derive(Error, Debug)]
pub enum ApiKeyServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] ApiKeyRepositoryError),

    #[error("API key not found")]
    NotFound,

    #[error("API key is disabled")]
    Disabled,

    #[error("API key has expired")]
    Expired,

    #[error("API key validation failed")]
    ValidationFailed,

    #[error("Insufficient permissions: missing {0}")]
    InsufficientPermissions(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Password hashing error: {0}")]
    HashingError(String),

    #[error("Invalid API key format")]
    InvalidFormat,
}

/// Information about a validated API key
#[derive(Debug, Clone)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
    /// The user who created/owns this API key
    pub user_id: Option<Uuid>,
}

impl From<&ApiKey> for ApiKeyInfo {
    fn from(key: &ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name.clone(),
            permissions: key.permissions.clone(),
            user_id: key.created_by,
        }
    }
}

/// API Key service for managing API keys
#[derive(Clone)]
pub struct ApiKeyService {
    repo: ApiKeyRepository,
    rate_limit_repo: RateLimitRepository,
}

impl ApiKeyService {
    pub fn new(repo: ApiKeyRepository, rate_limit_repo: RateLimitRepository) -> Self {
        Self {
            repo,
            rate_limit_repo,
        }
    }

    /// Generate a cryptographically secure API key
    /// Requirements: 12.2 - Generate cryptographically secure API keys (32+ bytes, base64 encoded)
    fn generate_key() -> String {
        let mut bytes = vec![0u8; API_KEY_MIN_BYTES];
        rand::rng().fill(&mut bytes[..]);
        URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// Extract the prefix from an API key for identification
    fn extract_prefix(key: &str) -> String {
        key.chars().take(API_KEY_PREFIX_LENGTH).collect()
    }

    /// Create a new API key
    /// Requirements: 12.1, 12.2, 12.3
    ///
    /// Returns the created API key with the plaintext key.
    /// The plaintext key is only returned once and should be stored securely by the caller.
    pub async fn create_key(
        &self,
        request: CreateApiKeyRequest,
        created_by: Option<Uuid>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<ApiKeyCreated, ApiKeyServiceError> {
        // Generate a secure random key
        let plaintext_key = Self::generate_key();
        let key_prefix = Self::extract_prefix(&plaintext_key);

        // Hash the key for storage (use spawn_blocking as bcrypt is CPU-intensive)
        // Requirements: 12.3 - Store API keys as hashed values
        let key_to_hash = plaintext_key.clone();
        let key_hash = tokio::task::spawn_blocking(move || hash_password(&key_to_hash))
            .await
            .map_err(|e| ApiKeyServiceError::HashingError(e.to_string()))?
            .map_err(|e| ApiKeyServiceError::HashingError(e.to_string()))?;

        // Create the API key in the database
        let api_key = self
            .repo
            .create_key(
                &request.name,
                request.description.as_deref(),
                &key_hash,
                &key_prefix,
                &request.permissions,
                request.expires_at,
                request.rate_limit,
                created_by,
            )
            .await?;

        Ok(ApiKeyCreated {
            id: api_key.id,
            key: plaintext_key,
            name: api_key.name,
            key_prefix,
            created_at: api_key.created_at,
        })
    }

    /// Reset an API key (generate a new key value)
    ///
    /// Returns the new plaintext key. The old key is immediately invalidated.
    pub async fn reset_key(
        &self,
        id: Uuid,
        _user_id: Option<Uuid>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<ApiKeyCreated, ApiKeyServiceError> {
        // Verify the key exists
        self.repo.get_key_by_id(id).await?;

        // Generate a new secure key
        let plaintext_key = Self::generate_key();
        let key_prefix = Self::extract_prefix(&plaintext_key);

        // Hash the new key
        let key_to_hash = plaintext_key.clone();
        let key_hash = tokio::task::spawn_blocking(move || hash_password(&key_to_hash))
            .await
            .map_err(|e| ApiKeyServiceError::HashingError(e.to_string()))?
            .map_err(|e| ApiKeyServiceError::HashingError(e.to_string()))?;

        // Update the key in the database
        let api_key = self.repo.reset_key(id, &key_hash, &key_prefix).await?;

        Ok(ApiKeyCreated {
            id: api_key.id,
            key: plaintext_key,
            name: api_key.name,
            key_prefix,
            created_at: api_key.created_at,
        })
    }

    /// Validate an API key and return its info
    /// Requirements: 12.5 - Validate API key and apply configured permissions
    pub async fn validate_key(
        &self,
        key: &str,
        ip_address: Option<&str>,
    ) -> Result<ApiKeyInfo, ApiKeyServiceError> {
        // Validate key format
        if key.len() < API_KEY_PREFIX_LENGTH {
            return Err(ApiKeyServiceError::InvalidFormat);
        }

        // Find all keys with matching prefix
        let prefix = Self::extract_prefix(key);
        let keys = self.repo.list_keys().await?;

        // Find the key that matches the hash
        for api_key in keys {
            if api_key.key_prefix != prefix {
                continue;
            }

            // Verify the key hash (use spawn_blocking as bcrypt is CPU-intensive)
            let k = key.to_string();
            let h = api_key.key_hash.clone();
            let verify_result =
                tokio::task::spawn_blocking(move || crate::auth::password::verify_password(&k, &h))
                    .await
                    .ok()
                    .and_then(|r| r.ok());

            if verify_result == Some(true) {
                // Check if key is enabled
                if !api_key.enabled {
                    return Err(ApiKeyServiceError::Disabled);
                }

                // Check if key has expired
                if let Some(expires_at) = api_key.expires_at {
                    if expires_at < Utc::now() {
                        return Err(ApiKeyServiceError::Expired);
                    }
                }

                // Atomic increment — every authed call consumes a token
                // regardless of audit emission (NAN-675).
                if let Some(limit) = api_key.rate_limit {
                    let tokens = self
                        .rate_limit_repo
                        .check_rate_limit(
                            API_KEY_RATE_LIMIT_CATEGORY,
                            &api_key.id.to_string(),
                            API_KEY_RATE_LIMIT_WINDOW_SECS,
                        )
                        .await
                        .map_err(|RateLimitRepositoryError::DatabaseError(e)| {
                            ApiKeyServiceError::RepositoryError(
                                ApiKeyRepositoryError::DatabaseError(e),
                            )
                        })?;
                    if tokens > limit {
                        return Err(ApiKeyServiceError::RateLimitExceeded);
                    }
                }

                // Record usage
                let _ = self.repo.record_usage(api_key.id, ip_address).await;

                return Ok(ApiKeyInfo::from(&api_key));
            }
        }

        Err(ApiKeyServiceError::ValidationFailed)
    }

    /// Check if an API key has a specific permission
    pub fn has_permission(info: &ApiKeyInfo, permission: &str) -> bool {
        info.permissions.contains(&permission.to_string())
    }

    /// Check if an API key has any of the specified permissions
    pub fn has_any_permission(info: &ApiKeyInfo, permissions: &[&str]) -> bool {
        permissions.iter().any(|p| Self::has_permission(info, p))
    }

    /// List all API keys (masked)
    pub async fn list_keys(&self) -> Result<Vec<ApiKey>, ApiKeyServiceError> {
        Ok(self.repo.list_keys().await?)
    }

    /// Get an API key by ID
    pub async fn get_key(&self, id: Uuid) -> Result<ApiKey, ApiKeyServiceError> {
        self.repo.get_key_by_id(id).await.map_err(|e| match e {
            ApiKeyRepositoryError::NotFound(_) => ApiKeyServiceError::NotFound,
            other => ApiKeyServiceError::RepositoryError(other),
        })
    }

    /// Enable an API key
    pub async fn enable_key(
        &self,
        id: Uuid,
        _user_id: Option<Uuid>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<ApiKey, ApiKeyServiceError> {
        let api_key = self.repo.set_enabled(id, true).await?;

        Ok(api_key)
    }

    /// Disable an API key
    pub async fn disable_key(
        &self,
        id: Uuid,
        _user_id: Option<Uuid>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<ApiKey, ApiKeyServiceError> {
        let api_key = self.repo.set_enabled(id, false).await?;

        Ok(api_key)
    }

    /// Delete an API key
    /// Requirements: 12.9 - Immediately reject requests using deleted key
    pub async fn delete_key(
        &self,
        id: Uuid,
        _user_id: Option<Uuid>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<(), ApiKeyServiceError> {
        self.repo.get_key_by_id(id).await?;

        self.repo.delete_key(id).await?;

        Ok(())
    }

    /// Update API key metadata
    pub async fn update_key(
        &self,
        id: Uuid,
        name: Option<&str>,
        description: Option<Option<&str>>,
        permissions: Option<&[String]>,
        expires_at: Option<Option<DateTime<Utc>>>,
        rate_limit: Option<Option<i32>>,
    ) -> Result<ApiKey, ApiKeyServiceError> {
        Ok(self
            .repo
            .update_key(id, name, description, permissions, expires_at, rate_limit)
            .await?)
    }

    /// Update API key expiration
    pub async fn update_expiration(
        &self,
        id: Uuid,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey, ApiKeyServiceError> {
        Ok(self.repo.update_expiration(id, expires_at).await?)
    }

    /// Update API key rate limit
    pub async fn update_rate_limit(
        &self,
        id: Uuid,
        rate_limit: Option<i32>,
    ) -> Result<ApiKey, ApiKeyServiceError> {
        Ok(self.repo.update_rate_limit(id, rate_limit).await?)
    }

    /// Cleanup expired API keys
    pub async fn cleanup_expired(&self) -> Result<u64, ApiKeyServiceError> {
        Ok(self.repo.cleanup_expired_keys().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_length() {
        let key = ApiKeyService::generate_key();
        // Base64 encoding of 32 bytes should be at least 43 characters
        assert!(key.len() >= 43);
    }

    #[test]
    fn test_generate_key_uniqueness() {
        let key1 = ApiKeyService::generate_key();
        let key2 = ApiKeyService::generate_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_extract_prefix() {
        let key = "abcdefghijklmnop";
        let prefix = ApiKeyService::extract_prefix(key);
        assert_eq!(prefix, "abcdefgh");
        assert_eq!(prefix.len(), API_KEY_PREFIX_LENGTH);
    }

    #[test]
    fn test_has_permission() {
        let info = ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "test".to_string(),
            permissions: vec!["search:view".to_string(), "search:execute".to_string()],
            user_id: None,
        };

        assert!(ApiKeyService::has_permission(&info, "search:view"));
        assert!(ApiKeyService::has_permission(&info, "search:execute"));
        assert!(!ApiKeyService::has_permission(&info, "search:save"));
    }

    #[test]
    fn test_has_any_permission() {
        let info = ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "test".to_string(),
            permissions: vec!["search:view".to_string()],
            user_id: None,
        };

        assert!(ApiKeyService::has_any_permission(
            &info,
            &["search:view", "search:execute"]
        ));
        assert!(!ApiKeyService::has_any_permission(
            &info,
            &["search:save", "search:share"]
        ));
    }
}
