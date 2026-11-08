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
use sha2::{Digest, Sha256};
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

/// Domain tag for the fast verifier digest (NAN-3798 port).
const API_KEY_DIGEST_TAG: &[u8] = b"nano-api-key-digest-v1\0";

/// SHA-256 verifier over the row's bcrypt `key_hash` and the secret.
///
/// The secret is 256 bits from the OS CSPRNG, so a fast digest is as strong as
/// bcrypt against offline guessing and costs microseconds instead of ~0.3 s per
/// request. Binding the digest to `key_hash` means a digest left behind after a
/// hash change can never authenticate: the verifier falls back to bcrypt.
pub(crate) fn api_key_digest(key_hash: &str, secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(API_KEY_DIGEST_TAG);
    hasher.update((key_hash.len() as u64).to_be_bytes());
    hasher.update(key_hash.as_bytes());
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

/// Constant-time equality for the digest comparison.
fn digests_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

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
        let (plaintext_key, key_prefix, key_hash) = Self::new_key_material().await?;

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

        self.store_digest(&api_key, &plaintext_key).await;

        Ok(ApiKeyCreated {
            id: api_key.id,
            key: plaintext_key,
            name: api_key.name,
            key_prefix,
            created_at: api_key.created_at,
        })
    }

    /// [`Self::create_key`] with the `apikey_created` audit record committed in
    /// the same PostgreSQL transaction as the key (NAN-4954). `audit` builds
    /// the event from the new key's id and name. Returns the recorded event so
    /// the caller can hand it to ClickHouse delivery.
    pub async fn create_key_audited<F>(
        &self,
        request: CreateApiKeyRequest,
        created_by: Option<Uuid>,
        audit: F,
    ) -> Result<(ApiKeyCreated, crate::audit::AuditEvent), ApiKeyServiceError>
    where
        F: FnOnce(Uuid, &str) -> crate::audit::AuditEvent,
    {
        let (plaintext_key, key_prefix, key_hash) = Self::new_key_material().await?;
        let (api_key, event) = self
            .repo
            .create_key_audited(
                &request.name,
                request.description.as_deref(),
                &key_hash,
                &key_prefix,
                &request.permissions,
                request.expires_at,
                request.rate_limit,
                created_by,
                |key| audit(key.id, &key.name),
            )
            .await?;
        self.store_digest(&api_key, &plaintext_key).await;
        Ok((
            ApiKeyCreated {
                id: api_key.id,
                key: plaintext_key,
                name: api_key.name,
                key_prefix,
                created_at: api_key.created_at,
            },
            event,
        ))
    }

    /// [`Self::delete_key`] with the `apikey_deleted` audit record committed in
    /// the same transaction as the delete (NAN-4954).
    pub async fn delete_key_audited(
        &self,
        id: Uuid,
        event: &crate::audit::AuditEvent,
    ) -> Result<(), ApiKeyServiceError> {
        self.repo.get_key_by_id(id).await?;
        self.repo.delete_key_audited(id, event).await?;
        Ok(())
    }

    /// Generate a key, its prefix, and its bcrypt hash (on the blocking pool).
    /// Requirements: 12.3 - Store API keys as hashed values
    async fn new_key_material() -> Result<(String, String, String), ApiKeyServiceError> {
        let plaintext_key = Self::generate_key();
        let key_prefix = Self::extract_prefix(&plaintext_key);
        let key_to_hash = plaintext_key.clone();
        let key_hash = tokio::task::spawn_blocking(move || hash_password(&key_to_hash))
            .await
            .map_err(|e| ApiKeyServiceError::HashingError(e.to_string()))?
            .map_err(|e| ApiKeyServiceError::HashingError(e.to_string()))?;
        Ok((plaintext_key, key_prefix, key_hash))
    }

    /// Write the fast verifier digest. Best-effort: a failure leaves the
    /// digest NULL and the next successful bcrypt verify backfills it.
    async fn store_digest(&self, api_key: &ApiKey, plaintext_key: &str) {
        let digest = api_key_digest(&api_key.key_hash, plaintext_key);
        if let Err(error) = self
            .repo
            .set_key_digest(api_key.id, &api_key.key_hash, &digest)
            .await
        {
            tracing::warn!(key_id = %api_key.id, %error, "api key digest write failed; bcrypt fallback stays in effect");
        }
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
        self.store_digest(&api_key, &plaintext_key).await;

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

        // Candidate keys with a matching prefix (indexed lookup).
        let prefix = Self::extract_prefix(key);
        let candidates = self.repo.list_candidates_by_prefix(&prefix).await?;

        for (api_key, stored_digest) in candidates {
            // NAN-3798 port: a matching fast digest authenticates without
            // bcrypt. A missing or mismatched digest falls back to bcrypt, so a
            // stale digest can never authenticate anything.
            let digest = api_key_digest(&api_key.key_hash, key);
            let verified = if stored_digest
                .as_deref()
                .is_some_and(|stored| digests_equal(stored, &digest))
            {
                true
            } else {
                // Verify the key hash (spawn_blocking: bcrypt is CPU-intensive)
                let k = key.to_string();
                let h = api_key.key_hash.clone();
                let ok = tokio::task::spawn_blocking(move || {
                    crate::auth::password::verify_password(&k, &h)
                })
                .await
                .ok()
                .and_then(|r| r.ok())
                    == Some(true);
                if ok {
                    // Backfill so the next request skips bcrypt.
                    let _ = self
                        .repo
                        .set_key_digest(api_key.id, &api_key.key_hash, &digest)
                        .await;
                }
                ok
            };

            if verified {
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

                // F-32: reject the key when its OWNER is no longer active. The
                // `enabled`/`expires_at` checks above never consulted the owning
                // user, so a disabled user's API key worked forever. A `system`
                // service account is exempt — those own non-interactive keys and
                // legitimately have no `active` login status. FAIL CLOSED: a
                // deleted owner (owner_status => None) or a PG error rejects the key.
                //
                // NULL created_by is only reachable now for genuine ownerless
                // system/bootstrap keys: key-chaining propagates the human owner
                // (api_keys handler) and delete_user removes a deleted user's keys
                // (users repo), so the two paths that previously produced orphaned
                // NULL-owner keys are closed. Pre-existing legacy NULL-owner keys
                // should be audited separately (see the red-team handoff note).
                if let Some(owner_id) = api_key.created_by {
                    match self.repo.owner_status(owner_id).await? {
                        Some(status) if status == "active" || status == "system" => {}
                        _ => return Err(ApiKeyServiceError::Disabled),
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
    fn digest_is_bound_to_hash_and_secret() {
        let a = api_key_digest("$2b$12$hashA", "secret-1");
        assert!(digests_equal(&a, &api_key_digest("$2b$12$hashA", "secret-1")));
        assert!(!digests_equal(&a, &api_key_digest("$2b$12$hashB", "secret-1")));
        assert!(!digests_equal(&a, &api_key_digest("$2b$12$hashA", "secret-2")));
        // Length-prefixing keeps the (hash, secret) split unambiguous.
        assert!(!digests_equal(
            &api_key_digest("ab", "c"),
            &api_key_digest("a", "bc")
        ));
        assert!(!digests_equal(&a, &a[..31]));
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
