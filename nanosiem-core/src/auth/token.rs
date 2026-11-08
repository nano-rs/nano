// SPDX-License-Identifier: AGPL-3.0-or-later

//! JWT Token Service
//!
//! Requirements: 2.1, 2.2, 2.5
//!
//! This module provides:
//! - Access token creation with configurable expiration
//! - Refresh token creation with rotation support
//! - Token validation and claims extraction
//! - Token decoding for inspection

use chrono::{Duration, Utc};
use dashmap::DashMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use redis::AsyncCommands;
use std::sync::{Arc, OnceLock};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::types::{config_defaults, TokenClaims, TokenPair};

/// Redis key prefix for revoked JTIs. The key TTL matches the remaining
/// access-token lifetime so Redis prunes entries automatically.
const REDIS_REVOKED_JTI_PREFIX: &str = "auth:revoked_jti:";

/// Shared Redis handle for the JTI denylist. Cloned across `TokenService`
/// instances so revocations made on one pod are visible to all.
pub type RedisDenylist = Arc<Mutex<redis::aio::ConnectionManager>>;

/// Build a [`RedisDenylist`] from a `redis://` URL. Lets callers wire the
/// shared denylist without taking a direct dependency on the `redis` crate.
pub async fn redis_denylist_from_url(url: &str) -> redis::RedisResult<RedisDenylist> {
    let client = redis::Client::open(url)?;
    let conn = redis::aio::ConnectionManager::new(client).await?;
    Ok(Arc::new(Mutex::new(conn)))
}

/// Token-related errors
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token creation failed: {0}")]
    CreationFailed(String),

    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    #[error("Token has expired")]
    Expired,

    #[error("Token is invalid: {0}")]
    Invalid(String),

    #[error("Token decoding failed: {0}")]
    DecodingFailed(String),
}

/// Default issuer for internal JWTs
pub const DEFAULT_TOKEN_ISSUER: &str = "nanosiem";
/// Default audience for internal JWTs
pub const DEFAULT_TOKEN_AUDIENCE: &str = "nanosiem-api";

/// Configuration for the token service
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// Secret key for signing JWTs
    pub jwt_secret: String,
    /// Access token time-to-live in seconds (default: 15 minutes)
    pub access_token_ttl: i64,
    /// Refresh token time-to-live in seconds (default: 7 days)
    pub refresh_token_ttl: i64,
    /// Token issuer (iss claim) - identifies the token issuer
    pub issuer: String,
    /// Token audience (aud claim) - intended recipient of the token
    pub audience: String,
}

impl Default for TokenConfig {
    /// Creates a TokenConfig from environment variables.
    ///
    /// # Panics
    /// Panics if JWT_SECRET is not set (unless NANOSIEM_ALLOW_DEFAULT_KEYS=true)
    /// or is shorter than 32 characters.
    fn default() -> Self {
        let secret = match std::env::var("JWT_SECRET") {
            Ok(secret) => {
                if secret.len() < 32 {
                    panic!(
                        "SECURITY ERROR: JWT_SECRET must be at least 32 characters. \
                         Set JWT_SECRET to a secure random value."
                    );
                }
                secret
            }
            Err(_) => {
                // NAN-1355: the public-key fallback is gated by its OWN flag,
                // NANOSIEM_ALLOW_DEFAULT_KEYS — deliberately NOT NANOSIEM_DEV_MODE.
                // NANOSIEM_DEV_MODE only relaxes the cookie Secure flag for plain-HTTP
                // deployments (nanosiem-api-lib/src/cookies.rs); it must not also unlock
                // built-in public keys, or an http:// deploy that enables dev-mode for
                // cookies would silently run on a publicly-known JWT secret.
                let allow_default_keys = std::env::var("NANOSIEM_ALLOW_DEFAULT_KEYS")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                if allow_default_keys {
                    tracing::warn!(
                        "SECURITY WARNING: Using the built-in public development JWT secret \
                         (NANOSIEM_ALLOW_DEFAULT_KEYS=true). Only acceptable in development — \
                         never set this in production!"
                    );
                    "default-dev-jwt-secret-32chars!!".to_string()
                } else {
                    panic!(
                        "SECURITY ERROR: JWT_SECRET not configured. \
                         Set JWT_SECRET environment variable to a secure random value (32+ characters). \
                         For local development only, set NANOSIEM_ALLOW_DEFAULT_KEYS=true to use the \
                         insecure built-in default secret."
                    );
                }
            }
        };

        let issuer =
            std::env::var("JWT_ISSUER").unwrap_or_else(|_| DEFAULT_TOKEN_ISSUER.to_string());
        let audience =
            std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| DEFAULT_TOKEN_AUDIENCE.to_string());

        Self {
            jwt_secret: secret,
            access_token_ttl: config_defaults::ACCESS_TOKEN_TTL,
            refresh_token_ttl: config_defaults::REFRESH_TOKEN_TTL,
            issuer,
            audience,
        }
    }
}

impl TokenConfig {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            access_token_ttl: config_defaults::ACCESS_TOKEN_TTL,
            refresh_token_ttl: config_defaults::REFRESH_TOKEN_TTL,
            issuer: DEFAULT_TOKEN_ISSUER.to_string(),
            audience: DEFAULT_TOKEN_AUDIENCE.to_string(),
        }
    }

    pub fn with_access_ttl(mut self, ttl_seconds: i64) -> Self {
        self.access_token_ttl = ttl_seconds;
        self
    }

    pub fn with_refresh_ttl(mut self, ttl_seconds: i64) -> Self {
        self.refresh_token_ttl = ttl_seconds;
        self
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = issuer;
        self
    }

    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = audience;
        self
    }
}

/// Token service for creating and validating JWTs
///
/// Requirements: 2.1, 2.2, 2.5
pub struct TokenService {
    config: TokenConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Revoked token JTIs mapped to their expiry timestamp.
    /// Entries are automatically pruned when expired.
    revoked_jtis: Arc<DashMap<Uuid, i64>>,
    /// Optional Redis-backed denylist shared across pods. Set once at
    /// startup via [`TokenService::set_redis`] (after the async runtime is
    /// up and `REDIS_URL` is connected). When configured, `revoke_token`
    /// writes here and `validate_access_token_async` consults it on every
    /// request that misses the local `DashMap`.
    redis: OnceLock<RedisDenylist>,
}

impl TokenService {
    /// Create a new token service with the given configuration
    pub fn new(config: TokenConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Self {
            config,
            encoding_key,
            decoding_key,
            revoked_jtis: Arc::new(DashMap::new()),
            redis: OnceLock::new(),
        }
    }

    /// Attach a Redis-backed denylist shared across pods.
    ///
    /// In multi-replica deployments the local `DashMap` denylist only sees
    /// revocations performed by the same pod, so a stolen access token can
    /// remain valid on other pods until its natural expiry. Wiring Redis
    /// makes revocations propagate within a single request.
    ///
    /// Idempotent: subsequent calls are no-ops once Redis is set, so it is
    /// safe to call once at startup before any auth traffic flows.
    pub fn set_redis(&self, redis: RedisDenylist) {
        let _ = self.redis.set(redis);
    }

    /// Create an access token for a user
    ///
    /// Requirements: 2.1 - Issue access tokens with configurable expiration (default 15 minutes)
    /// Requirements: 2.5 - Include user ID, roles, and permissions in JWT claims
    ///
    /// Security: Tokens include iss (issuer) and aud (audience) claims to prevent
    /// token substitution attacks and cross-service token reuse.
    ///
    /// Note: PII (email, name) is intentionally excluded from tokens. The frontend
    /// should fetch user profile data separately via /api/auth/me endpoint.
    ///
    /// # Arguments
    /// * `user_id` - The user's UUID
    /// * `roles` - List of role names assigned to the user
    ///
    /// # Returns
    /// * `Ok(String)` - The encoded JWT access token
    /// * `Err(TokenError)` - If token creation fails
    pub fn create_access_token(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<String, TokenError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.access_token_ttl);

        let claims = TokenClaims {
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            sub: user_id,
            roles,
            permissions: Vec::new(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| TokenError::CreationFailed(e.to_string()))
    }

    /// Create a short-lived MFA challenge token (5 minutes)
    ///
    /// This token proves the user passed password verification but still needs
    /// to complete MFA. It cannot be used as an access token.
    pub fn create_mfa_challenge_token(&self, user_id: Uuid) -> Result<String, TokenError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(300); // 5 minutes

        let claims = TokenClaims {
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            sub: user_id,
            roles: Vec::new(),
            permissions: Vec::new(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::now_v7(),
            purpose: "mfa_challenge".to_string(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| TokenError::CreationFailed(e.to_string()))
    }

    /// Validate an MFA challenge token and return the user ID
    ///
    /// Ensures the token has purpose="mfa_challenge", is not expired,
    /// and has not been revoked (single-use).
    pub fn validate_mfa_challenge_token(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let claims = self.validate_access_token(token)?;
        if claims.purpose != "mfa_challenge" {
            return Err(TokenError::Invalid(
                "Not an MFA challenge token".to_string(),
            ));
        }
        Ok(claims)
    }

    /// Create a refresh token
    ///
    /// Requirements: 2.2 - Issue refresh tokens with configurable expiration (default 7 days)
    ///
    /// The refresh token is a simple JWT containing only the user ID and expiration.
    /// It's used to obtain new access tokens without re-authenticating.
    ///
    /// # Arguments
    /// * `user_id` - The user's UUID
    ///
    /// # Returns
    /// * `Ok(String)` - The encoded JWT refresh token
    /// * `Err(TokenError)` - If token creation fails
    pub fn create_refresh_token(&self, user_id: Uuid) -> Result<String, TokenError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.refresh_token_ttl);

        // Refresh token has minimal claims - just enough to identify the user
        // and validate expiration
        let claims = RefreshTokenClaims {
            sub: user_id,
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::now_v7(),
            token_type: "refresh".to_string(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| TokenError::CreationFailed(e.to_string()))
    }

    /// Create both access and refresh tokens
    ///
    /// This is a convenience method that creates both tokens at once.
    ///
    /// # Arguments
    /// * `user_id` - The user's UUID
    /// * `roles` - List of role names assigned to the user
    ///
    /// # Returns
    /// * `Ok(TokenPair)` - Both access and refresh tokens
    /// * `Err(TokenError)` - If token creation fails
    pub fn create_token_pair(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
    ) -> Result<TokenPair, TokenError> {
        let access_token = self.create_access_token(user_id, roles)?;
        let refresh_token = self.create_refresh_token(user_id)?;

        Ok(TokenPair::new(
            access_token,
            refresh_token,
            self.config.access_token_ttl,
        ))
    }

    /// Validate an access token and extract claims
    ///
    /// Requirements: 2.5 - Validate and decode access tokens
    ///
    /// Security validations performed:
    /// - Algorithm: Must be HS256 (prevents algorithm confusion attacks)
    /// - Signature: Must be valid for configured secret
    /// - Expiration: Token must not be expired (no leeway)
    /// - Issuer: Must match configured issuer (prevents token substitution)
    /// - Audience: Must match configured audience (prevents cross-service reuse)
    ///
    /// # Arguments
    /// * `token` - The JWT access token to validate
    ///
    /// # Returns
    /// * `Ok(TokenClaims)` - The decoded and validated claims
    /// * `Err(TokenError)` - If validation fails (expired, invalid signature, etc.)
    pub fn validate_access_token(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let claims = self.decode_and_validate_claims(token)?;
        if self.is_revoked(&claims.jti) {
            return Err(TokenError::Invalid("Token has been revoked".to_string()));
        }
        Ok(claims)
    }

    /// Crypto + iss/aud/exp validation, no revocation check. Shared by the
    /// sync and async public validators so the JWT decoding path stays in
    /// lockstep — the only difference between the two is *where* the
    /// revocation lookup happens (local DashMap vs. local + Redis).
    fn decode_and_validate_claims(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0; // No leeway for expiration

        // Validate issuer and audience to prevent token substitution attacks
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    TokenError::Invalid("Malformed token".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    TokenError::Invalid("Invalid signature".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    TokenError::Invalid("Invalid token issuer".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    TokenError::Invalid("Invalid token audience".to_string())
                }
                _ => TokenError::ValidationFailed(e.to_string()),
            })
    }

    /// Validate a refresh token and extract the user ID
    ///
    /// # Arguments
    /// * `token` - The JWT refresh token to validate
    ///
    /// # Returns
    /// * `Ok(RefreshTokenClaims)` - The decoded and validated claims
    /// * `Err(TokenError)` - If validation fails
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, TokenError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.leeway = 0; // No leeway for expiration

        let claims = decode::<RefreshTokenClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    TokenError::Invalid("Malformed token".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    TokenError::Invalid("Invalid signature".to_string())
                }
                _ => TokenError::ValidationFailed(e.to_string()),
            })?;

        // Verify this is actually a refresh token
        if claims.token_type != "refresh" {
            return Err(TokenError::Invalid("Not a refresh token".to_string()));
        }

        Ok(claims)
    }

    /// Decode token claims without validation (for inspection only)
    ///
    /// This is useful for debugging or logging purposes where you need to
    /// see the claims even if the token is expired or invalid.
    ///
    /// WARNING: Do not use this for authentication! Use validate_access_token instead.
    ///
    /// # Arguments
    /// * `token` - The JWT token to decode
    ///
    /// # Returns
    /// * `Ok(TokenClaims)` - The decoded claims (not validated)
    /// * `Err(TokenError)` - If decoding fails
    pub fn decode_token_claims(&self, token: &str) -> Result<TokenClaims, TokenError> {
        // Use the dangerous insecure_decode for inspection purposes only
        jsonwebtoken::dangerous::insecure_decode::<TokenClaims>(token)
            .map(|data| data.claims)
            .map_err(|e| TokenError::DecodingFailed(e.to_string()))
    }

    /// Get the access token TTL in seconds
    pub fn access_token_ttl(&self) -> i64 {
        self.config.access_token_ttl
    }

    /// Get the refresh token TTL in seconds
    pub fn refresh_token_ttl(&self) -> i64 {
        self.config.refresh_token_ttl
    }

    /// Revoke a token by its JTI. Writes to the local `DashMap` and, if
    /// Redis is configured, to the shared denylist so other pods see the
    /// revocation immediately. The Redis key TTL is set to the remaining
    /// token lifetime so entries are auto-pruned.
    pub async fn revoke_token(&self, jti: Uuid, exp: i64) {
        self.revoked_jtis.insert(jti, exp);
        self.prune_expired_revocations();

        if let Some(redis) = self.redis.get() {
            let now = Utc::now().timestamp();
            let ttl_secs = (exp - now).max(1) as u64;
            let key = format!("{}{}", REDIS_REVOKED_JTI_PREFIX, jti);
            let mut conn = redis.lock().await;
            let result: redis::RedisResult<()> = conn.set_ex(&key, 1u8, ttl_secs).await;
            if let Err(e) = result {
                // Local + PG paths still record the revocation; log and continue.
                tracing::warn!(jti = %jti, error = %e, "failed to write revoked JTI to Redis");
            }
        }
    }

    /// Check whether a JTI has been revoked, consulting only the local
    /// `DashMap`. Used by the synchronous validation path (tests, single-pod
    /// deployments). Production code paths should prefer
    /// [`TokenService::is_revoked_async`].
    fn is_revoked(&self, jti: &Uuid) -> bool {
        // Prune every 100 entries to bound memory growth between revoke_token() calls
        if self.revoked_jtis.len() > 100 {
            self.prune_expired_revocations();
        }
        self.revoked_jtis.contains_key(jti)
    }

    /// Async revocation check that consults the local `DashMap` first
    /// (cheap) and falls through to the shared Redis denylist on miss.
    /// Returns `true` only when revocation is positively confirmed; if
    /// Redis is unreachable we conservatively log and return the local
    /// result to avoid locking out users during a Dragonfly outage.
    async fn is_revoked_async(&self, jti: &Uuid) -> bool {
        if self.is_revoked(jti) {
            return true;
        }
        let Some(redis) = self.redis.get() else {
            return false;
        };
        let key = format!("{}{}", REDIS_REVOKED_JTI_PREFIX, jti);
        let mut conn = redis.lock().await;
        let exists: redis::RedisResult<bool> = conn.exists(&key).await;
        match exists {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::warn!(jti = %jti, error = %e, "failed to read revoked JTI from Redis");
                false
            }
        }
    }

    /// Async variant of [`TokenService::validate_access_token`] that also
    /// consults the shared Redis denylist. **Production auth middleware
    /// MUST use this** — the sync variant only sees revocations made on
    /// the same pod and is unsafe in multi-replica deployments.
    pub async fn validate_access_token_async(
        &self,
        token: &str,
    ) -> Result<TokenClaims, TokenError> {
        let claims = self.decode_and_validate_claims(token)?;
        if self.is_revoked_async(&claims.jti).await {
            return Err(TokenError::Invalid("Token has been revoked".to_string()));
        }
        Ok(claims)
    }

    /// Remove revocation entries whose tokens have already expired naturally.
    fn prune_expired_revocations(&self) {
        let now = Utc::now().timestamp();
        self.revoked_jtis.retain(|_, exp| *exp > now);
    }

    /// Get a shared handle to the revocation map (for sharing across Arc<TokenService> instances).
    pub fn revoked_jtis_handle(&self) -> Arc<DashMap<Uuid, i64>> {
        Arc::clone(&self.revoked_jtis)
    }

    /// Create a TokenService that shares the revocation denylist with another instance.
    pub fn new_with_shared_denylist(
        config: TokenConfig,
        denylist: Arc<DashMap<Uuid, i64>>,
    ) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Self {
            config,
            encoding_key,
            decoding_key,
            revoked_jtis: denylist,
            redis: OnceLock::new(),
        }
    }
}

// H8: PostgreSQL-backed revocation persistence

/// Load previously persisted revoked JTIs from PostgreSQL into the in-memory map.
/// Call this at API startup before serving requests.
pub async fn load_revoked_tokens(
    pool: &sqlx::PgPool,
    map: &DashMap<Uuid, i64>,
) -> Result<usize, sqlx::Error> {
    let now = Utc::now().timestamp();
    let rows = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT jti, expires_at FROM revoked_tokens WHERE expires_at > $1",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    let count = rows.len();
    for (jti, exp) in rows {
        map.insert(jti, exp);
    }

    // Clean up expired entries in PG
    let _ = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await;

    Ok(count)
}

/// Persist a revoked JTI to PostgreSQL (call alongside in-memory revoke_token).
pub async fn persist_revoked_token(pool: &sqlx::PgPool, jti: Uuid, exp: i64) {
    let result = sqlx::query(
        "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(exp)
    .execute(pool)
    .await;

    if let Err(e) = result {
        tracing::warn!(jti = %jti, error = %e, "Failed to persist token revocation to database");
    }
}

/// Claims for refresh tokens (minimal)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenClaims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Expiration timestamp (Unix epoch)
    pub exp: i64,
    /// Issued at timestamp (Unix epoch)
    pub iat: i64,
    /// JWT ID (for revocation tracking)
    pub jti: Uuid,
    /// Token type identifier
    pub token_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> TokenService {
        let config = TokenConfig::new("test-secret-key-for-testing".to_string())
            .with_access_ttl(900) // 15 minutes
            .with_refresh_ttl(604800); // 7 days
        TokenService::new(config)
    }

    #[test]
    fn test_create_access_token() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let token = service
            .create_access_token(user_id, vec!["Admin".to_string()])
            .expect("Token creation should succeed");

        assert!(!token.is_empty());
        // JWT tokens have 3 parts separated by dots
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_create_refresh_token() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let token = service
            .create_refresh_token(user_id)
            .expect("Token creation should succeed");

        assert!(!token.is_empty());
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn test_create_token_pair() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let pair = service
            .create_token_pair(user_id, vec!["Editor".to_string()])
            .expect("Token pair creation should succeed");

        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.token_type, "Bearer");
        assert_eq!(pair.expires_in, 900);
    }

    #[test]
    fn test_validate_access_token() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();
        let roles = vec!["Admin".to_string()];

        let token = service
            .create_access_token(user_id, roles.clone())
            .expect("Token creation should succeed");

        let claims = service
            .validate_access_token(&token)
            .expect("Token validation should succeed");

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, DEFAULT_TOKEN_ISSUER);
        assert_eq!(claims.aud, DEFAULT_TOKEN_AUDIENCE);
        assert_eq!(claims.roles, roles);
        // Permissions are no longer in the JWT — they're resolved server-side
        assert!(claims.permissions.is_empty());
    }

    #[test]
    fn test_validate_refresh_token() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let token = service
            .create_refresh_token(user_id)
            .expect("Token creation should succeed");

        let claims = service
            .validate_refresh_token(&token)
            .expect("Token validation should succeed");

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_invalid_token() {
        let service = create_test_service();

        let result = service.validate_access_token("invalid.token.here");
        assert!(result.is_err());

        match result {
            Err(TokenError::Invalid(_)) | Err(TokenError::ValidationFailed(_)) => {}
            _ => panic!("Expected Invalid or ValidationFailed error"),
        }
    }

    #[test]
    fn test_wrong_secret() {
        let service1 = TokenService::new(TokenConfig::new("secret1".to_string()));
        let service2 = TokenService::new(TokenConfig::new("secret2".to_string()));

        let user_id = Uuid::now_v7();
        let token = service1
            .create_access_token(user_id, vec![])
            .expect("Token creation should succeed");

        // Validating with different secret should fail
        let result = service2.validate_access_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_issuer() {
        let service1 = TokenService::new(
            TokenConfig::new("same-secret".to_string()).with_issuer("issuer1".to_string()),
        );
        let service2 = TokenService::new(
            TokenConfig::new("same-secret".to_string()).with_issuer("issuer2".to_string()),
        );

        let user_id = Uuid::now_v7();
        let token = service1
            .create_access_token(user_id, vec![])
            .expect("Token creation should succeed");

        // Validating with different issuer should fail
        let result = service2.validate_access_token(&token);
        assert!(result.is_err());
        match result {
            Err(TokenError::Invalid(msg)) => assert!(msg.contains("issuer")),
            _ => panic!("Expected Invalid error with issuer message"),
        }
    }

    #[test]
    fn test_wrong_audience() {
        let service1 = TokenService::new(
            TokenConfig::new("same-secret".to_string()).with_audience("audience1".to_string()),
        );
        let service2 = TokenService::new(
            TokenConfig::new("same-secret".to_string()).with_audience("audience2".to_string()),
        );

        let user_id = Uuid::now_v7();
        let token = service1
            .create_access_token(user_id, vec![])
            .expect("Token creation should succeed");

        // Validating with different audience should fail
        let result = service2.validate_access_token(&token);
        assert!(result.is_err());
        match result {
            Err(TokenError::Invalid(msg)) => assert!(msg.contains("audience")),
            _ => panic!("Expected Invalid error with audience message"),
        }
    }

    #[test]
    fn test_expired_token() {
        // Create a service with very short TTL
        let config = TokenConfig::new("test-secret".to_string()).with_access_ttl(1); // 1 second TTL
        let service = TokenService::new(config);

        let user_id = Uuid::now_v7();
        let token = service
            .create_access_token(user_id, vec![])
            .expect("Token creation should succeed");

        // Wait for token to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        let result = service.validate_access_token(&token);
        // Token should be expired
        assert!(result.is_err(), "Expected error but got: {:?}", result);
        match result {
            Err(TokenError::Expired) => {} // Expected
            Err(e) => panic!("Expected TokenError::Expired but got: {:?}", e),
            Ok(_) => panic!("Expected error but validation succeeded"),
        }
    }

    #[test]
    fn test_decode_token_claims_without_validation() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let token = service
            .create_access_token(user_id, vec!["Admin".to_string()])
            .expect("Token creation should succeed");

        // Should be able to decode without validation
        let claims = service
            .decode_token_claims(&token)
            .expect("Decoding should succeed");

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, DEFAULT_TOKEN_ISSUER);
    }

    #[test]
    fn test_token_claims_has_permission() {
        let claims = TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["Admin".to_string()],
            permissions: vec![
                "search:view".to_string(),
                "search:execute".to_string(),
                "dashboards:view".to_string(),
            ],
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };

        assert!(claims.has_permission("search:view"));
        assert!(claims.has_permission("dashboards:view"));
        assert!(!claims.has_permission("detections:create"));

        assert!(claims.has_any_permission(&["search:view", "detections:create"]));
        assert!(!claims.has_any_permission(&["detections:create", "alerts:view"]));

        assert!(claims.has_all_permissions(&["search:view", "search:execute"]));
        assert!(!claims.has_all_permissions(&["search:view", "detections:create"]));
    }

    #[test]
    fn test_refresh_token_not_valid_as_access_token() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let refresh_token = service
            .create_refresh_token(user_id)
            .expect("Token creation should succeed");

        // Refresh token should not be valid as access token
        // (different claims structure)
        let result = service.validate_access_token(&refresh_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_access_token_not_valid_as_refresh_token() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let access_token = service
            .create_access_token(user_id, vec![])
            .expect("Token creation should succeed");

        // Access token should not be valid as refresh token
        let result = service.validate_refresh_token(&access_token);
        assert!(result.is_err());
    }

    /// NAN-682: revocations made via `revoke_token().await` must reject
    /// subsequent `validate_access_token_async` calls on the same instance
    /// even when no Redis denylist is wired (single-pod fallback path).
    #[tokio::test]
    async fn test_async_revoke_blocks_async_validate_local() {
        let service = create_test_service();
        let user_id = Uuid::now_v7();

        let token = service
            .create_access_token(user_id, vec![])
            .expect("token creation");

        // Pre-revoke: validates fine.
        let claims = service
            .validate_access_token_async(&token)
            .await
            .expect("validation should pass before revoke");

        // Revoke and try again.
        service.revoke_token(claims.jti, claims.exp).await;

        let err = service
            .validate_access_token_async(&token)
            .await
            .expect_err("validation should fail after revoke");
        match err {
            TokenError::Invalid(msg) => assert!(
                msg.contains("revoked"),
                "expected revoked error, got: {msg}"
            ),
            other => panic!("expected Invalid(revoked), got {other:?}"),
        }
    }

    /// NAN-682: when the same DashMap denylist is shared (the existing
    /// pattern between `token_service` and the AuthService's internal copy),
    /// a revocation on one instance must propagate to the other via the
    /// shared local map. This guards against regressions in the shared
    /// denylist plumbing independent of Redis.
    #[tokio::test]
    async fn test_async_revoke_propagates_via_shared_denylist() {
        let primary = create_test_service();
        let secondary = TokenService::new_with_shared_denylist(
            TokenConfig::new("test-secret-key-for-testing".to_string()),
            primary.revoked_jtis_handle(),
        );

        let user_id = Uuid::now_v7();
        let token = primary
            .create_access_token(user_id, vec![])
            .expect("token creation");
        let claims = primary
            .validate_access_token_async(&token)
            .await
            .expect("primary should validate");
        // Sanity: secondary also accepts the freshly minted token.
        secondary
            .validate_access_token_async(&token)
            .await
            .expect("secondary should validate before revoke");

        primary.revoke_token(claims.jti, claims.exp).await;

        // Secondary must reject — they share the DashMap.
        secondary
            .validate_access_token_async(&token)
            .await
            .expect_err("secondary should reject revoked token");
    }

    /// NAN-682: with no Redis configured, `is_revoked_async` must collapse
    /// to a pure local-DashMap check and return `false` for unknown JTIs
    /// (no panic, no spurious revocation, no I/O).
    #[tokio::test]
    async fn test_is_revoked_async_no_redis_fallback() {
        let service = create_test_service();
        assert!(!service.is_revoked_async(&Uuid::now_v7()).await);
        // And a positive local hit still returns true.
        let jti = Uuid::now_v7();
        service
            .revoke_token(jti, Utc::now().timestamp() + 60)
            .await;
        assert!(service.is_revoked_async(&jti).await);
    }
}
