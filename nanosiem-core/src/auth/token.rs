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
/// Upper bound on the replica acknowledgement wait after a revocation.
const REVOCATION_WAIT_TIMEOUT_MS: i64 = 500;
/// NAN-5214: a Valkey failover closes every client connection (the router's
/// shutdown-sessions). The ConnectionManager reconnects, but the first command
/// on the dead socket fails ("broken pipe"). Retrying covers that reconnect,
/// so a revocation is neither lost nor skipped (fail-open) across a failover.
const REDIS_ATTEMPTS: u32 = 4;
const REDIS_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
/// Per-attempt bound: while reconnecting, the ConnectionManager can hold a
/// command through its own reconnect backoff (tens of seconds). Every auth
/// request would stall that long; bound each attempt instead (worst case
/// about REDIS_ATTEMPTS x (timeout + delay) = 4 s, then 503).
const REDIS_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

async fn bounded<T>(
    attempt: impl std::future::Future<Output = redis::RedisResult<T>>,
) -> redis::RedisResult<T> {
    tokio::time::timeout(REDIS_ATTEMPT_TIMEOUT, attempt)
        .await
        .unwrap_or_else(|_| {
            Err(redis::RedisError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Valkey command timed out",
            )))
        })
}

/// NAN-5214: `NANO_AUTH_REVOCATION_FAIL_CLOSED=true` (set by the HA Compose
/// render, alongside replicated Valkey) makes an unreadable revocation
/// denylist refuse the request (503) instead of accepting the token.
/// Single-node and single-app-host installs keep the original behaviour:
/// warn and allow, so a local Valkey restart never locks every user out.
pub fn revocation_fail_closed_from_env() -> bool {
    std::env::var("NANO_AUTH_REVOCATION_FAIL_CLOSED")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// NAN-5243: how long a durable revocation keeps retrying SETEX + WAIT
/// (covers a Sentinel failover and the router moving to the new master).
const REVOCATION_DURABLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);

/// NAN-5243: PostgreSQL (`revoked_tokens`) is the durable record of logouts.
/// Every API/search process re-reads it into its local denylist on this
/// interval, so a revocation the shared Valkey lost (resync, restart) is
/// enforced again within one interval everywhere.
pub const REVOCATION_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Periodically merge PostgreSQL's unexpired revocations into `map`.
pub fn spawn_revocation_sync(pool: sqlx::PgPool, map: Arc<DashMap<Uuid, i64>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REVOCATION_SYNC_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failures: u64 = 0;
        loop {
            interval.tick().await;
            match merge_revoked_tokens(&pool, &map).await {
                Ok(_) if failures > 0 => {
                    tracing::info!(failures, "revoked-token sync from PostgreSQL recovered");
                    failures = 0;
                }
                Ok(_) => {}
                Err(error) => {
                    // First failure, then about once a minute while it lasts.
                    if failures % 12 == 0 {
                        tracing::warn!(%error, failures = failures + 1, "revoked-token sync from PostgreSQL failed; retrying");
                    }
                    failures += 1;
                }
            }
        }
    })
}

/// `connected_slaves` of the Valkey this connection reaches (None: unknown).
async fn connected_replicas(conn: &mut redis::aio::ConnectionManager) -> Option<i64> {
    let info: String = bounded(redis::cmd("INFO").arg("replication").query_async(conn))
        .await
        .ok()?;
    info.lines()
        .find_map(|line| line.trim().strip_prefix("connected_slaves:"))
        .and_then(|value| value.trim().parse().ok())
}

/// Bound on the replica acknowledgement round trip itself.
const REVOCATION_WAIT_BOUND: std::time::Duration = std::time::Duration::from_millis(1_000);

/// `NANO_VALKEY_WAIT_REPLICAS` (set by the HA Compose render): how many Valkey
/// replicas must hold a revocation before `revoke_token` returns. Unset or 0
/// (a single Valkey) skips the wait, which would otherwise always time out.
fn revocation_wait_replicas() -> Option<i64> {
    static VALUE: std::sync::OnceLock<Option<i64>> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("NANO_VALKEY_WAIT_REPLICAS")
            .ok()
            .and_then(|raw| raw.trim().parse::<i64>().ok())
            .filter(|count| *count > 0)
    })
}

/// Shared Redis handle for the JTI denylist. Cloned across `TokenService`
/// instances so revocations made on one pod are visible to all.
pub type RedisDenylist = Arc<Mutex<redis::aio::ConnectionManager>>;

/// Build a [`RedisDenylist`] from a `redis://` URL. Lets callers wire the
/// shared denylist without taking a direct dependency on the `redis` crate.
/// NAN-5214: the shared denylist slot of a [`TokenService`] (clones of the
/// handle see the same slot), so a background task can wire Valkey in later.
pub type DenylistSlot = Arc<OnceLock<RedisDenylist>>;

/// Keep connecting to `url` until it succeeds, then wire the denylist into
/// every slot. Used when the revocation check fails closed: Valkey being down
/// at boot must not leave the process fail-open for its whole life.
pub fn spawn_denylist_connect_retry(url: String, slots: Vec<DenylistSlot>) {
    tokio::spawn(async move {
        let mut delay = std::time::Duration::from_secs(1);
        loop {
            match redis_denylist_from_url(&url).await {
                Ok(denylist) => {
                    for slot in &slots {
                        let _ = slot.set(denylist.clone());
                    }
                    tracing::info!("JWT JTI denylist connected to Valkey after a failed boot attempt");
                    return;
                }
                Err(error) => {
                    tracing::warn!(%error, retry_in_secs = delay.as_secs(), "JWT JTI denylist still unreachable; requests fail closed (503)");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(std::time::Duration::from_secs(15));
                }
            }
        }
    });
}

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

    /// The shared revocation denylist could not be read. Fail closed: the
    /// caller answers 503 + Retry-After (never 401, so the UI does not treat
    /// a store outage as a logout, and never 200 for a possibly revoked
    /// token).
    #[error("Token revocation status is temporarily unavailable")]
    RevocationUnavailable,
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

/// Reject a `JWT_SECRET` that cannot protect anything: shorter than 32
/// characters, or a value nano itself shipped as a default or an example
/// (security review 2026-11-08). Anyone can sign tokens with a public value.
///
/// Shared by every service that verifies or mints JWTs (api, search, jobs), so
/// they accept and refuse exactly the same secrets. The error is the
/// operator-facing boot message and names the fix; it never contains the
/// secret.
pub fn validate_jwt_secret(secret: &str) -> Result<(), String> {
    use crate::known_public_secrets::{is_known_public, SecretKind};
    if is_known_public(SecretKind::Jwt, secret) {
        return Err(
            "SECURITY ERROR: JWT_SECRET is a publicly known default or example value, so anyone \
             can forge login tokens. Generate a new one (`openssl rand -hex 32`), put it in \
             JWT_SECRET for every nano service, and restart. Running install.sh again does this \
             automatically. Existing sessions sign in again; API keys are unaffected."
                .to_string(),
        );
    }
    if secret.len() < 32 {
        return Err(format!(
            "SECURITY ERROR: JWT_SECRET must be at least 32 characters (got {}). Generate one \
             with `openssl rand -hex 32`.",
            secret.len()
        ));
    }
    Ok(())
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
                if let Err(message) = validate_jwt_secret(&secret) {
                    panic!("{message}");
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
    redis: DenylistSlot,
    /// NAN-5214: refuse (503) instead of accepting a token whose revocation
    /// status cannot be read. Off unless the HA render sets
    /// `NANO_AUTH_REVOCATION_FAIL_CLOSED=true`.
    revocation_fail_closed: std::sync::atomic::AtomicBool,
    /// `NANO_VALKEY_WAIT_REPLICAS` (0 = single Valkey, no replica wait).
    wait_replicas: std::sync::atomic::AtomicI64,
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
            redis: Arc::new(OnceLock::new()),
            revocation_fail_closed: std::sync::atomic::AtomicBool::new(revocation_fail_closed_from_env()),
            wait_replicas: std::sync::atomic::AtomicI64::new(revocation_wait_replicas().unwrap_or(0)),
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
    /// The shared slot `set_redis` fills (for [`spawn_denylist_connect_retry`]).
    pub fn denylist_slot(&self) -> DenylistSlot {
        Arc::clone(&self.redis)
    }

    /// Whether an unreadable denylist refuses the token (HA) or allows it.
    pub fn set_revocation_fail_closed(&self, fail_closed: bool) {
        self.revocation_fail_closed
            .store(fail_closed, std::sync::atomic::Ordering::SeqCst);
    }

    /// Replicas a revocation must reach before it counts as durable (0 = none).
    pub fn set_revocation_wait_replicas(&self, replicas: i64) {
        self.wait_replicas
            .store(replicas.max(0), std::sync::atomic::Ordering::SeqCst);
    }

    pub fn revocation_fail_closed(&self) -> bool {
        self.revocation_fail_closed.load(std::sync::atomic::Ordering::SeqCst)
    }

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
    /// token lifetime so entries are auto-pruned. Best effort; callers that
    /// must not claim success on a lost revocation use
    /// [`TokenService::revoke_token_durable`].
    pub async fn revoke_token(&self, jti: Uuid, exp: i64) {
        if let Err(error) = self.revoke_token_durable(jti, exp).await {
            tracing::warn!(jti = %jti, %error, "revocation not confirmed on the shared denylist");
        }
    }

    /// NAN-5243: revoke and, with replicated Valkey (`NANO_VALKEY_WAIT_REPLICAS`),
    /// report whether a replica holds the revocation.
    ///
    /// A write the router sent to an isolated old master is acknowledged by
    /// no replica of the elected master, and is discarded when Sentinel
    /// resyncs that node. So each attempt is SETEX + bounded WAIT, retried
    /// for up to [`REVOCATION_DURABLE_BUDGET`] (long enough for the router to
    /// move to the new master) while the master has a replica attached. With
    /// no replica attached (one of two members down) there is nothing to wait
    /// for: it returns at once. In fail-closed (HA) mode an unconfirmed
    /// revocation is [`TokenError::RevocationUnavailable`]; the logout path
    /// only logs it, because the revocation is durable in PostgreSQL, which
    /// every API/search process re-reads ([`spawn_revocation_sync`]), and the
    /// local `DashMap` always records it.
    pub async fn revoke_token_durable(&self, jti: Uuid, exp: i64) -> Result<(), TokenError> {
        self.revoked_jtis.insert(jti, exp);
        self.prune_expired_revocations();

        let Some(redis) = self.redis.get() else {
            return if self.revocation_fail_closed() {
                Err(TokenError::RevocationUnavailable)
            } else {
                Ok(())
            };
        };
        let now = Utc::now().timestamp();
        let ttl_secs = (exp - now).max(1) as u64;
        let key = format!("{}{}", REDIS_REVOKED_JTI_PREFIX, jti);
        let replicas = Some(self.wait_replicas.load(std::sync::atomic::Ordering::SeqCst)).filter(|count| *count > 0);
        let deadline = tokio::time::Instant::now() + REVOCATION_DURABLE_BUDGET;
        let mut last_error: String;
        loop {
            // ConnectionManager is a cheap, multiplexed clone: never hold the
            // Mutex across retries or the WAIT (it would queue every request).
            let mut conn = redis.lock().await.clone();
            match bounded(conn.set_ex::<_, _, ()>(&key, 1u8, ttl_secs)).await {
                Err(e) => last_error = e.to_string(),
                Ok(()) => match replicas {
                    None => return Ok(()),
                    Some(replicas) => {
                        let acked: redis::RedisResult<i64> = tokio::time::timeout(
                            REVOCATION_WAIT_BOUND,
                            redis::cmd("WAIT")
                                .arg(replicas)
                                .arg(REVOCATION_WAIT_TIMEOUT_MS)
                                .query_async(&mut conn),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            Err(redis::RedisError::from(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "Valkey WAIT timed out",
                            )))
                        });
                        match acked {
                            Ok(count) if count >= replicas => return Ok(()),
                            Ok(count) => {
                                last_error = format!("{count} of {replicas} replicas acknowledged");
                                if connected_replicas(&mut conn).await == Some(0) {
                                    // Degraded set (a member is down): no
                                    // replica can acknowledge; don't stall.
                                    last_error.push_str("; no replica attached");
                                    break;
                                }
                            }
                            Err(e) => last_error = e.to_string(),
                        }
                    }
                },
            }
            if tokio::time::Instant::now() + REDIS_RETRY_DELAY >= deadline {
                break;
            }
            tokio::time::sleep(REDIS_RETRY_DELAY).await;
        }
        tracing::warn!(jti = %jti, error = %last_error, "revoked JTI not confirmed on a Valkey replica");
        if self.revocation_fail_closed() {
            Err(TokenError::RevocationUnavailable)
        } else {
            Ok(())
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
    ///
    /// NAN-5214: with [`TokenService::revocation_fail_closed`] (HA), a
    /// denylist that cannot be read after [`REDIS_ATTEMPTS`] bounded tries,
    /// or that has not connected yet, is [`TokenError::RevocationUnavailable`]
    /// (the middleware answers 503), never "not revoked". Otherwise the
    /// original single-node behaviour applies: warn and allow.
    async fn is_revoked_async(&self, jti: &Uuid) -> Result<bool, TokenError> {
        if self.is_revoked(jti) {
            return Ok(true);
        }
        let fail_closed = self.revocation_fail_closed();
        let Some(redis) = self.redis.get() else {
            return if fail_closed {
                tracing::warn!(jti = %jti, "JWT JTI denylist not connected yet; refusing the token (503)");
                Err(TokenError::RevocationUnavailable)
            } else {
                Ok(false)
            };
        };
        let key = format!("{}{}", REDIS_REVOKED_JTI_PREFIX, jti);
        // Clone the multiplexed manager; the Mutex is held only for the clone,
        // so concurrent checks never queue behind one request's retries.
        let mut conn = redis.lock().await.clone();
        let mut exists: redis::RedisResult<bool> = bounded(conn.exists(&key)).await;
        for _ in 1..REDIS_ATTEMPTS {
            if exists.is_ok() {
                break;
            }
            tokio::time::sleep(REDIS_RETRY_DELAY).await;
            exists = bounded(conn.exists(&key)).await;
        }
        match exists {
            Ok(revoked) => Ok(revoked),
            Err(e) if fail_closed => {
                tracing::warn!(jti = %jti, error = %e, "revoked-JTI lookup failed; refusing the token (503)");
                Err(TokenError::RevocationUnavailable)
            }
            Err(e) => {
                tracing::warn!(jti = %jti, error = %e, "failed to read revoked JTI from Redis");
                Ok(false)
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
        if self.is_revoked_async(&claims.jti).await? {
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
            redis: Arc::new(OnceLock::new()),
            revocation_fail_closed: std::sync::atomic::AtomicBool::new(revocation_fail_closed_from_env()),
            wait_replicas: std::sync::atomic::AtomicI64::new(revocation_wait_replicas().unwrap_or(0)),
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
    let count = merge_revoked_tokens(pool, map).await?;
    let now = Utc::now().timestamp();

    // Clean up expired entries in PG
    let _ = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at <= $1")
        .bind(now)
        .execute(pool)
        .await;

    Ok(count)
}

/// Persist a revoked JTI to PostgreSQL (call alongside in-memory revoke_token).
pub async fn persist_revoked_token(pool: &sqlx::PgPool, jti: Uuid, exp: i64) -> Result<(), sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(exp)
    .execute(pool)
    .await;

    if let Err(e) = &result {
        tracing::warn!(jti = %jti, error = %e, "Failed to persist token revocation to database");
    }
    result.map(|_| ())
}

/// Merge PostgreSQL's unexpired revocations into `map` (read-only).
async fn merge_revoked_tokens(pool: &sqlx::PgPool, map: &DashMap<Uuid, i64>) -> Result<usize, sqlx::Error> {
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
    Ok(count)
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
#[path = "token_secret_policy_tests.rs"]
mod secret_policy_tests;

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
        assert!(!service.is_revoked_async(&Uuid::now_v7()).await.unwrap());
        // And a positive local hit still returns true.
        let jti = Uuid::now_v7();
        service
            .revoke_token(jti, Utc::now().timestamp() + 60)
            .await;
        assert!(service.is_revoked_async(&jti).await.unwrap());
    }

    /// A RESP server that answers `+OK` to every command until killed, then
    /// refuses connections: Valkey reachable at connect, gone afterwards.
    async fn start_fake_valkey() -> (String, Vec<tokio::task::JoinHandle<()>>, Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>) {
        start_fake_valkey_acking(
            Arc::new(std::sync::atomic::AtomicI64::new(0)),
            Arc::new(std::sync::atomic::AtomicI64::new(1)),
        )
        .await
    }

    /// As [`start_fake_valkey`], answering `WAIT` with the current `acks`
    /// (how many replicas hold the write) and `INFO` with `attached`
    /// (`connected_slaves`) instead of `+OK`.
    async fn start_fake_valkey_acking(
        acks: Arc<std::sync::atomic::AtomicI64>,
        attached: Arc<std::sync::atomic::AtomicI64>,
    ) -> (String, Vec<tokio::task::JoinHandle<()>>, Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}", listener.local_addr().unwrap());
        let connections = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tracked = Arc::clone(&connections);
        let acceptor = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let acks = Arc::clone(&acks);
                let attached = Arc::clone(&attached);
                let handle = tokio::spawn(async move {
                    let mut buffer: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let Ok(read) = socket.read(&mut chunk).await else { return };
                        if read == 0 {
                            return;
                        }
                        buffer.extend_from_slice(&chunk[..read]);
                        // Count complete RESP arrays; answer each with +OK.
                        loop {
                            let Some(consumed) = complete_resp_command(&buffer) else { break };
                            let command = &buffer[..consumed];
                            let is = |name: &[u8]| {
                                command.windows(name.len() + 2).any(|w| {
                                    w[..2] == *b"\r\n" && w[2..].eq_ignore_ascii_case(name)
                                })
                            };
                            let (is_wait, is_info) = (is(b"WAIT"), is(b"INFO"));
                            buffer.drain(..consumed);
                            let reply = if is_wait {
                                format!(":{}\r\n", acks.load(std::sync::atomic::Ordering::SeqCst))
                            } else if is_info {
                                let body = format!(
                                    "# Replication\r\nrole:master\r\nconnected_slaves:{}\r\n",
                                    attached.load(std::sync::atomic::Ordering::SeqCst)
                                );
                                format!("${}\r\n{}\r\n", body.len(), body)
                            } else {
                                "+OK\r\n".to_string()
                            };
                            if socket.write_all(reply.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                });
                tracked.lock().unwrap().push(handle);
            }
        });
        (url, vec![acceptor], connections)
    }

    /// Length of the first complete RESP array command in `buffer`.
    fn complete_resp_command(buffer: &[u8]) -> Option<usize> {
        fn line(buffer: &[u8], at: usize) -> Option<(usize, usize)> {
            let end = buffer[at..].windows(2).position(|w| w == b"\r\n")? + at;
            let value = std::str::from_utf8(&buffer[at + 1..end]).ok()?.parse().ok()?;
            Some((value, end + 2))
        }
        if buffer.first() != Some(&b'*') {
            return None;
        }
        let (count, mut at) = line(buffer, 0)?;
        for _ in 0..count {
            if buffer.get(at) != Some(&b'$') {
                return None;
            }
            let (len, data_at) = line(buffer, at)?;
            at = data_at + len + 2;
            if at > buffer.len() {
                return None;
            }
        }
        Some(at)
    }

    /// NAN-5214: a revocation check that cannot reach Valkey must FAIL
    /// CLOSED. Before, `is_revoked_async` returned false on any Redis error,
    /// so a logged-out token kept working through a Valkey restart/failover.
    #[tokio::test]
    async fn valkey_unreachable_refuses_the_token_instead_of_accepting_it() {
        let (url, acceptor, connections) = start_fake_valkey().await;
        let service = create_test_service();
        service.set_revocation_fail_closed(true);
        service.set_redis(redis_denylist_from_url(&url).await.expect("fake Valkey connects"));
        let token = service
            .create_access_token(Uuid::now_v7(), vec!["Admin".to_string()])
            .unwrap();
        // Valkey goes away: listener closed and every connection dropped.
        for handle in acceptor {
            handle.abort();
        }
        for handle in connections.lock().unwrap().drain(..) {
            handle.abort();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        let result = service.validate_access_token_async(&token).await;
        assert!(
            matches!(result, Err(TokenError::RevocationUnavailable)),
            "a token must not be accepted while the denylist is unreadable: {result:?}"
        );
        // Bounded: the retries cover a reconnect, not an indefinite stall.
        assert!(started.elapsed() < std::time::Duration::from_secs(6), "took {:?}", started.elapsed());
    }

    /// Stop the fake Valkey: listener closed and every connection dropped.
    async fn kill_fake_valkey(
        acceptor: Vec<tokio::task::JoinHandle<()>>,
        connections: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    ) {
        for handle in acceptor {
            handle.abort();
        }
        for handle in connections.lock().unwrap().drain(..) {
            handle.abort();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    /// NAN-5214 (review M1): single-node / one-app installs keep warn-and-
    /// allow, so a local Valkey restart never 503s every JWT request.
    #[tokio::test]
    async fn without_the_ha_flag_an_unreachable_valkey_still_allows() {
        let (url, acceptor, connections) = start_fake_valkey().await;
        let service = create_test_service();
        service.set_revocation_fail_closed(false);
        service.set_redis(redis_denylist_from_url(&url).await.expect("fake Valkey connects"));
        let token = service.create_access_token(Uuid::now_v7(), vec!["Admin".to_string()]).unwrap();
        kill_fake_valkey(acceptor, connections).await;
        assert!(service.validate_access_token_async(&token).await.is_ok());
    }

    /// NAN-5214 (review M1): in HA, a denylist that never connected at boot
    /// is fail-closed too, not fail-open for the life of the process.
    #[tokio::test]
    async fn ha_mode_without_a_connected_denylist_refuses() {
        let service = create_test_service();
        service.set_revocation_fail_closed(true);
        let token = service.create_access_token(Uuid::now_v7(), vec!["Admin".to_string()]).unwrap();
        assert!(matches!(
            service.validate_access_token_async(&token).await,
            Err(TokenError::RevocationUnavailable)
        ));
    }

    async fn durable_fixture(
        fail_closed: bool,
        acks: i64,
    ) -> (TokenService, Arc<std::sync::atomic::AtomicI64>, Vec<tokio::task::JoinHandle<()>>, Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>) {
        durable_fixture_attached(fail_closed, acks, 1).await
    }

    async fn durable_fixture_attached(
        fail_closed: bool,
        acks: i64,
        attached: i64,
    ) -> (TokenService, Arc<std::sync::atomic::AtomicI64>, Vec<tokio::task::JoinHandle<()>>, Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>) {
        let acks = Arc::new(std::sync::atomic::AtomicI64::new(acks));
        let (url, acceptor, connections) = start_fake_valkey_acking(
            Arc::clone(&acks),
            Arc::new(std::sync::atomic::AtomicI64::new(attached)),
        )
        .await;
        let service = create_test_service();
        service.set_revocation_fail_closed(fail_closed);
        service.set_revocation_wait_replicas(1);
        service.set_redis(redis_denylist_from_url(&url).await.expect("fake Valkey connects"));
        (service, acks, acceptor, connections)
    }

    /// NAN-5243: a revocation no replica acknowledged (the write went to an
    /// isolated old master) is not durable: HA logout must not report success.
    #[tokio::test]
    async fn durable_revocation_without_a_replica_ack_fails_in_ha() {
        let (service, _acks, _acceptor, _connections) = durable_fixture(true, 0).await;
        let jti = Uuid::now_v7();
        let started = std::time::Instant::now();
        let result = service.revoke_token_durable(jti, Utc::now().timestamp() + 60).await;
        assert!(matches!(result, Err(TokenError::RevocationUnavailable)), "{result:?}");
        assert!(started.elapsed() >= std::time::Duration::from_secs(3), "gave up after {:?}", started.elapsed());
        assert!(started.elapsed() < std::time::Duration::from_secs(7), "took {:?}", started.elapsed());
        // This process still refuses the token at once.
        assert!(service.is_revoked(&jti));
    }

    /// NAN-5243: retrying covers the router moving to the newly promoted
    /// master: once a replica acknowledges, the revocation is durable.
    #[tokio::test]
    async fn durable_revocation_retries_until_a_replica_acknowledges() {
        let (service, acks, _acceptor, _connections) = durable_fixture(true, 0).await;
        let flip = Arc::clone(&acks);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
            flip.store(1, std::sync::atomic::Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        let result = service.revoke_token_durable(Uuid::now_v7(), Utc::now().timestamp() + 60).await;
        assert!(result.is_ok(), "{result:?}");
        assert!(started.elapsed() >= std::time::Duration::from_millis(1_200));
    }

    #[tokio::test]
    async fn durable_revocation_acknowledged_at_once_succeeds_without_retrying() {
        let (service, _acks, _acceptor, _connections) = durable_fixture(true, 1).await;
        let started = std::time::Instant::now();
        assert!(service.revoke_token_durable(Uuid::now_v7(), Utc::now().timestamp() + 60).await.is_ok());
        assert!(started.elapsed() < std::time::Duration::from_millis(1_000), "took {:?}", started.elapsed());
    }

    /// NAN-5243 review: a two-member set with one member down has no replica
    /// attached; WAIT can never succeed, so do not stall (logout then rests
    /// on PostgreSQL and only logs this).
    #[tokio::test]
    async fn durable_revocation_with_no_replica_attached_returns_at_once() {
        let (service, _acks, _acceptor, _connections) = durable_fixture_attached(true, 0, 0).await;
        let jti = Uuid::now_v7();
        let started = std::time::Instant::now();
        let result = service.revoke_token_durable(jti, Utc::now().timestamp() + 60).await;
        assert!(matches!(result, Err(TokenError::RevocationUnavailable)), "{result:?}");
        assert!(started.elapsed() < std::time::Duration::from_millis(1_000), "took {:?}", started.elapsed());
        assert!(service.is_revoked(&jti));
    }

    /// Single-node / one-app installs (no fail-closed flag) keep best effort.
    #[tokio::test]
    async fn durable_revocation_without_the_ha_flag_is_best_effort() {
        let (service, _acks, _acceptor, _connections) = durable_fixture(false, 0).await;
        assert!(service.revoke_token_durable(Uuid::now_v7(), Utc::now().timestamp() + 60).await.is_ok());
    }

    #[tokio::test]
    async fn durable_revocation_with_valkey_down_fails_in_ha() {
        let (service, _acks, acceptor, connections) = durable_fixture(true, 1).await;
        kill_fake_valkey(acceptor, connections).await;
        let result = service.revoke_token_durable(Uuid::now_v7(), Utc::now().timestamp() + 60).await;
        assert!(matches!(result, Err(TokenError::RevocationUnavailable)), "{result:?}");
    }

    /// NAN-5214 (review M2): concurrent checks with Valkey down must not
    /// queue behind each other's retries on the denylist Mutex.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_checks_with_valkey_down_all_return_promptly() {
        let (url, acceptor, connections) = start_fake_valkey().await;
        let service = Arc::new(create_test_service());
        service.set_revocation_fail_closed(true);
        service.set_redis(redis_denylist_from_url(&url).await.expect("fake Valkey connects"));
        let token = service.create_access_token(Uuid::now_v7(), vec!["Admin".to_string()]).unwrap();
        kill_fake_valkey(acceptor, connections).await;
        let started = std::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..50 {
            let service = Arc::clone(&service);
            let token = token.clone();
            tasks.push(tokio::spawn(async move { service.validate_access_token_async(&token).await }));
        }
        for task in tasks {
            assert!(matches!(task.await.unwrap(), Err(TokenError::RevocationUnavailable)));
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(6),
            "50 parallel checks took {:?} (serialised on the Mutex?)",
            started.elapsed()
        );
    }
}
