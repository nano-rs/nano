// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication Service
//!
//! Requirements: 1.2, 1.3, 1.5, 1.6, 2.3, 2.4, 2.6
//!
//! This module provides the core authentication service handling:
//! - Login with credential validation and lockout
//! - Logout with session invalidation
//! - Token refresh with rotation
//! - Password reset request and completion

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::password::{validate_password, verify_password, PasswordError};
use super::repository::{
    BackupCodeRotation, GroupRepository, GroupRepositoryError, SessionRepository,
    SessionRepositoryError, UserRepository, UserRepositoryError,
};
use super::token::{TokenError, TokenService};
use super::types::{
    config_defaults, AuthResponse, LandingPage, LoginResult, QueryMode, TimeRangePreset, TokenPair,
    User, UserInfo,
};
use super::{ResolvedTenantMembership, TenantMembershipResolver, TenantResolutionError, TrustedTenantContext};
use crate::settings::local_auth::LocalAuthSettings;

// Hosted tenant-bound AuthService entry points (NAN-3861).
#[cfg(feature = "enterprise")]
mod enterprise_shared_auth;

/// SECURITY: Dummy bcrypt hash used for timing attack mitigation
/// This is a valid bcrypt hash that will always fail verification
/// but takes the same time as a real verification
const DUMMY_BCRYPT_HASH: &str = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/pWrZ5Wiq";

/// Authentication service errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account is locked. Please try again later.")]
    AccountLocked,

    #[error("Account is disabled")]
    AccountDisabled,

    /// Local password sign-in is turned off for this tenant (NAN-2181).
    ///
    /// Distinct from `InvalidCredentials` on purpose. This is a statement about
    /// tenant configuration, which `GET /api/auth/methods` already publishes
    /// unauthenticated, and it reveals nothing about which accounts exist —
    /// the check runs before any user lookup, so every request gets the same
    /// answer. Collapsing it into a generic 401 would strand users watching a
    /// correct password fail with no way to learn why.
    #[error("Password sign-in is disabled. Use single sign-on.")]
    LocalPasswordDisabled,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("An active tenant selection is required")]
    TenantRequired,

    #[error("Tenant access denied")]
    TenantAccessDenied,

    #[error("Tenant membership is temporarily unavailable")]
    TenantUnavailable,

    #[error("Password does not meet requirements: {0}")]
    PasswordRequirementsNotMet(String),

    #[error("Invalid password reset token")]
    InvalidResetToken,

    #[error("Password reset token has expired")]
    ResetTokenExpired,

    #[error("User not found")]
    UserNotFound,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<UserRepositoryError> for AuthError {
    fn from(err: UserRepositoryError) -> Self {
        match err {
            UserRepositoryError::NotFound(_) | UserRepositoryError::NotFoundByEmail(_) => {
                AuthError::UserNotFound
            }
            UserRepositoryError::InvalidResetToken => AuthError::InvalidResetToken,
            UserRepositoryError::ResetTokenExpired => AuthError::ResetTokenExpired,
            _ => AuthError::DatabaseError(err.to_string()),
        }
    }
}

impl From<SessionRepositoryError> for AuthError {
    fn from(err: SessionRepositoryError) -> Self {
        match err {
            SessionRepositoryError::NotFound(_) | SessionRepositoryError::NotFoundByToken => {
                AuthError::SessionNotFound
            }
            SessionRepositoryError::SessionExpired => AuthError::SessionNotFound,
            _ => AuthError::DatabaseError(err.to_string()),
        }
    }
}

impl From<GroupRepositoryError> for AuthError {
    fn from(err: GroupRepositoryError) -> Self {
        AuthError::DatabaseError(err.to_string())
    }
}

impl From<TokenError> for AuthError {
    fn from(err: TokenError) -> Self {
        match err {
            TokenError::Expired => AuthError::InvalidToken,
            TokenError::Invalid(_) => AuthError::InvalidToken,
            TokenError::ValidationFailed(_) => AuthError::InvalidToken,
            TokenError::CreationFailed(msg) => AuthError::TokenError(msg),
            TokenError::DecodingFailed(_) => AuthError::InvalidToken,
        }
    }
}

impl From<PasswordError> for AuthError {
    fn from(err: PasswordError) -> Self {
        match err {
            PasswordError::ComplexityNotMet(msg) => AuthError::PasswordRequirementsNotMet(msg),
            // A password past MAX_PASSWORD_BYTES is a client error (400), not a
            // 500 — it must not fall into the InternalError arm below.
            PasswordError::TooLong(_) => AuthError::PasswordRequirementsNotMet(err.to_string()),
            _ => AuthError::InternalError(err.to_string()),
        }
    }
}

/// Configuration for the auth service
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Number of failed login attempts before lockout
    pub lockout_threshold: i32,
    /// Duration of account lockout in seconds
    pub lockout_duration: i64,
    /// Password reset token validity in seconds (default: 1 hour)
    pub reset_token_ttl: i64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            lockout_threshold: config_defaults::LOCKOUT_THRESHOLD,
            lockout_duration: config_defaults::LOCKOUT_DURATION,
            reset_token_ttl: 3600, // 1 hour
        }
    }
}

/// Outcome of a successful MFA challenge completion.
///
/// Carries the authenticated `response` plus whether a single-use backup code
/// (rather than a live TOTP code) satisfied the challenge, so the caller can
/// audit `mfa_backup_code_used` distinctly from a normal `mfa_challenge_success`.
pub struct MfaCompletion {
    /// The completed authentication response (tokens + user).
    pub response: AuthResponse,
    /// True when a backup code (not a TOTP code) satisfied the challenge.
    pub used_backup_code: bool,
    /// Hosted shared only: the tenant the challenge was revalidated against,
    /// so the caller can write the login audit in that tenant (NAN-3790).
    pub tenant: Option<TrustedTenantContext>,
}

/// Authentication service
///
/// Requirements: 1.2, 1.3, 1.5, 1.6, 2.3, 2.4, 2.6
pub struct AuthService {
    user_repo: UserRepository,
    session_repo: SessionRepository,
    group_repo: GroupRepository,
    token_service: TokenService,
    config: AuthConfig,
    /// Legacy deployment-wide toggle for local password sign-in (NAN-2181).
    /// Exact hosted shared deliberately ignores this singleton: the
    /// per-tenant policy (`shared_tenant_auth_methods`, NAN-2361
    /// wave 8) is consulted by slug instead.
    local_auth_settings: LocalAuthSettings,
    /// Present only for the exact hosted-shared profile.
    tenant_resolver: Option<TenantMembershipResolver>,
}

impl AuthService {
    /// Create a new auth service
    pub fn new(
        user_repo: UserRepository,
        session_repo: SessionRepository,
        group_repo: GroupRepository,
        token_service: TokenService,
        config: AuthConfig,
        local_auth_settings: LocalAuthSettings,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            group_repo,
            token_service,
            config,
            local_auth_settings,
            tenant_resolver: None,
        }
    }

    fn map_tenant_error(error: TenantResolutionError) -> AuthError {
        match error {
            TenantResolutionError::AccessDenied => AuthError::TenantAccessDenied,
            TenantResolutionError::Unavailable => AuthError::TenantUnavailable,
        }
    }

    /// Enforce policy only after authoritative membership resolution. Legacy
    /// deployments never enter this path and keep their existing admission.
    async fn require_tenant_ip_policy(
        &self,
        tenant: &ResolvedTenantMembership,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        use crate::ip_allowlist::tenant::{
            require_tenant_ip_allowed, TenantIpPolicyError, TenantIpPolicyScope,
        };
        require_tenant_ip_allowed(
            self.user_repo.pool(),
            &tenant.context,
            ip_address.and_then(|ip| ip.parse().ok()),
            TenantIpPolicyScope::Api,
        )
        .await
        .map_err(|error| match error {
            TenantIpPolicyError::Denied => AuthError::TenantAccessDenied,
            TenantIpPolicyError::Unavailable => AuthError::TenantUnavailable,
        })
    }

    async fn resolve_login_tenant(
        &self,
        user_id: uuid::Uuid,
        tenant_slug: Option<&str>,
    ) -> Result<Option<ResolvedTenantMembership>, AuthError> {
        let Some(resolver) = &self.tenant_resolver else {
            return Ok(None);
        };
        let slug = tenant_slug.ok_or(AuthError::TenantRequired)?;
        resolver
            .resolve_slug(user_id, slug)
            .await
            .map(Some)
            .map_err(Self::map_tenant_error)
    }

    /// Authenticate user with email and password
    ///
    /// Requirements: 1.2, 1.3, 1.5, 1.6
    /// - 1.2: Issue JWT access token and refresh token on valid credentials
    /// - 1.3: Return authentication error without revealing which field was incorrect
    /// - 1.5: Reject authentication for locked accounts
    /// - 1.6: Lock accounts after 5 consecutive failed login attempts for 15 minutes
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        tenant_slug: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AuthError> {
        // NAN-2181: SSO-only tenants reject local password sign-in outright.
        //
        // Deliberately the first check, before the user lookup. A gate placed
        // after the lookup would answer faster for unknown emails than for
        // known ones, turning an SSO-only tenant into an account oracle. Here
        // every request costs one settings read and returns the same error.
        if self.tenant_resolver.is_none() {
            if !self
                .local_auth_settings
                .is_local_password_enabled()
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            {
                return Err(AuthError::LocalPasswordDisabled);
            }
        } else if let Some(slug) = tenant_slug
            .and_then(|slug| crate::auth::CanonicalTenantOidcSlug::parse(slug).ok())
        {
            // NAN-2361 wave 8: the shared product keeps the toggle per tenant
            // (`shared_tenant_auth_methods`, 9001020). The slug is
            // only a selector: it is read through the control login before
            // any user lookup, answers the same for every request against
            // that tenant, and an unknown slug reads as "password allowed" so
            // the flow fails on membership exactly as it does today. A slug
            // that does not parse is left to `resolve_login_tenant`.
            if !crate::auth::tenant_login_local_password_enabled(self.user_repo.pool(), &slug)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            {
                return Err(AuthError::LocalPasswordDisabled);
            }
        }

        // Try to find the user by email. Hosted shared identities are
        // tenant-scoped (FRO-754): resolve the selected tenant's own identity
        // first, the legacy global row only when that tenant has none.
        #[cfg(feature = "enterprise")]
        let lookup = if self.tenant_resolver.is_some() {
            self.user_repo
                .get_enterprise_shared_user_for_login(tenant_slug, email)
                .await
        } else {
            self.user_repo.get_user_by_email(email).await
        };
        #[cfg(not(feature = "enterprise"))]
        let lookup = self.user_repo.get_user_by_email(email).await;
        let user = match lookup {
            Ok(user) => user,
            Err(UserRepositoryError::NotFoundByEmail(_)) => {
                // SECURITY: Perform dummy password verification to prevent timing attacks
                // This ensures the response time is similar whether user exists or not
                let pwd = password.to_string();
                let _ =
                    tokio::task::spawn_blocking(move || verify_password(&pwd, DUMMY_BCRYPT_HASH))
                        .await;

                // Return generic error (Requirement 1.3)
                return Err(AuthError::InvalidCredentials);
            }
            Err(e) => return Err(e.into()),
        };

        // Check if account is disabled
        if user.status == "disabled" {
            // SECURITY: Still perform password verification to prevent timing attacks
            if let Some(hash) = user.password_hash.as_ref() {
                let pwd = password.to_string();
                let h = hash.clone();
                let _ = tokio::task::spawn_blocking(move || verify_password(&pwd, &h)).await;
            }

            // SECURITY: Return generic error to prevent account status enumeration
            return Err(AuthError::InvalidCredentials);
        }

        // Check if account is locked (Requirement 1.5)
        if self.is_account_locked(&user).await? {
            // SECURITY: Still perform password verification to prevent timing attacks
            if let Some(hash) = user.password_hash.as_ref() {
                let pwd = password.to_string();
                let h = hash.clone();
                let _ = tokio::task::spawn_blocking(move || verify_password(&pwd, &h)).await;
            }

            // SECURITY: Return generic error to prevent account status enumeration
            return Err(AuthError::InvalidCredentials);
        }

        // Verify password
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;

        let pwd = password.to_string();
        let h = password_hash.clone();
        let password_valid = tokio::task::spawn_blocking(move || verify_password(&pwd, &h))
            .await
            .map_err(|e| AuthError::InternalError(e.to_string()))?
            .map_err(|_| AuthError::InvalidCredentials)?;

        if !password_valid {
            // Increment failed attempts and potentially lock account (Requirement 1.6)
            let failed_attempts = self.user_repo.increment_failed_attempts(user.id).await?;

            // M1: Use exponential backoff instead of hard lockout to prevent
            // DoS via locking out admin accounts during active incidents.
            // After 5+ failed attempts, delay doubles each time (max 5 min).
            if failed_attempts >= self.config.lockout_threshold {
                let exponent = (failed_attempts as u32)
                    .saturating_sub(self.config.lockout_threshold as u32)
                    .min(8);
                let backoff_secs = std::cmp::min(2u64.pow(exponent), 300);
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;

                // Signal the lock ONLY on the crossing attempt — the one whose
                // increment first reaches the threshold — so the login handler
                // audits user_locked exactly once per lock episode (the counter
                // resets to 0 on the next successful login). Subsequent attempts
                // against the already-throttled account still back off but fall
                // through to the generic InvalidCredentials below, so they are not
                // re-audited as fresh locks. `increment_failed_attempts` is an
                // atomic DB increment returning the new value, so concurrent
                // failures each see a distinct count and exactly one hits `==`.
                // `from_auth_error` normalizes AccountLocked to the same generic
                // 401 as InvalidCredentials (no account enumeration).
                if failed_attempts == self.config.lockout_threshold {
                    return Err(AuthError::AccountLocked);
                }
            }

            // Return generic error (Requirement 1.3)
            return Err(AuthError::InvalidCredentials);
        }

        // In shared mode, bcrypt success is only provisional. Wait behind any
        // in-flight password reset/change, lock the current users row, require
        // the byte-for-byte hash we actually verified, then obtain the durable
        // authentication fence. This closes the old-hash MVCC race without
        // holding a database connection during bcrypt.
        let shared_authentication_fence = if self.tenant_resolver.is_some() {
            Some(
                self.user_repo
                    .lock_current_password_authentication(user.id, password_hash)
                    .await?
                    .ok_or(AuthError::InvalidCredentials)?,
            )
        } else {
            None
        };

        // Successful login - reset failed attempts and update last login
        self.user_repo.reset_failed_attempts(user.id).await?;

        // A tenant slug is only a selector. Resolve it after password
        // verification (avoids a pre-auth membership oracle) and carry only
        // the server-resolved UUID into signed credentials.
        let tenant = self.resolve_login_tenant(user.id, tenant_slug).await?;
        if let Some(tenant) = &tenant {
            self.require_tenant_ip_policy(tenant, ip_address).await?;
        }

        // === MFA Check ===
        // If user has MFA enabled, issue a challenge token instead of full auth
        if user.mfa_enabled {
            let challenge_token = match &tenant {
                #[cfg(feature = "enterprise")]
                Some(tenant) => self
                    .token_service
                    .create_enterprise_shared_mfa_challenge_token(
                        user.id,
                        tenant.context.tenant_id,
                        shared_authentication_fence.expect("shared authentication fence"),
                    )?,
                #[cfg(not(feature = "enterprise"))]
                Some(_) => return Err(AuthError::TenantUnavailable),
                None => self.token_service.create_mfa_challenge_token(user.id)?,
            };
            return Ok(LoginResult::MfaRequired { challenge_token });
        }

        // Exact hosted-shared always requires local MFA, regardless of
        // the legacy deployment-wide setting or an optional tenant OIDC
        // identity. Dedicated/open-core keep their existing configurable
        // behavior.
        let mfa_required = if tenant.is_some() {
            true
        } else if user.oidc_provider_id.is_none() {
            self.user_repo
                .is_mfa_required_globally()
                .await
                .unwrap_or(false)
        } else {
            false
        };
        if mfa_required {
            if !user.mfa_setup_pending {
                let _ = self.user_repo.set_mfa_setup_pending(user.id, true).await;
            }
            let challenge_token = match &tenant {
                #[cfg(feature = "enterprise")]
                Some(tenant) => self
                    .token_service
                    .create_enterprise_shared_mfa_challenge_token(
                        user.id,
                        tenant.context.tenant_id,
                        shared_authentication_fence.expect("shared authentication fence"),
                    )?,
                #[cfg(not(feature = "enterprise"))]
                Some(_) => return Err(AuthError::TenantUnavailable),
                None => self.token_service.create_mfa_challenge_token(user.id)?,
            };
            return Ok(LoginResult::MfaSetupRequired { challenge_token });
        }

        let (roles, permissions) = match &tenant {
            Some(tenant) => (tenant.roles.clone(), tenant.permissions.clone()),
            None => (
                self.group_repo.get_user_roles(user.id).await?,
                self.group_repo.get_user_permissions(user.id).await?,
            ),
        };

        // Create tokens (Requirement 1.2)
        // Permissions are NOT embedded in the JWT — they are resolved server-side
        // by the auth middleware via PermissionResolver.
        let shared_authenticated_at = tenant
            .as_ref()
            .map(|_| shared_authentication_fence.expect("shared authentication fence"));
        let token_pair = match &tenant {
            #[cfg(feature = "enterprise")]
            Some(tenant) => self
                .token_service
                .create_enterprise_shared_token_pair_with_authentication(
                    user.id,
                    roles.clone(),
                    tenant.context.tenant_id,
                    shared_authenticated_at.expect("shared authentication time"),
                    None,
                )?,
            #[cfg(not(feature = "enterprise"))]
            Some(_) => return Err(AuthError::TenantUnavailable),
            None => self
                .token_service
                .create_token_pair(user.id, roles.clone())?,
        };

        // Create session with hashed refresh token
        let refresh_token_hash = hash_token(&token_pair.refresh_token);
        let expires_at = Utc::now() + Duration::seconds(self.token_service.refresh_token_ttl());

        // M6: Enforce per-user session limit (max 10) — evict oldest sessions
        const MAX_SESSIONS_PER_USER: i64 = 10;
        let current_count = self
            .session_repo
            .count_user_sessions(user.id)
            .await
            .unwrap_or(0);
        if current_count >= MAX_SESSIONS_PER_USER {
            // Delete oldest sessions to make room
            let excess = (current_count - MAX_SESSIONS_PER_USER + 1) as i64;
            if let Err(e) = self
                .session_repo
                .delete_oldest_user_sessions(user.id, excess)
                .await
            {
                tracing::warn!(user_id = %user.id, error = %e, "Failed to evict oldest sessions");
            }
        }

        match &tenant {
            Some(tenant) => {
                self.session_repo
                    .create_tenant_session(
                        user.id,
                        tenant.context.tenant_id,
                        shared_authenticated_at.expect("shared authentication time"),
                        None,
                        &refresh_token_hash,
                        ip_address,
                        user_agent,
                        expires_at,
                    )
                    .await?;
            }
            None => {
                self.session_repo
                    .create_session(
                        user.id,
                        &refresh_token_hash,
                        ip_address,
                        user_agent,
                        expires_at,
                    )
                    .await?;
            }
        }

        // Parse query mode preference (default to Standard if not set)
        let preferred_query_mode = user
            .preferred_query_mode
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(QueryMode::Standard);

        // Parse default time range preference (default to Last24Hours if not set)
        let default_time_range = user
            .default_time_range
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(TimeRangePreset::Last24Hours);

        // Parse landing page preference (default to Home if not set)
        let landing_page = user
            .landing_page
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LandingPage::Home);

        Ok(LoginResult::Success(AuthResponse {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                roles,
                permissions,
                preferred_query_mode,
                default_time_range,
                landing_page,
            },
            tokens: token_pair,
        }))
    }

    /// Complete MFA login by verifying a TOTP code or backup code
    ///
    /// Called after the user receives a challenge token from login().
    /// Verifies the TOTP code, creates tokens and session, and returns AuthResponse.
    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub async fn complete_mfa_login(
        &self,
        challenge_token: &str,
        code: &str,
        tenant_slug: Option<&str>,
        encryption: &crate::crypto::EncryptionService,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<MfaCompletion, AuthError> {
        // Shared challenges carry the already-resolved tenant UUID. Revalidate
        // membership before accepting the MFA code; a suspended membership
        // cannot finish a challenge minted moments earlier.
        let (claims, tenant, challenge_authenticated_at): (
            super::types::TokenClaims,
            Option<ResolvedTenantMembership>,
            Option<DateTime<Utc>>,
        ) = match &self.tenant_resolver {
            #[cfg(feature = "enterprise")]
            Some(_) => {
                let shared = self
                    .token_service
                    .validate_enterprise_shared_mfa_challenge_token_async(challenge_token)
                    .await
                    .map_err(|_| AuthError::InvalidToken)?;
                let authenticated_at = DateTime::<Utc>::from_timestamp_micros(
                    shared
                        .credential_time_micros
                        .ok_or(AuthError::InvalidToken)?,
                )
                .ok_or(AuthError::InvalidToken)?;
                if crate::auth::token::is_persisted_access_token_revoked(
                    self.user_repo.pool(),
                    shared.claims.jti,
                    shared.claims.sub,
                    authenticated_at.timestamp_micros(),
                )
                .await
                .map_err(|error| AuthError::DatabaseError(error.to_string()))?
                {
                    return Err(AuthError::InvalidToken);
                }
                let tenant = self
                    .resolve_enterprise_shared_continuation(
                        shared.claims.sub,
                        shared.tenant_id,
                        authenticated_at.timestamp_micros(),
                        tenant_slug,
                        ip_address,
                    )
                    .await?;
                (shared.claims, Some(tenant), Some(authenticated_at))
            }
            #[cfg(not(feature = "enterprise"))]
            Some(_) => return Err(AuthError::TenantUnavailable),
            None => (
                self.token_service
                    .validate_mfa_challenge_token_async(challenge_token)
                    .await
                    .map_err(|_| AuthError::InvalidToken)?,
                None,
                None,
            ),
        };
        let user_id = claims.sub;

        // Get the user
        let user = self.user_repo.get_user_by_id(user_id).await?;

        // A password-verified challenge is not a durable grant. Account
        // disable/lock changes made during the MFA window must take effect
        // before the second factor can mint a session.
        if user.status == "disabled" {
            return Err(AuthError::AccountDisabled);
        }
        if user.status == "locked" && self.is_account_locked(&user).await? {
            return Err(AuthError::AccountLocked);
        }

        if !user.mfa_enabled {
            return Err(AuthError::InvalidToken);
        }

        // Decrypt the TOTP secret
        let totp_encrypted =
            user.totp_secret_encrypted
                .as_ref()
                .ok_or(AuthError::InternalError(
                    "MFA enabled but no TOTP secret".to_string(),
                ))?;
        let totp_nonce = user
            .totp_secret_nonce
            .as_ref()
            .ok_or(AuthError::InternalError(
                "MFA enabled but no TOTP nonce".to_string(),
            ))?;

        let secret = super::mfa::decrypt_secret(totp_encrypted, totp_nonce, &(encryption).with_context(crate::crypto::CredentialScope::Account(user.id), "account.totp", user.id))
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        // Try TOTP verification first
        let totp_valid = super::mfa::verify_totp(&secret, &user.email, code).unwrap_or(false);

        let mut used_backup_code = false;
        let mut backup_rotation = None;
        if !totp_valid {
            // Try backup code
            if let (Some(backup_enc), Some(backup_nonce)) =
                (&user.backup_codes_encrypted, &user.backup_codes_nonce)
            {
                let mut hashed_codes =
                    super::mfa::decrypt_backup_codes(backup_enc, backup_nonce, &(encryption).with_context(crate::crypto::CredentialScope::Account(user.id), "account.backup-codes", user.id))
                        .map_err(|e| AuthError::InternalError(e.to_string()))?;

                if let Some(idx) = super::mfa::verify_backup_code(code, &hashed_codes) {
                    used_backup_code = true;
                    // Remove used backup code and re-encrypt
                    hashed_codes.remove(idx);
                    let new_encrypted = super::mfa::encrypt_backup_codes(&hashed_codes, &(encryption).with_context(crate::crypto::CredentialScope::Account(user.id), "account.backup-codes", user.id))
                        .map_err(|e| AuthError::InternalError(e.to_string()))?;
                    let ciphertext = base64::engine::general_purpose::STANDARD
                        .decode(&new_encrypted.ciphertext)
                        .map_err(|e| AuthError::InternalError(e.to_string()))?;
                    backup_rotation = Some((
                        backup_enc.clone(),
                        backup_nonce.clone(),
                        ciphertext,
                        new_encrypted.nonce,
                    ));
                } else {
                    // Neither TOTP nor backup code matched
                    return Err(AuthError::InvalidCredentials);
                }
            } else {
                // No backup codes, TOTP failed
                return Err(AuthError::InvalidCredentials);
            }
        }

        let rotation = backup_rotation.as_ref().map(
            |(expected_encrypted, expected_nonce, replacement_encrypted, replacement_nonce)| {
                BackupCodeRotation {
                    expected_encrypted,
                    expected_nonce,
                    replacement_encrypted,
                    replacement_nonce,
                }
            },
        );
        #[cfg(feature = "enterprise")]
        let consumed = if let Some(authenticated_at) = challenge_authenticated_at {
            let tenant_id = tenant
                .as_ref()
                .ok_or(AuthError::InvalidToken)?
                .context
                .tenant_id;
            self.user_repo
                .consume_enterprise_shared_mfa_challenge(
                    tenant_id,
                    user_id,
                    claims.jti,
                    claims.exp,
                    authenticated_at,
                    rotation,
                )
                .await?
        } else {
            self.user_repo
                .consume_mfa_challenge(user_id, claims.jti, claims.exp, rotation)
                .await?
        };
        #[cfg(not(feature = "enterprise"))]
        let consumed = self
            .user_repo
            .consume_mfa_challenge(user_id, claims.jti, claims.exp, rotation)
            .await?;
        if !consumed {
            return Err(AuthError::InvalidToken);
        }

        // Publish the durable challenge claim to the process/Redis denylist.
        self.token_service
            .revoke_token(claims.jti, claims.exp)
            .await;

        // MFA verified — now complete login (same flow as non-MFA)
        let (roles, permissions) = match &tenant {
            Some(tenant) => (tenant.roles.clone(), tenant.permissions.clone()),
            None => (
                self.group_repo.get_user_roles(user_id).await?,
                self.group_repo.get_user_permissions(user_id).await?,
            ),
        };
        // Preserve the original password-authentication fence. Advancing this
        // to MFA completion time would let a challenge minted from an old
        // password appear newer than a reset/logout that happened meanwhile.
        let authenticated_at = challenge_authenticated_at.unwrap_or_else(Utc::now);
        let mfa_authenticated_at = Utc::now();
        let token_pair = match &tenant {
            #[cfg(feature = "enterprise")]
            Some(tenant) => self
                .token_service
                .create_enterprise_shared_token_pair_with_authentication(
                    user_id,
                    roles.clone(),
                    tenant.context.tenant_id,
                    authenticated_at,
                    Some(mfa_authenticated_at),
                )?,
            #[cfg(not(feature = "enterprise"))]
            Some(_) => return Err(AuthError::TenantUnavailable),
            None => self
                .token_service
                .create_token_pair(user_id, roles.clone())?,
        };

        let refresh_token_hash = hash_token(&token_pair.refresh_token);
        let expires_at = Utc::now() + Duration::seconds(self.token_service.refresh_token_ttl());

        const MAX_SESSIONS_PER_USER: i64 = 10;
        let current_count = self
            .session_repo
            .count_user_sessions(user_id)
            .await
            .unwrap_or(0);
        if current_count >= MAX_SESSIONS_PER_USER {
            let excess = (current_count - MAX_SESSIONS_PER_USER + 1) as i64;
            let _ = self
                .session_repo
                .delete_oldest_user_sessions(user_id, excess)
                .await;
        }

        match &tenant {
            Some(tenant) => {
                self.session_repo
                    .create_tenant_session(
                        user_id,
                        tenant.context.tenant_id,
                        authenticated_at,
                        Some(mfa_authenticated_at),
                        &refresh_token_hash,
                        ip_address,
                        user_agent,
                        expires_at,
                    )
                    .await?;
            }
            None => {
                self.session_repo
                    .create_session(
                        user_id,
                        &refresh_token_hash,
                        ip_address,
                        user_agent,
                        expires_at,
                    )
                    .await?;
            }
        }

        let preferred_query_mode = user
            .preferred_query_mode
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(QueryMode::Standard);
        let default_time_range = user
            .default_time_range
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(TimeRangePreset::Last24Hours);
        let landing_page = user
            .landing_page
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LandingPage::Home);

        Ok(MfaCompletion {
            used_backup_code,
            tenant: tenant.map(|tenant| tenant.context),
            response: AuthResponse {
                user: UserInfo {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    roles,
                    permissions,
                    preferred_query_mode,
                    default_time_range,
                    landing_page,
                },
                tokens: token_pair,
            },
        })
    }

    /// Logout and invalidate session
    ///
    /// Requirements: 2.6 - Invalidate the refresh token on logout
    pub async fn logout(
        &self,
        refresh_token: &str,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<(), AuthError> {
        let refresh_token_hash = hash_token(refresh_token);

        // Delete the session. Even if the session wasn't found, we consider
        // logout successful (the token might have already expired).
        let _ = self
            .session_repo
            .delete_session_by_token_hash(&refresh_token_hash)
            .await;

        Ok(())
    }

    /// Refresh access token using refresh token
    ///
    /// Requirements: 2.3, 2.4
    /// - 2.3: Allow token refresh using a valid refresh token
    /// - 2.4: Issue new access token and rotate the refresh token
    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        tenant_slug: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<TokenPair, AuthError> {
        let (claims, tenant_id) = match &self.tenant_resolver {
            #[cfg(feature = "enterprise")]
            Some(_) => {
                let shared = self
                    .token_service
                    .validate_enterprise_shared_refresh_token(refresh_token)?;
                (shared.claims, Some(shared.tenant_id))
            }
            #[cfg(not(feature = "enterprise"))]
            Some(_) => return Err(AuthError::TenantUnavailable),
            None => (
                self.token_service.validate_refresh_token(refresh_token)?,
                None,
            ),
        };

        // Find the session by token hash
        let refresh_token_hash = hash_token(refresh_token);
        let session = self
            .session_repo
            .get_session_by_token_hash(&refresh_token_hash)
            .await?;

        // The signed tenant binding and durable session binding must be exact.
        if session.user_id != claims.sub || session.tenant_id != tenant_id {
            return Err(AuthError::InvalidToken);
        }

        // A shared session carries the original authentication fence across
        // every refresh. This also rejects the narrow race where MFA
        // completion inserts a session after logout deleted the prior session
        // rows but after logout advanced the user's watermark.
        #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
        let shared_credential_time_micros = if tenant_id.is_some() {
            let authenticated_at = session.authenticated_at.ok_or(AuthError::InvalidToken)?;
            if crate::auth::token::is_persisted_access_token_revoked(
                self.user_repo.pool(),
                claims.jti,
                claims.sub,
                authenticated_at.timestamp_micros(),
            )
            .await
            .map_err(|error| AuthError::DatabaseError(error.to_string()))?
            {
                return Err(AuthError::InvalidToken);
            }
            Some(authenticated_at.timestamp_micros())
        } else {
            None
        };

        // Get the user
        let user = self.user_repo.get_user_by_id(claims.sub).await?;

        // Check if account is still active
        if user.status == "disabled" {
            return Err(AuthError::AccountDisabled);
        }

        if user.status == "locked" {
            if self.is_account_locked(&user).await? {
                return Err(AuthError::AccountLocked);
            }
        }

        let tenant: Option<ResolvedTenantMembership> = match (&self.tenant_resolver, tenant_id) {
            #[cfg(feature = "enterprise")]
            (Some(_), Some(tenant_id)) => Some(
                self.resolve_enterprise_shared_continuation(
                    user.id,
                    tenant_id,
                    shared_credential_time_micros.ok_or(AuthError::InvalidToken)?,
                    tenant_slug,
                    ip_address,
                )
                .await?,
            ),
            #[cfg(not(feature = "enterprise"))]
            (Some(_), Some(_)) => return Err(AuthError::TenantUnavailable),
            (Some(_), None) => return Err(AuthError::InvalidToken),
            (None, _) => None,
        };

        // Get fresh roles (permissions are resolved server-side by auth middleware)
        let mut roles = match &tenant {
            Some(tenant) => tenant.roles.clone(),
            None => self.group_repo.get_user_roles(user.id).await?,
        };

        // Preserve demo_analyst role for active demo sessions.
        // Demo users have no database role assignments — the role is injected
        // at session creation. Without this, token refresh strips all permissions.
        if !roles.contains(&"demo_analyst".to_string())
            && crate::demo::is_demo_session_active(self.user_repo.pool(), user.id).await
        {
            roles.push("demo_analyst".to_string());
        }

        // Create new token pair (Requirement 2.4 - rotation)
        // Permissions are NOT embedded in the JWT — resolved server-side.
        let new_token_pair = match &tenant {
            #[cfg(feature = "enterprise")]
            Some(tenant) => {
                let authenticated_at = session.authenticated_at.ok_or(AuthError::InvalidToken)?;
                self.token_service
                    .create_enterprise_shared_token_pair_with_authentication(
                        user.id,
                        roles,
                        tenant.context.tenant_id,
                        authenticated_at,
                        session.mfa_authenticated_at,
                    )?
            }
            #[cfg(not(feature = "enterprise"))]
            Some(_) => return Err(AuthError::TenantUnavailable),
            None => self.token_service.create_token_pair(user.id, roles)?,
        };

        // Rotate the refresh token in the session
        let new_refresh_token_hash = hash_token(&new_token_pair.refresh_token);
        let new_expires_at = Utc::now() + Duration::seconds(self.token_service.refresh_token_ttl());

        // Compare-and-swap on the old hash so only one concurrent refresh of a
        // single-use token wins; losers/replays get NotFoundByToken -> 401.
        self.session_repo
            .rotate_refresh_token(
                session.id,
                &refresh_token_hash,
                &new_refresh_token_hash,
                new_expires_at,
                ip_address,
                user_agent,
            )
            .await?;

        Ok(new_token_pair)
    }

    /// Request a password reset
    ///
    /// Requirements: 1.7 - Generate a time-limited reset token valid for 1 hour
    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub async fn request_password_reset(
        &self,
        email: &str,
        tenant_slug: Option<&str>,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<String, AuthError> {
        // Try to find the user, with the same tenant-scoped resolution as
        // login (FRO-754): a reset only ever touches one tenant's identity.
        #[cfg(feature = "enterprise")]
        let lookup = if self.tenant_resolver.is_some() {
            self.user_repo
                .get_enterprise_shared_user_for_login(tenant_slug, email)
                .await
        } else {
            self.user_repo.get_user_by_email(email).await
        };
        #[cfg(not(feature = "enterprise"))]
        let lookup = self.user_repo.get_user_by_email(email).await;
        let user = match lookup {
            Ok(user) => user,
            Err(UserRepositoryError::NotFoundByEmail(_)) => {
                // SECURITY: Don't reveal whether user exists
                // Return a dummy token (in production, you'd send an email regardless)
                return Ok(generate_reset_token());
            }
            Err(e) => return Err(e.into()),
        };

        // Generate reset token
        let reset_token = generate_reset_token();
        let expires_at = Utc::now() + Duration::seconds(self.config.reset_token_ttl);

        // Store the token
        self.user_repo
            .set_password_reset_token(user.id, &reset_token, expires_at)
            .await?;

        Ok(reset_token)
    }

    /// Reset password using a reset token
    ///
    /// Requirements: 1.7 - Reset password with valid token
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<uuid::Uuid, AuthError> {
        // Validate complexity AND the MAX_PASSWORD_BYTES upper bound before any
        // bcrypt work is scheduled, so an oversized body cannot dictate hashing
        // cost (same cap the activation paths enforce).
        validate_password(new_password)?;

        // Consume the reset token, update the password, advance the durable
        // credential watermark and delete refresh sessions atomically. The
        // account whose password changed is returned so the caller can audit
        // it in that account's tenant(s) (NAN-3790).
        let user_id = self
            .user_repo
            .reset_password_and_revoke_sessions(token, new_password)
            .await?;

        Ok(user_id)
    }

    /// Change password for an authenticated user
    ///
    /// Verifies the current password, validates the new password complexity,
    /// updates the password, and invalidates all other sessions.
    pub async fn change_password(
        &self,
        user_id: uuid::Uuid,
        current_password: &str,
        new_password: &str,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<(), AuthError> {
        // Get the user
        let user = self.user_repo.get_user_by_id(user_id).await?;

        // Verify current password
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;
        let pwd = current_password.to_string();
        let h = password_hash.clone();
        let password_valid = tokio::task::spawn_blocking(move || verify_password(&pwd, &h))
            .await
            .map_err(|e| AuthError::InternalError(e.to_string()))?
            .map_err(|_| AuthError::InvalidCredentials)?;

        if !password_valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Validate new-password complexity AND the MAX_PASSWORD_BYTES upper
        // bound before scheduling the bcrypt hash.
        validate_password(new_password)?;

        // Compare-and-swap the exact hash we verified. A concurrent reset or
        // password change cannot be overwritten by this slower bcrypt path.
        if !self
            .user_repo
            .change_password_and_revoke_sessions_if_current(user_id, password_hash, new_password)
            .await?
        {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(())
    }

    /// Check if an account is currently locked
    async fn is_account_locked(&self, user: &User) -> Result<bool, AuthError> {
        if user.status != "locked" {
            return Ok(false);
        }

        // Check if lock has expired
        if let Some(locked_until) = user.locked_until {
            if locked_until > Utc::now() {
                return Ok(true);
            }
            // Lock expired, auto-unlock
            self.user_repo.unlock_user(user.id).await?;
        }

        Ok(false)
    }

    /// Get the token service (for middleware use)
    pub fn token_service(&self) -> &TokenService {
        &self.token_service
    }

    /// Validate an access token
    pub fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<super::types::TokenClaims, AuthError> {
        self.token_service
            .validate_access_token(token)
            .map_err(|e| e.into())
    }

    /// Create a session for a user (used by OIDC callback)
    ///
    /// This method creates tokens and a session for a user who has already been
    /// authenticated through an external provider (OIDC).
    pub async fn create_session_for_user(
        &self,
        user: &User,
        roles: &[String],
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<TokenPair, AuthError> {
        // The existing OIDC callback has no tenant selector in its signed state.
        // Refuse tenantless issuance in hosted-shared until that flow gains
        // the same authoritative membership resolution as password login.
        if self.tenant_resolver.is_some() {
            return Err(AuthError::TenantRequired);
        }
        // Create tokens — permissions are NOT embedded in the JWT
        let token_pair = self
            .token_service
            .create_token_pair(user.id, roles.to_vec())?;

        // Create session with hashed refresh token
        let refresh_token_hash = hash_token(&token_pair.refresh_token);
        let expires_at = Utc::now() + Duration::seconds(self.token_service.refresh_token_ttl());

        self.session_repo
            .create_session(
                user.id,
                &refresh_token_hash,
                ip_address,
                user_agent,
                expires_at,
            )
            .await?;

        Ok(token_pair)
    }
}

/// Hash a token using SHA-256 for storage.
/// Used by auth service, session service, and demo service.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Generate a secure random reset token
fn generate_reset_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let token = "test-token-123";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Hash should be 64 characters (SHA-256 hex)
        assert_eq!(hash1.len(), 64);

        // Different input should produce different hash
        let hash3 = hash_token("different-token");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_generate_reset_token() {
        let token1 = generate_reset_token();
        let token2 = generate_reset_token();

        // Tokens should be unique
        assert_ne!(token1, token2);

        // Token should be 64 characters (32 bytes hex encoded)
        assert_eq!(token1.len(), 64);
    }

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();

        assert_eq!(config.lockout_threshold, 5);
        assert_eq!(config.lockout_duration, 900); // 15 minutes
        assert_eq!(config.reset_token_ttl, 3600); // 1 hour
    }
}
