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
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::password::{validate_password, verify_password, PasswordError};
use super::repository::{
    audit_actions, AuditRepository, AuditRepositoryError, GroupRepository, GroupRepositoryError,
    SessionRepository, SessionRepositoryError, UserRepository, UserRepositoryError,
};
use super::token::{TokenError, TokenService};
use super::types::{
    config_defaults, AuthResponse, LandingPage, LoginResult, QueryMode, TimeRangePreset, TokenPair,
    User, UserInfo,
};

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

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Session not found or expired")]
    SessionNotFound,

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

impl From<AuditRepositoryError> for AuthError {
    fn from(err: AuditRepositoryError) -> Self {
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

/// Authentication service
///
/// Requirements: 1.2, 1.3, 1.5, 1.6, 2.3, 2.4, 2.6
pub struct AuthService {
    user_repo: UserRepository,
    session_repo: SessionRepository,
    group_repo: GroupRepository,
    audit_repo: AuditRepository,
    token_service: TokenService,
    config: AuthConfig,
}

impl AuthService {
    /// Create a new auth service
    pub fn new(
        user_repo: UserRepository,
        session_repo: SessionRepository,
        group_repo: GroupRepository,
        audit_repo: AuditRepository,
        token_service: TokenService,
        config: AuthConfig,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            group_repo,
            audit_repo,
            token_service,
            config,
        }
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
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<LoginResult, AuthError> {
        // Try to find the user by email
        let user = match self.user_repo.get_user_by_email(email).await {
            Ok(user) => user,
            Err(UserRepositoryError::NotFoundByEmail(_)) => {
                // SECURITY: Perform dummy password verification to prevent timing attacks
                // This ensures the response time is similar whether user exists or not
                let pwd = password.to_string();
                let _ =
                    tokio::task::spawn_blocking(move || verify_password(&pwd, DUMMY_BCRYPT_HASH))
                        .await;

                // Log failed attempt (no user_id since user doesn't exist)
                let _ = self
                    .audit_repo
                    .log_event(
                        None,
                        None,
                        audit_actions::LOGIN_FAILED,
                        Some("user"),
                        None,
                        // SECURITY: Don't log "user_not_found" - just log generic failure
                        Some(serde_json::json!({ "email": email })),
                        ip_address,
                        user_agent,
                        false,
                    )
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

            let _ = self
                .audit_repo
                .log_event(
                    Some(user.id),
                    None,
                    audit_actions::LOGIN_FAILED,
                    Some("user"),
                    Some(user.id),
                    // SECURITY: Don't reveal specific reason in logs accessible to attackers
                    None,
                    ip_address,
                    user_agent,
                    false,
                )
                .await;

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

            let _ = self
                .audit_repo
                .log_event(
                    Some(user.id),
                    None,
                    audit_actions::LOGIN_FAILED,
                    Some("user"),
                    Some(user.id),
                    // SECURITY: Don't reveal specific reason in logs accessible to attackers
                    None,
                    ip_address,
                    user_agent,
                    false,
                )
                .await;

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

                let _ = self
                    .audit_repo
                    .log_event(
                        Some(user.id),
                        None,
                        audit_actions::USER_LOCK,
                        Some("user"),
                        Some(user.id),
                        Some(serde_json::json!({
                            "reason": "failed_login_backoff",
                            "failed_attempts": failed_attempts,
                            "backoff_secs": backoff_secs,
                        })),
                        ip_address,
                        user_agent,
                        true,
                    )
                    .await;
            }

            let _ = self
                .audit_repo
                .log_event(
                    Some(user.id),
                    None,
                    audit_actions::LOGIN_FAILED,
                    Some("user"),
                    Some(user.id),
                    Some(serde_json::json!({
                        "failed_attempts": failed_attempts
                    })),
                    ip_address,
                    user_agent,
                    false,
                )
                .await;

            // Return generic error (Requirement 1.3)
            return Err(AuthError::InvalidCredentials);
        }

        // Successful login - reset failed attempts and update last login
        self.user_repo.reset_failed_attempts(user.id).await?;

        // === MFA Check ===
        // If user has MFA enabled, issue a challenge token instead of full auth
        if user.mfa_enabled {
            let challenge_token = self.token_service.create_mfa_challenge_token(user.id)?;
            let _ = self
                .audit_repo
                .log_event(
                    Some(user.id),
                    None,
                    audit_actions::MFA_CHALLENGE_ISSUED,
                    Some("user"),
                    Some(user.id),
                    None,
                    ip_address,
                    user_agent,
                    true,
                )
                .await;
            return Ok(LoginResult::MfaRequired { challenge_token });
        }

        // If admin requires MFA globally and this non-OIDC user hasn't set up yet
        if user.oidc_provider_id.is_none() {
            let mfa_required = self
                .user_repo
                .is_mfa_required_globally()
                .await
                .unwrap_or(false);
            if mfa_required && !user.mfa_enabled {
                if !user.mfa_setup_pending {
                    let _ = self.user_repo.set_mfa_setup_pending(user.id, true).await;
                }
                let challenge_token = self.token_service.create_mfa_challenge_token(user.id)?;
                return Ok(LoginResult::MfaSetupRequired { challenge_token });
            }
        }

        // Get user's roles and permissions
        let roles = self.group_repo.get_user_roles(user.id).await?;
        let permissions = self.group_repo.get_user_permissions(user.id).await?;

        // Create tokens (Requirement 1.2)
        // Permissions are NOT embedded in the JWT — they are resolved server-side
        // by the auth middleware via PermissionResolver.
        let token_pair = self
            .token_service
            .create_token_pair(user.id, roles.clone())?;

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

        self.session_repo
            .create_session(
                user.id,
                &refresh_token_hash,
                ip_address,
                user_agent,
                expires_at,
            )
            .await?;

        // Log successful login
        let _ = self
            .audit_repo
            .log_event(
                Some(user.id),
                None,
                audit_actions::LOGIN_SUCCESS,
                Some("user"),
                Some(user.id),
                None,
                ip_address,
                user_agent,
                true,
            )
            .await;

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
    pub async fn complete_mfa_login(
        &self,
        challenge_token: &str,
        code: &str,
        encryption: &crate::crypto::EncryptionService,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuthResponse, AuthError> {
        // Validate the challenge token
        let claims = self
            .token_service
            .validate_mfa_challenge_token(challenge_token)
            .map_err(|_| AuthError::InvalidToken)?;
        let user_id = claims.sub;

        // Get the user
        let user = self.user_repo.get_user_by_id(user_id).await?;

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

        let secret = super::mfa::decrypt_secret(totp_encrypted, totp_nonce, encryption)
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        // Try TOTP verification first
        let totp_valid = super::mfa::verify_totp(&secret, &user.email, code).unwrap_or(false);

        if !totp_valid {
            // Try backup code
            if let (Some(backup_enc), Some(backup_nonce)) =
                (&user.backup_codes_encrypted, &user.backup_codes_nonce)
            {
                let mut hashed_codes =
                    super::mfa::decrypt_backup_codes(backup_enc, backup_nonce, encryption)
                        .map_err(|e| AuthError::InternalError(e.to_string()))?;

                if let Some(idx) = super::mfa::verify_backup_code(code, &hashed_codes) {
                    // Remove used backup code and re-encrypt
                    hashed_codes.remove(idx);
                    let new_encrypted = super::mfa::encrypt_backup_codes(&hashed_codes, encryption)
                        .map_err(|e| AuthError::InternalError(e.to_string()))?;
                    let ciphertext = base64::engine::general_purpose::STANDARD
                        .decode(&new_encrypted.ciphertext)
                        .map_err(|e| AuthError::InternalError(e.to_string()))?;
                    let _ = self
                        .user_repo
                        .update_backup_codes(user_id, &ciphertext, &new_encrypted.nonce)
                        .await;

                    let _ = self
                        .audit_repo
                        .log_event(
                            Some(user_id),
                            None,
                            audit_actions::MFA_BACKUP_CODE_USED,
                            Some("user"),
                            Some(user_id),
                            Some(serde_json::json!({ "codes_remaining": hashed_codes.len() })),
                            ip_address,
                            user_agent,
                            true,
                        )
                        .await;
                } else {
                    // Neither TOTP nor backup code matched
                    let _ = self
                        .audit_repo
                        .log_event(
                            Some(user_id),
                            None,
                            audit_actions::MFA_CHALLENGE_FAILED,
                            Some("user"),
                            Some(user_id),
                            None,
                            ip_address,
                            user_agent,
                            false,
                        )
                        .await;
                    return Err(AuthError::InvalidCredentials);
                }
            } else {
                // No backup codes, TOTP failed
                let _ = self
                    .audit_repo
                    .log_event(
                        Some(user_id),
                        None,
                        audit_actions::MFA_CHALLENGE_FAILED,
                        Some("user"),
                        Some(user_id),
                        None,
                        ip_address,
                        user_agent,
                        false,
                    )
                    .await;
                return Err(AuthError::InvalidCredentials);
            }
        }

        // Revoke the challenge token (single-use)
        self.token_service.revoke_token(claims.jti, claims.exp).await;

        // MFA verified — now complete login (same flow as non-MFA)
        let _ = self
            .audit_repo
            .log_event(
                Some(user_id),
                None,
                audit_actions::MFA_CHALLENGE_SUCCESS,
                Some("user"),
                Some(user_id),
                None,
                ip_address,
                user_agent,
                true,
            )
            .await;

        let roles = self.group_repo.get_user_roles(user_id).await?;
        let permissions = self.group_repo.get_user_permissions(user_id).await?;
        let token_pair = self
            .token_service
            .create_token_pair(user_id, roles.clone())?;

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

        self.session_repo
            .create_session(
                user_id,
                &refresh_token_hash,
                ip_address,
                user_agent,
                expires_at,
            )
            .await?;

        let _ = self
            .audit_repo
            .log_event(
                Some(user_id),
                None,
                audit_actions::LOGIN_SUCCESS,
                Some("user"),
                Some(user_id),
                Some(serde_json::json!({ "mfa_verified": true })),
                ip_address,
                user_agent,
                true,
            )
            .await;

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

        Ok(AuthResponse {
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
        })
    }

    /// Logout and invalidate session
    ///
    /// Requirements: 2.6 - Invalidate the refresh token on logout
    pub async fn logout(
        &self,
        refresh_token: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AuthError> {
        let refresh_token_hash = hash_token(refresh_token);

        // Find the session to get user_id for audit logging
        let session = self
            .session_repo
            .get_session_by_token_hash(&refresh_token_hash)
            .await;

        let user_id = session.as_ref().ok().map(|s| s.user_id);

        // Delete the session
        let result = self
            .session_repo
            .delete_session_by_token_hash(&refresh_token_hash)
            .await;

        // Log logout event
        let _ = self
            .audit_repo
            .log_event(
                user_id,
                None,
                audit_actions::LOGOUT,
                Some("session"),
                None,
                None,
                ip_address,
                user_agent,
                result.is_ok(),
            )
            .await;

        // Even if session wasn't found, we consider logout successful
        // (token might have already expired)
        Ok(())
    }

    /// Refresh access token using refresh token
    ///
    /// Requirements: 2.3, 2.4
    /// - 2.3: Allow token refresh using a valid refresh token
    /// - 2.4: Issue new access token and rotate the refresh token
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<TokenPair, AuthError> {
        // Validate the refresh token JWT
        let claims = self.token_service.validate_refresh_token(refresh_token)?;

        // Find the session by token hash
        let refresh_token_hash = hash_token(refresh_token);
        let session = self
            .session_repo
            .get_session_by_token_hash(&refresh_token_hash)
            .await?;

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

        // Get fresh roles (permissions are resolved server-side by auth middleware)
        let mut roles = self.group_repo.get_user_roles(user.id).await?;

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
        let new_token_pair = self.token_service.create_token_pair(user.id, roles)?;

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
            )
            .await?;

        // Log token refresh
        let _ = self
            .audit_repo
            .log_event(
                Some(user.id),
                None,
                audit_actions::TOKEN_REFRESH,
                Some("session"),
                Some(session.id),
                None,
                ip_address,
                user_agent,
                true,
            )
            .await;

        Ok(new_token_pair)
    }

    /// Request a password reset
    ///
    /// Requirements: 1.7 - Generate a time-limited reset token valid for 1 hour
    pub async fn request_password_reset(
        &self,
        email: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<String, AuthError> {
        // Try to find the user
        let user = match self.user_repo.get_user_by_email(email).await {
            Ok(user) => user,
            Err(UserRepositoryError::NotFoundByEmail(_)) => {
                // SECURITY: Don't reveal whether user exists
                // Log the attempt but don't include user_found status
                let _ = self
                    .audit_repo
                    .log_event(
                        None,
                        None,
                        audit_actions::PASSWORD_RESET_REQUEST,
                        Some("user"),
                        None,
                        Some(serde_json::json!({ "email": email })),
                        ip_address,
                        user_agent,
                        true, // Mark as success to not reveal user existence
                    )
                    .await;

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

        // Log the request
        let _ = self
            .audit_repo
            .log_event(
                Some(user.id),
                None,
                audit_actions::PASSWORD_RESET_REQUEST,
                Some("user"),
                Some(user.id),
                None,
                ip_address,
                user_agent,
                true,
            )
            .await;

        Ok(reset_token)
    }

    /// Reset password using a reset token
    ///
    /// Requirements: 1.7 - Reset password with valid token
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AuthError> {
        // Validate password complexity
        validate_password(new_password)?;

        // Find user by reset token (this also validates expiration)
        let user = self.user_repo.get_user_by_reset_token(token).await?;

        // Update the password
        self.user_repo
            .update_password(user.id, new_password)
            .await?;

        // Invalidate all existing sessions for security
        self.session_repo.delete_user_sessions(user.id).await?;

        // Log the password reset
        let _ = self
            .audit_repo
            .log_event(
                Some(user.id),
                None,
                audit_actions::PASSWORD_RESET_COMPLETE,
                Some("user"),
                Some(user.id),
                None,
                ip_address,
                user_agent,
                true,
            )
            .await;

        Ok(())
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
        ip_address: Option<&str>,
        user_agent: Option<&str>,
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

        // Validate new password complexity
        validate_password(new_password)?;

        // Update the password
        self.user_repo
            .update_password(user_id, new_password)
            .await?;

        // Invalidate all existing sessions for security
        self.session_repo.delete_user_sessions(user_id).await?;

        // Log the password change
        let _ = self
            .audit_repo
            .log_event(
                Some(user_id),
                None,
                audit_actions::PASSWORD_CHANGE,
                Some("user"),
                Some(user_id),
                None,
                ip_address,
                user_agent,
                true,
            )
            .await;

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
