// SPDX-License-Identifier: AGPL-3.0-or-later

//! User repository for CRUD operations
//!
//! Requirements: 1.1, 1.6, 1.7

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::password::hash_password;
use crate::auth::types::{
    builtin_groups, CreateUserRequest, GroupSummary, LandingPage, QueryMode,
    SearchHubStyle, TimeRangePreset, UpdateUserRequest, User, UserPreferences,
};

#[derive(Error, Debug)]
pub enum UserRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("User not found: {0}")]
    NotFound(Uuid),
    #[error("User not found by email: {0}")]
    NotFoundByEmail(String),
    #[error("Email already exists: {0}")]
    EmailExists(String),
    #[error("Password hashing error: {0}")]
    PasswordHashError(String),
    #[error("Invalid password reset token")]
    InvalidResetToken,
    #[error("Password reset token expired")]
    ResetTokenExpired,
}

/// Repository for user operations
#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the database pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a new local user
    /// Requirements: 1.1
    ///
    /// Uses database unique constraint to atomically prevent duplicate emails (race-condition safe)
    pub async fn create_user(
        &self,
        request: &CreateUserRequest,
    ) -> Result<User, UserRepositoryError> {
        // Hash the password first (use spawn_blocking as bcrypt is CPU-intensive)
        let pwd = request.password.clone();
        let password_hash = tokio::task::spawn_blocking(move || hash_password(&pwd))
            .await
            .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?
            .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?;

        // Create the user - rely on unique constraint for email uniqueness (race-condition safe)
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, name, password_hash, status)
            VALUES ($1, $2, $3, 'active')
            RETURNING *
            "#,
        )
        .bind(&request.email)
        .bind(&request.name)
        .bind(&password_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            // Check for unique constraint violation
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("users_email_key") {
                    return UserRepositoryError::EmailExists(request.email.clone());
                }
            }
            UserRepositoryError::DatabaseError(e)
        })?;

        // Add user to specified groups (if any)
        for group_id in &request.group_ids {
            // Skip the Everyone group as it's auto-added by trigger
            if *group_id != builtin_groups::EVERYONE_ID {
                sqlx::query(
                    "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
                )
                .bind(user.id)
                .bind(group_id)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(user)
    }

    /// Get a user by ID
    pub async fn get_user_by_id(&self, id: Uuid) -> Result<User, UserRepositoryError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(UserRepositoryError::NotFound(id))
    }

    /// Get a user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<User, UserRepositoryError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| UserRepositoryError::NotFoundByEmail(email.to_string()))
    }

    /// List all users
    pub async fn list_users(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<User>, UserRepositoryError> {
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT * FROM users
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    /// Get groups for a user
    pub async fn get_user_groups(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<GroupSummary>, UserRepositoryError> {
        let groups = sqlx::query_as::<_, GroupSummary>(
            r#"
            SELECT g.id, g.name
            FROM groups g
            INNER JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = $1
            ORDER BY g.name
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(groups)
    }

    /// Update a user
    ///
    /// Uses database unique constraint to atomically prevent duplicate emails (race-condition safe)
    pub async fn update_user(
        &self,
        id: Uuid,
        request: &UpdateUserRequest,
    ) -> Result<User, UserRepositoryError> {
        // Check if user exists
        let existing = self.get_user_by_id(id).await?;

        // Build update query dynamically
        let email = request.email.as_ref().unwrap_or(&existing.email);
        let name = request.name.as_ref().unwrap_or(&existing.name);
        let status = request.status.as_ref().unwrap_or(&existing.status);

        // Handle password update (use spawn_blocking as bcrypt is CPU-intensive)
        let password_hash = if let Some(ref new_password) = request.password {
            let pwd = new_password.clone();
            Some(
                tokio::task::spawn_blocking(move || hash_password(&pwd))
                    .await
                    .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?
                    .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?,
            )
        } else {
            existing.password_hash.clone()
        };

        // Rely on unique constraint for email uniqueness (race-condition safe)
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users SET
                email = $2,
                name = $3,
                status = $4,
                password_hash = $5,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(email)
        .bind(name)
        .bind(status)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            // Check for unique constraint violation
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("users_email_key") {
                    return UserRepositoryError::EmailExists(email.clone());
                }
            }
            UserRepositoryError::DatabaseError(e)
        })?;

        Ok(user)
    }

    /// Delete a user
    pub async fn delete_user(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        // F-32: delete the user's API keys first. The api_keys.created_by FK is
        // ON DELETE SET NULL, which would orphan the keys (created_by => NULL)
        // and let them keep authenticating with the deleted user's permissions
        // (the owner-status check in validate_key can't fire on a NULL owner).
        // Removing them makes deletion a real revocation.
        sqlx::query("DELETE FROM api_keys WHERE created_by = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Increment failed login attempts
    /// Requirements: 1.6
    pub async fn increment_failed_attempts(&self, id: Uuid) -> Result<i32, UserRepositoryError> {
        let user = sqlx::query_as::<_, User>(
            r#"
            UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(UserRepositoryError::NotFound(id))?;

        Ok(user.failed_login_attempts)
    }

    /// Reset failed login attempts (on successful login)
    pub async fn reset_failed_attempts(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                failed_login_attempts = 0,
                locked_until = NULL,
                last_login_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Unlock a user account
    pub async fn unlock_user(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                status = 'active',
                locked_until = NULL,
                failed_login_attempts = 0,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Check if a user account is locked
    pub async fn is_locked(&self, id: Uuid) -> Result<bool, UserRepositoryError> {
        let user = self.get_user_by_id(id).await?;

        if user.status == "locked" {
            // Check if lock has expired
            if let Some(locked_until) = user.locked_until {
                if locked_until > Utc::now() {
                    return Ok(true);
                }
                // Lock expired, auto-unlock
                self.unlock_user(id).await?;
            }
        }

        Ok(false)
    }

    /// Set password reset token
    /// Requirements: 1.7
    pub async fn set_password_reset_token(
        &self,
        id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                password_reset_token = $2,
                password_reset_expires = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(token)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Get user by password reset token
    pub async fn get_user_by_reset_token(&self, token: &str) -> Result<User, UserRepositoryError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE password_reset_token = $1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(UserRepositoryError::InvalidResetToken)?;

        // Check if token has expired
        if let Some(expires) = user.password_reset_expires {
            if expires < Utc::now() {
                return Err(UserRepositoryError::ResetTokenExpired);
            }
        } else {
            return Err(UserRepositoryError::InvalidResetToken);
        }

        Ok(user)
    }

    /// Update user password
    pub async fn update_password(
        &self,
        id: Uuid,
        new_password: &str,
    ) -> Result<(), UserRepositoryError> {
        // Use spawn_blocking as bcrypt is CPU-intensive
        let pwd = new_password.to_string();
        let password_hash = tokio::task::spawn_blocking(move || hash_password(&pwd))
            .await
            .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?
            .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?;

        let result = sqlx::query(
            r#"
            UPDATE users SET
                password_hash = $2,
                password_reset_token = NULL,
                password_reset_expires = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Set user groups (replaces existing group memberships)
    pub async fn set_user_groups(
        &self,
        user_id: Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), UserRepositoryError> {
        // Verify user exists
        self.get_user_by_id(user_id).await?;

        // Remove existing group memberships (except Everyone)
        sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id != $2")
            .bind(user_id)
            .bind(builtin_groups::EVERYONE_ID)
            .execute(&self.pool)
            .await?;

        // Add new group memberships
        for group_id in group_ids {
            sqlx::query(
                "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(user_id)
            .bind(group_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Count total users
    pub async fn count_users(&self) -> Result<i64, UserRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE status != 'system'")
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    /// Check if any human users exist (for first-run setup)
    /// Excludes system service accounts (status = 'system')
    pub async fn has_users(&self) -> Result<bool, UserRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE status != 'system'")
                .fetch_one(&self.pool)
                .await?;
        Ok(count > 0)
    }

    /// Disable a user account.
    ///
    /// F-32: also stamps `tokens_valid_from = NOW()` in the SAME update so every
    /// already-issued (still-unexpired) access token is invalidated atomically
    /// with the status flip — the auth middleware rejects any token whose `iat`
    /// predates this watermark. Flipping `status` alone left outstanding JWTs
    /// working until natural expiry (default 900s).
    pub async fn disable_user(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            "UPDATE users SET status = 'disabled', tokens_valid_from = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// F-32: stamp the forced-revocation watermark (`tokens_valid_from = NOW()`)
    /// for a user without changing their status. Called on password change so a
    /// still-`active` user's previously-issued access tokens stop working
    /// immediately (the refresh path + session delete already handle refresh
    /// tokens; this closes the access-token hole).
    pub async fn stamp_tokens_valid_from(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            "UPDATE users SET tokens_valid_from = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Enable a user account
    pub async fn enable_user(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        let result =
            sqlx::query("UPDATE users SET status = 'active', updated_at = NOW() WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Get user preferences
    pub async fn get_preferences(&self, id: Uuid) -> Result<UserPreferences, UserRepositoryError> {
        let user = self.get_user_by_id(id).await?;

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

        let search_hub_style = user
            .search_hub_style
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(SearchHubStyle::Popover);

        let landing_page = user
            .landing_page
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(LandingPage::Home);

        Ok(UserPreferences {
            preferred_query_mode,
            default_time_range,
            search_hub_style,
            landing_page,
        })
    }

    /// Update user preferences
    pub async fn update_preferences(
        &self,
        id: Uuid,
        query_mode: Option<QueryMode>,
        time_range: Option<TimeRangePreset>,
        hub_style: Option<SearchHubStyle>,
        landing_page: Option<LandingPage>,
    ) -> Result<UserPreferences, UserRepositoryError> {
        if let Some(mode) = query_mode {
            let result = sqlx::query(
                "UPDATE users SET preferred_query_mode = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .bind(mode.to_string())
            .execute(&self.pool)
            .await?;

            if result.rows_affected() == 0 {
                return Err(UserRepositoryError::NotFound(id));
            }
        }

        if let Some(range) = time_range {
            let result = sqlx::query(
                "UPDATE users SET default_time_range = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .bind(range.to_string())
            .execute(&self.pool)
            .await?;

            if result.rows_affected() == 0 {
                return Err(UserRepositoryError::NotFound(id));
            }
        }

        if let Some(style) = hub_style {
            let result = sqlx::query(
                "UPDATE users SET search_hub_style = $2, updated_at = NOW() WHERE id = $1",
            )
            .bind(id)
            .bind(style.to_string())
            .execute(&self.pool)
            .await?;

            if result.rows_affected() == 0 {
                return Err(UserRepositoryError::NotFound(id));
            }
        }

        if let Some(page) = landing_page {
            let result =
                sqlx::query("UPDATE users SET landing_page = $2, updated_at = NOW() WHERE id = $1")
                    .bind(id)
                    .bind(page.to_string())
                    .execute(&self.pool)
                    .await?;

            if result.rows_affected() == 0 {
                return Err(UserRepositoryError::NotFound(id));
            }
        }

        self.get_preferences(id).await
    }

    // === MFA Methods ===

    /// Enable MFA for a user (stores encrypted TOTP secret and backup codes)
    pub async fn enable_mfa(
        &self,
        user_id: Uuid,
        totp_encrypted: &[u8],
        totp_nonce: &str,
        backup_encrypted: &[u8],
        backup_nonce: &str,
    ) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                mfa_enabled = TRUE,
                totp_secret_encrypted = $2,
                totp_secret_nonce = $3,
                backup_codes_encrypted = $4,
                backup_codes_nonce = $5,
                mfa_setup_pending = FALSE,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(totp_encrypted)
        .bind(totp_nonce)
        .bind(backup_encrypted)
        .bind(backup_nonce)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(user_id));
        }
        Ok(())
    }

    /// Store a pending TOTP secret before MFA is activated (setup phase).
    /// Sets `mfa_setup_pending = TRUE` atomically — `verify_mfa_setup`
    /// gates on this flag so a half-finished setup can't be advanced
    /// from a stale request.
    pub async fn store_pending_totp_secret(
        &self,
        user_id: Uuid,
        totp_encrypted: &[u8],
        totp_nonce: &str,
    ) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                totp_secret_encrypted = $2,
                totp_secret_nonce = $3,
                mfa_setup_pending = TRUE,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(totp_encrypted)
        .bind(totp_nonce)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(user_id));
        }
        Ok(())
    }

    /// Disable MFA for a user (clears all MFA fields)
    pub async fn disable_mfa(&self, user_id: Uuid) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                mfa_enabled = FALSE,
                totp_secret_encrypted = NULL,
                totp_secret_nonce = NULL,
                backup_codes_encrypted = NULL,
                backup_codes_nonce = NULL,
                mfa_setup_pending = FALSE,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(user_id));
        }
        Ok(())
    }

    /// Set MFA setup pending flag (for admin-enforced enrollment)
    pub async fn set_mfa_setup_pending(
        &self,
        user_id: Uuid,
        pending: bool,
    ) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            "UPDATE users SET mfa_setup_pending = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .bind(pending)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(user_id));
        }
        Ok(())
    }

    /// Update backup codes (after one is used)
    pub async fn update_backup_codes(
        &self,
        user_id: Uuid,
        backup_encrypted: &[u8],
        backup_nonce: &str,
    ) -> Result<(), UserRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE users SET
                backup_codes_encrypted = $2,
                backup_codes_nonce = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(backup_encrypted)
        .bind(backup_nonce)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(UserRepositoryError::NotFound(user_id));
        }
        Ok(())
    }

    /// Check if MFA is required globally
    pub async fn is_mfa_required_globally(&self) -> Result<bool, UserRepositoryError> {
        let result: Option<(bool,)> =
            sqlx::query_as("SELECT mfa_required FROM system_settings WHERE id = 'default'")
                .fetch_optional(&self.pool)
                .await?;

        Ok(result.map(|r| r.0).unwrap_or(false))
    }

    /// Set global MFA requirement
    pub async fn set_mfa_required_globally(
        &self,
        required: bool,
    ) -> Result<(), UserRepositoryError> {
        sqlx::query("UPDATE system_settings SET mfa_required = $1 WHERE id = 'default'")
            .bind(required)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
