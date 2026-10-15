// SPDX-License-Identifier: AGPL-3.0-or-later

//! User repository for CRUD operations
//!
//! Requirements: 1.1, 1.6, 1.7

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::password::{hash_password, validate_password, PasswordError};
use crate::auth::types::{
    builtin_groups, CreateUserRequest, GroupSummary, LandingPage, QueryMode, SearchHubStyle,
    TimeRangePreset, UpdateUserRequest, User, UserPreferences,
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
    #[error("Password does not meet requirements: {0}")]
    PasswordRequirementsNotMet(String),
    #[error("Invalid password reset token")]
    InvalidResetToken,
    #[error("Password reset token expired")]
    ResetTokenExpired,
    #[error("grant authority changed during validation; retry the request")]
    GrantAuthorityChanged,
}

impl From<PasswordError> for UserRepositoryError {
    fn from(err: PasswordError) -> Self {
        match err {
            PasswordError::ComplexityNotMet(msg) => {
                UserRepositoryError::PasswordRequirementsNotMet(msg)
            }
            PasswordError::TooLong(_) => {
                UserRepositoryError::PasswordRequirementsNotMet(err.to_string())
            }
            PasswordError::HashingFailed(_) | PasswordError::VerificationFailed(_) => {
                UserRepositoryError::PasswordHashError(err.to_string())
            }
        }
    }
}

/// Reject a plaintext that does not satisfy the single authoritative policy
/// (`PasswordRequirements::default()` plus `MAX_PASSWORD_BYTES`).
///
/// SECURITY (password-policy bypass): the admin user-management endpoints used
/// to hand `CreateUserRequest.password` / `UpdateUserRequest.password` straight
/// to `hash_password`, so `POST /api/users` and `PUT /api/users/{id}` could
/// install a one-character credential that `login`, `reset_password` and
/// `change_password` would all have refused. The check lives in the repository
/// rather than in the HTTP handler deliberately: `create_user` has three
/// independent callers (the admin endpoint, first-run `POST
/// /api/setup/initialize`, and demo provisioning), and handler-level validation
/// would leave every current and future non-HTTP caller able to skip it. This
/// is the last layer before `users.password_hash` is written, so it is the only
/// place the policy cannot be routed around.
fn reject_noncompliant_password(password: &str) -> Result<(), UserRepositoryError> {
    validate_password(password).map_err(UserRepositoryError::from)
}

/// Validate a new plaintext against the authoritative policy, then hash it off
/// the async runtime (bcrypt is CPU-intensive).
///
/// Every repository path that writes `users.password_hash` calls this — it is
/// the only place `hash_password` is invoked in this module, which is asserted
/// by `hashing_only_happens_behind_validation` below. Validation runs first so
/// a rejected password is never hashed.
async fn validate_and_hash_password(password: &str) -> Result<String, UserRepositoryError> {
    reject_noncompliant_password(password)?;
    let pwd = password.to_string();
    tokio::task::spawn_blocking(move || hash_password(&pwd))
        .await
        .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))?
        .map_err(|e| UserRepositoryError::PasswordHashError(e.to_string()))
}

/// Repository for user operations
#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

/// Compare-and-swap material for consuming one encrypted backup-code list.
pub struct BackupCodeRotation<'a> {
    pub expected_encrypted: &'a [u8],
    pub expected_nonce: &'a str,
    pub replacement_encrypted: &'a [u8],
    pub replacement_nonce: &'a str,
}

/// Exact enterprise-shared credential allowed to mutate a pending MFA setup.
/// The values come from a validated, tenant-bound signed token.
#[derive(Debug, Clone, Copy)]
pub struct SharedMfaSetupAuthority {
    pub tenant_id: Uuid,
    pub jti: Uuid,
    pub authenticated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_challenge: bool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the database pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Database-clock fence for non-password authentication continuations.
    pub async fn authentication_fence_time(&self) -> Result<DateTime<Utc>, UserRepositoryError> {
        Ok(sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&self.pool)
            .await?)
    }

    /// Revalidate the exact password hash after its expensive bcrypt check and
    /// return a database-clock authentication fence while holding a shared row
    /// lock. An already-running reset/change wins first and exposes its new
    /// hash; a later reset/change waits and advances `tokens_valid_from` beyond
    /// the returned fence, invalidating every shared continuation minted from
    /// this authentication.
    pub async fn lock_current_password_authentication(
        &self,
        user_id: Uuid,
        expected_password_hash: &str,
    ) -> Result<Option<DateTime<Utc>>, UserRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query_as::<_, (Option<String>, String)>(
            r#"
            SELECT password_hash, status
            FROM users
            WHERE id = $1
            FOR SHARE
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((password_hash, status)) = current else {
            tx.rollback().await?;
            return Ok(None);
        };
        if status != "active" || password_hash.as_deref() != Some(expected_password_hash) {
            tx.rollback().await?;
            return Ok(None);
        }
        let authenticated_at = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(authenticated_at))
    }

    /// Create a new local user
    /// Requirements: 1.1
    ///
    /// Uses database unique constraint to atomically prevent duplicate emails (race-condition safe)
    pub async fn create_user(
        &self,
        request: &CreateUserRequest,
    ) -> Result<User, UserRepositoryError> {
        // Validate against the authoritative policy, then hash (spawn_blocking:
        // bcrypt is CPU-intensive). Rejected before any row is written.
        let password_hash = validate_and_hash_password(&request.password).await?;

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

    /// Create a user and all requested memberships under the generation
    /// returned by the authoritative privilege-grant validator.
    pub async fn create_user_authorized(
        &self,
        request: &CreateUserRequest,
        stamp: crate::auth::GrantAuthorityStamp,
    ) -> Result<User, UserRepositoryError> {
        let password_hash = validate_and_hash_password(&request.password).await?;

        let mut tx = self.pool.begin().await?;
        if !crate::auth::lock_and_verify_grant_authority(&mut tx, stamp).await? {
            return Err(UserRepositoryError::GrantAuthorityChanged);
        }
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
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("users_email_key") {
                    return UserRepositoryError::EmailExists(request.email.clone());
                }
            }
            UserRepositoryError::DatabaseError(e)
        })?;

        for group_id in &request.group_ids {
            if *group_id != builtin_groups::EVERYONE_ID {
                sqlx::query(
                    "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(user.id)
                .bind(group_id)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
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

    #[cfg(feature = "enterprise")]
    /// Hosted `enterprise_shared` sign-in identity for `email` (FRO-754).
    ///
    /// Identities are tenant-scoped: the same e-mail in two tenants is two
    /// `users` rows with separate credentials (`users.home_tenant_id`,
    /// migration 9003465). With a tenant selector, that tenant's scoped
    /// identity wins; the legacy global row (`home_tenant_id IS NULL`, exact
    /// e-mail as before) is the fallback only when the tenant has none.
    /// Without a selector only a legacy row can match. A scoped identity of
    /// another tenant is never returned. The slug is only a selector:
    /// membership is still resolved after the password check.
    ///
    /// Never call this outside the shared profile: the column exists only
    /// with the enterprise overlay.
    pub async fn get_enterprise_shared_user_for_login(
        &self,
        tenant_slug: Option<&str>,
        email: &str,
    ) -> Result<User, UserRepositoryError> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT u.* FROM users u
             WHERE ($1::text IS NOT NULL
                    AND u.home_tenant_id = (SELECT t.id FROM tenants t WHERE t.slug = $1::text)
                    AND lower(u.email) = lower($2))
                OR (u.home_tenant_id IS NULL AND u.email = $2)
             ORDER BY (u.home_tenant_id IS NULL) ASC
             LIMIT 1
            "#,
        )
        .bind(tenant_slug)
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
        self.update_user_with_groups(id, request, None).await
    }

    /// Update a user's profile and, optionally, replace their group memberships
    /// in a SINGLE transaction (NAN-2121). Committing the profile write and the
    /// membership replacement together means a failure in EITHER rolls back the
    /// whole request — the endpoint can no longer persist an
    /// email/password/name/status change while the membership update fails (which
    /// also skipped the success audit). `group_ids = None` leaves memberships
    /// untouched; `Some(&[])` clears all non-Everyone memberships.
    pub async fn update_user_with_groups(
        &self,
        id: Uuid,
        request: &UpdateUserRequest,
        group_ids: Option<&[Uuid]>,
    ) -> Result<User, UserRepositoryError> {
        // Read current values (for field defaults) and hash the password BEFORE
        // opening the transaction (bcrypt is CPU-intensive → spawn_blocking).
        let existing = self.get_user_by_id(id).await?;
        let password_hash = if let Some(ref new_password) = request.password {
            Some(validate_and_hash_password(new_password).await?)
        } else {
            existing.password_hash.clone()
        };

        let mut tx = self.pool.begin().await?;
        let user =
            Self::apply_profile_update_in(&mut tx, id, &existing, request, password_hash).await?;
        if let Some(group_ids) = group_ids {
            Self::replace_user_groups_in(&mut tx, id, group_ids).await?;
        }
        tx.commit().await?;
        Ok(user)
    }

    /// Update profile fields and memberships only while the authoritative
    /// privilege-grant generation remains current.
    pub async fn update_user_with_groups_authorized(
        &self,
        id: Uuid,
        request: &UpdateUserRequest,
        group_ids: Option<&[Uuid]>,
        stamp: crate::auth::GrantAuthorityStamp,
    ) -> Result<User, UserRepositoryError> {
        let existing = self.get_user_by_id(id).await?;
        let password_hash = if let Some(ref new_password) = request.password {
            Some(validate_and_hash_password(new_password).await?)
        } else {
            existing.password_hash.clone()
        };

        let mut tx = self.pool.begin().await?;
        if !crate::auth::lock_and_verify_grant_authority(&mut tx, stamp).await? {
            return Err(UserRepositoryError::GrantAuthorityChanged);
        }
        let user =
            Self::apply_profile_update_in(&mut tx, id, &existing, request, password_hash).await?;
        if let Some(group_ids) = group_ids {
            Self::replace_user_groups_in(&mut tx, id, group_ids).await?;
        }
        tx.commit().await?;
        Ok(user)
    }

    /// Apply the profile-column update within a caller-provided transaction.
    async fn apply_profile_update_in(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        existing: &User,
        request: &UpdateUserRequest,
        password_hash: Option<String>,
    ) -> Result<User, UserRepositoryError> {
        let email = request.email.as_ref().unwrap_or(&existing.email);
        let name = request.name.as_ref().unwrap_or(&existing.name);
        let status = request.status.as_ref().unwrap_or(&existing.status);

        // Rely on unique constraint for email uniqueness (race-condition safe)
        sqlx::query_as::<_, User>(
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
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            // Check for unique constraint violation
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("users_email_key") {
                    return UserRepositoryError::EmailExists(email.clone());
                }
            }
            UserRepositoryError::DatabaseError(e)
        })
    }

    /// Delete a user
    pub async fn delete_user(&self, id: Uuid) -> Result<(), UserRepositoryError> {
        let mut tx = self.pool.begin().await?;

        // Serialize assignment with deletion before touching any dependent
        // rows. A concurrent approval insert takes a foreign-key key-share lock
        // on this row: it either commits before this lock (and is withdrawn
        // below) or waits until deletion commits and then fails its FK check.
        // Without the lock, an assignment could land after the withdrawal
        // statement and be converted to an open approval by ON DELETE SET NULL.
        let locked: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            tx.rollback().await?;
            return Err(UserRepositoryError::NotFound(id));
        }

        // F-32: delete the user's API keys first. The api_keys.created_by FK is
        // ON DELETE SET NULL, which would orphan the keys (created_by => NULL)
        // and let them keep authenticating with the deleted user's permissions
        // (the owner-status check in validate_key can't fire on a NULL owner).
        // Removing them makes deletion a real revocation.
        sqlx::query("DELETE FROM api_keys WHERE created_by = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        // NAN-2098: an assigned playbook approval must not become an OPEN
        // approval when its reviewer is hard-deleted. The FK below is
        // intentionally ON DELETE SET NULL, so terminalize pending assignments
        // before deleting the user. Otherwise an API key (which has no human
        // assignee claim) could answer the now-NULL row despite the
        // human-only orphan-recovery rule.
        //
        // Keep this repository usable against minimal/auth-only schemas used by
        // tests and tooling, where the enterprise playbook tables may not exist.
        let approvals_exist: bool =
            sqlx::query_scalar("SELECT to_regclass('public.playbook_approvals') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await?;
        if approvals_exist {
            sqlx::query(
                r#"UPDATE playbook_approvals
                      SET status = 'withdrawn',
                          response = COALESCE(
                              response,
                              'Assigned reviewer was deleted; resubmit for review'
                          ),
                          responded_at = NOW()
                    WHERE approver_id = $1
                      AND status = 'pending'"#,
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
        }

        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        debug_assert_eq!(result.rows_affected(), 1);

        tx.commit().await?;
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
        let password_hash = validate_and_hash_password(new_password).await?;

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

    /// Consume a reset token, replace the password, advance the credential
    /// watermark and remove every refresh session in one transaction.
    /// NAN-3790: the tenants a hosted-shared account's security events are
    /// audited in. A tenant-scoped identity (`home_tenant_id`, FRO-754 /
    /// NAN-3788) belongs to exactly its home tenant; a legacy global identity
    /// to every tenant where it holds an active membership. Only active
    /// tenants. Empty when the account belongs to none.
    #[cfg(feature = "enterprise")]
    pub async fn audit_tenants_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<crate::auth::TrustedTenantContext>, UserRepositoryError> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT t.id, t.slug
              FROM public.users u
              JOIN public.tenants t ON t.status = 'active' AND (
                   t.id = u.home_tenant_id
                   OR (u.home_tenant_id IS NULL AND EXISTS (
                       SELECT 1 FROM public.tenant_members m
                        WHERE m.tenant_id = t.id AND m.user_id = u.id AND m.status = 'active')))
             WHERE u.id = $1
             ORDER BY t.id
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(tenant_id, tenant_slug)| crate::auth::TrustedTenantContext { tenant_id, tenant_slug })
            .collect())
    }

    pub async fn reset_password_and_revoke_sessions(
        &self,
        reset_token: &str,
        new_password: &str,
    ) -> Result<Uuid, UserRepositoryError> {
        let password_hash = validate_and_hash_password(new_password).await?;
        let mut tx = self.pool.begin().await?;
        let user_id = sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE users SET
                password_hash = $2,
                password_reset_token = NULL,
                password_reset_expires = NULL,
                totp_secret_encrypted = CASE WHEN mfa_enabled THEN totp_secret_encrypted ELSE NULL END,
                totp_secret_nonce = CASE WHEN mfa_enabled THEN totp_secret_nonce ELSE NULL END,
                mfa_setup_pending = CASE WHEN mfa_enabled THEN mfa_setup_pending ELSE FALSE END,
                mfa_setup_authority_tenant_id = NULL,
                mfa_setup_authority_jti = NULL,
                mfa_setup_authority_authenticated_at = NULL,
                mfa_setup_authority_expires_at = NULL,
                mfa_setup_authority_is_challenge = NULL,
                tokens_valid_from = clock_timestamp(),
                updated_at = clock_timestamp()
            WHERE password_reset_token = $1
              AND password_reset_expires > clock_timestamp()
            RETURNING id
            "#,
        )
        .bind(reset_token)
        .bind(password_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(UserRepositoryError::InvalidResetToken)?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(user_id)
    }

    /// Replace a password only if the hash verified by the caller is still
    /// the exact current hash, while advancing the revocation watermark and
    /// deleting refresh sessions in the same users-row transaction.
    pub async fn change_password_and_revoke_sessions_if_current(
        &self,
        user_id: Uuid,
        expected_password_hash: &str,
        new_password: &str,
    ) -> Result<bool, UserRepositoryError> {
        let password_hash = validate_and_hash_password(new_password).await?;
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE users SET
                password_hash = $3,
                password_reset_token = NULL,
                password_reset_expires = NULL,
                totp_secret_encrypted = CASE WHEN mfa_enabled THEN totp_secret_encrypted ELSE NULL END,
                totp_secret_nonce = CASE WHEN mfa_enabled THEN totp_secret_nonce ELSE NULL END,
                mfa_setup_pending = CASE WHEN mfa_enabled THEN mfa_setup_pending ELSE FALSE END,
                mfa_setup_authority_tenant_id = NULL,
                mfa_setup_authority_jti = NULL,
                mfa_setup_authority_authenticated_at = NULL,
                mfa_setup_authority_expires_at = NULL,
                mfa_setup_authority_is_challenge = NULL,
                tokens_valid_from = clock_timestamp(),
                updated_at = clock_timestamp()
            WHERE id = $1
              AND password_hash = $2
              AND status = 'active'
            "#,
        )
        .bind(user_id)
        .bind(expected_password_hash)
        .bind(password_hash)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Set user groups (replaces existing group memberships)
    pub async fn set_user_groups(
        &self,
        user_id: Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), UserRepositoryError> {
        // Verify user exists
        self.get_user_by_id(user_id).await?;

        // Replace atomically so a bad group_id (FK violation) cannot leave the
        // user with their prior non-Everyone memberships already deleted
        // (NAN-2121 partial-mutation hardening).
        let mut tx = self.pool.begin().await?;
        Self::replace_user_groups_in(&mut tx, user_id, group_ids).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replace memberships under an authoritative privilege-grant generation.
    pub async fn set_user_groups_authorized(
        &self,
        user_id: Uuid,
        group_ids: &[Uuid],
        stamp: crate::auth::GrantAuthorityStamp,
    ) -> Result<(), UserRepositoryError> {
        let mut tx = self.pool.begin().await?;
        if !crate::auth::lock_and_verify_grant_authority(&mut tx, stamp).await? {
            return Err(UserRepositoryError::GrantAuthorityChanged);
        }
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(UserRepositoryError::NotFound(user_id));
        }
        Self::replace_user_groups_in(&mut tx, user_id, group_ids).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replace a user's non-Everyone group memberships within a caller-provided
    /// transaction. Everyone (built-in) is deliberately preserved (`group_id !=
    /// EVERYONE_ID`), so every user always retains baseline membership. Shared by
    /// `set_user_groups` and `update_user_with_groups` so the two stay in lock-step.
    async fn replace_user_groups_in(
        conn: &mut sqlx::PgConnection,
        user_id: Uuid,
        group_ids: &[Uuid],
    ) -> Result<(), UserRepositoryError> {
        // Remove existing group memberships (except Everyone)
        sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id != $2")
            .bind(user_id)
            .bind(builtin_groups::EVERYONE_ID)
            .execute(&mut *conn)
            .await?;

        // Add new group memberships
        for group_id in group_ids {
            sqlx::query(
                "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(user_id)
            .bind(group_id)
            .execute(&mut *conn)
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
            "UPDATE users SET status = 'disabled', tokens_valid_from = NOW(), \
             totp_secret_encrypted = CASE WHEN mfa_enabled THEN totp_secret_encrypted ELSE NULL END, \
             totp_secret_nonce = CASE WHEN mfa_enabled THEN totp_secret_nonce ELSE NULL END, \
             mfa_setup_pending = CASE WHEN mfa_enabled THEN mfa_setup_pending ELSE FALSE END, \
             mfa_setup_authority_tenant_id = NULL, mfa_setup_authority_jti = NULL, \
             mfa_setup_authority_authenticated_at = NULL, mfa_setup_authority_expires_at = NULL, \
             mfa_setup_authority_is_challenge = NULL, updated_at = NOW() \
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
            "UPDATE users SET tokens_valid_from = NOW(), \
             totp_secret_encrypted = CASE WHEN mfa_enabled THEN totp_secret_encrypted ELSE NULL END, \
             totp_secret_nonce = CASE WHEN mfa_enabled THEN totp_secret_nonce ELSE NULL END, \
             mfa_setup_pending = CASE WHEN mfa_enabled THEN mfa_setup_pending ELSE FALSE END, \
             mfa_setup_authority_tenant_id = NULL, mfa_setup_authority_jti = NULL, \
             mfa_setup_authority_authenticated_at = NULL, mfa_setup_authority_expires_at = NULL, \
             mfa_setup_authority_is_challenge = NULL, updated_at = NOW() WHERE id = $1",
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

    /// Store a shared pending TOTP secret only while the exact signed
    /// credential remains current. The JTI advisory lock orders this mutation
    /// with durable exact-token revocation; the users-row update orders it
    /// with logout/password-reset watermarks.
    pub async fn store_pending_totp_secret_for_shared_authority(
        &self,
        user_id: Uuid,
        authority: SharedMfaSetupAuthority,
        totp_encrypted: &[u8],
        totp_nonce: &str,
    ) -> Result<bool, UserRepositoryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 2361))")
            .bind(authority.jti)
            .execute(&mut *tx)
            .await?;
        let updated = sqlx::query(
            r#"
            UPDATE users SET
                totp_secret_encrypted = $2,
                totp_secret_nonce = $3,
                mfa_setup_pending = TRUE,
                mfa_setup_authority_tenant_id = $4,
                mfa_setup_authority_jti = $5,
                mfa_setup_authority_authenticated_at = $6,
                mfa_setup_authority_expires_at = $7,
                mfa_setup_authority_is_challenge = $8,
                updated_at = clock_timestamp()
            WHERE id = $1
              AND status = 'active'
              AND mfa_enabled = FALSE
              AND (tokens_valid_from IS NULL OR tokens_valid_from < $6)
              AND NOT EXISTS (SELECT 1 FROM revoked_tokens WHERE jti = $5)
              AND (
                    mfa_setup_pending = FALSE
                    OR totp_secret_encrypted IS NULL
                    OR mfa_setup_authority_jti = $5
                  )
            "#,
        )
        .bind(user_id)
        .bind(totp_encrypted)
        .bind(totp_nonce)
        .bind(authority.tenant_id)
        .bind(authority.jti)
        .bind(authority.authenticated_at)
        .bind(authority.expires_at)
        .bind(authority.is_challenge)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        let tenant_authority_current = sqlx::query_scalar::<_, Uuid>(
            "SELECT member.user_id
             FROM tenants AS tenant
             JOIN tenant_members AS member ON member.tenant_id = tenant.id
             WHERE tenant.id = $1 AND member.user_id = $2
               AND tenant.status = 'active' AND member.status = 'active'
               AND (tenant.tokens_valid_from IS NULL OR tenant.tokens_valid_from < $3)
               AND (member.tokens_valid_from IS NULL OR member.tokens_valid_from < $3)
             FOR SHARE OF tenant, member",
        )
        .bind(authority.tenant_id)
        .bind(user_id)
        .bind(authority.authenticated_at)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !tenant_authority_current {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Activate MFA only for the exact shared credential and exact pending
    /// secret that were verified. Challenge credentials are durably consumed
    /// in the same transaction as the MFA state transition.
    pub async fn enable_mfa_for_shared_authority(
        &self,
        user_id: Uuid,
        authority: SharedMfaSetupAuthority,
        expected_totp_encrypted: &[u8],
        expected_totp_nonce: &str,
        backup_encrypted: &[u8],
        backup_nonce: &str,
    ) -> Result<bool, UserRepositoryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 2361))")
            .bind(authority.jti)
            .execute(&mut *tx)
            .await?;
        let updated = sqlx::query(
            r#"
            UPDATE users SET
                mfa_enabled = TRUE,
                backup_codes_encrypted = $2,
                backup_codes_nonce = $3,
                mfa_setup_pending = FALSE,
                mfa_setup_authority_tenant_id = NULL,
                mfa_setup_authority_jti = NULL,
                mfa_setup_authority_authenticated_at = NULL,
                mfa_setup_authority_expires_at = NULL,
                mfa_setup_authority_is_challenge = NULL,
                updated_at = clock_timestamp()
            WHERE id = $1
              AND status = 'active'
              AND mfa_enabled = FALSE
              AND mfa_setup_pending = TRUE
              AND totp_secret_encrypted = $4
              AND totp_secret_nonce = $5
              AND mfa_setup_authority_tenant_id = $6
              AND mfa_setup_authority_jti = $7
              AND mfa_setup_authority_authenticated_at = $8
              AND mfa_setup_authority_expires_at = $9
              AND mfa_setup_authority_is_challenge = $10
              AND mfa_setup_authority_expires_at > clock_timestamp()
              AND (tokens_valid_from IS NULL OR tokens_valid_from < $8)
              AND NOT EXISTS (SELECT 1 FROM revoked_tokens WHERE jti = $7)
            "#,
        )
        .bind(user_id)
        .bind(backup_encrypted)
        .bind(backup_nonce)
        .bind(expected_totp_encrypted)
        .bind(expected_totp_nonce)
        .bind(authority.tenant_id)
        .bind(authority.jti)
        .bind(authority.authenticated_at)
        .bind(authority.expires_at)
        .bind(authority.is_challenge)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        let tenant_authority_current = sqlx::query_scalar::<_, Uuid>(
            "SELECT member.user_id
             FROM tenants AS tenant
             JOIN tenant_members AS member ON member.tenant_id = tenant.id
             WHERE tenant.id = $1 AND member.user_id = $2
               AND tenant.status = 'active' AND member.status = 'active'
               AND (tenant.tokens_valid_from IS NULL OR tenant.tokens_valid_from < $3)
               AND (member.tokens_valid_from IS NULL OR member.tokens_valid_from < $3)
             FOR SHARE OF tenant, member",
        )
        .bind(authority.tenant_id)
        .bind(user_id)
        .bind(authority.authenticated_at)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !tenant_authority_current {
            tx.rollback().await?;
            return Ok(false);
        }
        if authority.is_challenge {
            let claimed = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) \
                 ON CONFLICT (jti) DO NOTHING RETURNING jti",
            )
            .bind(authority.jti)
            .bind(authority.expires_at.timestamp())
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            if !claimed {
                tx.rollback().await?;
                return Ok(false);
            }
        }
        tx.commit().await?;
        Ok(true)
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

    /// Atomically claim a single-use MFA challenge and, when a backup code was
    /// used, rotate the exact encrypted list that was verified. The unique JTI
    /// insert and backup-code compare-and-swap share one transaction, so only
    /// one concurrent completion can reach session issuance.
    pub async fn consume_mfa_challenge(
        &self,
        user_id: Uuid,
        challenge_jti: Uuid,
        challenge_exp: i64,
        backup_rotation: Option<BackupCodeRotation<'_>>,
    ) -> Result<bool, UserRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let claimed = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) \
             ON CONFLICT (jti) DO NOTHING RETURNING jti",
        )
        .bind(challenge_jti)
        .bind(challenge_exp)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !claimed {
            return Ok(false);
        }

        if let Some(rotation) = backup_rotation {
            let updated = sqlx::query(
                r#"
                UPDATE users SET
                    backup_codes_encrypted = $2,
                    backup_codes_nonce = $3,
                    updated_at = NOW()
                WHERE id = $1
                  AND backup_codes_encrypted = $4
                  AND backup_codes_nonce = $5
                "#,
            )
            .bind(user_id)
            .bind(rotation.replacement_encrypted)
            .bind(rotation.replacement_nonce)
            .bind(rotation.expected_encrypted)
            .bind(rotation.expected_nonce)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() != 1 {
                return Ok(false);
            }
        }

        transaction.commit().await?;
        Ok(true)
    }

    #[cfg(feature = "enterprise")]
    /// Shared challenge consumption adds the immutable password-authentication
    /// fence to the same row/JTI transaction. Logout/reset either commits its
    /// watermark first and this fails, or commits later and invalidates every
    /// token/session carrying this older authentication time.
    pub async fn consume_enterprise_shared_mfa_challenge(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        challenge_jti: Uuid,
        challenge_exp: i64,
        authenticated_at: DateTime<Utc>,
        backup_rotation: Option<BackupCodeRotation<'_>>,
    ) -> Result<bool, UserRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 2361))")
            .bind(challenge_jti)
            .execute(&mut *transaction)
            .await?;
        let current = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM users
             WHERE id = $1
               AND status = 'active'
               AND (tokens_valid_from IS NULL OR tokens_valid_from < $2)
             FOR UPDATE",
        )
        .bind(user_id)
        .bind(authenticated_at)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !current {
            transaction.rollback().await?;
            return Ok(false);
        }
        let tenant_authority_current = sqlx::query_scalar::<_, Uuid>(
            "SELECT member.user_id
             FROM tenants AS tenant
             JOIN tenant_members AS member ON member.tenant_id = tenant.id
             WHERE tenant.id = $1 AND member.user_id = $2
               AND tenant.status = 'active' AND member.status = 'active'
               AND (tenant.tokens_valid_from IS NULL OR tenant.tokens_valid_from < $3)
               AND (member.tokens_valid_from IS NULL OR member.tokens_valid_from < $3)
             FOR SHARE OF tenant, member",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(authenticated_at)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !tenant_authority_current {
            transaction.rollback().await?;
            return Ok(false);
        }
        let claimed = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) \
             ON CONFLICT (jti) DO NOTHING RETURNING jti",
        )
        .bind(challenge_jti)
        .bind(challenge_exp)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !claimed {
            transaction.rollback().await?;
            return Ok(false);
        }
        if let Some(rotation) = backup_rotation {
            let updated = sqlx::query(
                r#"
                UPDATE users SET
                    backup_codes_encrypted = $2,
                    backup_codes_nonce = $3,
                    updated_at = NOW()
                WHERE id = $1
                  AND backup_codes_encrypted = $4
                  AND backup_codes_nonce = $5
                "#,
            )
            .bind(user_id)
            .bind(rotation.replacement_encrypted)
            .bind(rotation.replacement_nonce)
            .bind(rotation.expected_encrypted)
            .bind(rotation.expected_nonce)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() != 1 {
                transaction.rollback().await?;
                return Ok(false);
            }
        }
        transaction.commit().await?;
        Ok(true)
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

#[cfg(test)]
mod password_policy_tests {
    use super::*;
    use crate::auth::password::MAX_PASSWORD_BYTES;

    #[test]
    fn admin_set_password_must_meet_complexity() {
        // The exact bypass that existed before: a one-character admin-set
        // password reached bcrypt unvalidated.
        for weak in ["x", "short", "alllowercase1!", "NoSpecials12345", "NoDigits-Here!"] {
            assert!(
                matches!(
                    reject_noncompliant_password(weak),
                    Err(UserRepositoryError::PasswordRequirementsNotMet(_))
                ),
                "{weak:?} must be rejected"
            );
        }
    }

    #[test]
    fn admin_set_password_respects_the_max_byte_cap() {
        let oversized = format!("Aa1!{}", "x".repeat(MAX_PASSWORD_BYTES));
        assert!(matches!(
            reject_noncompliant_password(&oversized),
            Err(UserRepositoryError::PasswordRequirementsNotMet(_))
        ));
    }

    #[test]
    fn compliant_password_is_accepted() {
        assert!(reject_noncompliant_password("Strong-Passphrase-2361!").is_ok());
    }

    /// Guard against a future call site re-introducing the bypass by hashing
    /// directly. `hash_password` must be invoked exactly once in this module —
    /// inside `validate_and_hash_password`, after validation.
    #[test]
    fn hashing_only_happens_behind_validation() {
        let source = include_str!("users.rs");
        // Assembled at runtime so this assertion does not match itself.
        let needle = format!("{}_password(&pwd)", "hash");
        let invocations = source.matches(needle.as_str()).count();
        assert_eq!(
            invocations, 1,
            "every password write must go through validate_and_hash_password"
        );
    }
}
