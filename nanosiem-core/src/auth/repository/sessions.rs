// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session repository for CRUD operations
//!
//! Requirements: 7.1, 7.4, 7.5, 7.6

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::types::Session;

#[derive(Error, Debug)]
pub enum SessionRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Session not found: {0}")]
    NotFound(Uuid),
    #[error("Session not found by token")]
    NotFoundByToken,
    #[error("Session expired")]
    SessionExpired,
}

/// Repository for session operations
#[derive(Clone)]
pub struct SessionRepository {
    pool: PgPool,
}

impl SessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new session
    /// Requirements: 7.1
    pub async fn create_session(
        &self,
        user_id: Uuid,
        refresh_token_hash: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Session, SessionRepositoryError> {
        let session = sqlx::query_as::<_, Session>(
            r#"
            INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(refresh_token_hash)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(session)
    }

    /// Create a tenant-bound enterprise-shared session.
    ///
    /// The composite database foreign key requires `(tenant_id, user_id)` to
    /// exist in `tenant_members`; a caller cannot create a session for a tenant
    /// selected only by a client-provided slug/header.
    pub async fn create_tenant_session(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        authenticated_at: DateTime<Utc>,
        mfa_authenticated_at: Option<DateTime<Utc>>,
        refresh_token_hash: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Session, SessionRepositoryError> {
        let session = sqlx::query_as::<_, Session>(
            r#"
            INSERT INTO sessions (
                user_id, tenant_id, authenticated_at, mfa_authenticated_at,
                refresh_token_hash, ip_address, user_agent, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(authenticated_at)
        .bind(mfa_authenticated_at)
        .bind(refresh_token_hash)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(session)
    }

    /// Get a session by its refresh token hash
    pub async fn get_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Session, SessionRepositoryError> {
        let session =
            sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE refresh_token_hash = $1")
                .bind(token_hash)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(SessionRepositoryError::NotFoundByToken)?;

        // Check if session has expired
        if session.expires_at < Utc::now() {
            // Delete the expired session
            self.delete_session(session.id).await?;
            return Err(SessionRepositoryError::SessionExpired);
        }

        Ok(session)
    }

    /// Get a session by ID
    pub async fn get_session_by_id(&self, id: Uuid) -> Result<Session, SessionRepositoryError> {
        sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(SessionRepositoryError::NotFound(id))
    }

    /// Get all sessions for a user
    /// Requirements: 7.4
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Session>, SessionRepositoryError> {
        let sessions = sqlx::query_as::<_, Session>(
            r#"
            SELECT * FROM sessions
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY last_used_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    /// Get all active sessions (admin view)
    pub async fn get_all_sessions(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>, SessionRepositoryError> {
        let sessions = sqlx::query_as::<_, Session>(
            r#"
            SELECT * FROM sessions
            WHERE expires_at > NOW()
            ORDER BY last_used_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    /// Delete a session (logout or admin termination)
    /// Requirements: 7.5
    pub async fn delete_session(&self, id: Uuid) -> Result<(), SessionRepositoryError> {
        let result = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(SessionRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Delete a session by token hash
    pub async fn delete_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<(), SessionRepositoryError> {
        let result = sqlx::query("DELETE FROM sessions WHERE refresh_token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(SessionRepositoryError::NotFoundByToken);
        }

        Ok(())
    }

    /// Delete all sessions for a user (force logout from all devices)
    pub async fn delete_user_sessions(&self, user_id: Uuid) -> Result<u64, SessionRepositoryError> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Revoke every refresh session and every access token minted before this
    /// operation in one database transaction.
    ///
    /// The users-row watermark is advanced first, establishing a shared lock
    /// order with MFA/password mutations. Session deletion then removes every
    /// refresh row before commit. Any refresh that won its row CAS earlier
    /// still carries the older immutable authentication fence and is rejected.
    pub async fn revoke_all_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<u64, SessionRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let stamped = sqlx::query(
            "UPDATE users
             SET tokens_valid_from = clock_timestamp(),
                 totp_secret_encrypted = CASE WHEN mfa_enabled THEN totp_secret_encrypted ELSE NULL END,
                 totp_secret_nonce = CASE WHEN mfa_enabled THEN totp_secret_nonce ELSE NULL END,
                 mfa_setup_pending = CASE WHEN mfa_enabled THEN mfa_setup_pending ELSE FALSE END,
                 mfa_setup_authority_tenant_id = NULL,
                 mfa_setup_authority_jti = NULL,
                 mfa_setup_authority_authenticated_at = NULL,
                 mfa_setup_authority_expires_at = NULL,
                 mfa_setup_authority_is_challenge = NULL,
                 updated_at = clock_timestamp()
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if stamped.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(SessionRepositoryError::NotFound(user_id));
        }
        let deleted = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }

    /// Revoke exactly one enterprise-shared tenant session namespace while
    /// preserving the same user's sessions in every other tenant.
    pub async fn revoke_tenant_user_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, SessionRepositoryError> {
        let mut tx = self.pool.begin().await?;
        // Keep the shared auth mutation lock order user -> tenant/member. Clear
        // only a pending setup owned by this tenant; active MFA and another
        // tenant's setup are never touched.
        sqlx::query(
            "UPDATE users
             SET totp_secret_encrypted = NULL,
                 totp_secret_nonce = NULL,
                 mfa_setup_pending = FALSE,
                 mfa_setup_authority_tenant_id = NULL,
                 mfa_setup_authority_jti = NULL,
                 mfa_setup_authority_authenticated_at = NULL,
                 mfa_setup_authority_expires_at = NULL,
                 mfa_setup_authority_is_challenge = NULL,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND mfa_enabled = FALSE
               AND mfa_setup_authority_tenant_id = $2",
        )
        .bind(user_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        let stamped = sqlx::query(
            "UPDATE tenant_members
             SET tokens_valid_from = clock_timestamp(),
                 updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if stamped.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(SessionRepositoryError::NotFound(user_id));
        }
        let deleted = sqlx::query("DELETE FROM sessions WHERE tenant_id = $1 AND user_id = $2")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }

    /// M6: Delete oldest sessions for a user, keeping the most recent ones
    pub async fn delete_oldest_user_sessions(
        &self,
        user_id: Uuid,
        count: i64,
    ) -> Result<u64, SessionRepositoryError> {
        let result = sqlx::query(
            "DELETE FROM sessions WHERE id IN (
                SELECT id FROM sessions WHERE user_id = $1
                ORDER BY last_used_at ASC LIMIT $2
            )",
        )
        .bind(user_id)
        .bind(count)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Update last used timestamp for a session
    pub async fn update_last_used(&self, id: Uuid) -> Result<(), SessionRepositoryError> {
        let result = sqlx::query("UPDATE sessions SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(SessionRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Atomically rotate a session's refresh token (single-use rotation).
    ///
    /// The UPDATE is a compare-and-swap: it only matches when the session
    /// still holds `current_token_hash`. Concurrent refreshes that read the
    /// same session race here — exactly one wins, and the losers (or any
    /// replay of an already-rotated token) match 0 rows and get
    /// `NotFoundByToken`, which the handler surfaces as 401. Without the
    /// `refresh_token_hash` predicate every concurrent request would succeed,
    /// minting multiple valid token pairs from a single-use token (NAN-1391).
    ///
    /// `ip_address` / `user_agent` are the client of THIS refresh request.
    /// They are not stored on the session (its network metadata belongs to
    /// creation); they are handed to the enterprise session audit trigger
    /// (migration 9012500) as transaction-local settings in the same
    /// transaction as the UPDATE, so the `auth_session_refreshed` audit row
    /// names the refreshing client (NAN-3460). Without the trigger the
    /// settings are inert.
    pub async fn rotate_refresh_token(
        &self,
        id: Uuid,
        current_token_hash: &str,
        new_token_hash: &str,
        new_expires_at: DateTime<Utc>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Session, SessionRepositoryError> {
        let mut tx = self.pool.begin().await?;
        // is_local => TRUE: scoped to this transaction, never visible to the
        // next request on the pooled connection. '' means unknown.
        sqlx::query(
            "SELECT set_config('nano_audit.session_client_ip', $1, TRUE), \
                    set_config('nano_audit.session_client_user_agent', $2, TRUE)",
        )
        .bind(ip_address.unwrap_or(""))
        .bind(user_agent.unwrap_or(""))
        .execute(&mut *tx)
        .await?;
        let session = sqlx::query_as::<_, Session>(
            r#"
            UPDATE sessions SET
                refresh_token_hash = $3,
                expires_at = $4,
                last_used_at = NOW()
            WHERE id = $1 AND refresh_token_hash = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(current_token_hash)
        .bind(new_token_hash)
        .bind(new_expires_at)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(session) = session else {
            tx.rollback().await?;
            return Err(SessionRepositoryError::NotFoundByToken);
        };
        tx.commit().await?;

        Ok(session)
    }

    /// Cleanup expired sessions
    /// Requirements: 7.6
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, SessionRepositoryError> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Count active sessions for a user
    pub async fn count_user_sessions(&self, user_id: Uuid) -> Result<i64, SessionRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND expires_at > NOW()",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Count total active sessions
    pub async fn count_all_sessions(&self) -> Result<i64, SessionRepositoryError> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()")
                .fetch_one(&self.pool)
                .await?;

        Ok(count)
    }

    /// Check if a session exists and is valid
    pub async fn is_session_valid(&self, id: Uuid) -> Result<bool, SessionRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sessions WHERE id = $1 AND expires_at > NOW()",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }
}
