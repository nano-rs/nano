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

    /// Update session with new refresh token (rotation)
    pub async fn rotate_refresh_token(
        &self,
        id: Uuid,
        new_token_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<Session, SessionRepositoryError> {
        let session = sqlx::query_as::<_, Session>(
            r#"
            UPDATE sessions SET
                refresh_token_hash = $2,
                expires_at = $3,
                last_used_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(new_token_hash)
        .bind(new_expires_at)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SessionRepositoryError::NotFound(id))?;

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
