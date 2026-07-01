// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session Management Service
//!
//! Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
//!
//! This module provides session management functionality:
//! - Create and track user sessions with metadata
//! - Allow users to view and terminate their own sessions
//! - Allow administrators to view and terminate any session
//! - Automatic cleanup of expired sessions
//! - Session termination invalidates associated tokens immediately

use chrono::{Duration, Utc};
use thiserror::Error;
use uuid::Uuid;

use super::repository::{
    SessionRepository, SessionRepositoryError, UserRepository, UserRepositoryError,
};
use super::types::{config_defaults, Session, SessionResponse};

/// Session service errors
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Session not found")]
    NotFound,

    #[error("Session expired")]
    Expired,

    #[error("User not found")]
    UserNotFound,

    #[error("Permission denied: cannot terminate another user's session")]
    PermissionDenied,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<SessionRepositoryError> for SessionError {
    fn from(err: SessionRepositoryError) -> Self {
        match err {
            SessionRepositoryError::NotFound(_) | SessionRepositoryError::NotFoundByToken => {
                SessionError::NotFound
            }
            SessionRepositoryError::SessionExpired => SessionError::Expired,
            SessionRepositoryError::DatabaseError(e) => SessionError::DatabaseError(e.to_string()),
        }
    }
}

impl From<UserRepositoryError> for SessionError {
    fn from(err: UserRepositoryError) -> Self {
        match err {
            UserRepositoryError::NotFound(_) | UserRepositoryError::NotFoundByEmail(_) => {
                SessionError::UserNotFound
            }
            _ => SessionError::DatabaseError(err.to_string()),
        }
    }
}

/// Configuration for the session service
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session inactivity timeout in seconds (default: 24 hours)
    pub session_timeout: i64,
    /// Refresh token TTL in seconds (default: 7 days)
    pub refresh_token_ttl: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_timeout: config_defaults::SESSION_TIMEOUT,
            refresh_token_ttl: config_defaults::REFRESH_TOKEN_TTL,
        }
    }
}

/// Session management service
///
/// Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
pub struct SessionService {
    session_repo: SessionRepository,
    user_repo: UserRepository,
    config: SessionConfig,
}

impl SessionService {
    /// Create a new session service
    pub fn new(
        session_repo: SessionRepository,
        user_repo: UserRepository,
        config: SessionConfig,
    ) -> Self {
        Self {
            session_repo,
            user_repo,
            config,
        }
    }

    /// Create a new session for a user
    ///
    /// Requirements: 7.1 - Track active sessions with user ID, IP address, user agent, and login timestamp
    pub async fn create_session(
        &self,
        user_id: Uuid,
        refresh_token: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Session, SessionError> {
        // Verify user exists
        let _user = self.user_repo.get_user_by_id(user_id).await?;

        // Hash the refresh token for storage
        let refresh_token_hash = hash_token(refresh_token);

        // Calculate expiration based on refresh token TTL
        let expires_at = Utc::now() + Duration::seconds(self.config.refresh_token_ttl);

        // Create the session
        let session = self
            .session_repo
            .create_session(
                user_id,
                &refresh_token_hash,
                ip_address,
                user_agent,
                expires_at,
            )
            .await?;

        Ok(session)
    }

    /// Terminate a specific session
    ///
    /// Requirements: 7.3, 7.5
    /// - 7.3: Allow administrators to terminate any session
    /// - 7.5: When a session is terminated, invalidate associated tokens immediately
    ///
    /// Parameters:
    /// - `session_id`: The ID of the session to terminate
    /// - `requesting_user_id`: The ID of the user making the request
    /// - `is_admin`: Whether the requesting user has admin privileges
    /// - `ip_address`: IP address of the request (for audit logging)
    /// - `user_agent`: User agent of the request (for audit logging)
    pub async fn terminate_session(
        &self,
        session_id: Uuid,
        requesting_user_id: Uuid,
        is_admin: bool,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<(), SessionError> {
        // Get the session to check ownership
        let session = self.session_repo.get_session_by_id(session_id).await?;

        // Check permission: users can only terminate their own sessions unless admin
        // Requirements: 7.4 - Allow users to view and terminate their own sessions
        if session.user_id != requesting_user_id && !is_admin {
            return Err(SessionError::PermissionDenied);
        }

        // Delete the session (this invalidates the refresh token)
        self.session_repo.delete_session(session_id).await?;

        Ok(())
    }

    /// Get all sessions for a specific user
    ///
    /// Requirements: 7.4 - Allow users to view their own sessions
    ///
    /// Parameters:
    /// - `user_id`: The ID of the user whose sessions to retrieve
    /// - `current_session_id`: Optional ID of the current session (to mark as current)
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
        current_session_id: Option<Uuid>,
    ) -> Result<Vec<SessionResponse>, SessionError> {
        let sessions = self.session_repo.get_user_sessions(user_id).await?;

        let session_responses: Vec<SessionResponse> = sessions
            .into_iter()
            .map(|session| {
                let is_current = current_session_id.map_or(false, |id| id == session.id);
                SessionResponse {
                    session,
                    is_current,
                }
            })
            .collect();

        Ok(session_responses)
    }

    /// Get all active sessions (admin view)
    ///
    /// Requirements: 7.2 - Allow administrators to view all active sessions
    ///
    /// Parameters:
    /// - `limit`: Maximum number of sessions to return
    /// - `offset`: Number of sessions to skip (for pagination)
    pub async fn get_all_sessions(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SessionResponse>, SessionError> {
        let sessions = self.session_repo.get_all_sessions(limit, offset).await?;

        // For admin view, no session is marked as "current"
        let session_responses: Vec<SessionResponse> = sessions
            .into_iter()
            .map(|session| SessionResponse {
                session,
                is_current: false,
            })
            .collect();

        Ok(session_responses)
    }

    /// Terminate all sessions for a user (force logout from all devices)
    ///
    /// Requirements: 7.5 - When a session is terminated, invalidate associated tokens immediately
    ///
    /// This is typically used when:
    /// - User changes their password
    /// - Admin forces logout of a user
    /// - Security incident response
    ///
    /// Parameters:
    /// - `user_id`: The ID of the user whose sessions to terminate
    /// - `requesting_user_id`: The ID of the user making the request
    /// - `is_admin`: Whether the requesting user has admin privileges
    /// - `ip_address`: IP address of the request (for audit logging)
    /// - `user_agent`: User agent of the request (for audit logging)
    pub async fn terminate_all_user_sessions(
        &self,
        user_id: Uuid,
        requesting_user_id: Uuid,
        is_admin: bool,
        _ip_address: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<u64, SessionError> {
        // Check permission: users can only terminate their own sessions unless admin
        if user_id != requesting_user_id && !is_admin {
            return Err(SessionError::PermissionDenied);
        }

        // Delete all sessions for the user
        let count = self.session_repo.delete_user_sessions(user_id).await?;

        Ok(count)
    }

    /// Cleanup expired sessions
    ///
    /// Requirements: 7.6 - Automatically expire sessions after configurable inactivity period
    ///
    /// This should be called periodically by a background task to remove
    /// expired sessions from the database.
    ///
    /// Returns the number of sessions that were cleaned up.
    pub async fn cleanup_expired(&self) -> Result<u64, SessionError> {
        let count = self.session_repo.cleanup_expired_sessions().await?;

        Ok(count)
    }

    /// Get session by ID
    ///
    /// Parameters:
    /// - `session_id`: The ID of the session to retrieve
    pub async fn get_session(&self, session_id: Uuid) -> Result<Session, SessionError> {
        self.session_repo
            .get_session_by_id(session_id)
            .await
            .map_err(|e| e.into())
    }

    /// Check if a session is valid (exists and not expired)
    ///
    /// Parameters:
    /// - `session_id`: The ID of the session to check
    pub async fn is_session_valid(&self, session_id: Uuid) -> Result<bool, SessionError> {
        self.session_repo
            .is_session_valid(session_id)
            .await
            .map_err(|e| e.into())
    }

    /// Count active sessions for a user
    ///
    /// Parameters:
    /// - `user_id`: The ID of the user
    pub async fn count_user_sessions(&self, user_id: Uuid) -> Result<i64, SessionError> {
        self.session_repo
            .count_user_sessions(user_id)
            .await
            .map_err(|e| e.into())
    }

    /// Count total active sessions in the system
    pub async fn count_all_sessions(&self) -> Result<i64, SessionError> {
        self.session_repo
            .count_all_sessions()
            .await
            .map_err(|e| e.into())
    }

    /// Update the last used timestamp for a session
    ///
    /// This should be called when a session is actively used (e.g., token refresh)
    /// to track activity for inactivity-based expiration.
    ///
    /// Parameters:
    /// - `session_id`: The ID of the session to update
    pub async fn touch_session(&self, session_id: Uuid) -> Result<(), SessionError> {
        self.session_repo
            .update_last_used(session_id)
            .await
            .map_err(|e| e.into())
    }
}

// Re-use the shared hash_token from auth::service
use super::service::hash_token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let token = "test-refresh-token-123";
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
    fn test_session_config_default() {
        let config = SessionConfig::default();

        assert_eq!(config.session_timeout, 86400); // 24 hours
        assert_eq!(config.refresh_token_ttl, 604800); // 7 days
    }
}
