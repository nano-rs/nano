// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cached, fail-closed user-status resolver (F-32).
//!
//! The auth middleware NEVER read the `users` row after validating a JWT — it
//! trusted the token until natural expiry (default 900s). A disabled user (or a
//! user whose password was changed) therefore kept a working access token for up
//! to that window. This resolver gives the middleware a cheap current view of
//! each user's `status` + `tokens_valid_from` watermark so it can reject:
//!
//! - any principal whose account is no longer `active` (disabled / locked /
//!   deleted), and
//! - any access token issued BEFORE a forced-revocation watermark
//!   (`users.tokens_valid_from`, stamped on disable + password change).
//!
//! FAIL-CLOSED: on a PostgreSQL error the resolver returns
//! [`UserStatusError::Unavailable`] — it NEVER falls through as "active" and
//! NEVER caches an error-path value. The caller (middleware) turns that into a
//! 503, mirroring `SourceScopeResolver`'s fail-closed posture.
//!
//! NAN-3904: the row is read on EVERY request (one primary-key lookup) rather
//! than cached for 30s. A forced revocation — disable, password change, or an
//! SSO group shrink that stamps `tokens_valid_from` and bumps
//! `authz_generation` — therefore takes effect on the next request on every
//! replica, with no cross-process staleness window.
//!
//! Like the source-scope resolver it INVERTS the permission resolver's failure
//! behaviour: permission resolution caches an empty set on error (safe for an
//! ADD-only permission model); a status gate must never answer a stale
//! "active".

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;


/// Errors from user-status resolution.
#[derive(Debug, thiserror::Error)]
pub enum UserStatusError {
    /// The user row could not be read and there is no safe answer — the caller
    /// MUST fail closed (respond 503), never proceed as if the user were active.
    #[error("user-status lookup unavailable — failing closed")]
    Unavailable,
}

/// Point-in-time view of a user's gate-relevant state.
#[derive(Debug, Clone)]
pub struct UserStatusSnapshot {
    /// `users.status` — `active` is the only value that passes the gate. An
    /// unknown/deleted user is represented by an empty string (never active).
    pub status: String,
    /// `users.tokens_valid_from` — forced-revocation watermark. `None` means no
    /// forced revocation has ever happened for this user.
    pub tokens_valid_from: Option<DateTime<Utc>>,
    /// `users.authz_generation` at read time (NAN-3904).
    pub authz_generation: Option<i64>,
}

impl UserStatusSnapshot {
    /// True only when the account is `active`.
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// True when a token issued at `iat` (unix seconds) predates the forced
    /// revocation watermark, i.e. it was minted before the user was disabled or
    /// changed their password and must be rejected. No watermark → never
    /// revoked (back-compat for users who were never disabled).
    pub fn token_predates_revocation(&self, iat: i64) -> bool {
        match self.tokens_valid_from {
            Some(watermark) => iat < watermark.timestamp(),
            None => false,
        }
    }
}


/// Fail-closed resolver of per-user status + revocation watermark.
///
/// Cheap to clone so it can live in `AuthState`.
#[derive(Clone)]
pub struct UserStatusResolver {
    pool: PgPool,
}

impl UserStatusResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Resolve the current [`UserStatusSnapshot`] for a user (read on every
    /// call, NAN-3904).
    ///
    /// FAIL-CLOSED: on a PostgreSQL error this returns
    /// [`UserStatusError::Unavailable`] (caller → 503). A missing user row is a
    /// definitive "not active".
    pub async fn resolve(&self, user_id: Uuid) -> Result<UserStatusSnapshot, UserStatusError> {
        // NAN-3904: read on every request — see the module docs.
        match sqlx::query_as::<_, (String, Option<DateTime<Utc>>, i64)>(
            "SELECT status, tokens_valid_from, authz_generation FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(Some((status, tokens_valid_from, authz_generation))) => {
                let snapshot = UserStatusSnapshot {
                    status,
                    tokens_valid_from,
                    authz_generation: Some(authz_generation),
                };
                Ok(snapshot)
            }
            // Deleted/unknown user holding a still-valid token: definitively not
            // active.
            Ok(None) => {
                let snapshot = UserStatusSnapshot {
                    status: String::new(),
                    tokens_valid_from: None,
                    authz_generation: None,
                };
                Ok(snapshot)
            }
            // F-32: FAIL CLOSED — never treat an unreadable status as active.
            // The middleware turns this into a 503.
            Err(e) => {
                tracing::error!(user_id = %user_id, error = %e, "user-status lookup failed — failing closed");
                Err(UserStatusError::Unavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(status: &str, tvf: Option<DateTime<Utc>>) -> UserStatusSnapshot {
        UserStatusSnapshot {
            status: status.to_string(),
            tokens_valid_from: tvf,
            authz_generation: None,
        }
    }

    #[test]
    fn only_active_status_passes() {
        assert!(snap("active", None).is_active());
        assert!(!snap("disabled", None).is_active());
        assert!(!snap("locked", None).is_active());
        assert!(!snap("", None).is_active()); // deleted/unknown
        assert!(!snap("system", None).is_active());
    }

    #[test]
    fn token_before_watermark_is_revoked() {
        let watermark = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        let s = snap("active", Some(watermark));
        // Issued before the watermark → revoked.
        assert!(s.token_predates_revocation(999));
        // Issued exactly at / after the watermark → still valid.
        assert!(!s.token_predates_revocation(1_000));
        assert!(!s.token_predates_revocation(1_001));
    }

    #[test]
    fn no_watermark_never_revokes() {
        let s = snap("active", None);
        assert!(!s.token_predates_revocation(0));
        assert!(!s.token_predates_revocation(i64::MAX));
    }
}
