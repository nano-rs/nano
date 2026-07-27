// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local password authentication toggle (NAN-2181)
//!
//! Tenant-level control over whether local email/password sign-in is accepted.
//! When disabled, users must authenticate through a configured OIDC provider.
//!
//! The flag is stored on the `system_settings` singleton and read by
//! [`AuthService::login`](crate::auth::service::AuthService::login), which is
//! the security boundary. Hiding the password field in the UI is presentation,
//! not enforcement — the login endpoint rejects the attempt regardless of what
//! the client renders.
//!
//! Scope is deliberately narrow. Only local password login consults this flag.
//! OIDC login, token refresh, logout, active sessions, API keys, service
//! authentication, and bootstrap/setup are not local password login, and
//! gating them here would remove the recovery paths an administrator needs
//! when SSO itself is what broke.

use sqlx::PgPool;

/// Errors for the local-auth settings repository.
#[derive(Debug, thiserror::Error)]
pub enum LocalAuthSettingsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Reads and writes the local-password-auth toggle on `system_settings`.
#[derive(Clone)]
pub struct LocalAuthSettings {
    pool: PgPool,
}

impl LocalAuthSettings {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Whether local email/password sign-in is currently accepted.
    ///
    /// A missing singleton row means a database that predates any settings
    /// write — a fresh install — which defaults to enabled, matching the
    /// column default and preserving current behavior.
    ///
    /// A genuine database error propagates rather than defaulting. Login
    /// cannot succeed without the database anyway (user lookup, password
    /// hash), so surfacing the error costs no availability and avoids
    /// answering "is SSO-only on?" with a guess.
    pub async fn is_local_password_enabled(&self) -> Result<bool, LocalAuthSettingsError> {
        let row = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT local_password_auth_enabled
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.unwrap_or(true))
    }

    /// Set the toggle, creating the singleton row if it does not exist yet.
    ///
    /// Callers are responsible for the lockout guard (at least one enabled
    /// OIDC provider before disabling local auth) — that check needs the OIDC
    /// service, which lives in the enterprise crate, so it cannot be enforced
    /// from here without inverting the dependency.
    pub async fn set_local_password_enabled(
        &self,
        enabled: bool,
    ) -> Result<(), LocalAuthSettingsError> {
        sqlx::query(
            r#"
            INSERT INTO system_settings (id, local_password_auth_enabled)
            VALUES ('default', $1)
            ON CONFLICT (id) DO UPDATE
                SET local_password_auth_enabled = EXCLUDED.local_password_auth_enabled,
                    updated_at = now()
            "#,
        )
        .bind(enabled)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
