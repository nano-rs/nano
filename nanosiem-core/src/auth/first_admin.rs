// SPDX-License-Identifier: AGPL-3.0-or-later

//! First-admin setup: who may call `POST /api/setup/initialize`, and the
//! atomic claim it performs (NAN-5237).
//!
//! # Admission
//!
//! While the system is uninitialized, the setup endpoint creates an Admin for
//! whoever calls it, so it must not be open to anyone who can reach the host.
//!
//! * **Setup token configured** (`NANO_SETUP_TOKEN`; install.sh and the Helm
//!   chart always generate one): the caller must present
//!   `Authorization: Bearer <token>`, compared in constant time. The loopback
//!   rule below does not apply: with a token configured, the token is the
//!   only way in.
//! * **No token configured** (a hand-run dev compose, an install whose `.env`
//!   predates the token): only a caller on the API host itself is accepted —
//!   the TCP peer (never a forwarded-for header) must be loopback AND the
//!   request must carry no forwarding header at all (`Forwarded`,
//!   `X-Forwarded-*`, `X-Real-IP`, CDN client-IP headers). A same-host reverse
//!   proxy makes every request arrive from loopback, and every nginx edge nano
//!   ships adds `X-Real-IP` / `X-Forwarded-For`, so anything that came
//!   through an edge is refused. Fail closed: a missing peer address is
//!   refused too. An operator running their own same-host proxy that strips
//!   forwarding headers must set `NANO_SETUP_TOKEN`.
//!
//! The token is never logged and never returned; `Debug` redacts it.
//!
//! # Claim
//!
//! [`claim_first_admin`] runs the whole initialization in ONE PostgreSQL
//! transaction under `pg_advisory_xact_lock(FIRST_ADMIN_CLAIM_LOCK_KEY)`:
//! re-check initialized + users, create the user, the Admins group and the
//! membership, mark the system initialized, commit. A concurrent caller
//! waits on the lock, then sees the committed state and gets
//! [`FirstAdminError::AlreadyInitialized`] / [`FirstAdminError::UsersExist`].

use std::net::IpAddr;

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::repository::{UserRepository, UserRepositoryError};
use crate::auth::service_credential::{constant_time_eq, is_loopback};
use crate::auth::types::{builtin_groups, builtin_roles, config_keys, CreateUserRequest, User};

/// Env var holding the installer-generated setup token.
pub const SETUP_TOKEN_ENV: &str = "NANO_SETUP_TOKEN";

/// Advisory lock serializing first-admin claims ("nano" + 5237).
pub const FIRST_ADMIN_CLAIM_LOCK_KEY: i64 = 0x6e61_6e6f_5237;

/// The configured setup token, if any. `Debug` never prints the value.
#[derive(Clone, Default)]
pub struct SetupToken {
    token: Option<String>,
}

impl std::fmt::Debug for SetupToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupToken")
            .field("configured", &self.token.is_some())
            .finish()
    }
}

/// How a setup caller was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupAdmission {
    /// Presented the configured setup token.
    Token,
    /// No token configured; a direct loopback caller.
    Loopback,
}

/// Why a setup caller was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupRefusal {
    /// A token is configured and no bearer was presented (HTTP 401).
    TokenMissing,
    /// A token is configured and the presented bearer is wrong (HTTP 403).
    TokenInvalid,
    /// No token is configured and the caller is not a direct loopback
    /// caller (HTTP 403).
    NotLocal,
    /// The configured token is a shipped `CHANGE_ME*` placeholder, which
    /// protects nothing; nothing is accepted until it is replaced (HTTP 403).
    TokenPlaceholder,
}

impl SetupToken {
    /// Empty / whitespace-only values count as unset.
    pub fn new(token: Option<String>) -> Self {
        Self {
            token: token
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty()),
        }
    }

    /// `NANO_SETUP_TOKEN`.
    pub fn from_env() -> Self {
        Self::new(std::env::var(SETUP_TOKEN_ENV).ok())
    }

    pub fn is_configured(&self) -> bool {
        self.token.is_some()
    }

    /// Decide whether a caller may run first-admin setup.
    ///
    /// `authorization` is the single `Authorization` header value (`None`
    /// when absent, repeated or not UTF-8). `peer` is the TCP peer address.
    /// `forwarded` is true when the request carries any forwarding header.
    pub fn admit(
        &self,
        authorization: Option<&str>,
        peer: Option<IpAddr>,
        forwarded: bool,
    ) -> Result<SetupAdmission, SetupRefusal> {
        match &self.token {
            Some(expected) if crate::known_public_secrets::is_placeholder(expected) => {
                Err(SetupRefusal::TokenPlaceholder)
            }
            Some(expected) => {
                let presented = authorization
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or(SetupRefusal::TokenMissing)?;
                if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
                    Ok(SetupAdmission::Token)
                } else {
                    Err(SetupRefusal::TokenInvalid)
                }
            }
            None if !forwarded && peer.is_some_and(is_loopback) => Ok(SetupAdmission::Loopback),
            None => Err(SetupRefusal::NotLocal),
        }
    }
}

#[derive(Error, Debug)]
pub enum FirstAdminError {
    #[error("system has already been initialized")]
    AlreadyInitialized,
    #[error("users already exist")]
    UsersExist,
    #[error(transparent)]
    User(#[from] UserRepositoryError),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Whether the `system_initialized` flag is set.
pub async fn is_system_initialized<'e, E>(executor: E) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let value = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_config WHERE key = $1",
    )
    .bind(config_keys::SYSTEM_INITIALIZED)
    .fetch_optional(executor)
    .await?;
    Ok(value.and_then(|v| v.as_bool()).unwrap_or(false))
}

/// Whether any human user exists (system service accounts excluded).
pub async fn has_human_users<'e, E>(executor: E) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM users WHERE status != 'system')")
        .fetch_one(executor)
        .await
}

/// Create the first Admin atomically. See the module docs.
///
/// The caller has authorized the request; this function guarantees that at
/// most one caller ever succeeds.
pub async fn claim_first_admin(
    pool: &PgPool,
    request: &CreateUserRequest,
) -> Result<User, FirstAdminError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(FIRST_ADMIN_CLAIM_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    if is_system_initialized(&mut *tx).await? {
        return Err(FirstAdminError::AlreadyInitialized);
    }
    if has_human_users(&mut *tx).await? {
        return Err(FirstAdminError::UsersExist);
    }

    let user = UserRepository::create_user_in(&mut tx, request).await?;
    let admins_group_id = ensure_admins_group_in(&mut tx).await?;
    UserRepository::replace_user_groups_in(
        &mut tx,
        user.id,
        &[admins_group_id, builtin_groups::EVERYONE_ID],
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO system_config (key, value, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
        "#,
    )
    .bind(config_keys::SYSTEM_INITIALIZED)
    .bind(serde_json::json!(true))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(user)
}

/// The Admins group (created with the Admin role when absent).
async fn ensure_admins_group_in(conn: &mut sqlx::PgConnection) -> Result<Uuid, sqlx::Error> {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE name = 'Admins'")
        .fetch_optional(&mut *conn)
        .await?
    {
        return Ok(id);
    }
    let group_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO groups (name, description, is_system)
        VALUES ('Admins', 'System administrators with full access', FALSE)
        RETURNING id
        "#,
    )
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(builtin_roles::ADMIN_ID)
    .execute(&mut *conn)
    .await?;
    Ok(group_id)
}
