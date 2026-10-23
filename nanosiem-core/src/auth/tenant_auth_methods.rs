// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant authentication methods for hosted-shared tenants (NAN-2361
//! wave 8, the NAN-2181 "SSO-only" toggle).
//!
//! Dedicated deployments keep the toggle on the `system_settings` singleton
//! ([`crate::settings::LocalAuthSettings`]). On the shared product that row is
//! deployment-global and is ignored; the tenant's own value lives in
//! `shared_tenant_auth_methods` (enterprise migration 9001020), a
//! control-plane table reached only through SECURITY DEFINER capabilities:
//!
//! * the admin surface (`GET/PUT /api/settings/auth-methods`) runs inside a
//!   signed tenant transaction and calls `read_` / `lock_` /
//!   `set_tenant_auth_methods`, which re-prove the signed tenant/actor, the
//!   actor's membership and the tenant permission before touching the row;
//!   the mutation and its audit row commit together;
//! * the login path (`AuthService::login`) reads the flag through the control
//!   login before any tenant context exists. The step-up SSO admin service
//!   reads its tenant's flag inside its authorized control transaction.
//!
//! The lockout guard is the dedicated one, verbatim (`auth_methods_change_allowed`
//! / `removal_would_lock_out`, previously private to the dedicated OIDC admin
//! handler): SSO-only needs at least one enabled provider, re-enabling
//! password sign-in is always allowed, and the last enabled provider cannot be
//! removed while SSO-only is on. This module lives outside the `enterprise`
//! feature because `AuthService::login` (open-core) is the enforcement point;
//! on a deployment without the shared tables the functions are never called.

use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::audit::{
    append_tenant_audit_in_transaction, AuditEmitError, AuditEvent, AuditSource, ClientContext,
    SYSTEM_SETTINGS_UPDATED,
};
use crate::auth::TrustedTenantContext;

/// SQLSTATE raised by `nano_shared.set_tenant_auth_methods` when SSO-only is
/// requested with no enabled provider (the dedicated handler's
/// `no_enabled_provider` 409).
pub const NO_ENABLED_PROVIDER_SQLSTATE: &str = "N2181";

/// May the tenant move to this local-password setting given its provider set?
///
/// Re-enabling is always permitted — it is the recovery direction, and blocking
/// it would turn a misconfiguration into a permanent lockout.
pub fn auth_methods_change_allowed(
    requested_local_password_enabled: bool,
    enabled_provider_count: usize,
) -> bool {
    requested_local_password_enabled || enabled_provider_count > 0
}

/// Would removing `target` from the enabled set leave the tenant with no way in?
///
/// True only when password sign-in is already off *and* `target` is the last
/// enabled provider. Counting providers other than `target` answers "would
/// anything be left?" rather than "is more than one configured?" — a tenant
/// with two providers where one is already disabled must still be protected.
pub fn removal_would_lock_out(
    local_password_enabled: bool,
    enabled_provider_ids: &[Uuid],
    target: Uuid,
) -> bool {
    if local_password_enabled {
        return false;
    }
    !enabled_provider_ids.iter().any(|id| *id != target)
}

/// The tenant's current configuration, in the dedicated admin shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TenantAuthMethods {
    pub local_password_enabled: bool,
    pub enabled_provider_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantAuthMethodsError {
    #[error("tenant auth methods access denied")]
    AccessDenied,
    /// SSO-only requested with no enabled provider to fall back to.
    #[error("Enable at least one SSO provider before disabling password sign-in.")]
    NoEnabledProvider,
    #[error("{0}")]
    InvalidInput(String),
    #[error("tenant auth methods audit persistence failed")]
    Audit(#[from] AuditEmitError),
    #[error("tenant auth methods transaction failed")]
    Database(#[source] sqlx::Error),
}

impl From<sqlx::Error> for TenantAuthMethodsError {
    fn from(error: sqlx::Error) -> Self {
        let Some(db) = error.as_database_error() else { return Self::Database(error) };
        match db.code().as_deref() {
            Some("42501") => Self::AccessDenied,
            Some("22023") => Self::InvalidInput(db.message().to_string()),
            Some(NO_ENABLED_PROVIDER_SQLSTATE) => Self::NoEnabledProvider,
            _ => Self::Database(error),
        }
    }
}

impl TenantAuthMethodsError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Database(error) if error
            .as_database_error()
            .and_then(|e| e.code())
            .is_some_and(|c| c == "40001" || c == "40P01"))
    }
}

fn require(tenant: &TrustedTenantContext, actor_id: Uuid) -> Result<(), TenantAuthMethodsError> {
    if tenant.tenant_id.is_nil() || actor_id.is_nil() {
        return Err(TenantAuthMethodsError::AccessDenied);
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct ReadRow {
    local_password_enabled: bool,
    enabled_provider_count: i64,
}

#[derive(sqlx::FromRow)]
struct LockRow {
    local_password_enabled: bool,
    enabled_provider_count: i64,
    actor_sso_linked: bool,
    revision: i64,
}

#[derive(sqlx::FromRow)]
struct SetRow {
    previous: bool,
    local_password_enabled: bool,
    enabled_provider_count: i64,
    revision: i64,
}

/// `GET /api/settings/auth-methods` (settings:view) inside the signed tenant
/// transaction.
pub async fn read_tenant_auth_methods_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &TrustedTenantContext,
    actor_id: Uuid,
) -> Result<TenantAuthMethods, TenantAuthMethodsError> {
    require(tenant, actor_id)?;
    let row = sqlx::query_as::<_, ReadRow>("SELECT * FROM nano_shared.read_tenant_auth_methods($1,$2)")
        .bind(tenant.tenant_id)
        .bind(actor_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(TenantAuthMethods {
        local_password_enabled: row.local_password_enabled,
        enabled_provider_count: usize::try_from(row.enabled_provider_count).unwrap_or(0),
    })
}

/// `PUT /api/settings/auth-methods` (settings:system) inside the signed tenant
/// transaction: lock the setting row and the tenant's enabled providers, apply
/// the dedicated lockout guard against that stable set, write, and append the
/// audit row. All of it commits (or rolls back) together.
pub async fn set_tenant_auth_methods_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &TrustedTenantContext,
    actor_id: Uuid,
    local_password_enabled: bool,
    client: &ClientContext,
) -> Result<TenantAuthMethods, TenantAuthMethodsError> {
    require(tenant, actor_id)?;
    let locked = sqlx::query_as::<_, LockRow>("SELECT * FROM nano_shared.lock_tenant_auth_methods($1,$2)")
        .bind(tenant.tenant_id)
        .bind(actor_id)
        .fetch_one(&mut **tx)
        .await?;
    let enabled_provider_count = usize::try_from(locked.enabled_provider_count).unwrap_or(0);
    // Turning password sign-in off with no working alternative locks the tenant
    // out of itself. Re-enabling is always allowed — it is the recovery
    // direction and must never be blocked. (The SQL capability re-checks this;
    // the Rust check is the dedicated guard, verbatim.)
    if !auth_methods_change_allowed(local_password_enabled, enabled_provider_count) {
        return Err(TenantAuthMethodsError::NoEnabledProvider);
    }
    let written = sqlx::query_as::<_, SetRow>("SELECT * FROM nano_shared.set_tenant_auth_methods($1,$2,$3)")
        .bind(tenant.tenant_id)
        .bind(actor_id)
        .bind(local_password_enabled)
        .fetch_one(&mut **tx)
        .await?;
    debug_assert_eq!(written.previous, locked.local_password_enabled);
    let event = AuditEvent::builder(AuditSource::Oidc, SYSTEM_SETTINGS_UPDATED)
        .actor(Some(actor_id), None)
        .resource("auth_methods", None, Some("auth_methods".to_string()))
        .client_context(client)
        .details(serde_json::json!({
            "setting": "local_password_auth_enabled",
            "tenant_id": tenant.tenant_id,
            "previous": written.previous,
            "current": written.local_password_enabled,
            // Recorded at decision time: this is the fallback the change was
            // authorized against, and it is what an incident reviewer needs
            // to judge whether the tenant had a way back in.
            "enabled_provider_count": written.enabled_provider_count,
            // Whether the administrator making the change can themselves sign
            // in through one of the tenant's providers (an SSO-linked identity).
            "actor_sso_linked": locked.actor_sso_linked,
            "revision": written.revision,
            "previous_revision": locked.revision,
        }))
        .build();
    append_tenant_audit_in_transaction(tx, tenant, &event).await?;
    Ok(TenantAuthMethods {
        local_password_enabled: written.local_password_enabled,
        enabled_provider_count: usize::try_from(written.enabled_provider_count).unwrap_or(0),
    })
}

/// Whether `/t/<slug>/login` accepts local email/password credentials. Read on
/// the control login before any user lookup, exactly where the dedicated check
/// sits, so an SSO-only tenant answers the same for every request and is not
/// an account oracle. Unknown slug / no row read as enabled: the login flow
/// then fails on membership exactly as it does today.
pub async fn tenant_login_local_password_enabled(
    pool: &PgPool,
    tenant_slug: &crate::auth::CanonicalTenantOidcSlug,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT nano_shared.tenant_login_local_password_enabled($1)")
        .bind(tenant_slug.as_str())
        .fetch_one(pool)
        .await
}

/// The same flag by tenant id for login-page discovery (control login).
/// Authorized SSO admin mutations read the setting in their own transaction.
pub async fn tenant_local_password_enabled<'e, E>(executor: E, tenant_id: Uuid) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar::<_, bool>("SELECT nano_shared.tenant_local_password_enabled($1)")
        .bind(tenant_id)
        .fetch_one(executor)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn removal_is_unrestricted_while_password_signin_works() {
        assert!(!removal_would_lock_out(true, &[id(1)], id(1)));
        assert!(!removal_would_lock_out(true, &[], id(1)));
    }

    #[test]
    fn removing_the_last_enabled_provider_locks_out_an_sso_only_tenant() {
        assert!(removal_would_lock_out(false, &[id(1)], id(1)));
    }

    #[test]
    fn removal_is_allowed_while_another_enabled_provider_remains() {
        assert!(!removal_would_lock_out(false, &[id(1), id(2)], id(1)));
        assert!(!removal_would_lock_out(false, &[id(1), id(2)], id(2)));
    }

    #[test]
    fn a_second_but_disabled_provider_is_not_a_fallback() {
        assert!(removal_would_lock_out(false, &[id(1)], id(1)));
    }

    #[test]
    fn removing_an_already_disabled_provider_is_not_blocked() {
        assert!(!removal_would_lock_out(false, &[id(2)], id(1)));
    }

    #[test]
    fn an_sso_only_tenant_with_no_enabled_providers_still_blocks_removal() {
        assert!(removal_would_lock_out(false, &[], id(1)));
    }

    #[test]
    fn sso_only_mode_requires_an_enabled_provider() {
        assert!(!auth_methods_change_allowed(false, 0));
        assert!(auth_methods_change_allowed(false, 1));
        assert!(auth_methods_change_allowed(false, 3));
    }

    #[test]
    fn re_enabling_password_signin_is_always_allowed() {
        assert!(auth_methods_change_allowed(true, 0));
        assert!(auth_methods_change_allowed(true, 1));
    }

    #[test]
    fn nil_tenant_or_actor_is_denied_before_any_query() {
        let tenant = TrustedTenantContext { tenant_id: Uuid::nil(), tenant_slug: "acme".into() };
        assert!(matches!(require(&tenant, id(1)), Err(TenantAuthMethodsError::AccessDenied)));
        let tenant = TrustedTenantContext { tenant_id: id(7), tenant_slug: "acme".into() };
        assert!(matches!(require(&tenant, Uuid::nil()), Err(TenantAuthMethodsError::AccessDenied)));
        assert!(require(&tenant, id(1)).is_ok());
    }

    #[test]
    fn retryable_only_for_serialization_and_deadlock() {
        assert!(!TenantAuthMethodsError::AccessDenied.is_retryable());
        assert!(!TenantAuthMethodsError::NoEnabledProvider.is_retryable());
        assert!(!TenantAuthMethodsError::Database(sqlx::Error::RowNotFound).is_retryable());
    }
}
