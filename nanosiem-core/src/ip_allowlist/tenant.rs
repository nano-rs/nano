// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosted tenant policy admission after authoritative tenant authentication.
//! Never accepts a client tenant selector or an environment-variable bypass.

use std::{net::IpAddr, time::Duration};
use sqlx::PgPool;
use crate::request_timing::RequestDb;
use crate::auth::TrustedTenantContext;

#[derive(Debug, Clone, Copy)]
pub enum TenantIpPolicyScope { Api, Search }

impl TenantIpPolicyScope {
    fn as_str(self) -> &'static str {
        match self { Self::Api => "api", Self::Search => "search" }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantIpPolicyError {
    #[error("Client IP is not permitted by tenant access policy")]
    Denied,
    #[error("Tenant access policy is temporarily unavailable")]
    Unavailable,
}

/// The caller supplies a tenant resolved from verified membership or a
/// validated tenant automation key, not a raw request header/slug/claim.
/// Reads are uncached so policy changes do not inherit a global cache window.
pub async fn require_tenant_ip_allowed(
    pool: &PgPool,
    tenant: &TrustedTenantContext,
    client_ip: Option<IpAddr>,
    scope: TenantIpPolicyScope,
) -> Result<(), TenantIpPolicyError> {
    let ip = client_ip.ok_or(TenantIpPolicyError::Denied)?;
    if tenant.tenant_id.is_nil() { return Err(TenantIpPolicyError::Unavailable); }
    // NAN-2361: the caller maps `Unavailable` to a bare 503; the SQL error
    // (a missing EXECUTE grant on `nano_shared.check_tenant_ip_policy`, a
    // dropped function, a pool timeout) is only visible here, so name it.
    let allowed = tokio::time::timeout(Duration::from_secs(2),
        sqlx::query_scalar::<_, bool>("SELECT nano_shared.check_tenant_ip_policy($1,$2::text::inet,$3)")
            .bind(tenant.tenant_id).bind(ip.to_string()).bind(scope.as_str()).fetch_one(pool).request_db(),
    ).await.map_err(|_| {
        tracing::error!(tenant_id = %tenant.tenant_id, scope = scope.as_str(),
            "tenant IP policy check timed out after 2s — failing closed");
        TenantIpPolicyError::Unavailable
    })?
        .map_err(|error| {
            tracing::error!(tenant_id = %tenant.tenant_id, scope = scope.as_str(), error = %error,
                "tenant IP policy check failed (nano_shared.check_tenant_ip_policy) — failing closed");
            TenantIpPolicyError::Unavailable
        })?;
    if allowed { Ok(()) } else { Err(TenantIpPolicyError::Denied) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tenant_policy_missing_ip_or_database_never_admits() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture:fixture@127.0.0.1:1/never_connect").unwrap();
        pool.close().await;
        let tenant = TrustedTenantContext { tenant_id: uuid::Uuid::new_v4(), tenant_slug: "fixture".into() };
        assert_eq!(require_tenant_ip_allowed(&pool, &tenant, None, TenantIpPolicyScope::Api).await,
            Err(TenantIpPolicyError::Denied));
        for ip in ["203.0.113.5", "127.0.0.1", "::1"] {
            assert_eq!(require_tenant_ip_allowed(&pool, &tenant, Some(ip.parse().unwrap()), TenantIpPolicyScope::Search).await,
                Err(TenantIpPolicyError::Unavailable));
        }
    }
}
