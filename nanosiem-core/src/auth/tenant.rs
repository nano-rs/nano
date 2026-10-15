// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-authoritative tenant membership resolution for enterprise-shared.
//!
//! A slug or JWT claim is only a selector. This resolver joins that selector
//! to an active user membership and derives roles/permissions from PostgreSQL.
//! Database errors fail closed and are never converted into an empty/default
//! tenant context.

use crate::request_timing::RequestDb;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Tenant identity trusted by downstream API/search/pivt handlers.
///
/// Only authentication middleware should construct and insert this as a
/// request extension. Client headers, route slugs, and raw JWT claims are not
/// instances of this type and cannot grant membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedTenantContext {
    pub tenant_id: Uuid,
    pub tenant_slug: String,
}

/// Fully resolved membership used while issuing or authenticating a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTenantMembership {
    pub context: TrustedTenantContext,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    /// Monotonic PostgreSQL generation covering role, permission, group, and
    /// tenant-member-role authority. Downstream caches must include this exact
    /// value; a user or `(tenant,user)` key alone is not authorization state.
    pub authority_revision: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantResolutionError {
    /// The selector did not resolve to an active tenant + active membership, or
    /// a tenant/member revocation watermark invalidated the token.
    #[error("tenant access denied")]
    AccessDenied,
    /// PostgreSQL could not authoritatively resolve membership. Callers must
    /// return unavailable rather than proceeding with an empty/default scope.
    #[error("tenant membership lookup unavailable — failing closed")]
    Unavailable,
}

#[derive(Debug, FromRow)]
struct MembershipRow {
    tenant_id: Uuid,
    tenant_slug: String,
    tenant_status: String,
    member_status: String,
    tenant_tokens_valid_from: Option<DateTime<Utc>>,
    member_tokens_valid_from: Option<DateTime<Utc>>,
    roles: Vec<String>,
    permissions: Vec<String>,
    authority_revision: i64,
}

/// PostgreSQL-backed membership resolver.
///
/// Phase 1 deliberately performs an authoritative read rather than caching.
/// That makes suspension/revocation immediately visible and gives later cache
/// work a clear invariant: any cache must be tenant-keyed and have a bounded,
/// explicitly tested revocation window.
#[derive(Clone)]
pub struct TenantMembershipResolver {
    pool: PgPool,
}

impl TenantMembershipResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Read-only service delegation, matching the discovery-actor pattern in
    /// 9000520. Signed RLS contexts require a live member. A service capability
    /// caller may borrow one active settings admin solely for a tenant read;
    /// callers must authenticate their service capability before invoking this.
    /// No actor is supplied by the remote caller and no control grants widen.
    pub async fn active_system_settings_actor(&self, tenant_id: Uuid) -> Result<Option<Uuid>, sqlx::Error> {
        if tenant_id.is_nil() { return Ok(None); }
        sqlx::query_scalar(
            "SELECT member.user_id FROM public.tenant_members member \
             JOIN public.tenants tenant ON tenant.id=member.tenant_id AND tenant.status='active' \
             JOIN public.users actor ON actor.id=member.user_id AND actor.status='active' \
             WHERE member.tenant_id=$1 AND member.status='active' \
               AND EXISTS (SELECT 1 FROM public.tenant_member_roles role \
                 JOIN public.role_permissions permission ON permission.role_id=role.role_id \
                 WHERE role.tenant_id=member.tenant_id AND role.user_id=member.user_id \
                   AND permission.permission_id='settings:system') \
             ORDER BY member.user_id LIMIT 1"
        ).bind(tenant_id).fetch_optional(&self.pool).await
    }

    /// Resolve a client-provided slug as a selector, never as authority.
    pub async fn resolve_slug(
        &self,
        user_id: Uuid,
        tenant_slug: &str,
    ) -> Result<ResolvedTenantMembership, TenantResolutionError> {
        if !valid_slug(tenant_slug) {
            return Err(TenantResolutionError::AccessDenied);
        }
        self.resolve(user_id, None, Some(tenant_slug), None).await
    }

    /// NAN-3548: map a browser route slug to its tenant id so the API can pick
    /// that tenant's session cookie name. A selector only: it grants nothing,
    /// and every credential read under the resulting name is still validated
    /// and slug-bound by `resolve_bound_slug_micros`. Unknown and malformed
    /// slugs both return `None`.
    pub async fn tenant_id_for_slug(
        &self,
        tenant_slug: &str,
    ) -> Result<Option<Uuid>, TenantResolutionError> {
        if !valid_slug(tenant_slug) {
            return Ok(None);
        }
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM tenants WHERE slug = $1")
            .bind(tenant_slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "tenant slug lookup for session cookie selection failed");
                TenantResolutionError::Unavailable
            })
    }

    /// Revalidate the tenant bound into a signed access/refresh token.
    pub async fn resolve_bound(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        token_iat: i64,
    ) -> Result<ResolvedTenantMembership, TenantResolutionError> {
        self.resolve(
            user_id,
            Some(tenant_id),
            None,
            Some(CredentialTime::WholeSeconds(token_iat)),
        )
        .await
    }

    /// Revalidate a tenant-bound shared credential using its signed
    /// PostgreSQL authentication timestamp. Unlike JWT `iat`, this preserves
    /// sub-second ordering with tenant/member revocation watermarks.
    pub async fn resolve_bound_micros(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        credential_time_micros: i64,
    ) -> Result<ResolvedTenantMembership, TenantResolutionError> {
        if credential_time_micros <= 0 {
            return Err(TenantResolutionError::AccessDenied);
        }
        self.resolve(
            user_id,
            Some(tenant_id),
            None,
            Some(CredentialTime::PreciseMicros(credential_time_micros)),
        )
        .await
    }

    /// Whether a tenant session's stamped grant revision is still current for
    /// THIS session: no platform-wide (unclassified) grant revision, no grant
    /// change of the session user (in this tenant or platform-wide) and no
    /// tenant-wide change of this tenant postdates `revision`.
    ///
    /// NAN-2610: this used to compare against the global
    /// `grant_authority_version.last_grant_change_version`, so any tenant's
    /// role, member, tenant-status or source-scope write retired every other
    /// tenant's in-flight session queries. It now uses the per-actor grant
    /// history (9000175 / 9001080 / 9001620) via
    /// `nano_shared.session_grant_history_active` (9001720): the automation-key
    /// predicate of NAN-2609 with the session user as the only actor. Grant ABA
    /// of the user's own authority still fails closed. The function is callable
    /// by the control login and by a bound `job` data-path principal for its
    /// own tenant (durable runners).
    ///
    /// This only checks grant history: callers must separately revalidate the
    /// query's own credential time, membership, permissions and source scope.
    pub async fn session_grants_unchanged_since(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        revision: i64,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT $3>0 AND $3<=version \
                AND COALESCE(nano_shared.session_grant_history_active($1,$2,$3),FALSE) \
               FROM grant_authority_version WHERE singleton=TRUE",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(revision)
        .fetch_one(&self.pool)
        .request_db()
        .await
    }

    /// Revalidate a tenant-bound credential and require that the browser's
    /// canonical route selector still names the same tenant. The UUID and
    /// membership lookup remain authoritative; the slug can only narrow the
    /// result, never select a different membership.
    pub async fn resolve_bound_slug(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        token_iat: i64,
        expected_slug: &str,
    ) -> Result<ResolvedTenantMembership, TenantResolutionError> {
        if !valid_slug(expected_slug) {
            return Err(TenantResolutionError::AccessDenied);
        }
        let membership = self.resolve_bound(user_id, tenant_id, token_iat).await?;
        if membership.context.tenant_slug != expected_slug {
            return Err(TenantResolutionError::AccessDenied);
        }
        Ok(membership)
    }

    /// Precise shared-credential counterpart to `resolve_bound_slug`.
    pub async fn resolve_bound_slug_micros(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        credential_time_micros: i64,
        expected_slug: &str,
    ) -> Result<ResolvedTenantMembership, TenantResolutionError> {
        if !valid_slug(expected_slug) {
            return Err(TenantResolutionError::AccessDenied);
        }
        let membership = self
            .resolve_bound_micros(user_id, tenant_id, credential_time_micros)
            .await?;
        if membership.context.tenant_slug != expected_slug {
            return Err(TenantResolutionError::AccessDenied);
        }
        Ok(membership)
    }

    async fn resolve(
        &self,
        user_id: Uuid,
        tenant_id: Option<Uuid>,
        tenant_slug: Option<&str>,
        credential_time: Option<CredentialTime>,
    ) -> Result<ResolvedTenantMembership, TenantResolutionError> {
        let row = sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT
                t.id AS tenant_id,
                t.slug AS tenant_slug,
                t.status AS tenant_status,
                tm.status AS member_status,
                t.tokens_valid_from AS tenant_tokens_valid_from,
                tm.tokens_valid_from AS member_tokens_valid_from,
                COALESCE(
                    array_agg(DISTINCT r.name::text ORDER BY r.name::text)
                        FILTER (WHERE r.name IS NOT NULL),
                    ARRAY[]::text[]
                ) AS roles,
                COALESCE(
                    array_agg(
                        DISTINCT rp.permission_id::text ORDER BY rp.permission_id::text
                    )
                        FILTER (WHERE rp.permission_id IS NOT NULL),
                    ARRAY[]::text[]
                ) AS permissions,
                gav.version AS authority_revision
            FROM tenants t
            JOIN tenant_members tm ON tm.tenant_id = t.id
            JOIN grant_authority_version gav ON gav.singleton = TRUE
            LEFT JOIN tenant_member_roles tmr
                ON tmr.tenant_id = tm.tenant_id AND tmr.user_id = tm.user_id
            LEFT JOIN roles r ON r.id = tmr.role_id
            LEFT JOIN role_permissions rp ON rp.role_id = r.id
            WHERE tm.user_id = $1
              AND ($2::uuid IS NULL OR t.id = $2)
              AND ($3::text IS NULL OR t.slug = $3)
            GROUP BY
                t.id,
                t.slug,
                t.status,
                tm.status,
                t.tokens_valid_from,
                tm.tokens_valid_from,
                gav.version
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(tenant_slug)
        .fetch_optional(&self.pool).request_db()
        .await
        .map_err(|error| {
            tracing::error!(
                user_id = %user_id,
                tenant_id = ?tenant_id,
                tenant_slug = ?tenant_slug,
                error = %error,
                "tenant membership lookup failed — failing closed"
            );
            TenantResolutionError::Unavailable
        })?
        .ok_or(TenantResolutionError::AccessDenied)?;

        if row.tenant_status != "active"
            || row.member_status != "active"
            || row.authority_revision <= 0
        {
            return Err(TenantResolutionError::AccessDenied);
        }

        if let Some(credential_time) = credential_time {
            if predates(credential_time, row.tenant_tokens_valid_from)
                || predates(credential_time, row.member_tokens_valid_from)
            {
                return Err(TenantResolutionError::AccessDenied);
            }
        }

        Ok(ResolvedTenantMembership {
            context: TrustedTenantContext {
                tenant_id: row.tenant_id,
                tenant_slug: row.tenant_slug,
            },
            roles: row.roles,
            permissions: row.permissions,
            authority_revision: row.authority_revision,
        })
    }
}

#[derive(Clone, Copy)]
enum CredentialTime {
    WholeSeconds(i64),
    PreciseMicros(i64),
}

fn predates(credential_time: CredentialTime, watermark: Option<DateTime<Utc>>) -> bool {
    watermark.is_some_and(|watermark| match credential_time {
        // Legacy JWTs have whole-second precision. Treat the entire watermark
        // second as revoked so a token minted just before the watermark in the
        // same second cannot survive.
        CredentialTime::WholeSeconds(iat) => iat <= watermark.timestamp(),
        // Shared credentials carry the exact DB authentication fence and can
        // safely admit a re-login later in that same wall-clock second.
        CredentialTime::PreciseMicros(micros) => micros <= watermark.timestamp_micros(),
    })
}

fn valid_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase_or_digit()
        && bytes[bytes.len() - 1].is_ascii_lowercase_or_digit()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase_or_digit() || *byte == b'-')
}

trait AsciiSlugByte {
    fn is_ascii_lowercase_or_digit(&self) -> bool;
}

impl AsciiSlugByte for u8 {
    fn is_ascii_lowercase_or_digit(&self) -> bool {
        self.is_ascii_lowercase() || self.is_ascii_digit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_selector_is_narrow_and_canonical() {
        for valid in ["a", "tenant-a", "tenant9", "a-1"] {
            assert!(valid_slug(valid), "{valid}");
        }
        for invalid in [
            "", "Tenant-a", "tenant_a", "-tenant", "tenant-", "tenant/a", " tenant",
        ] {
            assert!(!valid_slug(invalid), "{invalid}");
        }
        assert!(!valid_slug(&"a".repeat(64)));
    }

    #[test]
    fn revocation_watermark_invalidates_its_whole_timestamp_second() {
        let watermark = DateTime::<Utc>::from_timestamp(1_000, 0);
        assert!(predates(CredentialTime::WholeSeconds(999), watermark));
        assert!(predates(CredentialTime::WholeSeconds(1_000), watermark));
        assert!(!predates(CredentialTime::WholeSeconds(1_001), watermark));
        assert!(!predates(CredentialTime::WholeSeconds(0), None));
    }

    #[test]
    fn precise_shared_fence_orders_relogin_inside_watermark_second() {
        let watermark = DateTime::<Utc>::from_timestamp(1_000, 500_000_000);
        assert!(predates(
            CredentialTime::PreciseMicros(1_000_499_999),
            watermark,
        ));
        assert!(predates(
            CredentialTime::PreciseMicros(1_000_500_000),
            watermark,
        ));
        assert!(!predates(
            CredentialTime::PreciseMicros(1_000_500_001),
            watermark,
        ));
    }
}
