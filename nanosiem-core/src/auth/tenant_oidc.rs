// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed OIDC authority substrate for hosted shared.
//!
//! This is intentionally separate from the dedicated OIDC repository. Shared
//! provider slugs are tenant-local selectors, browser state is only an opaque
//! lookup key. Identities link to active invited members or group-admitted JIT
//! memberships through a tenant-scoped capability and provenance reconciliation.

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "enterprise")]
use super::{service::hash_token, TokenService};
use super::{
    tenant::{ResolvedTenantMembership, TenantMembershipResolver, TrustedTenantContext},
    TokenPair,
};
use crate::tenant_entitlements::{
    TenantComponent, TenantEntitlementResolver, TenantEntitlementSnapshot,
};

const AUTH_TRANSACTION_TTL_SECONDS: i64 = 300;
const MAX_ENTRY_TTL_SECONDS: i64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTenantOidcSlug(String);

impl CanonicalTenantOidcSlug {
    pub fn parse(value: &str) -> Result<Self, TenantOidcError> {
        if value.is_empty()
            || value.len() > 63
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || value.starts_with('-')
            || value.ends_with('-')
        {
            return Err(TenantOidcError::InvalidSelector);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Redirect validated against the API's configured canonical origin. The
/// callback never gets to replace this value; it is loaded from the consumed
/// server transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalOidcRedirect(String);

impl CanonicalOidcRedirect {
    pub fn parse(value: &str, allowed_origin: &str) -> Result<Self, TenantOidcError> {
        if value.len() > 2048 || allowed_origin.len() > 2048 {
            return Err(TenantOidcError::InvalidRedirect);
        }
        let redirect = url::Url::parse(value).map_err(|_| TenantOidcError::InvalidRedirect)?;
        let allowed =
            url::Url::parse(allowed_origin).map_err(|_| TenantOidcError::InvalidRedirect)?;
        if redirect.scheme() != "https"
            || allowed.scheme() != "https"
            || redirect.scheme() != allowed.scheme()
            || redirect.host_str() != allowed.host_str()
            || redirect.port_or_known_default() != allowed.port_or_known_default()
            || redirect.username() != ""
            || redirect.password().is_some()
            || redirect.fragment().is_some()
        {
            return Err(TenantOidcError::InvalidRedirect);
        }
        Ok(Self(redirect.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SHA-256 digest of an opaque entry generated and delivered by the platform.
///
/// The registration substrate accepts only this pre-hashed value. It has no
/// plaintext constructor and deliberately omits `Debug`/serialization so it
/// cannot be emitted by routine request or error tracing.
#[derive(Clone, PartialEq, Eq)]
pub struct PrehashedTenantOidcEntryDigest(Vec<u8>);

impl PrehashedTenantOidcEntryDigest {
    pub fn from_sha256_bytes(value: &[u8]) -> Result<Self, TenantOidcError> {
        if value.len() != 32 || value.iter().all(|byte| *byte == 0) {
            return Err(TenantOidcError::InvalidEntryRegistration);
        }
        Ok(Self(value.to_vec()))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Private owner-plane registration input. All identity fields are exact
/// server-owned database identifiers; none may be selected by the browser.
/// This type contains a bearer-derived digest and therefore has no `Debug`.
pub struct TenantOidcEntryRegistration {
    pub entry_digest: PrehashedTenantOidcEntryDigest,
    pub tenant_id: Uuid,
    pub provider_id: Uuid,
    pub registration_request_id: Uuid,
    pub idempotency_key: Uuid,
    pub expires_at: DateTime<Utc>,
    pub intended_user_id: Option<Uuid>,
    pub intended_email: Option<String>,
}

/// Nonsecret registration receipt suitable for private owner-plane audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOidcEntryReceipt {
    pub entry_id: Uuid,
    pub tenant_id: Uuid,
    pub provider_id: Uuid,
    pub registration_request_id: Uuid,
    pub idempotency_key: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// Minimal pre-auth login label. Tenant/provider selectors remain
/// non-authoritative; no issuer, client identity, or credential leaves the
/// repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOidcLoginProvider {
    pub slug: String,
    pub name: String,
}

/// Non-secret authorization metadata returned to the shared authorize handler.
/// The PKCE verifier never leaves PostgreSQL.
// Contains the one-time authorization state and nonce. Deliberately omit
// `Debug`/serialization so routine tracing cannot disclose either value.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantOidcAuthorization {
    pub tenant: TrustedTenantContext,
    pub provider_id: Uuid,
    pub provider_slug: String,
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub group_claim: Option<String>,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub redirect_uri: String,
    pub authority_revision: i64,
}

/// A consumed callback transaction. It is deliberately non-serializable and
/// non-Debug because it carries the PKCE verifier and encrypted client secret.
pub struct ConsumedTenantOidcAuthorization {
    tenant: TrustedTenantContext,
    provider_id: Uuid,
    provider_slug: String,
    issuer: String,
    client_id: String,
    client_secret_encrypted: Vec<u8>,
    group_claim: Option<String>,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    expires_at: DateTime<Utc>,
    intended_user_id: Option<Uuid>,
    intended_email: Option<String>,
    provider_revision: i64,
    secret_revision: i64,
    access_policy: super::SsoAccessPolicy,
    google_service_account_encrypted: Option<Vec<u8>>,
}

impl ConsumedTenantOidcAuthorization {
    pub fn access_policy(&self) -> &super::SsoAccessPolicy {
        &self.access_policy
    }
    pub fn tenant(&self) -> &TrustedTenantContext {
        &self.tenant
    }

    pub fn provider_id(&self) -> Uuid {
        self.provider_id
    }

    pub fn provider_slug(&self) -> &str {
        &self.provider_slug
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn group_claim(&self) -> Option<&str> {
        self.group_claim.as_deref()
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn intended_user_id(&self) -> Option<Uuid> {
        self.intended_user_id
    }

    pub fn intended_email(&self) -> Option<&str> {
        self.intended_email.as_deref()
    }
}

/// Claims accepted only after the existing OIDC validator has verified the ID
/// token signature, issuer, audience, expiration, and transaction nonce.
pub struct ValidatedTenantOidcIdentity {
    subject: String,
    email: String,
    email_verified: bool,
    display_name: String,
    groups: Vec<String>,
}

impl ValidatedTenantOidcIdentity {
    /// The IdP `sub` of this verified ID token (audit naming, NAN-4547).
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The IdP-asserted e-mail (or UPN) of this verified ID token.
    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn from_verified_id_token(
        subject: String,
        email: String,
        email_verified: bool,
        display_name: String,
        groups: Vec<String>,
    ) -> Result<Self, TenantOidcError> {
        if subject.is_empty()
            || subject.len() > 2048
            || email.trim().is_empty()
            || email.len() > 320
            || display_name.trim().is_empty()
            || display_name.len() > 512
            || groups.len() > 2048
            || groups
                .iter()
                .any(|group| group.trim().is_empty() || group.len() > 512)
        {
            return Err(TenantOidcError::InvalidIdentity);
        }
        Ok(Self {
            subject,
            email,
            email_verified,
            display_name,
            groups,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOidcMemberIdentity {
    pub tenant: TrustedTenantContext,
    pub provider_id: Uuid,
    pub user_id: Uuid,
    // These revisions are copied only from the consumed server transaction.
    // Keeping them private prevents an HTTP adapter from upgrading stale IdP
    // authority to the provider's current credential revision.
    provider_revision: i64,
    secret_revision: i64,
    /// Tenant-local roles selected by this provider's exact group mappings.
    /// Session issuance still re-resolves membership and its effective roles;
    /// these IDs have been persisted by the source-aware reconciler.
    pub mapped_role_ids: Vec<Uuid>,
}

/// Fresh server-owned authority captured after the IdP identity has resolved
/// to an existing member. Session insertion compares both revisions again in
/// its own statement, closing the revocation/plan-change race.
#[derive(Debug, Clone, PartialEq)]
pub struct TenantOidcSessionAuthority {
    pub user_id: Uuid,
    pub membership: ResolvedTenantMembership,
    pub entitlement: TenantEntitlementSnapshot,
}

/// A successfully issued tenant-bound browser session. Deliberately omit
/// `Debug`/serialization because this value contains bearer credentials.
pub struct TenantOidcIssuedSession {
    pub membership: ResolvedTenantMembership,
    pub entitlement: TenantEntitlementSnapshot,
    pub tokens: TokenPair,
}

#[derive(Debug, Error)]
pub enum TenantOidcError {
    #[error("invalid tenant OIDC selector")]
    InvalidSelector,
    #[error("invalid tenant OIDC redirect")]
    InvalidRedirect,
    #[error("invalid validated OIDC identity")]
    InvalidIdentity,
    #[error("tenant OIDC access denied")]
    AccessDenied,
    #[error("tenant OIDC transaction is invalid, expired, or already consumed")]
    InvalidTransaction,
    #[error("invalid tenant OIDC entry registration")]
    InvalidEntryRegistration,
    #[error("tenant OIDC identity is not linked to an active invited member")]
    IdentityNotInvited,
    #[error("your account is not in a group allowed to access this tenant")]
    GroupNotAllowed,
    #[error("group membership could not be verified")]
    GroupMembershipUnknown,
    #[error("tenant OIDC lookup unavailable — failing closed")]
    Unavailable,
    #[error("tenant OIDC credential could not be decrypted")]
    CredentialUnavailable,
}

#[derive(Clone)]
pub struct TenantOidcRepository {
    pool: PgPool,
    encryption: crate::crypto::EncryptionService,
}

impl TenantOidcRepository {
    pub fn new(pool: PgPool) -> Self {
        Self::with_encryption(pool, crate::crypto::EncryptionService::from_env())
    }

    pub fn with_encryption(pool: PgPool, encryption: crate::crypto::EncryptionService) -> Self {
        Self { pool, encryption }
    }

    /// List only enabled providers for one exact active tenant whose current
    /// plan explicitly enables SSO. Unknown tenant, inactive assignment,
    /// missing/disabled SSO, and no enabled provider all return the same
    /// access-denied result.
    pub async fn discover_login_providers(
        &self,
        tenant_slug: &CanonicalTenantOidcSlug,
    ) -> Result<Vec<TenantOidcLoginProvider>, TenantOidcError> {
        let providers = sqlx::query_as::<_, LoginProviderRow>(
            r#"
            SELECT provider.slug, provider.name
              FROM tenants tenant
              JOIN enterprise_shared_tenant_plan_assignments assignment
                ON assignment.tenant_id = tenant.id
               AND assignment.state = 'active'
               AND assignment.effective_at <= NOW()
               AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
              JOIN enterprise_shared_plan_versions plan
                ON plan.plan_code = assignment.plan_code
               AND plan.revision = assignment.plan_revision
               AND plan.state IN ('active', 'retired')
              JOIN enterprise_shared_plan_components component
                ON component.plan_code = plan.plan_code
               AND component.plan_revision = plan.revision
               AND component.component_code = 'sso'
               AND component.enabled = TRUE
              JOIN enterprise_shared_oidc_providers provider
                ON provider.tenant_id = tenant.id
               AND provider.enabled = TRUE
             WHERE tenant.slug = $1 AND tenant.status = 'active'
             ORDER BY provider.slug
             LIMIT 9
            "#,
        )
        .bind(tenant_slug.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "tenant OIDC provider discovery failed");
            TenantOidcError::Unavailable
        })?;
        if providers.is_empty() || providers.len() > 8 {
            return Err(TenantOidcError::AccessDenied);
        }
        providers
            .into_iter()
            .map(|provider| {
                if provider.name.trim().is_empty()
                    || provider.name.len() > 255
                    || CanonicalTenantOidcSlug::parse(&provider.slug).is_err()
                {
                    return Err(TenantOidcError::Unavailable);
                }
                Ok(TenantOidcLoginProvider {
                    slug: provider.slug,
                    name: provider.name,
                })
            })
            .collect()
    }

    /// Register a one-time entry prepared by the platform. The caller must create
    /// and deliver the opaque plaintext itself, then pass only its SHA-256
    /// digest here. Repeating the same request/idempotency UUIDs is accepted
    /// only when every authority field and the digest are byte-identical.
    pub async fn register_entry(
        &self,
        registration: TenantOidcEntryRegistration,
    ) -> Result<TenantOidcEntryReceipt, TenantOidcError> {
        let now = Utc::now();
        if registration.tenant_id.is_nil()
            || registration.provider_id.is_nil()
            || registration.registration_request_id.is_nil()
            || registration.idempotency_key.is_nil()
            || registration.expires_at <= now
            || registration.expires_at > now + Duration::seconds(MAX_ENTRY_TTL_SECONDS)
            || registration.intended_user_id.is_some_and(|id| id.is_nil())
        {
            return Err(TenantOidcError::InvalidEntryRegistration);
        }
        let intended_email = registration.intended_email.as_deref();
        if intended_email.is_some_and(|email| {
            email.len() < 3
                || email.len() > 320
                || email != email.trim()
                || email
                    .bytes()
                    .any(|byte| byte.is_ascii_uppercase() || byte.is_ascii_control())
        }) {
            return Err(TenantOidcError::InvalidEntryRegistration);
        }

        let row = sqlx::query_as::<_, EntryReceiptRow>(
            r#"
            WITH eligible AS (
                SELECT tenant.id AS tenant_id, provider.id AS provider_id
                FROM tenants tenant
                JOIN enterprise_shared_oidc_providers provider
                  ON provider.tenant_id = tenant.id
                 AND provider.id = $2
                 AND provider.enabled = TRUE
                WHERE tenant.id = $1
                  AND tenant.status = 'active'
                  AND $6 > NOW()
                  AND $6 <= NOW() + INTERVAL '10 minutes'
                  AND (
                      ($7::uuid IS NULL AND $8::text IS NULL)
                      OR EXISTS (
                          SELECT 1
                          FROM tenant_members member
                          JOIN users user_account
                            ON user_account.id = member.user_id
                           AND user_account.status = 'active'
                          WHERE member.tenant_id = tenant.id
                            AND member.status = 'active'
                            AND ($7::uuid IS NULL OR member.user_id = $7)
                            AND ($8::text IS NULL OR lower(user_account.email) = $8)
                      )
                  )
            ), inserted AS (
                INSERT INTO enterprise_shared_oidc_entries
                    (entry_digest, tenant_id, provider_id,
                     registration_request_id, idempotency_key,
                     intended_user_id, intended_email, expires_at)
                SELECT $3, tenant_id, provider_id, $4, $5, $7, $8, $6
                FROM eligible
                ON CONFLICT (registration_request_id, idempotency_key)
                DO UPDATE SET registration_request_id = EXCLUDED.registration_request_id
                WHERE enterprise_shared_oidc_entries.entry_digest = EXCLUDED.entry_digest
                  AND enterprise_shared_oidc_entries.tenant_id = EXCLUDED.tenant_id
                  AND enterprise_shared_oidc_entries.provider_id = EXCLUDED.provider_id
                  AND enterprise_shared_oidc_entries.intended_user_id
                        IS NOT DISTINCT FROM EXCLUDED.intended_user_id
                  AND enterprise_shared_oidc_entries.intended_email
                        IS NOT DISTINCT FROM EXCLUDED.intended_email
                  AND enterprise_shared_oidc_entries.expires_at = EXCLUDED.expires_at
                RETURNING id, tenant_id, provider_id, registration_request_id,
                          idempotency_key, expires_at
            )
            SELECT * FROM inserted
            "#,
        )
        .bind(registration.tenant_id)
        .bind(registration.provider_id)
        .bind(registration.entry_digest.as_bytes())
        .bind(registration.registration_request_id)
        .bind(registration.idempotency_key)
        .bind(registration.expires_at)
        .bind(registration.intended_user_id)
        .bind(intended_email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "tenant OIDC entry registration failed");
            TenantOidcError::Unavailable
        })?
        .ok_or(TenantOidcError::AccessDenied)?;

        Ok(TenantOidcEntryReceipt {
            entry_id: row.id,
            tenant_id: row.tenant_id,
            provider_id: row.provider_id,
            registration_request_id: row.registration_request_id,
            idempotency_key: row.idempotency_key,
            expires_at: row.expires_at,
        })
    }

    /// Atomically consume one opaque browser entry and create the normal
    /// state/nonce/PKCE authorization transaction. The token is accepted only
    /// here, is hashed immediately, and is never returned or logged.
    pub async fn consume_entry_and_begin_authorization(
        &self,
        entry_token: &str,
        redirect: &CanonicalOidcRedirect,
    ) -> Result<TenantOidcAuthorization, TenantOidcError> {
        if entry_token.len() < 43
            || entry_token.len() > 512
            || !entry_token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(TenantOidcError::InvalidTransaction);
        }
        let entry_digest = Sha256::digest(entry_token.as_bytes()).to_vec();
        let secrets = TransactionSecrets::generate();
        let state_hash = hash_state(&secrets.state);
        let expires_at = Utc::now() + Duration::seconds(AUTH_TRANSACTION_TTL_SECONDS);
        let row = sqlx::query_as::<_, BeginAuthorizationRow>(
            r#"
            WITH eligible AS (
                SELECT entry.id
                FROM enterprise_shared_oidc_entries entry
                JOIN tenants tenant
                  ON tenant.id = entry.tenant_id
                 AND tenant.status = 'active'
                JOIN enterprise_shared_oidc_providers provider
                  ON provider.tenant_id = entry.tenant_id
                 AND provider.id = entry.provider_id
                 AND provider.enabled = TRUE
                JOIN enterprise_shared_tenant_plan_assignments assignment
                  ON assignment.tenant_id = tenant.id
                 AND assignment.state = 'active'
                 AND assignment.effective_at <= NOW()
                 AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
                JOIN enterprise_shared_plan_versions plan
                  ON plan.plan_code = assignment.plan_code
                 AND plan.revision = assignment.plan_revision
                 AND plan.state IN ('active', 'retired')
                JOIN enterprise_shared_plan_components component
                  ON component.plan_code = plan.plan_code
                 AND component.plan_revision = plan.revision
                 AND component.component_code = 'sso'
                 AND component.enabled = TRUE
                WHERE entry.entry_digest = $1
                  AND entry.consumed_at IS NULL
                  AND entry.expires_at > NOW()
                  AND (
                      (entry.intended_user_id IS NULL AND entry.intended_email IS NULL)
                      OR EXISTS (
                          SELECT 1
                          FROM tenant_members member
                          JOIN users user_account
                            ON user_account.id = member.user_id
                           AND user_account.status = 'active'
                          WHERE member.tenant_id = entry.tenant_id
                            AND member.status = 'active'
                            AND (entry.intended_user_id IS NULL
                                 OR member.user_id = entry.intended_user_id)
                            AND (entry.intended_email IS NULL
                                 OR lower(user_account.email) = entry.intended_email)
                      )
                  )
                FOR UPDATE OF entry
            ), consumed_entry AS (
                UPDATE enterprise_shared_oidc_entries entry
                SET consumed_at = NOW()
                FROM eligible
                WHERE entry.id = eligible.id
                RETURNING entry.*
            ), inserted AS (
                INSERT INTO enterprise_shared_oidc_auth_transactions
                    (state_hash, tenant_id, provider_id, entry_id, nonce,
                     code_verifier, redirect_uri, expires_at,
                     intended_user_id, intended_email, provider_revision,
                     secret_revision)
                SELECT $2, entry.tenant_id, entry.provider_id, entry.id, $3,
                       $4, $5, $6, entry.intended_user_id, entry.intended_email,
                       provider.revision, provider.secret_revision
                FROM consumed_entry entry
                JOIN enterprise_shared_oidc_providers provider
                  ON provider.tenant_id = entry.tenant_id
                 AND provider.id = entry.provider_id
                 AND provider.enabled = TRUE
                RETURNING tenant_id, provider_id, provider_revision,
                          secret_revision
            )
            SELECT
                tenant.id AS tenant_id,
                tenant.slug AS tenant_slug,
                provider.id AS provider_id,
                provider.slug AS provider_slug,
                provider.issuer,
                provider.client_id,
                provider.scopes,
                provider.group_claim,
                authz.version AS authority_revision
            FROM inserted
            JOIN tenants tenant ON tenant.id = inserted.tenant_id
            JOIN enterprise_shared_oidc_providers provider
             ON provider.tenant_id = inserted.tenant_id
             AND provider.id = inserted.provider_id
             AND provider.revision = inserted.provider_revision
             AND provider.secret_revision = inserted.secret_revision
            JOIN grant_authority_version authz ON authz.singleton = TRUE
            "#,
        )
        .bind(entry_digest)
        .bind(state_hash)
        .bind(&secrets.nonce)
        .bind(&secrets.code_verifier)
        .bind(redirect.as_str())
        .bind(expires_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "tenant OIDC entry consume failed");
            TenantOidcError::Unavailable
        })?
        .ok_or(TenantOidcError::InvalidTransaction)?;

        Ok(TenantOidcAuthorization {
            tenant: TrustedTenantContext {
                tenant_id: row.tenant_id,
                tenant_slug: row.tenant_slug,
            },
            provider_id: row.provider_id,
            provider_slug: row.provider_slug,
            issuer: row.issuer,
            client_id: row.client_id,
            scopes: row.scopes,
            group_claim: row.group_claim,
            state: secrets.state,
            nonce: secrets.nonce,
            code_challenge: secrets.code_challenge,
            redirect_uri: redirect.as_str().to_string(),
            authority_revision: row.authority_revision,
        })
    }

    /// Start authorization from canonical tenant/provider selectors. The
    /// active tenant, active SSO plan component, and enabled tenant-local
    /// provider are resolved by the INSERT statement that persists state.
    pub async fn begin_authorization(
        &self,
        tenant_slug: &CanonicalTenantOidcSlug,
        provider_slug: &CanonicalTenantOidcSlug,
        redirect: &CanonicalOidcRedirect,
    ) -> Result<TenantOidcAuthorization, TenantOidcError> {
        let secrets = TransactionSecrets::generate();
        let state_hash = hash_state(&secrets.state);
        let expires_at = Utc::now() + Duration::seconds(AUTH_TRANSACTION_TTL_SECONDS);
        let row = sqlx::query_as::<_, BeginAuthorizationRow>(
            r#"
            WITH pruned AS (
                DELETE FROM enterprise_shared_oidc_auth_transactions
                WHERE state_hash IN (
                    SELECT state_hash
                    FROM enterprise_shared_oidc_auth_transactions
                    WHERE expires_at <= NOW()
                    ORDER BY expires_at
                    LIMIT 1000
                )
                RETURNING state_hash
            ), eligible AS (
                SELECT
                    t.id AS tenant_id,
                    t.slug AS tenant_slug,
                    provider.id AS provider_id,
                    provider.slug AS provider_slug,
                    provider.issuer,
                    provider.client_id,
                    provider.scopes,
                    provider.group_claim,
                    provider.revision AS provider_revision,
                    provider.secret_revision,
                    authz.version AS authority_revision
                FROM tenants t
                JOIN enterprise_shared_tenant_plan_assignments assignment
                  ON assignment.tenant_id = t.id
                 AND assignment.state = 'active'
                 AND assignment.effective_at <= NOW()
                 AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
                JOIN enterprise_shared_plan_versions plan
                  ON plan.plan_code = assignment.plan_code
                 AND plan.revision = assignment.plan_revision
                 AND plan.state IN ('active', 'retired')
                JOIN enterprise_shared_plan_components component
                  ON component.plan_code = plan.plan_code
                 AND component.plan_revision = plan.revision
                 AND component.component_code = 'sso'
                 AND component.enabled = TRUE
                JOIN enterprise_shared_oidc_providers provider
                  ON provider.tenant_id = t.id
                 AND provider.slug = $2
                 AND provider.enabled = TRUE
                JOIN grant_authority_version authz ON authz.singleton = TRUE
                WHERE t.slug = $1 AND t.status = 'active'
            ), inserted AS (
                INSERT INTO enterprise_shared_oidc_auth_transactions
                    (state_hash, tenant_id, provider_id, nonce, code_verifier,
                     redirect_uri, expires_at, provider_revision,
                     secret_revision)
                SELECT $3, tenant_id, provider_id, $4, $5, $6, $7,
                       provider_revision, secret_revision
                FROM eligible
                RETURNING tenant_id, provider_id, provider_revision,
                          secret_revision
            )
            SELECT eligible.*
            FROM eligible
            JOIN inserted USING
                (tenant_id, provider_id, provider_revision, secret_revision)
            "#,
        )
        .bind(tenant_slug.as_str())
        .bind(provider_slug.as_str())
        .bind(state_hash)
        .bind(&secrets.nonce)
        .bind(&secrets.code_verifier)
        .bind(redirect.as_str())
        .bind(expires_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "tenant OIDC authorization start failed");
            TenantOidcError::Unavailable
        })?
        .ok_or(TenantOidcError::AccessDenied)?;

        Ok(TenantOidcAuthorization {
            tenant: TrustedTenantContext {
                tenant_id: row.tenant_id,
                tenant_slug: row.tenant_slug,
            },
            provider_id: row.provider_id,
            provider_slug: row.provider_slug,
            issuer: row.issuer,
            client_id: row.client_id,
            scopes: row.scopes,
            group_claim: row.group_claim,
            state: secrets.state,
            nonce: secrets.nonce,
            code_challenge: secrets.code_challenge,
            redirect_uri: redirect.as_str().to_string(),
            authority_revision: row.authority_revision,
        })
    }

    /// Atomically consume callback state and recover all authority from the
    /// server-side row. No tenant, provider, redirect, nonce, or PKCE value is
    /// accepted from callback claims or JSON.
    pub async fn consume_authorization(
        &self,
        state: &str,
    ) -> Result<ConsumedTenantOidcAuthorization, TenantOidcError> {
        if state.len() < 32 || state.len() > 512 {
            return Err(TenantOidcError::InvalidTransaction);
        }
        let row = sqlx::query_as::<_, ConsumedAuthorizationRow>(
            r#"
            WITH eligible AS (
                SELECT auth_tx.state_hash
                FROM enterprise_shared_oidc_auth_transactions auth_tx
                JOIN tenants tenant
                  ON tenant.id = auth_tx.tenant_id AND tenant.status = 'active'
                JOIN enterprise_shared_oidc_providers provider
                 ON provider.tenant_id = auth_tx.tenant_id
                 AND provider.id = auth_tx.provider_id
                 AND provider.enabled = TRUE
                 AND provider.revision = auth_tx.provider_revision
                 AND provider.secret_revision = auth_tx.secret_revision
                JOIN enterprise_shared_tenant_plan_assignments assignment
                  ON assignment.tenant_id = tenant.id
                 AND assignment.state = 'active'
                 AND assignment.effective_at <= NOW()
                 AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
                JOIN enterprise_shared_plan_versions plan
                  ON plan.plan_code = assignment.plan_code
                 AND plan.revision = assignment.plan_revision
                 AND plan.state IN ('active', 'retired')
                JOIN enterprise_shared_plan_components component
                  ON component.plan_code = plan.plan_code
                 AND component.plan_revision = plan.revision
                 AND component.component_code = 'sso'
                 AND component.enabled = TRUE
                WHERE auth_tx.state_hash = $1
                  AND auth_tx.consumed_at IS NULL
                  AND auth_tx.expires_at > NOW()
            ), consumed AS (
                UPDATE enterprise_shared_oidc_auth_transactions auth_tx
                SET consumed_at = NOW()
                FROM eligible
                WHERE auth_tx.state_hash = eligible.state_hash
                  AND auth_tx.consumed_at IS NULL
                  AND auth_tx.expires_at > NOW()
                RETURNING auth_tx.*
            )
            SELECT
                consumed.tenant_id,
                tenant.slug AS tenant_slug,
                consumed.provider_id,
                provider.slug AS provider_slug,
                provider.issuer,
                provider.client_id,
                provider.client_secret_encrypted,
                provider.access_policy,provider.google_service_account_encrypted,
                provider.group_claim,
                consumed.nonce,
                consumed.code_verifier,
                consumed.redirect_uri,
                consumed.expires_at,
                consumed.intended_user_id,
                consumed.intended_email,
                consumed.provider_revision,
                consumed.secret_revision
            FROM consumed
            JOIN tenants tenant ON tenant.id = consumed.tenant_id
            JOIN enterprise_shared_oidc_providers provider
             ON provider.tenant_id = consumed.tenant_id
             AND provider.id = consumed.provider_id
             AND provider.revision = consumed.provider_revision
             AND provider.secret_revision = consumed.secret_revision
            "#,
        )
        .bind(hash_state(state))
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "tenant OIDC transaction consume failed");
            TenantOidcError::Unavailable
        })?
        .ok_or(TenantOidcError::InvalidTransaction)?;

        Ok(ConsumedTenantOidcAuthorization {
            tenant: TrustedTenantContext {
                tenant_id: row.tenant_id,
                tenant_slug: row.tenant_slug,
            },
            provider_id: row.provider_id,
            provider_slug: row.provider_slug,
            issuer: row.issuer,
            client_id: row.client_id,
            client_secret_encrypted: row.client_secret_encrypted,
            access_policy: row.access_policy,
            google_service_account_encrypted: row.google_service_account_encrypted,
            group_claim: row.group_claim,
            nonce: row.nonce,
            code_verifier: row.code_verifier,
            redirect_uri: row.redirect_uri,
            expires_at: row.expires_at,
            intended_user_id: row.intended_user_id,
            intended_email: row.intended_email,
            provider_revision: row.provider_revision,
            secret_revision: row.secret_revision,
        })
    }

    pub fn decrypt_client_secret(
        &self,
        authorization: &ConsumedTenantOidcAuthorization,
    ) -> Result<String, TenantOidcError> {
        self.decrypt_provider_secret(authorization, &authorization.client_secret_encrypted, "oidc.client-secret")
    }

    fn decrypt_provider_secret(&self, authorization: &ConsumedTenantOidcAuthorization, value: &[u8], purpose: &'static str) -> Result<String, TenantOidcError> {
        let stored: serde_json::Value =
            serde_json::from_slice(value).map_err(|_| TenantOidcError::CredentialUnavailable)?;
        let encrypted = crate::crypto::EncryptedData {
            ciphertext: stored
                .get("ciphertext")
                .and_then(serde_json::Value::as_str)
                .ok_or(TenantOidcError::CredentialUnavailable)?
                .to_string(),
            nonce: stored
                .get("nonce")
                .and_then(serde_json::Value::as_str)
                .ok_or(TenantOidcError::CredentialUnavailable)?
                .to_string(),
        };
        let plaintext = self
            .encryption
            .with_context(crate::crypto::CredentialScope::Tenant(authorization.tenant.tenant_id), purpose, authorization.provider_id)
            .decrypt(&encrypted)
            .map_err(|_| TenantOidcError::CredentialUnavailable)?;
        String::from_utf8(plaintext).map_err(|_| TenantOidcError::CredentialUnavailable)
    }

    /// Google ID tokens never establish group membership. Missing delegated
    /// credentials is invitation-only; configured but unavailable lookup denies.
    pub async fn resolve_google_membership(
        &self,
        authorization: &ConsumedTenantOidcAuthorization,
        identity: &mut ValidatedTenantOidcIdentity,
    ) -> Result<(), TenantOidcError> {
        if authorization.issuer != "https://accounts.google.com" {
            return Ok(());
        }
        identity.groups.clear();
        if let Some(encrypted) = &authorization.google_service_account_encrypted {
            if authorization.access_policy.google_delegated_admin.is_none() {
                return Ok(());
            }
            let credential = self
                .decrypt_provider_secret(authorization, encrypted, "oidc.google-service-account")
                .map_err(|_| TenantOidcError::GroupMembershipUnknown)?;
            identity.groups = super::google_workspace_groups(
                &authorization.access_policy,
                &credential,
                &identity.email,
            )
            .await
            .map_err(|_| TenantOidcError::GroupMembershipUnknown)?;
        }
        Ok(())
    }

    /// Link/update a validated IdP subject only inside the consumed
    /// transaction's tenant. A new identity requires a verified email matching
    /// one exact active user who is already an active tenant member.
    pub async fn resolve_invited_identity(
        &self,
        authorization: &ConsumedTenantOidcAuthorization,
        identity: &ValidatedTenantOidcIdentity,
    ) -> Result<TenantOidcMemberIdentity, TenantOidcError> {
        if authorization.provider_revision <= 0 || authorization.secret_revision <= 0 {
            return Err(TenantOidcError::InvalidTransaction);
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| TenantOidcError::Unavailable)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(|_| TenantOidcError::Unavailable)?;

        // Keep every mutable authority row locked through the identity write.
        // A read-only EXISTS check is insufficient: provider rotation or plan
        // suspension could otherwise commit after the check but before this
        // transaction records stale identity metadata. Identity linking does
        // not yet know the invited user, so it first fences the tenant-owned
        // control rows in the stable order tenant -> assignment/plan/component
        // -> provider; the identity/member row is locked once resolved below.
        let tenant_current = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM tenants WHERE id = $1 AND status = 'active' FOR SHARE",
        )
        .bind(authorization.tenant.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?
        .is_some();
        // The control login holds only SELECT on the plan tables and a row
        // lock needs UPDATE (NAN-3797), so the assignment/plan/sso-component
        // fence goes through the control-only definer
        // lock_tenant_plan_entitlement (9013580).
        let entitlement_current = sqlx::query_scalar::<_, bool>(
            "SELECT nano_shared.lock_tenant_plan_entitlement($1, 'sso', NULL, NULL, NULL)",
        )
        .bind(authorization.tenant.tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?;
        let provider_current = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
            FROM enterprise_shared_oidc_providers
            WHERE tenant_id = $1
              AND id = $2
              AND enabled = TRUE
              AND revision = $3
              AND secret_revision = $4
            FOR SHARE
            "#,
        )
        .bind(authorization.tenant.tenant_id)
        .bind(authorization.provider_id)
        .bind(authorization.provider_revision)
        .bind(authorization.secret_revision)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?
        .is_some();
        let authorization_current =
            sqlx::query_scalar::<_, bool>("SELECT $1::timestamptz > clock_timestamp()")
                .bind(authorization.expires_at)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| TenantOidcError::Unavailable)?;
        if !tenant_current || !entitlement_current || !provider_current || !authorization_current {
            tx.rollback()
                .await
                .map_err(|_| TenantOidcError::Unavailable)?;
            return Err(TenantOidcError::InvalidTransaction);
        }

        let admitted: Option<Uuid> = sqlx::query_scalar(
            "SELECT nano_shared.resolve_sso_member($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(authorization.tenant.tenant_id)
        .bind(authorization.provider_id)
        .bind(authorization.provider_revision)
        .bind(authorization.secret_revision)
        .bind(authorization.expires_at)
        .bind(&identity.subject)
        .bind(&identity.email)
        .bind(identity.email_verified)
        .bind(&identity.display_name)
        .bind(&identity.groups)
        .bind(authorization.intended_user_id)
        .bind(&authorization.intended_email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?;
        if admitted.is_none() {
            // Reconciliation of a departed JIT user's grants must survive denial.
            tx.commit()
                .await
                .map_err(|_| TenantOidcError::Unavailable)?;
            return Err(TenantOidcError::GroupNotAllowed);
        }

        let existing_user = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT identity.user_id
            FROM enterprise_shared_oidc_identities identity
            JOIN tenants tenant
              ON tenant.id = identity.tenant_id AND tenant.status = 'active'
            JOIN tenant_members member
              ON member.tenant_id = identity.tenant_id
             AND member.user_id = identity.user_id
             AND member.status = 'active'
            JOIN users user_account
              ON user_account.id = identity.user_id AND user_account.status = 'active'
            JOIN enterprise_shared_oidc_providers provider
             ON provider.tenant_id = identity.tenant_id
             AND provider.id = identity.provider_id
             AND provider.enabled = TRUE
             AND provider.revision = $4
             AND provider.secret_revision = $5
            JOIN enterprise_shared_tenant_plan_assignments assignment
              ON assignment.tenant_id = identity.tenant_id
             AND assignment.state = 'active'
             AND assignment.effective_at <= NOW()
             AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
            JOIN enterprise_shared_plan_versions plan
              ON plan.plan_code = assignment.plan_code
             AND plan.revision = assignment.plan_revision
             AND plan.state IN ('active', 'retired')
            JOIN enterprise_shared_plan_components component
              ON component.plan_code = plan.plan_code
             AND component.plan_revision = plan.revision
             AND component.component_code = 'sso'
             AND component.enabled = TRUE
            WHERE identity.tenant_id = $1
              AND identity.provider_id = $2
              AND identity.subject = $3
            FOR UPDATE OF identity, member
            "#,
        )
        .bind(authorization.tenant.tenant_id)
        .bind(authorization.provider_id)
        .bind(&identity.subject)
        .bind(authorization.provider_revision)
        .bind(authorization.secret_revision)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?;

        let user_id = if let Some(user_id) = existing_user {
            user_id
        } else {
            if !identity.email_verified {
                return Err(TenantOidcError::IdentityNotInvited);
            }
            let invited = sqlx::query_scalar::<_, Uuid>(
                r#"
                SELECT user_account.id
                FROM users user_account
                JOIN tenant_members member
                  ON member.user_id = user_account.id
                 AND member.tenant_id = $1
                 AND member.status = 'active'
                JOIN tenants tenant
                  ON tenant.id = member.tenant_id AND tenant.status = 'active'
                WHERE user_account.status = 'active'
                  AND lower(user_account.email) = lower($2)
                FOR UPDATE OF user_account, member
                "#,
            )
            .bind(authorization.tenant.tenant_id)
            .bind(&identity.email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| TenantOidcError::Unavailable)?
            .ok_or(TenantOidcError::IdentityNotInvited)?;

            sqlx::query(
                r#"
                INSERT INTO enterprise_shared_oidc_identities
                    (tenant_id, provider_id, subject, user_id, email,
                     display_name, last_groups, last_authenticated_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
                "#,
            )
            .bind(authorization.tenant.tenant_id)
            .bind(authorization.provider_id)
            .bind(&identity.subject)
            .bind(invited)
            .bind(&identity.email)
            .bind(&identity.display_name)
            .bind(&identity.groups)
            .execute(&mut *tx)
            .await
            .map_err(|_| TenantOidcError::AccessDenied)?;
            invited
        };

        if authorization.intended_email.is_some() && !identity.email_verified {
            return Err(TenantOidcError::IdentityNotInvited);
        }
        let entry_binding_matches = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM tenant_members member
                JOIN users user_account
                  ON user_account.id = member.user_id
                 AND user_account.status = 'active'
                WHERE member.tenant_id = $1
                  AND member.user_id = $2
                  AND member.status = 'active'
                  AND ($3::uuid IS NULL OR member.user_id = $3)
                  AND ($4::text IS NULL OR lower(user_account.email) = $4)
                  AND ($4::text IS NULL OR lower($5::text) = $4)
            )
            "#,
        )
        .bind(authorization.tenant.tenant_id)
        .bind(user_id)
        .bind(authorization.intended_user_id)
        .bind(authorization.intended_email.as_deref())
        .bind(&identity.email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?;
        if !entry_binding_matches {
            return Err(TenantOidcError::IdentityNotInvited);
        }

        sqlx::query(
            r#"
            UPDATE enterprise_shared_oidc_identities
            SET email=$4, display_name=$5, last_groups=$6,
                last_authenticated_at=NOW(), updated_at=NOW()
            WHERE tenant_id=$1 AND provider_id=$2 AND subject=$3 AND user_id=$7
            "#,
        )
        .bind(authorization.tenant.tenant_id)
        .bind(authorization.provider_id)
        .bind(&identity.subject)
        .bind(&identity.email)
        .bind(&identity.display_name)
        .bind(&identity.groups)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?;

        let mut mapped_role_ids: Vec<Uuid> = authorization
            .access_policy
            .matching(&identity.groups)
            .iter()
            .flat_map(|m| m.role_ids.iter().copied())
            .collect();
        mapped_role_ids.sort();
        mapped_role_ids.dedup();
        // Locks prevent authority mutation, but wall-clock expiry can advance
        // while claims and group mappings are evaluated. Recheck both bounded
        // windows immediately before the identity metadata becomes durable.
        let still_current = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT $2::timestamptz > clock_timestamp()
               AND assignment.state = 'active'
               AND assignment.effective_at <= clock_timestamp()
               AND (assignment.expires_at IS NULL
                    OR assignment.expires_at > clock_timestamp())
            FROM enterprise_shared_tenant_plan_assignments assignment
            WHERE assignment.tenant_id = $1
            "#,
        )
        .bind(authorization.tenant.tenant_id)
        .bind(authorization.expires_at)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?
        .unwrap_or(false);
        if !still_current {
            tx.rollback()
                .await
                .map_err(|_| TenantOidcError::Unavailable)?;
            return Err(TenantOidcError::InvalidTransaction);
        }
        tx.commit()
            .await
            .map_err(|_| TenantOidcError::Unavailable)?;

        Ok(TenantOidcMemberIdentity {
            tenant: authorization.tenant.clone(),
            provider_id: authorization.provider_id,
            user_id,
            provider_revision: authorization.provider_revision,
            secret_revision: authorization.secret_revision,
            mapped_role_ids,
        })
    }

    /// Resolve the exact active membership and SSO assignment immediately
    /// before session issuance. Callers must pass this snapshot unchanged to
    /// `issue_tenant_session`; no selector or role from the browser is used.
    pub async fn resolve_session_authority(
        &self,
        identity: &TenantOidcMemberIdentity,
    ) -> Result<TenantOidcSessionAuthority, TenantOidcError> {
        let membership = TenantMembershipResolver::new(self.pool.clone())
            .resolve_slug(identity.user_id, &identity.tenant.tenant_slug)
            .await
            .map_err(|error| match error {
                super::TenantResolutionError::AccessDenied => TenantOidcError::AccessDenied,
                super::TenantResolutionError::Unavailable => TenantOidcError::Unavailable,
            })?;
        if membership.context != identity.tenant {
            return Err(TenantOidcError::AccessDenied);
        }

        let entitlement = TenantEntitlementResolver::new(self.pool.clone())
            .resolve(&membership.context)
            .await
            .map_err(|error| match error {
                crate::tenant_entitlements::TenantEntitlementError::Unavailable => {
                    TenantOidcError::Unavailable
                }
                _ => TenantOidcError::AccessDenied,
            })?;
        entitlement
            .require_component(&membership.context, TenantComponent::Sso)
            .map_err(|_| TenantOidcError::AccessDenied)?;

        Ok(TenantOidcSessionAuthority {
            user_id: identity.user_id,
            membership,
            entitlement,
        })
    }

    #[cfg(feature = "enterprise")]
    /// Issue a tenant-bound token pair and persist only the refresh-token hash.
    /// The INSERT repeats the exact membership, entitlement, global authz
    /// revision, and assignment revision checks atomically. A concurrent
    /// revocation or plan reassignment therefore discards the freshly-created
    /// in-memory tokens and returns access denied without creating a session.
    pub async fn issue_tenant_session(
        &self,
        identity: &TenantOidcMemberIdentity,
        authority: &TenantOidcSessionAuthority,
        token_service: &TokenService,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<TenantOidcIssuedSession, TenantOidcError> {
        if identity.user_id != authority.user_id
            || identity.user_id == Uuid::nil()
            || identity.tenant != authority.membership.context
            || authority.entitlement.tenant_id != identity.tenant.tenant_id
        {
            return Err(TenantOidcError::AccessDenied);
        }

        // Check before opening the issuance transaction: a one-connection
        // pool must not deadlock trying to borrow another policy connection.
        crate::ip_allowlist::tenant::require_tenant_ip_allowed(
            &self.pool,
            &identity.tenant,
            ip_address.and_then(|ip| ip.parse().ok()),
            crate::ip_allowlist::tenant::TenantIpPolicyScope::Api,
        )
        .await
        .map_err(|error| match error {
            crate::ip_allowlist::tenant::TenantIpPolicyError::Denied => {
                TenantOidcError::AccessDenied
            }
            crate::ip_allowlist::tenant::TenantIpPolicyError::Unavailable => {
                TenantOidcError::Unavailable
            }
        })?;

        // Establish the authentication fence from PostgreSQL, not the API
        // process clock. Keep the exact user -> tenant -> membership rows
        // share-locked through session insertion so logout/reset/suspension
        // has a deterministic commit order with this issuance.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| TenantOidcError::Unavailable)?;
        // The exact-role capability holds the same ordered authority locks
        // without granting this login mutation privileges over plan tables.
        let current = sqlx::query_scalar::<_, bool>(
            "SELECT nano_shared.lock_oidc_session_authority($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(identity.user_id)
        .bind(identity.tenant.tenant_id)
        .bind(authority.membership.authority_revision)
        .bind(authority.entitlement.assignment_revision)
        .bind(&authority.entitlement.plan_code)
        .bind(authority.entitlement.plan_revision)
        .bind(identity.provider_id)
        .bind(identity.provider_revision)
        .bind(identity.secret_revision)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| TenantOidcError::Unavailable)?;
        if !current {
            tx.rollback()
                .await
                .map_err(|_| TenantOidcError::Unavailable)?;
            return Err(TenantOidcError::AccessDenied);
        }
        let authenticated_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| TenantOidcError::Unavailable)?;
        let tokens = token_service
            .create_enterprise_shared_token_pair_with_authentication(
                identity.user_id,
                authority.membership.roles.clone(),
                identity.tenant.tenant_id,
                authenticated_at,
                None,
            )
            .map_err(|_| TenantOidcError::Unavailable)?;
        let refresh_token_hash = hash_token(&tokens.refresh_token);
        let expires_at = authenticated_at + Duration::seconds(token_service.refresh_token_ttl());

        let inserted = sqlx::query_scalar::<_, bool>(
            r#"
            WITH eligible AS (
                SELECT member.user_id, member.tenant_id
                FROM tenant_members member
                JOIN tenants tenant
                  ON tenant.id = member.tenant_id AND tenant.status = 'active'
                JOIN users user_account
                  ON user_account.id = member.user_id AND user_account.status = 'active'
                JOIN enterprise_shared_oidc_providers provider
                 ON provider.tenant_id = member.tenant_id
                 AND provider.id = $7
                 AND provider.enabled = TRUE
                 AND provider.revision = $8
                 AND provider.secret_revision = $9
                JOIN grant_authority_version authz ON authz.singleton = TRUE
                JOIN enterprise_shared_tenant_plan_assignments assignment
                  ON assignment.tenant_id = member.tenant_id
                 AND assignment.state = 'active'
                 AND assignment.effective_at <= NOW()
                 AND (assignment.expires_at IS NULL OR assignment.expires_at > NOW())
                JOIN enterprise_shared_plan_versions plan
                  ON plan.plan_code = assignment.plan_code
                 AND plan.revision = assignment.plan_revision
                 AND plan.state IN ('active', 'retired')
                JOIN enterprise_shared_plan_components component
                  ON component.plan_code = plan.plan_code
                 AND component.plan_revision = plan.revision
                 AND component.component_code = 'sso'
                 AND component.enabled = TRUE
                WHERE member.tenant_id = $1
                  AND member.user_id = $2
                  AND member.status = 'active'
                  AND authz.version = $3
                  AND assignment.assignment_revision = $4
                  AND assignment.plan_code = $5
                  AND assignment.plan_revision = $6
            ), inserted AS (
                INSERT INTO sessions
                    (user_id, tenant_id, authenticated_at, mfa_authenticated_at,
                     refresh_token_hash, ip_address, user_agent, expires_at)
                SELECT user_id, tenant_id, $10, NULL, $11, $12, $13, $14
                FROM eligible
                RETURNING id
            )
            SELECT EXISTS(SELECT 1 FROM inserted)
            "#,
        )
        .bind(identity.tenant.tenant_id)
        .bind(identity.user_id)
        .bind(authority.membership.authority_revision)
        .bind(authority.entitlement.assignment_revision)
        .bind(&authority.entitlement.plan_code)
        .bind(authority.entitlement.plan_revision)
        .bind(identity.provider_id)
        .bind(identity.provider_revision)
        .bind(identity.secret_revision)
        .bind(authenticated_at)
        .bind(&refresh_token_hash)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "tenant OIDC session insert failed");
            TenantOidcError::Unavailable
        })?;

        if !inserted {
            tx.rollback()
                .await
                .map_err(|_| TenantOidcError::Unavailable)?;
            return Err(TenantOidcError::AccessDenied);
        }
        tx.commit()
            .await
            .map_err(|_| TenantOidcError::Unavailable)?;

        Ok(TenantOidcIssuedSession {
            membership: authority.membership.clone(),
            entitlement: authority.entitlement.clone(),
            tokens,
        })
    }
}

struct TransactionSecrets {
    state: String,
    nonce: String,
    code_verifier: String,
    code_challenge: String,
}

impl TransactionSecrets {
    fn generate() -> Self {
        let state = random_urlsafe(32);
        let nonce = random_urlsafe(32);
        let code_verifier = random_urlsafe(64);
        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(code_verifier.as_bytes()));
        Self {
            state,
            nonce,
            code_verifier,
            code_challenge,
        }
    }
}

fn random_urlsafe(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn hash_state(state: &str) -> Vec<u8> {
    Sha256::digest(state.as_bytes()).to_vec()
}

#[derive(FromRow)]
struct BeginAuthorizationRow {
    tenant_id: Uuid,
    tenant_slug: String,
    provider_id: Uuid,
    provider_slug: String,
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    group_claim: Option<String>,
    authority_revision: i64,
}

#[derive(FromRow)]
struct EntryReceiptRow {
    id: Uuid,
    tenant_id: Uuid,
    provider_id: Uuid,
    registration_request_id: Uuid,
    idempotency_key: Uuid,
    expires_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct LoginProviderRow {
    slug: String,
    name: String,
}

#[derive(FromRow)]
struct ConsumedAuthorizationRow {
    tenant_id: Uuid,
    tenant_slug: String,
    provider_id: Uuid,
    provider_slug: String,
    issuer: String,
    client_id: String,
    client_secret_encrypted: Vec<u8>,
    group_claim: Option<String>,
    nonce: String,
    code_verifier: String,
    redirect_uri: String,
    expires_at: DateTime<Utc>,
    intended_user_id: Option<Uuid>,
    intended_email: Option<String>,
    provider_revision: i64,
    secret_revision: i64,
    #[sqlx(json)]
    access_policy: super::SsoAccessPolicy,
    google_service_account_encrypted: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_canonical_and_redirect_is_same_https_origin() {
        assert!(CanonicalTenantOidcSlug::parse("tenant-a").is_ok());
        assert!(CanonicalTenantOidcSlug::parse("Tenant-A").is_err());
        assert!(CanonicalTenantOidcSlug::parse("../tenant-a").is_err());
        assert!(CanonicalOidcRedirect::parse(
            "https://app.nano.rs/auth/callback",
            "https://app.nano.rs"
        )
        .is_ok());
        assert!(CanonicalOidcRedirect::parse(
            "https://evil.example/auth/callback",
            "https://app.nano.rs"
        )
        .is_err());
        assert!(CanonicalOidcRedirect::parse(
            "http://app.nano.rs/auth/callback",
            "https://app.nano.rs"
        )
        .is_err());
    }

    #[test]
    fn transaction_state_is_not_the_stored_lookup_value() {
        let secrets = TransactionSecrets::generate();
        assert_ne!(hash_state(&secrets.state), secrets.state.as_bytes());
        assert!(secrets.code_verifier.len() >= 43);
        assert!(!secrets.code_challenge.contains('='));
    }

    #[test]
    fn private_entry_digest_requires_exact_nonzero_sha256_bytes() {
        assert!(PrehashedTenantOidcEntryDigest::from_sha256_bytes(&[7_u8; 32]).is_ok());
        assert!(PrehashedTenantOidcEntryDigest::from_sha256_bytes(&[0_u8; 32]).is_err());
        assert!(PrehashedTenantOidcEntryDigest::from_sha256_bytes(&[7_u8; 31]).is_err());
        assert!(PrehashedTenantOidcEntryDigest::from_sha256_bytes(&[7_u8; 33]).is_err());
    }
}
