// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session cookie naming and selection (NAN-3548).
//!
//! Framework-free core of the browser session cookies. `nanosiem-api-lib`
//! wraps it for axum `HeaderMap`s; keeping the logic here lets the
//! hosted-shared integration tests drive the exact selection and issuance
//! code the handlers use.
//!
//! Single-tenant deployments (dedicated, open-core, self-hosted) use the
//! historical names `access_token`, `refresh_token` and `mfa_challenge`,
//! byte-identical to before NAN-3548.
//!
//! hosted-shared (the pooled host `the pooled host/t/<slug>`) serves many
//! tenants from one origin, so one browser cookie jar can hold sessions for
//! several tenants. Each tenant's cookies are named
//! `<base>__<discriminator>`, where the discriminator is
//! [`tenant_cookie_discriminator`] of the tenant UUID. Signing in to tenant B,
//! refreshing B, or a refused refresh for B therefore never overwrites or
//! clears tenant A's cookies.
//!
//! The name is only a selector. The tenant is always the signed `tenant_id`
//! in the token, and a token whose signed tenant does not map to the name it
//! was read from is refused.
//!
//! Migration: for one release the legacy unsuffixed cookie is still read in
//! hosted-shared, but only when its token is bound to the target tenant.
//! It is cleared whenever the same tenant's suffixed pair is issued.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{AuthError, TokenService};

// Hosted tenant-scoped cookie selection and issuance (NAN-3861).
#[cfg(feature = "enterprise")]
mod enterprise_shared_cookies;
#[cfg(feature = "enterprise")]
pub use enterprise_shared_cookies::{
    issued_session_set_cookies, select_shared_refresh_cookie, session_cookie_scope_for_issued,
    shared_access_token_tenant, shared_mfa_challenge_tenant, shared_refresh_token_tenant,
};

/// Base cookie names (and the exact single-tenant names).
pub const ACCESS_TOKEN_COOKIE: &str = "access_token";
pub const REFRESH_TOKEN_COOKIE: &str = "refresh_token";
pub const MFA_CHALLENGE_COOKIE: &str = "mfa_challenge";

/// Hex characters in the per-tenant cookie-name discriminator.
pub const TENANT_COOKIE_DISCRIMINATOR_LEN: usize = 16;

/// Upper bound on distinct tenant session cookie pairs one browser keeps on
/// the pooled host. Each tenant adds an `access_token__<d>` cookie (Path=/, so
/// it is sent on every request) and a `refresh_token__<d>` cookie. A JWT cookie
/// is about 0.5 to 1 KiB, so eight tenants stay well under the 8 KiB
/// request-header budget most proxies enforce, and far below the browser's
/// per-host cookie cap. When a sign-in would go over the bound, the same
/// response clears the excess pairs of *other* tenants, in a fixed order by
/// name. Those tenants sign in again.
pub const MAX_TENANT_SESSION_COOKIES: usize = 8;

/// Which cookie names a session uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionCookieScope {
    /// Historical unsuffixed names. All single-tenant modes, plus the
    /// hosted-shared legacy (pre-NAN-3548) cookie.
    Default,
    /// hosted-shared: `<base>__<tenant_cookie_discriminator(tenant)>`.
    Tenant(Uuid),
}

impl SessionCookieScope {
    /// Cookie name for `base` in this scope.
    pub fn cookie_name(self, base: &str) -> String {
        match self {
            Self::Default => base.to_string(),
            Self::Tenant(tenant_id) => {
                format!("{base}__{}", tenant_cookie_discriminator(tenant_id))
            }
        }
    }
}

/// Stable, non-secret tenant discriminator for cookie names: the first 16 hex
/// characters of SHA-256 over the tenant UUID's 16 raw bytes. The slug and the
/// raw UUID never appear in a cookie name.
pub fn tenant_cookie_discriminator(tenant_id: Uuid) -> String {
    Sha256::digest(tenant_id.as_bytes())
        .iter()
        .take(TENANT_COOKIE_DISCRIMINATOR_LEN / 2)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// If `name` is `<base>__<16 lowercase hex>`, return the discriminator.
pub fn scoped_cookie_discriminator<'a>(name: &'a str, base: &str) -> Option<&'a str> {
    let discriminator = name.strip_prefix(base)?.strip_prefix("__")?;
    (discriminator.len() == TENANT_COOKIE_DISCRIMINATOR_LEN
        && discriminator
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(discriminator)
}

// Attributes are identical in every scope; only the name changes.
const ACCESS_ATTRS: (&str, &str) = ("Lax", "/");
const REFRESH_ATTRS: (&str, &str) = ("Strict", "/api/auth");
const MFA_ATTRS: (&str, &str) = ("Strict", "/api/auth/mfa");

/// `Secure` is set in production; omitted only when NANOSIEM_DEV_MODE=true
/// (http://localhost).
fn is_dev_mode() -> bool {
    std::env::var("NANOSIEM_DEV_MODE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn set_cookie(name: &str, value: &str, (same_site, path): (&str, &str), max_age: i64) -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!("{name}={value}; HttpOnly; SameSite={same_site}; Path={path}; Max-Age={max_age}{secure}")
}

/// Access-token cookie. HttpOnly prevents XSS access; SameSite=Lax prevents
/// CSRF while allowing top-level navigations (Swagger UI in a new tab).
pub fn build_access_token_cookie_for(scope: SessionCookieScope, token: &str, max_age: i64) -> String {
    set_cookie(&scope.cookie_name(ACCESS_TOKEN_COOKIE), token, ACCESS_ATTRS, max_age)
}

pub fn clear_access_token_cookie_for(scope: SessionCookieScope) -> String {
    set_cookie(&scope.cookie_name(ACCESS_TOKEN_COOKIE), "", ACCESS_ATTRS, 0)
}

/// Refresh-token cookie: `Path=/api/auth` (refresh/logout only) and
/// `SameSite=Strict` (never needed on navigations).
pub fn build_refresh_token_cookie_for(scope: SessionCookieScope, token: &str, max_age: i64) -> String {
    set_cookie(&scope.cookie_name(REFRESH_TOKEN_COOKIE), token, REFRESH_ATTRS, max_age)
}

pub fn clear_refresh_token_cookie_for(scope: SessionCookieScope) -> String {
    set_cookie(&scope.cookie_name(REFRESH_TOKEN_COOKIE), "", REFRESH_ATTRS, 0)
}

/// Short-lived MFA enrollment challenge cookie, scoped to MFA endpoints and
/// never an authenticated application session.
pub fn build_mfa_challenge_cookie_for(scope: SessionCookieScope, token: &str, max_age: i64) -> String {
    set_cookie(&scope.cookie_name(MFA_CHALLENGE_COOKIE), token, MFA_ATTRS, max_age)
}

pub fn clear_mfa_challenge_cookie_for(scope: SessionCookieScope) -> String {
    set_cookie(&scope.cookie_name(MFA_CHALLENGE_COOKIE), "", MFA_ATTRS, 0)
}

/// Set-Cookie values that clear one scope's access + refresh pair.
pub fn clear_session_cookies_for(scope: SessionCookieScope) -> Vec<String> {
    vec![clear_access_token_cookie_for(scope), clear_refresh_token_cookie_for(scope)]
}

/// Parsed request cookies (all `Cookie` header values, in order).
#[derive(Debug, Clone, Default)]
pub struct RequestCookies(Vec<(String, String)>);

impl RequestCookies {
    pub fn parse<'a>(cookie_headers: impl IntoIterator<Item = &'a str>) -> Self {
        Self(
            cookie_headers
                .into_iter()
                .flat_map(|cookies| cookies.split(';'))
                .filter_map(|pair| pair.trim().split_once('='))
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        )
    }

    /// Value of the first cookie named exactly `name`, when non-empty.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(cookie_name, _)| cookie_name == name)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty())
    }

    pub fn scoped(&self, base: &str, scope: SessionCookieScope) -> Option<String> {
        self.get(&scope.cookie_name(base)).map(str::to_string)
    }

    /// Whether any non-empty `base` cookie is present, unsuffixed or suffixed.
    pub fn has_any(&self, base: &str) -> bool {
        self.0.iter().any(|(name, value)| {
            !value.is_empty()
                && (name == base || scoped_cookie_discriminator(name, base).is_some())
        })
    }

    /// Distinct tenant discriminators of non-empty suffixed access/refresh
    /// session cookies, sorted.
    pub fn tenant_session_discriminators(&self) -> Vec<String> {
        let mut discriminators: Vec<String> = self
            .0
            .iter()
            .filter(|(_, value)| !value.is_empty())
            .filter_map(|(name, _)| {
                scoped_cookie_discriminator(name, ACCESS_TOKEN_COOKIE)
                    .or_else(|| scoped_cookie_discriminator(name, REFRESH_TOKEN_COOKIE))
            })
            .map(str::to_string)
            .collect();
        discriminators.sort();
        discriminators.dedup();
        discriminators
    }
}

/// A session cookie chosen for one target tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantCookie {
    pub value: String,
    /// True when the value came from the legacy unsuffixed cookie.
    pub legacy: bool,
}

/// Choose the `base` cookie that belongs to `tenant_id`.
///
/// `decode_tenant` returns the signed `tenant_id` of a token that validates
/// (signature and expiry), or `None`. The suffixed cookie wins. A suffixed
/// cookie whose valid token names a *different* tenant is refused. A suffixed
/// token that does not validate is still returned, so the caller's full
/// validation rejects it and the stale cookie gets cleared.
///
/// Legacy fallback (one release): the unsuffixed cookie is used only when its
/// token validates and is bound to `tenant_id`.
pub fn select_tenant_cookie(
    cookies: &RequestCookies,
    base: &str,
    tenant_id: Uuid,
    decode_tenant: impl Fn(&str) -> Option<Uuid>,
) -> Option<TenantCookie> {
    if let Some(value) = cookies.scoped(base, SessionCookieScope::Tenant(tenant_id)) {
        return match decode_tenant(&value) {
            Some(bound) if bound != tenant_id => None,
            _ => Some(TenantCookie { value, legacy: false }),
        };
    }
    let value = cookies.scoped(base, SessionCookieScope::Default)?;
    (decode_tenant(&value) == Some(tenant_id)).then_some(TenantCookie { value, legacy: true })
}

#[cfg(not(feature = "enterprise"))]
/// Open build: no tenant-bound refresh token can be issued or validated.
pub fn shared_refresh_token_tenant(_token_service: &TokenService, _token: &str) -> Option<Uuid> {
    None
}

#[cfg(not(feature = "enterprise"))]
/// Open build: no tenant-bound access token can be issued or validated.
pub fn shared_access_token_tenant(_token_service: &TokenService, _token: &str) -> Option<Uuid> {
    None
}

#[cfg(not(feature = "enterprise"))]
/// Open build: no tenant-bound MFA challenge can be issued or validated.
pub fn shared_mfa_challenge_tenant(_token_service: &TokenService, _token: &str) -> Option<Uuid> {
    None
}

#[cfg(not(feature = "enterprise"))]
/// Open build: sessions always use the historical single-tenant names.
pub fn session_cookie_scope_for_issued(
    _token_service: &TokenService,
    _tenant_scoped_deployment: bool,
    _refresh_token: &str,
) -> SessionCookieScope {
    SessionCookieScope::Default
}

#[cfg(not(feature = "enterprise"))]
/// Open build: exactly the historical `access_token` and `refresh_token` pair.
pub fn issued_session_set_cookies(
    _cookies: &RequestCookies,
    _token_service: &TokenService,
    _tenant_scoped_deployment: bool,
    access_token: &str,
    access_max_age: i64,
    refresh_token: &str,
    refresh_max_age: i64,
) -> Vec<String> {
    let scope = SessionCookieScope::Default;
    vec![
        build_access_token_cookie_for(scope, access_token, access_max_age),
        build_refresh_token_cookie_for(scope, refresh_token, refresh_max_age),
    ]
}

/// Tenant bound into the legacy unsuffixed session cookies, if a valid one is
/// present: the refresh cookie first, then the access cookie.
pub fn legacy_session_cookie_tenant(cookies: &RequestCookies, token_service: &TokenService) -> Option<Uuid> {
    cookies
        .scoped(REFRESH_TOKEN_COOKIE, SessionCookieScope::Default)
        .and_then(|token| shared_refresh_token_tenant(token_service, &token))
        .or_else(|| {
            cookies
                .scoped(ACCESS_TOKEN_COOKIE, SessionCookieScope::Default)
                .and_then(|token| shared_access_token_tenant(token_service, &token))
        })
}

/// The refresh cookie an hosted-shared refresh request should use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRefreshCookie {
    pub tenant_id: Uuid,
    pub value: String,
    /// What a refused refresh may clear: only this tenant's pair, plus the
    /// legacy pair when that is what was presented (it is bound to this
    /// tenant). Never another tenant's cookies.
    pub refusal_clears: Vec<String>,
}

#[derive(Debug)]
pub enum SharedRefreshCookieError {
    /// No refresh cookie for the target tenant (or an unknown slug). Answered
    /// like a request with no cookie at all, so it is not a slug oracle.
    Missing,
    Auth(AuthError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenConfig;

    fn token_service() -> TokenService {
        TokenService::new(TokenConfig::new("nan-3548-cookie-test-secret-at-least-32-bytes".to_string()))
    }

    fn secure() -> &'static str {
        if is_dev_mode() { "" } else { "; Secure" }
    }

    #[test]
    fn single_tenant_cookie_names_and_attributes_are_byte_identical() {
        let secure = secure();
        let d = SessionCookieScope::Default;
        assert_eq!(build_access_token_cookie_for(d, "a", 900), format!("access_token=a; HttpOnly; SameSite=Lax; Path=/; Max-Age=900{secure}"));
        assert_eq!(clear_access_token_cookie_for(d), format!("access_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{secure}"));
        assert_eq!(build_refresh_token_cookie_for(d, "r", 604800), format!("refresh_token=r; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=604800{secure}"));
        assert_eq!(clear_refresh_token_cookie_for(d), format!("refresh_token=; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=0{secure}"));
        assert_eq!(build_mfa_challenge_cookie_for(d, "c", 300), format!("mfa_challenge=c; HttpOnly; SameSite=Strict; Path=/api/auth/mfa; Max-Age=300{secure}"));
        assert_eq!(clear_mfa_challenge_cookie_for(d), format!("mfa_challenge=; HttpOnly; SameSite=Strict; Path=/api/auth/mfa; Max-Age=0{secure}"));

        // Single-tenant issuance ignores any tenant cookies in the jar.
        let service = token_service();
        let pair = service.create_token_pair(Uuid::now_v7(), vec![]).unwrap();
        let jar = RequestCookies::parse(["access_token__0123456789abcdef=x; refresh_token=old"]);
        assert_eq!(
            issued_session_set_cookies(&jar, &service, false, &pair.access_token, 900, &pair.refresh_token, 604800),
            vec![build_access_token_cookie_for(d, &pair.access_token, 900), build_refresh_token_cookie_for(d, &pair.refresh_token, 604800)]
        );
    }

    #[test]
    fn tenant_cookie_names_use_a_stable_non_identifying_discriminator() {
        let tenant = Uuid::parse_str("0192f0e4-3b7a-7c1e-9a55-1d2f3e4a5b6c").unwrap();
        let discriminator = tenant_cookie_discriminator(tenant);
        assert_eq!(discriminator.len(), TENANT_COOKIE_DISCRIMINATOR_LEN);
        assert_eq!(discriminator, tenant_cookie_discriminator(tenant), "stable");
        let digest = Sha256::digest(tenant.as_bytes());
        let expected: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(discriminator, expected, "first 16 hex of sha256(uuid bytes)");
        assert_ne!(discriminator, tenant_cookie_discriminator(Uuid::now_v7()));

        let scope = SessionCookieScope::Tenant(tenant);
        let name = scope.cookie_name(REFRESH_TOKEN_COOKIE);
        assert_eq!(name, format!("refresh_token__{discriminator}"));
        assert!(!name.contains(&tenant.to_string()) && !name.contains(&tenant.simple().to_string()));
        assert_eq!(scoped_cookie_discriminator(&name, REFRESH_TOKEN_COOKIE), Some(discriminator.as_str()));
        assert_eq!(scoped_cookie_discriminator("refresh_token", REFRESH_TOKEN_COOKIE), None);
        assert_eq!(scoped_cookie_discriminator("refresh_token__ABCDEF0123456789", REFRESH_TOKEN_COOKIE), None);
        assert_eq!(scoped_cookie_discriminator("refresh_token__0123", REFRESH_TOKEN_COOKIE), None);

        // Same attributes as the unsuffixed cookies; only the name differs.
        let secure = secure();
        assert_eq!(build_access_token_cookie_for(scope, "a", 900), format!("access_token__{discriminator}=a; HttpOnly; SameSite=Lax; Path=/; Max-Age=900{secure}"));
        assert_eq!(build_refresh_token_cookie_for(scope, "r", 604800), format!("refresh_token__{discriminator}=r; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=604800{secure}"));
        assert_eq!(build_mfa_challenge_cookie_for(scope, "c", 300), format!("mfa_challenge__{discriminator}=c; HttpOnly; SameSite=Strict; Path=/api/auth/mfa; Max-Age=300{secure}"));
        assert_eq!(clear_refresh_token_cookie_for(scope), format!("refresh_token__{discriminator}=; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=0{secure}"));
    }
}
