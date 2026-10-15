// SPDX-License-Identifier: AGPL-3.0-or-later

//! Set-Cookie header builders for the access/refresh-token cookies.
//!
//! These helpers are shared between password login (open-core,
//! `handlers::auth`), MFA verify, OIDC callback (enterprise,
//! `handlers::oidc::auth`), and session refresh — every entry point that
//! mints a session must produce identical cookie attributes so the browser
//! treats them as the same cookie.

use axum::http::{header::SET_COOKIE, HeaderMap, HeaderValue};
use nanosiem_core::auth::TokenService;
use uuid::Uuid;

use nanosiem_core::auth::session_cookies as shared_cookies;
// NAN-3548: naming, selection and issuance live in
// `nanosiem_core::auth::session_cookies` (framework-free, so the
// hosted-shared integration tests drive the same code). These are the
// axum `HeaderMap` adapters plus re-exports.
pub use shared_cookies::{
    build_access_token_cookie_for, build_mfa_challenge_cookie_for, build_refresh_token_cookie_for,
    clear_access_token_cookie_for, clear_mfa_challenge_cookie_for, clear_refresh_token_cookie_for,
    clear_session_cookies_for, scoped_cookie_discriminator, session_cookie_scope_for_issued,
    shared_access_token_tenant, shared_mfa_challenge_tenant, shared_refresh_token_tenant,
    tenant_cookie_discriminator, RequestCookies, SessionCookieScope, SharedRefreshCookie,
    SharedRefreshCookieError, TenantCookie, ACCESS_TOKEN_COOKIE, MAX_TENANT_SESSION_COOKIES,
    MFA_CHALLENGE_COOKIE, REFRESH_TOKEN_COOKIE, TENANT_COOKIE_DISCRIMINATOR_LEN,
};

/// Build a Set-Cookie header value for the (unsuffixed) access_token JWT cookie.
/// HttpOnly prevents XSS access, SameSite=Lax prevents CSRF while allowing
/// top-level navigations (needed for Swagger UI opening in new tabs).
/// `Secure` is set in production (omitted only when NANOSIEM_DEV_MODE=true for http://localhost).
pub fn build_access_token_cookie(token: &str, max_age_seconds: i64) -> String {
    build_access_token_cookie_for(SessionCookieScope::Default, token, max_age_seconds)
}

/// Build a Set-Cookie header value that clears the access_token cookie.
pub fn clear_access_token_cookie() -> String {
    clear_access_token_cookie_for(SessionCookieScope::Default)
}

/// Build a Set-Cookie header value for the (unsuffixed) refresh_token HttpOnly cookie.
/// - `Path=/api/auth` scopes cookie to only refresh/logout endpoints
/// - `SameSite=Strict` is stronger than Lax — refresh tokens never needed on navigations
pub fn build_refresh_token_cookie(token: &str, max_age_seconds: i64) -> String {
    build_refresh_token_cookie_for(SessionCookieScope::Default, token, max_age_seconds)
}

/// Build a Set-Cookie header value that clears the refresh_token cookie.
pub fn clear_refresh_token_cookie() -> String {
    clear_refresh_token_cookie_for(SessionCookieScope::Default)
}

/// Build the short-lived, HttpOnly (unsuffixed) MFA enrollment challenge
/// cookie. Scoped to MFA endpoints; never an authenticated application session.
pub fn build_mfa_challenge_cookie(token: &str, max_age_seconds: i64) -> String {
    build_mfa_challenge_cookie_for(SessionCookieScope::Default, token, max_age_seconds)
}

/// Clear the (unsuffixed) MFA enrollment challenge after setup completes.
pub fn clear_mfa_challenge_cookie() -> String {
    clear_mfa_challenge_cookie_for(SessionCookieScope::Default)
}

/// Parse every `Cookie` header of a request.
pub fn request_cookies(headers: &HeaderMap) -> RequestCookies {
    RequestCookies::parse(
        headers
            .get_all(axum::http::header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

/// Extract the MFA enrollment challenge without exposing it to browser JS.
pub fn extract_mfa_challenge_cookie(headers: &HeaderMap) -> Option<String> {
    extract_scoped_cookie(headers, MFA_CHALLENGE_COOKIE, SessionCookieScope::Default)
}

/// Extract the unsuffixed refresh_token from the Cookie header.
pub fn extract_refresh_token_cookie(headers: &HeaderMap) -> Option<String> {
    extract_scoped_cookie(headers, REFRESH_TOKEN_COOKIE, SessionCookieScope::Default)
}

/// Extract the `base` cookie for `scope` (exact name match, non-empty).
pub fn extract_scoped_cookie(headers: &HeaderMap, base: &str, scope: SessionCookieScope) -> Option<String> {
    request_cookies(headers).scoped(base, scope)
}

/// See [`shared_cookies::select_tenant_cookie`].
pub fn select_tenant_cookie(
    headers: &HeaderMap,
    base: &str,
    tenant_id: Uuid,
    decode_tenant: impl Fn(&str) -> Option<Uuid>,
) -> Option<TenantCookie> {
    shared_cookies::select_tenant_cookie(&request_cookies(headers), base, tenant_id, decode_tenant)
}

/// See [`shared_cookies::legacy_session_cookie_tenant`].
pub fn legacy_session_cookie_tenant(headers: &HeaderMap, token_service: &TokenService) -> Option<Uuid> {
    shared_cookies::legacy_session_cookie_tenant(&request_cookies(headers), token_service)
}

/// See [`shared_cookies::issued_session_set_cookies`].
pub fn issued_session_set_cookies(
    request_headers: &HeaderMap,
    token_service: &TokenService,
    tenant_scoped: bool,
    access_token: &str,
    access_max_age: i64,
    refresh_token: &str,
    refresh_max_age: i64,
) -> Vec<String> {
    shared_cookies::issued_session_set_cookies(
        &request_cookies(request_headers),
        token_service,
        tenant_scoped,
        access_token,
        access_max_age,
        refresh_token,
        refresh_max_age,
    )
}

/// Append Set-Cookie headers in order.
pub fn append_set_cookies(headers: &mut HeaderMap, cookies: impl IntoIterator<Item = String>) {
    for cookie in cookies {
        headers.append(SET_COOKIE, HeaderValue::from_str(&cookie).expect("valid cookie header"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header::COOKIE, HeaderValue};

    #[test]
    fn session_cookies_are_host_only_http_only_and_path_scoped() {
        let access = build_access_token_cookie("tenant-bound-access", 900);
        let refresh = build_refresh_token_cookie("tenant-bound-refresh", 604800);
        for cookie in [&access, &refresh] {
            assert!(cookie.contains("; HttpOnly;"));
            assert!(!cookie.to_ascii_lowercase().contains("domain="));
        }
        assert!(access.contains("SameSite=Lax; Path=/;"));
        assert!(refresh.contains("SameSite=Strict; Path=/api/auth;"));
    }

    #[test]
    fn mfa_challenge_cookie_is_http_only_strict_and_narrowly_scoped() {
        let cookie = build_mfa_challenge_cookie("opaque-challenge", 300);
        assert!(cookie.starts_with("mfa_challenge=opaque-challenge;"));
        assert!(cookie.contains("; HttpOnly; SameSite=Strict; Path=/api/auth/mfa; Max-Age=300"));
        assert!(!cookie.contains("Path=/;"));

        let cleared = clear_mfa_challenge_cookie();
        assert!(cleared.starts_with("mfa_challenge=;"));
        assert!(cleared.contains("Path=/api/auth/mfa; Max-Age=0"));
    }

    #[test]
    fn mfa_challenge_extraction_does_not_confuse_session_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static(
                "access_token=access; mfa_challenge=challenge; refresh_token=refresh",
            ),
        );
        assert_eq!(extract_mfa_challenge_cookie(&headers).as_deref(), Some("challenge"));
        assert_eq!(extract_refresh_token_cookie(&headers).as_deref(), Some("refresh"));
    }

    #[test]
    fn tenant_cookies_are_read_by_exact_name_across_cookie_headers() {
        // HTTP/2 may split the Cookie header; every value is considered.
        let tenant = Uuid::now_v7();
        let scope = SessionCookieScope::Tenant(tenant);
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("refresh_token=legacy"));
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("{}=scoped", scope.cookie_name(REFRESH_TOKEN_COOKIE))).unwrap(),
        );
        assert_eq!(extract_refresh_token_cookie(&headers).as_deref(), Some("legacy"));
        assert_eq!(extract_scoped_cookie(&headers, REFRESH_TOKEN_COOKIE, scope).as_deref(), Some("scoped"));
        // Prefix collisions never match: `refresh_token` is not `refresh_token__<d>`.
        assert_eq!(
            extract_scoped_cookie(&headers, REFRESH_TOKEN_COOKIE, SessionCookieScope::Tenant(Uuid::now_v7())),
            None
        );
    }
}
