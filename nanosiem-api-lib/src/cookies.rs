//! Set-Cookie header builders for the access/refresh-token cookies.
//!
//! These helpers are shared between password login (open-core,
//! `handlers::auth`), MFA verify, OIDC callback (enterprise,
//! `handlers::oidc::auth`), and session refresh — every entry point that
//! mints a session must produce identical cookie attributes so the browser
//! treats them as the same cookie.

use axum::http::HeaderMap;

/// Build a Set-Cookie header value for the access_token JWT cookie.
/// HttpOnly prevents XSS access, SameSite=Lax prevents CSRF while allowing
/// top-level navigations (needed for Swagger UI opening in new tabs).
/// `Secure` is set in production (omitted only when NANOSIEM_DEV_MODE=true for http://localhost).
pub fn build_access_token_cookie(token: &str, max_age_seconds: i64) -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "access_token={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{}",
        token, max_age_seconds, secure
    )
}

/// Build a Set-Cookie header value that clears the access_token cookie.
pub fn clear_access_token_cookie() -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "access_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0{}",
        secure
    )
}

/// Build a Set-Cookie header value for the refresh_token HttpOnly cookie.
///
/// Crate-private on purpose (NAN-5483): callers use
/// [`append_refresh_token_cookies`], which also sets the `nano_session`
/// presence cookie. A refresh cookie issued without it would make every
/// reload skip the silent refresh and drop the user on /login.
/// - `Path=/api/auth` scopes cookie to only refresh/logout endpoints
/// - `SameSite=Strict` is stronger than Lax — refresh tokens never needed on navigations
/// - `Secure` is set in production (omitted only when NANOSIEM_DEV_MODE=true for http://localhost)
pub(crate) fn build_refresh_token_cookie(token: &str, max_age_seconds: i64) -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "refresh_token={}; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age={}{}",
        token, max_age_seconds, secure
    )
}

/// Build a Set-Cookie header value that clears the refresh_token cookie.
/// Crate-private: callers use [`append_clear_refresh_token_cookies`].
pub(crate) fn clear_refresh_token_cookie() -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "refresh_token=; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=0{}",
        secure
    )
}

/// Name of the non-secret session-presence cookie (NAN-5483).
///
/// The refresh token lives in an HttpOnly cookie the SPA cannot see, so on
/// page load it could not tell a returning user from a visitor who never
/// signed in and always probed `POST /api/auth/refresh` — a 400 the browser
/// logs in red on every signed-out load. This cookie mirrors the refresh
/// cookie's lifetime and carries no credential (its value is always `1`), so
/// it is readable from JS: present means "a refresh cookie was issued and
/// not cleared", absent means the probe can be skipped.
pub const SESSION_PRESENCE_COOKIE: &str = "nano_session";

/// Build a Set-Cookie header value for the session-presence cookie.
///
/// Same `SameSite`, `Secure` and `Max-Age` as the refresh cookie it shadows.
/// `Path=/` rather than `/api/auth`: `document.cookie` only lists cookies
/// whose path matches the page, and the SPA reads it from `/login` and
/// friends. Deliberately NOT HttpOnly — it holds no secret.
pub(crate) fn build_session_presence_cookie(max_age_seconds: i64) -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "{}=1; SameSite=Strict; Path=/; Max-Age={}{}",
        SESSION_PRESENCE_COOKIE, max_age_seconds, secure
    )
}

/// Build a Set-Cookie header value that clears the session-presence cookie.
pub(crate) fn clear_session_presence_cookie() -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "{}=; SameSite=Strict; Path=/; Max-Age=0{}",
        SESSION_PRESENCE_COOKIE, secure
    )
}

/// Append the refresh-token cookie and its presence cookie to a response.
///
/// Every site that issues or rotates the refresh cookie goes through this so
/// the two can never drift apart.
pub fn append_refresh_token_cookies(headers: &mut HeaderMap, token: &str, max_age_seconds: i64) {
    for cookie in [
        build_refresh_token_cookie(token, max_age_seconds),
        build_session_presence_cookie(max_age_seconds),
    ] {
        headers.append(
            axum::http::header::SET_COOKIE,
            cookie.parse().expect("valid cookie header"),
        );
    }
}

/// Append Set-Cookie headers clearing the refresh-token cookie and its
/// presence cookie. Pair of [`append_refresh_token_cookies`].
pub fn append_clear_refresh_token_cookies(headers: &mut HeaderMap) {
    for cookie in [clear_refresh_token_cookie(), clear_session_presence_cookie()] {
        headers.append(
            axum::http::header::SET_COOKIE,
            cookie.parse().expect("valid cookie header"),
        );
    }
}

/// Extract refresh_token from Cookie header.
/// Same parsing pattern as `extract_jwt_cookie` in middleware/auth.rs.
pub fn extract_refresh_token_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("refresh_token="))
                .map(|s| s["refresh_token=".len()..].to_string())
                .filter(|s| !s.is_empty())
        })
}

/// Check whether we're running in dev mode (NANOSIEM_DEV_MODE=true).
/// Used to decide whether to set the `Secure` flag on cookies.
fn is_dev_mode() -> bool {
    std::env::var("NANOSIEM_DEV_MODE")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
#[path = "cookies_tests.rs"]
mod cookies_tests;
