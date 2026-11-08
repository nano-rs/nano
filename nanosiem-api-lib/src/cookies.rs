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
/// - `Path=/api/auth` scopes cookie to only refresh/logout endpoints
/// - `SameSite=Strict` is stronger than Lax — refresh tokens never needed on navigations
/// - `Secure` is set in production (omitted only when NANOSIEM_DEV_MODE=true for http://localhost)
pub fn build_refresh_token_cookie(token: &str, max_age_seconds: i64) -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "refresh_token={}; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age={}{}",
        token, max_age_seconds, secure
    )
}

/// Build a Set-Cookie header value that clears the refresh_token cookie.
pub fn clear_refresh_token_cookie() -> String {
    let secure = if is_dev_mode() { "" } else { "; Secure" };
    format!(
        "refresh_token=; HttpOnly; SameSite=Strict; Path=/api/auth; Max-Age=0{}",
        secure
    )
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
