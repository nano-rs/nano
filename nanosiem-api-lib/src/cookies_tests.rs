// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5483: the session-presence cookie travels with the refresh cookie.

use axum::http::{header::SET_COOKIE, HeaderMap};

use super::*;

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

#[test]
fn presence_cookie_is_readable_from_js_and_holds_no_secret() {
    let c = build_session_presence_cookie(604_800);
    assert!(c.starts_with("nano_session=1;"), "{c}");
    assert!(!c.contains("HttpOnly"), "JS must be able to read it: {c}");
    // Path=/ so document.cookie on /login lists it.
    assert!(c.contains("Path=/;"), "{c}");
    assert!(c.contains("SameSite=Strict"), "{c}");
    assert!(c.contains("Max-Age=604800"), "{c}");
}

#[test]
fn issuing_refresh_cookie_also_issues_presence_cookie_with_same_lifetime() {
    let mut h = HeaderMap::new();
    append_refresh_token_cookies(&mut h, "tok", 1234);
    let cookies = set_cookies(&h);
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert!(cookies[0].starts_with("refresh_token=tok;"));
    assert!(cookies[0].contains("HttpOnly"));
    assert!(cookies[0].contains("Max-Age=1234"));
    assert!(cookies[1].starts_with("nano_session=1;"));
    assert!(cookies[1].contains("Max-Age=1234"));
    // The secure flag matches between the pair (whatever the env says).
    assert_eq!(cookies[0].contains("Secure"), cookies[1].contains("Secure"));
}

#[test]
fn clearing_refresh_cookie_also_clears_presence_cookie() {
    let mut h = HeaderMap::new();
    append_clear_refresh_token_cookies(&mut h);
    let cookies = set_cookies(&h);
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert!(cookies[0].starts_with("refresh_token=;"));
    assert!(cookies[0].contains("Max-Age=0"));
    assert!(cookies[1].starts_with("nano_session=;"));
    assert!(cookies[1].contains("Path=/;"));
    assert!(cookies[1].contains("Max-Age=0"));
}
