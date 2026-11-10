// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5237: `POST /api/setup/initialize` admission, as the handler applies
//! it to real request headers and the TCP peer.

use std::net::SocketAddr;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use nanosiem_core::auth::first_admin::{SetupAdmission, SetupToken};

use super::authorize_setup;

const TOKEN: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn token() -> SetupToken {
    SetupToken::new(Some(TOKEN.to_string()))
}

fn bearer(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {value}")).unwrap());
    h
}

fn remote() -> SocketAddr {
    "203.0.113.9:51000".parse().unwrap()
}

fn nginx_container() -> SocketAddr {
    "172.18.0.4:40000".parse().unwrap()
}

fn loopback() -> SocketAddr {
    "127.0.0.1:52000".parse().unwrap()
}

fn status(r: Result<SetupAdmission, (StatusCode, axum::Json<super::SetupError>)>) -> Result<SetupAdmission, (StatusCode, String)> {
    r.map_err(|(s, body)| (s, body.0.error.clone()))
}

#[test]
fn setup_token_accepted() {
    assert_eq!(status(authorize_setup(&token(), &bearer(TOKEN), nginx_container())), Ok(SetupAdmission::Token));
    assert_eq!(status(authorize_setup(&token(), &bearer(TOKEN), remote())), Ok(SetupAdmission::Token));
}

#[test]
fn setup_token_missing_is_401() {
    assert_eq!(
        status(authorize_setup(&token(), &HeaderMap::new(), remote())),
        Err((StatusCode::UNAUTHORIZED, "setup_token_required".into()))
    );
    // Loopback is no substitute once a token is configured.
    assert_eq!(
        status(authorize_setup(&token(), &HeaderMap::new(), loopback())),
        Err((StatusCode::UNAUTHORIZED, "setup_token_required".into()))
    );
}

#[test]
fn setup_token_wrong_is_403() {
    assert_eq!(
        status(authorize_setup(&token(), &bearer("not-the-token"), remote())),
        Err((StatusCode::FORBIDDEN, "invalid_setup_token".into()))
    );
}

#[test]
fn repeated_authorization_header_is_not_a_token() {
    let mut h = bearer(TOKEN);
    h.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer other"));
    assert_eq!(
        status(authorize_setup(&token(), &h, remote())),
        Err((StatusCode::UNAUTHORIZED, "setup_token_required".into()))
    );
}

#[test]
fn no_token_non_loopback_is_refused() {
    let none = SetupToken::new(None);
    for peer in [remote(), nginx_container()] {
        assert_eq!(
            status(authorize_setup(&none, &HeaderMap::new(), peer)),
            Err((StatusCode::FORBIDDEN, "setup_not_local".into()))
        );
    }
}

#[test]
fn no_token_loopback_via_proxy_is_refused() {
    let none = SetupToken::new(None);
    for (name, value) in [
        ("x-forwarded-for", "127.0.0.1"),
        ("x-real-ip", "127.0.0.1"),
        ("forwarded", "for=127.0.0.1"),
        ("x-forwarded-proto", "https"),
        ("cf-connecting-ip", "127.0.0.1"),
    ] {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_static(value));
        assert_eq!(
            status(authorize_setup(&none, &h, loopback())),
            Err((StatusCode::FORBIDDEN, "setup_not_local".into())),
            "{name} must mark the request as proxied"
        );
    }
}

#[test]
fn no_token_direct_loopback_is_allowed() {
    let none = SetupToken::new(None);
    assert_eq!(status(authorize_setup(&none, &HeaderMap::new(), loopback())), Ok(SetupAdmission::Loopback));
    let v6: SocketAddr = "[::1]:52000".parse().unwrap();
    assert_eq!(status(authorize_setup(&none, &HeaderMap::new(), v6)), Ok(SetupAdmission::Loopback));
}

#[test]
fn refusal_bodies_never_echo_the_token() {
    for headers in [bearer("wrong"), HeaderMap::new()] {
        if let Err((_, body)) = authorize_setup(&token(), &headers, remote()) {
            let json = serde_json::to_string(&body.0).unwrap();
            assert!(!json.contains(TOKEN));
        }
    }
}
