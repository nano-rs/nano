// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5237: who may run first-admin setup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::first_admin::{SetupAdmission, SetupRefusal, SetupToken};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn configured() -> SetupToken {
    SetupToken::new(Some(TOKEN.to_string()))
}

fn remote() -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
}

fn loopback() -> Option<IpAddr> {
    Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

#[test]
fn token_accepted_from_any_peer() {
    let bearer = format!("Bearer {TOKEN}");
    assert_eq!(configured().admit(Some(&bearer), remote(), true), Ok(SetupAdmission::Token));
    assert_eq!(configured().admit(Some(&bearer), loopback(), false), Ok(SetupAdmission::Token));
}

#[test]
fn token_missing_is_refused_even_from_loopback() {
    assert_eq!(configured().admit(None, remote(), true), Err(SetupRefusal::TokenMissing));
    // With a token configured, loopback is no substitute for it.
    assert_eq!(configured().admit(None, loopback(), false), Err(SetupRefusal::TokenMissing));
    assert_eq!(configured().admit(Some("Bearer "), loopback(), false), Err(SetupRefusal::TokenMissing));
    assert_eq!(configured().admit(Some(TOKEN), loopback(), false), Err(SetupRefusal::TokenMissing));
}

#[test]
fn wrong_token_is_refused() {
    let wrong = format!("Bearer {}x", &TOKEN[..TOKEN.len() - 1]);
    assert_eq!(configured().admit(Some(&wrong), loopback(), false), Err(SetupRefusal::TokenInvalid));
    assert_eq!(
        configured().admit(Some("Bearer short"), remote(), false),
        Err(SetupRefusal::TokenInvalid)
    );
}

#[test]
fn no_token_refuses_non_loopback_peer() {
    let none = SetupToken::new(None);
    assert_eq!(none.admit(None, remote(), false), Err(SetupRefusal::NotLocal));
    // A private-network peer (the nginx container) is not local either.
    let bridge = Some(IpAddr::V4(Ipv4Addr::new(172, 18, 0, 5)));
    assert_eq!(none.admit(None, bridge, false), Err(SetupRefusal::NotLocal));
    // Fail closed when the peer is unknown.
    assert_eq!(none.admit(None, None, false), Err(SetupRefusal::NotLocal));
    // A bearer does not help when nothing is configured.
    assert_eq!(none.admit(Some("Bearer anything"), remote(), false), Err(SetupRefusal::NotLocal));
}

#[test]
fn no_token_refuses_loopback_that_came_through_a_proxy() {
    let none = SetupToken::new(None);
    assert_eq!(none.admit(None, loopback(), true), Err(SetupRefusal::NotLocal));
}

#[test]
fn no_token_allows_direct_loopback() {
    let none = SetupToken::new(None);
    assert_eq!(none.admit(None, loopback(), false), Ok(SetupAdmission::Loopback));
    let v6 = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(none.admit(None, v6, false), Ok(SetupAdmission::Loopback));
    let mapped = Some(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()));
    assert_eq!(none.admit(None, mapped, false), Ok(SetupAdmission::Loopback));
}

#[test]
fn blank_token_counts_as_unset() {
    assert!(!SetupToken::new(Some("   ".into())).is_configured());
    assert!(!SetupToken::new(Some(String::new())).is_configured());
    assert!(configured().is_configured());
}

#[test]
fn debug_never_prints_the_token() {
    let rendered = format!("{:?}", configured());
    assert!(!rendered.contains(TOKEN));
    assert!(rendered.contains("configured: true"));
}

#[test]
fn placeholder_token_accepts_nothing() {
    let placeholder = SetupToken::new(Some("CHANGE_ME_GENERATED".into()));
    assert!(placeholder.is_configured());
    for auth in [Some("Bearer CHANGE_ME_GENERATED"), None] {
        assert_eq!(placeholder.admit(auth, loopback(), false), Err(SetupRefusal::TokenPlaceholder));
    }
}
