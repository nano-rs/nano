// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2042: private routes fail closed without the service credential.

use super::service_credential::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use LoopbackPolicy::{AllowWhenUnconfigured as JOBS, RequireToken as USER_FACING};

const POD_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 17));
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn configured() -> ServiceCredential {
    ServiceCredential::new(Some("s3rvice-token".into()), None)
}

#[test]
fn configured_credential_is_required_from_every_peer() {
    let cred = configured();
    assert_eq!(cred.admit(Some("Bearer s3rvice-token"), Some(POD_PEER), JOBS), ServiceAdmission::Credential);
    // Loopback is no bypass once a credential exists.
    assert_eq!(cred.admit(None, Some(LOOPBACK), JOBS), ServiceAdmission::Denied);
    assert_eq!(cred.admit(None, Some(POD_PEER), JOBS), ServiceAdmission::Denied);
    for wrong in ["Bearer s3rvice-tokeN", "Bearer s3rvice-token ", "s3rvice-token", "Basic s3rvice-token", "Bearer "] {
        assert_eq!(cred.admit(Some(wrong), Some(POD_PEER), JOBS), ServiceAdmission::Denied, "{wrong}");
    }
}

#[test]
fn unconfigured_admits_only_loopback_peers() {
    let cred = ServiceCredential::new(None, None);
    assert!(!cred.is_configured());
    assert_eq!(cred.admit(None, Some(LOOPBACK), JOBS), ServiceAdmission::Loopback);
    assert_eq!(cred.admit(None, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), JOBS), ServiceAdmission::Loopback);
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    assert_eq!(cred.admit(None, Some(mapped), JOBS), ServiceAdmission::Loopback);
    assert_eq!(cred.admit(None, Some(POD_PEER), JOBS), ServiceAdmission::Denied);
    // A guessed bearer does not help when nothing is configured.
    assert_eq!(cred.admit(Some("Bearer anything"), Some(POD_PEER), JOBS), ServiceAdmission::Denied);
    // Unknown peer (no ConnectInfo) fails closed.
    assert_eq!(cred.admit(None, None, JOBS), ServiceAdmission::Denied);
}

#[test]
fn legacy_metrics_token_is_a_fallback_and_blank_values_are_unset() {
    let legacy = ServiceCredential::new(None, Some("legacy".into()));
    assert_eq!(legacy.admit(Some("Bearer legacy"), Some(POD_PEER), JOBS), ServiceAdmission::Credential);
    let primary_wins = ServiceCredential::new(Some("primary".into()), Some("legacy".into()));
    assert_eq!(primary_wins.admit(Some("Bearer legacy"), Some(POD_PEER), JOBS), ServiceAdmission::Denied);
    assert!(!ServiceCredential::new(Some("  ".into()), Some(String::new())).is_configured());
}

#[test]
fn debug_never_prints_the_token() {
    assert!(!format!("{:?}", configured()).contains("s3rvice"));
}

#[test]
fn jobs_listener_defaults_to_loopback() {
    let addr = private_bind_addr(None, 3001).unwrap();
    assert!(addr.ip().is_loopback());
    assert_eq!(addr.port(), 3001);
    assert!(private_bind_addr(Some(""), 3001).unwrap().ip().is_loopback());
    assert_eq!(private_bind_addr(Some("0.0.0.0"), 3003).unwrap().to_string(), "0.0.0.0:3003");
    assert!(private_bind_addr(Some("not-an-ip"), 3001).is_err());
}

#[test]
fn user_facing_listeners_never_admit_tokenless_loopback() {
    // A same-host reverse proxy makes every remote request arrive from
    // loopback: on api/search the token is required regardless.
    let unconfigured = ServiceCredential::new(None, None);
    assert_eq!(unconfigured.admit(None, Some(LOOPBACK), USER_FACING), ServiceAdmission::Denied);
    assert_eq!(unconfigured.admit(None, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), USER_FACING), ServiceAdmission::Denied);
    assert_eq!(configured().admit(Some("Bearer s3rvice-token"), Some(LOOPBACK), USER_FACING), ServiceAdmission::Credential);
}
