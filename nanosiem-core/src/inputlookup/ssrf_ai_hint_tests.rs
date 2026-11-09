// SPDX-License-Identifier: AGPL-3.0-or-later

//! The AI provider URL rejection says how to enable private endpoints, but
//! only where the opt-in would actually admit the address.

use super::*;

fn private(ip: &str) -> SsrfError {
    SsrfError::PrivateIpBlocked(ip.parse().unwrap())
}

#[test]
fn private_loopback_and_link_local_rejections_carry_the_hint() {
    for error in [
        private("192.168.1.20"),
        private("10.0.0.5"),
        private("fd00::1"),
        SsrfError::LocalhostBlocked,
        SsrfError::LinkLocalBlocked("169.254.10.1".parse().unwrap()),
    ] {
        let message = describe_ai_base_url_error_with(&error, false);
        assert!(message.starts_with(&error.to_string()), "{message}");
        assert!(message.contains("NANOSIEM_ALLOW_PRIVATE_AI_ENDPOINTS=true"), "{message}");
        assert!(message.contains("re-run the installer"), "{message}");
    }
}

#[test]
fn always_blocked_targets_never_suggest_the_opt_in() {
    for error in [
        SsrfError::MetadataEndpointBlocked("169.254.169.254".into()),
        private("0.0.0.0"),
        private("224.0.0.1"),
        private("192.0.2.1"),
        SsrfError::InvalidScheme("ftp".into()),
        SsrfError::DnsResolutionFailed("llm.local".into(), "nxdomain".into()),
    ] {
        assert_eq!(describe_ai_base_url_error_with(&error, false), error.to_string());
    }
}

#[test]
fn no_hint_once_private_endpoints_are_allowed() {
    let error = private("192.168.1.20");
    assert_eq!(describe_ai_base_url_error_with(&error, true), error.to_string());
}
