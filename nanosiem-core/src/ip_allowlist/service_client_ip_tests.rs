// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5015: the loopback pass is for the TCP peer, not for a header claim.

use super::*;

#[tokio::test]
async fn a_forwarded_loopback_claim_gets_no_free_pass() {
    let svc = IpAllowlistService::with_cached_rules(&[("203.0.113.0/24", IpAllowlistScope::Global)]);
    // Exploit: `CF-Connecting-IP: 127.0.0.1` through a trusted proxy.
    assert!(!svc.is_allowed_client("127.0.0.1", false, IpAllowlistScope::Search).await.is_allowed());
    assert!(!svc.is_allowed_client("::1", false, IpAllowlistScope::Search).await.is_allowed());
}

#[tokio::test]
async fn real_local_callers_and_listed_clients_still_pass() {
    let svc = IpAllowlistService::with_cached_rules(&[("203.0.113.0/24", IpAllowlistScope::Global)]);
    // The socket peer really is local (health probes, sidecars).
    assert!(svc.is_allowed_client("127.0.0.1", true, IpAllowlistScope::Search).await.is_allowed());
    // A listed client, whether vouched for by a proxy or seen directly.
    assert!(svc.is_allowed_client("203.0.113.9", false, IpAllowlistScope::Search).await.is_allowed());
    assert!(svc.is_allowed_client("203.0.113.9", true, IpAllowlistScope::Search).await.is_allowed());
    // An unlisted one is denied.
    assert!(!svc.is_allowed_client("198.51.100.7", false, IpAllowlistScope::Search).await.is_allowed());
}
