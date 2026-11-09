// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5077: a failed rule load must never switch the allowlist off.

use super::*;

const LISTED: &str = "203.0.113.9";
const UNLISTED: &str = "198.51.100.7";

/// Exploit regression: with the database unreachable and no rule set ever
/// loaded, every client used to be allowed (`has_any_rules: false`).
#[tokio::test]
async fn an_unloadable_allowlist_refuses_remote_clients() {
    let svc = IpAllowlistService::with_unreachable_database();

    for (ip, from_socket) in [(UNLISTED, true), (UNLISTED, false), (LISTED, false)] {
        assert_eq!(
            svc.is_allowed_client(ip, from_socket, IpAllowlistScope::Api).await,
            AllowlistDecision::Unavailable,
            "{ip} (from_socket={from_socket}) must be refused while the rules cannot load"
        );
    }
    assert!(!svc.is_allowed(UNLISTED, IpAllowlistScope::Search).await);

    // One database attempt, then the retry back-off answers the rest.
    assert_eq!(svc.failure_streak_len().await, 1);
    // One failed load is a blip: logged, not published to the health bus.
    assert!(!svc.streak_reported().await);
}

/// Break-glass: the TCP-loopback peer (a shell in the container or pod, a
/// `kubectl port-forward`) still gets in while the rules cannot load.
#[tokio::test]
async fn the_loopback_peer_still_gets_in_while_rules_cannot_load() {
    let svc = IpAllowlistService::with_unreachable_database();
    assert_eq!(
        svc.is_allowed_client("127.0.0.1", true, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );
    assert_eq!(
        svc.is_allowed_client("::1", true, IpAllowlistScope::Search).await,
        AllowlistDecision::Allowed
    );
    // A forwarded loopback claim is still not the peer (NAN-5015).
    assert_eq!(
        svc.is_allowed_client("127.0.0.1", false, IpAllowlistScope::Api).await,
        AllowlistDecision::Unavailable
    );
}

/// A refresh that fails after a successful load keeps enforcing the
/// last-known rules — it used to replace them with "no rules".
#[tokio::test]
async fn a_failed_refresh_keeps_enforcing_the_last_known_rules() {
    let mut svc = IpAllowlistService::with_cached_rules(&[("203.0.113.0/24", IpAllowlistScope::Global)]);
    svc.pool = IpAllowlistService::with_unreachable_database().pool;

    // Within the TTL, and again after the TTL with the refresh failing.
    for expire in [false, true] {
        if expire {
            svc.expire_cache_for_test().await;
        }
        assert_eq!(
            svc.is_allowed_client(LISTED, false, IpAllowlistScope::Api).await,
            AllowlistDecision::Allowed
        );
        assert_eq!(
            svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
            AllowlistDecision::Denied
        );
    }

    // invalidate_cache (after CRUD) followed by a failed reload: same.
    svc.invalidate_cache().await;
    assert_eq!(
        svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Denied
    );
}

/// The settings "test IP" endpoint reports the outage instead of claiming
/// the allowlist is inactive.
#[tokio::test]
async fn test_ip_reports_unavailable_rules() {
    let svc = IpAllowlistService::with_unreachable_database();
    assert!(matches!(
        svc.test_ip(UNLISTED, None).await,
        Err(IpAllowlistServiceError::RulesUnavailable)
    ));
}

/// The kill switch still opens everything (operator recovery path).
#[tokio::test]
async fn the_disable_switch_still_bypasses_an_unloadable_allowlist() {
    let mut svc = IpAllowlistService::with_unreachable_database();
    svc.disabled = true;
    assert_eq!(
        svc.is_allowed_client(UNLISTED, false, IpAllowlistScope::Api).await,
        AllowlistDecision::Allowed
    );
}

fn streak(
    now: chrono::DateTime<chrono::Utc>,
    failures: u64,
    age_secs: i64,
    reported_secs_ago: Option<i64>,
) -> FailureStreak {
    FailureStreak {
        failures,
        since: now - chrono::Duration::seconds(age_secs),
        last_error: String::new(),
        failed_closed: true,
        reported_at: reported_secs_ago.map(|s| now - chrono::Duration::seconds(s)),
        last_report: None,
    }
}

/// Alert-storm guard: a blip does not page; a sustained outage does, once,
/// then only heartbeats (which update the row without notifying).
#[test]
fn a_streak_reports_only_past_the_threshold_then_heartbeats() {
    let now = chrono::Utc::now();
    assert!(!streak(now, 1, 0, None).report_due(now));
    assert!(!streak(now, 2, 10, None).report_due(now));
    assert!(streak(now, REPORT_AFTER_FAILURES, 10, None).report_due(now));
    assert!(streak(now, 1, REPORT_AFTER_SECS, None).report_due(now));
    // Reported: quiet until the heartbeat interval.
    assert!(!streak(now, 10, 120, Some(60)).report_due(now));
    assert!(streak(now, 10, 600, Some(REPORT_HEARTBEAT_SECS)).report_due(now));
}

/// Each replica owns its own lifecycle: the key names the instance.
#[tokio::test]
async fn the_condition_key_names_the_component_and_instance() {
    let a = IpAllowlistService::with_unreachable_database()
        .with_component("nanosiem-api")
        .with_instance("api-0");
    let b = IpAllowlistService::with_unreachable_database()
        .with_component("nanosiem-api")
        .with_instance("api-1");
    assert_eq!(a.load_failed_dedup_key(), "ip_allowlist:load_failed:nanosiem-api:api-0");
    assert_ne!(a.load_failed_dedup_key(), b.load_failed_dedup_key());
}
