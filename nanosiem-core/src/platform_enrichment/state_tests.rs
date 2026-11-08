// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn row(now: DateTime<Utc>, tor_expiry: DateTime<Utc>) -> StateRow {
    let descriptor = serde_json::json!({
        "descriptor": {
            "sequence": 12,
            "notice": "NOTICE: x",
            "feeds": {
                "ipinfo_lite": {"revision": 7, "license_id": "CC-BY-SA-4.0", "terms_revision": "t", "upstream_at": now - Duration::hours(3),
                    "produced_at": now - Duration::hours(2), "hard_expiry": now + Duration::days(5), "row_count": 10, "source_sha256": "a"},
                "tor_exit_nodes": {"revision": 3, "license_id": "LicenseRef-tor-bulk-exit-list-public", "terms_revision": "t", "upstream_at": now - Duration::hours(3),
                    "produced_at": now - Duration::hours(2), "hard_expiry": tor_expiry, "row_count": 5, "source_sha256": "a"}
            }
        },
        "signature": "00"
    });
    StateRow {
        signed_descriptor: Some(descriptor),
        sequence: Some(12),
        payload_sha256: Some("f".repeat(64)),
        source: Some(SOURCE_ONLINE.into()),
        channel: Some("open".into()),
        installed_at: Some(now),
        feeds: [
            ("ipinfo_lite".to_string(), FeedInstall { loaded: 0, active: false, detail: Some("Past its hard expiry when installed.".into()) }),
            ("tor_exit_nodes".to_string(), FeedInstall { loaded: 5, active: true, detail: None }),
        ]
        .into(),
        last_check_status: Some("installed".into()),
        ..Default::default()
    }
}

#[test]
fn status_reports_installed_feeds_with_activity_and_freshness() {
    let now = Utc::now();
    let ctx = StatusContext { auto_update: true, now };
    let status = build_status(Some(&row(now, now + Duration::hours(10))), &ctx);
    assert!(status.available && status.installed);
    assert_eq!(status.sequence, Some(12));
    assert_eq!(status.notice.as_deref(), Some("NOTICE: x"));
    let ipinfo = &status.feeds[0];
    assert_eq!((ipinfo.feed_id.as_str(), ipinfo.state, ipinfo.active), ("ipinfo_lite", FeedState::Fresh, false));
    assert!(ipinfo.detail.as_deref().unwrap().contains("hard expiry"));
    let tor = &status.feeds[1];
    assert_eq!((tor.state, tor.active, tor.loaded, tor.records), (FeedState::Fresh, true, Some(5), Some(5)));
    assert_eq!(tor.name, "Tor exit nodes");
}

#[test]
fn an_expired_feed_is_reported_inactive_even_before_the_withdrawal_runs() {
    let now = Utc::now();
    let status = build_status(Some(&row(now, now - Duration::minutes(1))), &StatusContext { auto_update: false, now });
    let tor = &status.feeds[1];
    assert_eq!((tor.state, tor.active), (FeedState::Expired, false));
    assert!(tor.detail.as_deref().unwrap().contains("hard expiry"));
    assert!(!status.auto_update);
}

#[test]
fn nothing_installed_is_available_but_not_installed() {
    let now = Utc::now();
    let ctx = StatusContext { auto_update: true, now };
    let empty = build_status(None, &ctx);
    assert!(empty.available && !empty.installed && empty.feeds.is_empty());
    let failed_only = StateRow { last_check_status: Some("failed".into()), last_error: Some("boom".into()), ..Default::default() };
    let status = build_status(Some(&failed_only), &ctx);
    assert!(!status.installed);
    assert_eq!(status.last_error.as_deref(), Some("boom"));
}

#[test]
fn freshness_follows_age_and_hard_expiry() {
    let now = Utc::now();
    let until = now + Duration::days(30);
    assert_eq!(feed_state(Some(now - Duration::hours(1)), until, now), FeedState::Fresh);
    assert_eq!(feed_state(Some(now - Duration::days(8)), until, now), FeedState::Stale);
    assert_eq!(feed_state(None, until, now), FeedState::Stale);
    assert_eq!(feed_state(Some(now - Duration::hours(1)), now, now), FeedState::Expired);
}
