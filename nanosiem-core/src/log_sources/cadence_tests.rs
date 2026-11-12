// SPDX-License-Identifier: AGPL-3.0-or-later

use super::cadence::*;

#[test]
fn sparse_audit_streams_get_hours() {
    for slug in ["gws_admin", "gws_drive", "gws_login", "gws_token"] {
        assert_eq!(expected_cadence_minutes(&[slug]), Some(24 * 60), "{slug}");
    }
    assert_eq!(expected_cadence_minutes(&["okta_system_log"]), Some(12 * 60));
    assert_eq!(expected_cadence_minutes(&["o365_audit_general"]), Some(24 * 60));
    assert_eq!(expected_cadence_minutes(&["m365_exchange"]), Some(12 * 60));
    assert_eq!(expected_cadence_minutes(&["slack_audit"]), Some(24 * 60));
    assert_eq!(expected_cadence_minutes(&["GWS_Admin "]), Some(24 * 60), "normalized");
}

#[test]
fn dense_streams_keep_the_default() {
    for slug in ["pan_traffic", "windows_sysmon", "aws_cloudtrail", "okta_users", "gws"] {
        assert_eq!(expected_cadence_minutes(&[slug]), None, "{slug}");
    }
    assert_eq!(expected_cadence_minutes::<&str>(&[]), None);
}

#[test]
fn longest_lane_cadence_wins() {
    assert_eq!(expected_cadence_minutes(&["pan_traffic", "gws_admin"]), Some(24 * 60));
    assert_eq!(expected_cadence_minutes(&["m365_x", "gws_admin"]), Some(24 * 60));
}

#[test]
fn route_keys_cover_source_type_and_match_values() {
    let values = vec!["gws_admin".to_string()];
    assert_eq!(route_keys("routed", Some(&values)), vec!["routed", "gws_admin"]);
    assert_eq!(route_keys("okta_system_log", None), vec!["okta_system_log"]);
    assert_eq!(
        expected_cadence_minutes(&route_keys("routed", Some(&values))),
        Some(24 * 60)
    );
}

#[test]
fn legacy_default_on_a_sparse_stream_uses_the_cadence() {
    // No created-at cutoff: a row made at 15 by any build reads as the cadence.
    assert_eq!(effective_stale_threshold_minutes(15, &["gws_admin"]), 24 * 60);
    // Any other value is honoured.
    assert_eq!(effective_stale_threshold_minutes(30, &["gws_admin"]), 30);
    assert_eq!(effective_stale_threshold_minutes(10_080, &["gws_admin"]), 10_080);
    // Dense streams keep the stored value.
    assert_eq!(effective_stale_threshold_minutes(15, &["pan_traffic"]), 15);
    assert_eq!(effective_stale_threshold_minutes(0, &["pan_traffic"]), 1);
}

#[test]
fn initial_threshold_is_the_cadence_or_the_default() {
    let values = vec!["gws_login".to_string()];
    assert_eq!(initial_stale_threshold_minutes("routed", Some(&values)), 24 * 60);
    assert_eq!(initial_stale_threshold_minutes("okta_system_log", None), 12 * 60);
    assert_eq!(initial_stale_threshold_minutes("pan_traffic", None), DEFAULT_STALE_THRESHOLD_MINUTES);
}
