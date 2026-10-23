// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3659: expected event cadence per source type.
//!
//! Every log source is created with `stale_threshold_minutes = 15` unless
//! something says otherwise. That fits a firewall or an EDR stream, but audit
//! streams such as Google Workspace admin / drive / login, Okta System Log,
//! Microsoft 365 management activity or Slack / GitHub audit can go hours
//! without an event while the feed is perfectly healthy, so they showed
//! `stale` and raised stale-feed alerts.
//!
//! [`expected_cadence_minutes`] maps a source's lane slugs (`match_values`,
//! the hosted feed's `source_slug`) to a default staleness threshold.
//! The hosted log-source create path stores it on new entries; the tenant
//! can still edit the threshold per source (1..10080 minutes). [`effective_stale_threshold_minutes`] covers
//! entries created before this default existed (coded backfill, no data
//! write): a pre-cutoff entry that still carries the old 15-minute default on
//! a sparse stream is judged against the stream's cadence instead.

use chrono::{DateTime, TimeZone, Utc};

/// The column default (`log_sources.stale_threshold_minutes DEFAULT 15`).
pub const DEFAULT_STALE_THRESHOLD_MINUTES: i32 = 15;

/// Entries created before this instant predate the cadence defaults. One
/// that still holds [`DEFAULT_STALE_THRESHOLD_MINUTES`] never had a cadence
/// applied, so its stream's cadence is used. Entries created after it store
/// their cadence at creation, so an explicit edit to 15 is honoured. The
/// cutoff is the end of the merge date (2026-10-18), so it is already in
/// the past when this ships: only rows written by the previous code (which
/// always stored 15) are reinterpreted. A pre-cutoff sparse-stream row a
/// tenant sets to exactly 15 again also reads as the cadence; any other
/// value is honoured.
pub fn cadence_defaults_since() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 19, 0, 0, 0)
        .single()
        .expect("valid cutoff")
}

const HOUR: i32 = 60;

/// `(slug pattern, minutes)`. A pattern ending in `*` is a prefix. First
/// match wins, so exact slugs go before the prefix that also covers them.
const CADENCES: &[(&str, i32)] = &[
    // Google Workspace Reports API activity streams (admin, drive, login,
    // token, ...): often hours between events in a small tenant.
    ("gws_*", 24 * HOUR),
    ("google_workspace*", 24 * HOUR),
    // Okta System Log: sign-ins, but quiet overnight in a small org.
    ("okta_system_log*", 12 * HOUR),
    ("okta_audit*", 12 * HOUR),
    // Microsoft 365 / Entra admin and directory audit.
    ("entra_audit*", 24 * HOUR),
    ("entra_signin*", 12 * HOUR),
    ("o365_audit*", 24 * HOUR),
    ("o365*", 12 * HOUR),
    ("m365*", 12 * HOUR),
    ("microsoft365*", 12 * HOUR),
    ("microsoft_365*", 12 * HOUR),
    // SaaS admin audit logs.
    ("slack_audit*", 24 * HOUR),
    ("slack_access_log*", 24 * HOUR),
    ("github_audit*", 24 * HOUR),
];

fn matches(pattern: &str, slug: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => slug.starts_with(prefix),
        None => slug == pattern,
    }
}

/// The expected cadence (a staleness threshold in minutes) for a source with
/// these lane slugs, or `None` for a stream that should use the 15-minute
/// default. With several slugs the longest cadence wins: the entry is fresh
/// while any of its lanes could legitimately be quiet.
pub fn expected_cadence_minutes<S: AsRef<str>>(slugs: &[S]) -> Option<i32> {
    slugs
        .iter()
        .filter_map(|slug| {
            let slug = slug.as_ref().trim().to_ascii_lowercase();
            CADENCES
                .iter()
                .find(|(pattern, _)| matches(pattern, &slug))
                .map(|(_, minutes)| *minutes)
        })
        .max()
}

/// The threshold to judge an entry against: the stored value, except that a
/// pre-cutoff entry still on the untouched 15-minute default uses its
/// stream's cadence (see the module docs). Always at least 1 minute.
pub fn effective_stale_threshold_minutes<S: AsRef<str>>(
    stored: i32,
    slugs: &[S],
    created_at: Option<DateTime<Utc>>,
) -> i32 {
    let legacy_default = stored == DEFAULT_STALE_THRESHOLD_MINUTES
        && created_at.is_none_or(|created| created < cadence_defaults_since());
    let threshold = if legacy_default {
        expected_cadence_minutes(slugs).unwrap_or(stored)
    } else {
        stored
    };
    threshold.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn legacy_default_on_a_sparse_stream_uses_the_cadence() {
        let before = Utc.with_ymd_and_hms(2026, 10, 12, 0, 0, 0).single();
        let after = Utc.with_ymd_and_hms(2026, 10, 20, 0, 0, 0).single();
        assert_eq!(effective_stale_threshold_minutes(15, &["gws_admin"], before), 24 * 60);
        assert_eq!(effective_stale_threshold_minutes(15, &["gws_admin"], None), 24 * 60);
        // Created after the defaults existed: 15 was chosen, honour it.
        assert_eq!(effective_stale_threshold_minutes(15, &["gws_admin"], after), 15);
        // Any edited value is honoured, before or after.
        assert_eq!(effective_stale_threshold_minutes(30, &["gws_admin"], before), 30);
        assert_eq!(effective_stale_threshold_minutes(10_080, &["gws_admin"], after), 10_080);
        // Dense streams keep the stored value.
        assert_eq!(effective_stale_threshold_minutes(15, &["pan_traffic"], before), 15);
        assert_eq!(effective_stale_threshold_minutes(0, &["pan_traffic"], before), 1);
    }
}
