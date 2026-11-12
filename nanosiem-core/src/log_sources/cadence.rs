// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3659 (ported for NAN-4912): expected event cadence per source type.
//!
//! Every log source is created with `stale_threshold_minutes = 15` unless
//! something says otherwise. That fits a firewall or an EDR stream, but audit
//! streams such as Google Workspace admin / drive / login, Okta System Log,
//! Microsoft 365 management activity or Slack / GitHub audit can go hours
//! without an event while the feed is perfectly healthy, so they showed
//! `stale` and raised stale-feed alerts.
//!
//! [`expected_cadence_minutes`] maps a source's route keys (`source_type` and
//! `match_values`) to a default staleness threshold. Log-source create stores
//! it on new entries; the user can still edit the threshold per source
//! (1..10080 minutes). [`effective_stale_threshold_minutes`] covers entries
//! created before this default existed (coded reinterpretation, no data
//! write): an entry that still carries the 15-minute default on a sparse
//! stream is judged against the stream's cadence instead.

/// The column default (`log_sources.stale_threshold_minutes DEFAULT 15`).
pub const DEFAULT_STALE_THRESHOLD_MINUTES: i32 = 15;

const HOUR: i32 = 60;

/// `(slug pattern, minutes)`. A pattern ending in `*` is a prefix. First
/// match wins, so exact slugs go before the prefix that also covers them.
const CADENCES: &[(&str, i32)] = &[
    // Google Workspace Reports API activity streams (admin, drive, login,
    // token, ...): often hours between events in a small organization.
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
/// these route keys, or `None` for a stream that should use the 15-minute
/// default. With several keys the longest cadence wins: the entry is fresh
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

/// A log source's route keys: its `source_type` plus any `match_values`.
pub fn route_keys(source_type: &str, match_values: Option<&[String]>) -> Vec<String> {
    let mut keys = vec![source_type.to_string()];
    keys.extend(match_values.unwrap_or_default().iter().cloned());
    keys
}

/// The threshold a new log source is created with: its stream's cadence, or
/// the 15-minute default for a dense stream.
pub fn initial_stale_threshold_minutes(source_type: &str, match_values: Option<&[String]>) -> i32 {
    expected_cadence_minutes(&route_keys(source_type, match_values))
        .unwrap_or(DEFAULT_STALE_THRESHOLD_MINUTES)
}

/// The threshold to judge an entry against: the stored value, except that an
/// entry still on the 15-minute default uses its stream's cadence (see the
/// module docs). Always at least 1 minute.
///
/// There is deliberately no created-at cutoff: an install can run a build
/// without this module and create sparse sources at 15 minutes long after
/// any fixed date, so a date gate would leave exactly those rows alerting.
/// The cost is that exactly 15 minutes cannot be chosen on a sparse stream
/// (14 or 16 can).
pub fn effective_stale_threshold_minutes<S: AsRef<str>>(stored: i32, slugs: &[S]) -> i32 {
    let legacy_default = stored == DEFAULT_STALE_THRESHOLD_MINUTES;
    let threshold = if legacy_default {
        expected_cadence_minutes(slugs).unwrap_or(stored)
    } else {
        stored
    };
    threshold.max(1)
}
