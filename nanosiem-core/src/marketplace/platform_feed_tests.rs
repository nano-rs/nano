// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

#[test]
fn maps_every_alias_to_its_bundle_feed() {
    for (slug, feed) in [
        ("ipinfo_lite", "ipinfo_lite"),
        ("IPinfo-Lite", "ipinfo_lite"),
        ("threatfox", "threatfox"),
        ("tor-exit-nodes", "tor_exit_nodes"),
        ("tor_exit_nodes", "tor_exit_nodes"),
        ("tor", "tor_exit_nodes"),
    ] {
        assert_eq!(bundle_feed_for_slug(slug), Some(feed), "{slug}");
    }
    for slug in BUNDLE_PROVIDED_SLUGS {
        assert!(bundle_feed_for_slug(slug).is_some(), "{slug}");
    }
}

#[test]
fn leaves_other_entries_alone() {
    for slug in ["urlhaus", "malwarebazaar", "shodan", "abuseipdb", "virustotal", "okta", "threatfox-api"] {
        assert_eq!(bundle_feed_for_slug(slug), None, "{slug}");
    }
}
