// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn notice(version: &str) -> ReleaseNotice {
    ReleaseNotice {
        latest_version: version.into(),
        release_notes_url: "https://nano.rs/docs/releases/v2-0-1".into(),
        upgrade_url: "https://nano.rs/docs/releases/upgrading".into(),
        security_release: false,
    }
}

#[test]
fn release_core_parses_the_numeric_core_only() {
    assert_eq!(release_core("2.0.1"), Some((2, 0, 1)));
    assert_eq!(release_core("v2.0.1-open"), Some((2, 0, 1)));
    assert_eq!(release_core("0.1.703"), Some((0, 1, 703)));
    assert_eq!(release_core("2.0"), None);
    assert_eq!(release_core("2.0.1.4"), None);
    assert_eq!(release_core("02.0.1"), None);
    assert_eq!(release_core("dev-abc1234"), None);
    assert_eq!(release_core(""), None);
}

#[test]
fn newer_compares_numerically_across_the_v2_break() {
    assert!(notice("2.0.1").is_newer_than("2.0.0"));
    assert!(notice("2.0.10").is_newer_than("2.0.9"));
    assert!(notice("2.0.0").is_newer_than("0.1.703"));
    assert!(!notice("2.0.1").is_newer_than("2.0.1"));
    assert!(!notice("2.0.1").is_newer_than("2.0.1-open"));
    assert!(!notice("2.0.1").is_newer_than("2.1.0"));
    // An unknown running version is never "behind".
    assert!(!notice("2.0.1").is_newer_than("dev"));
}

#[test]
fn links_must_be_https_on_the_nano_domain() {
    assert!(is_nano_link("https://nano.rs/docs/releases/v2-0-1"));
    assert!(is_nano_link("https://blog.nano.rs/changelog"));
    assert!(!is_nano_link("http://nano.rs/docs"));
    assert!(!is_nano_link("https://nano.rs.evil.example/docs"));
    assert!(!is_nano_link("https://evilnano.rs/docs"));
    assert!(!is_nano_link("https://user@nano.rs/docs"));
    assert!(!is_nano_link("javascript:alert(1)"));
}

#[test]
fn from_wire_drops_incomplete_or_foreign_values() {
    let ok = ReleaseNotice::from_wire(
        Some("v2.0.1".into()),
        Some("https://nano.rs/docs/releases/v2-0-1".into()),
        Some("https://nano.rs/docs/releases/upgrading".into()),
        Some(true),
    )
    .expect("complete notice");
    assert_eq!(ok.latest_version, "2.0.1");
    assert!(ok.security_release);

    let links = || {
        (
            Some("https://nano.rs/docs/releases/v2-0-1".to_string()),
            Some("https://nano.rs/docs/releases/upgrading".to_string()),
        )
    };
    let (notes, upgrade) = links();
    assert!(ReleaseNotice::from_wire(None, notes, upgrade, Some(true)).is_none());
    let (notes, upgrade) = links();
    assert!(ReleaseNotice::from_wire(Some("latest".into()), notes, upgrade, None).is_none());
    let (_, upgrade) = links();
    assert!(ReleaseNotice::from_wire(
        Some("2.0.1".into()),
        Some("https://evil.example/notes".into()),
        upgrade,
        None
    )
    .is_none());
    let (notes, _) = links();
    assert!(ReleaseNotice::from_wire(Some("2.0.1".into()), notes, None, None).is_none());
    let (notes, upgrade) = links();
    assert!(
        !ReleaseNotice::from_wire(Some("2.0.1".into()), notes, upgrade, None)
            .unwrap()
            .security_release
    );
}
