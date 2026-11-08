// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::platform_enrichment::test_support::{entry, ioc, ring, seal};
use chrono::Utc;
use std::collections::BTreeMap;

#[test]
fn sections_slice_the_verified_payload_and_rows_round_trip() {
    let now = Utc::now();
    let feeds: BTreeMap<_, _> = [
        ("ipinfo_lite".to_string(), entry("ipinfo_lite", 3, now, 1)),
        ("threatfox".to_string(), entry("threatfox", 9, now, 2)),
        ("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 4, now, 1)),
    ]
    .into();
    let rows = vec![
        ioc("threatfox", "domain", "Evil.Example", "botnet_cc"),
        ioc("threatfox", "ip:port", "203.0.113.7:8080", "botnet_cc"),
        ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit"),
    ];
    let sealed = seal(feeds, Some(b"MMDB-SECTION-BYTES"), &rows, 7, now);
    let (file, verified) = open_verified(&sealed.path, &ring()).unwrap();
    let s = sections(&file, &verified).unwrap();
    assert_eq!(read_mmdb(&file, &s).unwrap(), b"MMDB-SECTION-BYTES");
    let mut reader = ioc_rows(file.clone(), &s);
    let mut seen = Vec::new();
    while let Some(row) = reader.next_row().unwrap() {
        seen.push((row.source_id, row.ioc_type, row.ioc_value));
    }
    assert_eq!(reader.count(), 3);
    // The writer lowercases values and sorts by (value, feed).
    assert_eq!(
        seen,
        vec![
            ("tor_exit_nodes".into(), "ip".into(), "198.51.100.9".into()),
            ("threatfox".into(), "ip:port".into(), "203.0.113.7:8080".into()),
            ("threatfox".into(), "domain".into(), "evil.example".into()),
        ]
    );
}

#[test]
fn a_bundle_without_ipinfo_has_an_empty_mmdb_section() {
    let now = Utc::now();
    let feeds: BTreeMap<_, _> = [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 1, now, 1))].into();
    let sealed = seal(feeds, None, &[ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit")], 1, now);
    let (file, verified) = open_verified(&sealed.path, &ring()).unwrap();
    let s = sections(&file, &verified).unwrap();
    assert_eq!(s.mmdb_len, 0);
    assert!(read_mmdb(&file, &s).unwrap().is_empty());
}

#[test]
fn a_container_grown_after_verification_is_refused() {
    let now = Utc::now();
    let feeds: BTreeMap<_, _> = [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 1, now, 1))].into();
    let sealed = seal(feeds, None, &[ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit")], 1, now);
    let (file, verified) = open_verified(&sealed.path, &ring()).unwrap();
    use std::io::Write;
    std::fs::OpenOptions::new().append(true).open(&sealed.path).unwrap().write_all(b"x").unwrap();
    assert!(sections(&file, &verified).is_err());
}

/// NAN-4948 review P1: once verified, replacing the PATH changes nothing the
/// loader reads; it only ever reads the verified descriptor's inode.
#[test]
fn replacing_the_path_after_verification_cannot_inject_rows() {
    let now = Utc::now();
    let feeds: BTreeMap<_, _> = [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 1, now, 1))].into();
    let sealed = seal(feeds.clone(), None, &[ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit")], 1, now);
    let (file, verified) = open_verified(&sealed.path, &ring()).unwrap();
    // An attacker swaps the path for a same-length bundle with other rows.
    let evil = seal(feeds, None, &[ioc("tor_exit_nodes", "ip", "198.51.100.66", "tor_exit")], 1, now);
    std::fs::remove_file(&sealed.path).unwrap();
    std::fs::copy(&evil.path, &sealed.path).unwrap();
    let s = sections(&file, &verified).unwrap();
    let mut rows = ioc_rows(file.clone(), &s);
    assert_eq!(rows.next_row().unwrap().unwrap().ioc_value, "198.51.100.9");
    assert!(rows.next_row().unwrap().is_none());
}

#[test]
fn a_symlinked_bundle_is_refused() {
    let now = Utc::now();
    let feeds: BTreeMap<_, _> = [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 1, now, 1))].into();
    let sealed = seal(feeds, None, &[ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit")], 1, now);
    let link = sealed.dir.path().join("link.nanfeed");
    std::os::unix::fs::symlink(&sealed.path, &link).unwrap();
    assert!(open_verified(&link, &ring()).is_err());
}
