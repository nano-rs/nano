// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::platform_enrichment::test_support::{entry, ioc};
use chrono::Duration;

#[test]
fn ioc_types_map_onto_the_ingest_dictionary_keys() {
    assert_eq!(ioc_key("ip", "198.51.100.9"), Some(("ip", "198.51.100.9".into())));
    assert_eq!(ioc_key("ip:port", "203.0.113.7:8080"), Some(("ip", "203.0.113.7".into())));
    assert_eq!(ioc_key("ip:port", "[2001:db8::1]:443"), Some(("ip", "2001:db8::1".into())));
    assert_eq!(ioc_key("domain", "Evil.Example"), Some(("domain", "evil.example".into())));
    assert_eq!(ioc_key("sha256_hash", "ABCD"), Some(("hash", "abcd".into())));
    assert_eq!(ioc_key("md5_hash", "ff"), Some(("hash", "ff".into())));
    assert_eq!(ioc_key("url", "http://x.example/a"), Some(("url", "http://x.example/a".into())));
    assert_eq!(ioc_key("ip", "not-an-ip"), None);
    assert_eq!(ioc_key("ip:port", "203.0.113.7"), None);
    assert_eq!(ioc_key("email", "a@b"), None);
}

#[test]
fn ioc_rows_carry_the_generation_key_and_the_sooner_expiry() {
    let now = Utc::now();
    let feed = entry("threatfox", 169, now, 1);
    let mut row = ioc("threatfox", "ip:port", "203.0.113.7:8080", "botnet_cc");
    row.malware = "win.vshell".into();
    let soon = now + Duration::hours(2);
    row.data = serde_json::json!({"effective_valid_until": soon.timestamp(), "first_seen": "2026-08-19T06:05:13Z"});
    let stored = ioc_row(&row, &feed, 42, now).unwrap();
    assert_eq!(stored.namespace, "platform_feed/threatfox/42");
    assert_eq!(stored.enrichment_name, "threatfox");
    assert_eq!((stored.key_type.as_str(), stored.key_value.as_str()), ("ip", "203.0.113.7"));
    assert_eq!(stored.expires_at, soon.timestamp() * 1000);
    assert!(stored.expires_at < feed.hard_expiry.timestamp_millis());
    assert_eq!((stored.is_ioc, stored.is_marketplace, stored.confidence, stored.version), (1, 1, 90, 169));
    assert_eq!(stored.platform_feed, 1, "ownership marker");
    let data: serde_json::Value = serde_json::from_str(&stored.data).unwrap();
    assert_eq!(data["ioc_value"], "203.0.113.7:8080");
    assert_eq!(data["bundle_sequence"], 42);
    assert_eq!(data["first_seen"], "2026-08-19T06:05:13Z");

    // Without an own expiry the signed hard expiry bounds the row.
    let tor = ioc_row(&ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit"), &entry("tor_exit_nodes", 1, now, 1), 42, now).unwrap();
    assert_eq!(tor.expires_at, entry("tor_exit_nodes", 1, now, 1).hard_expiry.timestamp_millis());

    // Already expired, or an unmatchable type: not loaded.
    row.data = serde_json::json!({"effective_valid_until": (now - Duration::hours(1)).timestamp()});
    assert!(ioc_row(&row, &feed, 42, now).is_none());
    assert!(ioc_row(&ioc("threatfox", "email", "a@b", "x"), &feed, 42, now).is_none());
}

#[test]
fn visibility_predicate_selects_the_latest_commit_per_feed() {
    let p = visible_predicate("namespace", "nanosiem.platform_feed_commits_distributed");
    assert_eq!(
        p,
        "(platform_feed = 0 OR namespace GLOBAL IN \
         (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits_distributed GROUP BY feed_id))"
    );
    assert_eq!(storage_key("ipinfo_lite", 7), "platform_feed/ipinfo_lite/7");
}

#[test]
fn feed_enrichment_ids_are_stable_per_feed() {
    assert_eq!(feed_enrichment_id("threatfox"), feed_enrichment_id("threatfox"));
    assert_ne!(feed_enrichment_id("threatfox"), feed_enrichment_id("tor_exit_nodes"));
    assert_eq!(feed_enrichment_id("threatfox").get_version_num(), 5);
}

/// Walk the IPinfo MMDB of a REAL bundle (verified with the production key
/// ring) and compare against its signed row count:
///
/// ```text
/// NANO_TEST_FEED_BUNDLE=/path/bundle.nanfeed \
///   cargo test -p nanosiem-core platform_enrichment::loader -- --ignored
/// ```
#[test]
#[ignore = "needs NANO_TEST_FEED_BUNDLE (a real signed bundle)"]
fn real_bundle_mmdb_walk_matches_the_signed_row_count() {
    let path = std::path::PathBuf::from(std::env::var("NANO_TEST_FEED_BUNDLE").unwrap());
    let verified = crate::platform_enrichment::portable::verify_file(&path, &crate::platform_enrichment::portable::KeyRing::production()).unwrap();
    let (file, verified2) = payload::open_verified(&path, &crate::platform_enrichment::portable::KeyRing::production()).unwrap();
    assert_eq!(verified2.descriptor(), verified.descriptor());
    let sections = payload::sections(&file, &verified2).unwrap();
    let mmdb = payload::read_mmdb(&file, &sections).unwrap();
    let mut v4 = 0u64;
    let mut sample = None;
    let count = walk_mmdb(&mmdb, "platform_feed/ipinfo_lite/1", 0, |row| {
        if !row.network.contains(':') {
            v4 += 1;
        }
        let covers = row
            .network
            .parse::<ipnetwork::IpNetwork>()
            .is_ok_and(|n| n.contains("8.8.8.8".parse().unwrap()));
        if covers {
            sample = Some(row.clone());
        }

        Ok(())
    })
    .unwrap();
    let expected = verified.descriptor().feeds["ipinfo_lite"].row_count;
    eprintln!("walked {count} networks ({v4} IPv4), descriptor row_count {expected}, 8.8.8.0 = {sample:?}");
    // The MMDB tree splits upstream ranges (5.7M leaves on the 2026-11-03
    // bundle); merging identical siblings restores exactly the upstream rows.
    assert_eq!(count, expected);
    let sample = sample.expect("a block covering 8.8.8.x present");
    assert_eq!(sample.asn, "AS15169");
}

fn rec(asn: &str) -> IpRow {
    IpRow {
        network: String::new(),
        country: "C".into(),
        country_code: "CC".into(),
        continent: "K".into(),
        continent_code: "KK".into(),
        asn: asn.into(),
        as_name: String::new(),
        as_domain: String::new(),
        source_id: "s".into(),
        updated_at: 0,
        deleted: 0,
        platform_feed: 1,
    }
}

fn merged(blocks: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut emit = |row: IpRow| -> Result<()> {
        out.push((row.network, row.asn));
        Ok(())
    };
    let mut m = CidrMerger::new();
    for (cidr, asn) in blocks {
        match cidr.parse::<ipnetwork::IpNetwork>().unwrap() {
            ipnetwork::IpNetwork::V4(n) => m.push(u32::from(n.network()) as u128, n.prefix(), 32, rec(asn), &mut emit).unwrap(),
            ipnetwork::IpNetwork::V6(n) => m.push(u128::from(n.network()), n.prefix(), 128, rec(asn), &mut emit).unwrap(),
        }
    }
    m.flush(&mut emit).unwrap();
    out.sort();
    out
}

#[test]
fn identical_sibling_blocks_merge_recursively_and_nothing_else_does() {
    let s = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
    // Four /26 quarters with one record collapse to the /24.
    assert_eq!(
        merged(&[("10.0.0.0/26", "A"), ("10.0.0.64/26", "A"), ("10.0.0.128/26", "A"), ("10.0.0.192/26", "A")]),
        s(&[("10.0.0.0/24", "A")])
    );
    // Different records stay apart; a right child that cannot merge is final.
    assert_eq!(
        merged(&[("10.0.0.0/25", "A"), ("10.0.0.128/25", "B")]),
        s(&[("10.0.0.0/25", "A"), ("10.0.0.128/25", "B")])
    );
    // A pending left block merges once its right sibling is assembled from parts.
    assert_eq!(
        merged(&[("10.0.0.0/25", "A"), ("10.0.0.128/26", "A"), ("10.0.0.192/26", "A")]),
        s(&[("10.0.0.0/24", "A")])
    );
    // A gap (no data) prevents merging; adjacency across a non-sibling boundary too.
    assert_eq!(
        merged(&[("10.0.0.0/26", "A"), ("10.0.0.128/26", "A"), ("10.0.1.0/24", "A")]),
        s(&[("10.0.0.0/26", "A"), ("10.0.0.128/26", "A"), ("10.0.1.0/24", "A")])
    );
    assert_eq!(
        merged(&[("10.0.0.128/25", "A"), ("10.0.1.0/25", "A")]),
        s(&[("10.0.0.128/25", "A"), ("10.0.1.0/25", "A")])
    );
    // Families never mix; IPv6 merges the same way.
    assert_eq!(
        merged(&[("10.0.0.0/25", "A"), ("2001:db8::/33", "A"), ("2001:db8:8000::/33", "A")]),
        s(&[("10.0.0.0/25", "A"), ("2001:db8::/32", "A")])
    );
}

/// NAN-4948 review P2: on a cluster, refresh completion is read from EVERY
/// replica, and only a refresh finished after the trigger counts.
#[test]
fn refresh_probe_reads_every_replica_on_a_cluster() {
    assert_eq!(refresh_status_source(None), "system.view_refreshes");
    assert_eq!(refresh_status_source(Some("  ")), "system.view_refreshes");
    assert_eq!(
        refresh_status_source(Some("nanosiem_cluster")),
        "clusterAllReplicas('nanosiem_cluster', system.view_refreshes)"
    );
    let sql = refresh_probe_sql("clusterAllReplicas('c', system.view_refreshes)", "nanosiem", "ip_enrichment_dict_refresh");
    assert!(sql.contains("FROM clusterAllReplicas('c', system.view_refreshes) WHERE database = 'nanosiem' AND view = 'ip_enrichment_dict_refresh'"), "{sql}");
    assert!(sql.contains("countIf(status != 'Running' AND last_success_time >= toDateTime(?)) AS done"), "{sql}");
    assert_eq!(sql.matches('?').count(), 2);
}
