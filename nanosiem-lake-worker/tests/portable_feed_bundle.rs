// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4759 (C19): the portable signed feed bundle carries an unmodified
//! NANPFB01 bundle, installs into the cell's content-addressed bundle dir and
//! stamps through the same load path hosted uses. Also (re)generates the
//! golden v1 fixture that `nanosiem-core` pins.
//!
//! Regenerate after an intentional format change:
//! `NANO_UPDATE_GOLDEN=1 cargo test -p nanosiem-lake-worker --test portable_feed_bundle`
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use nanosiem_core::platform_enrichment::portable::{self, FeedEntry, KeyRing, SignedDescriptor};
use nanosiem_lake_worker::{
    enrichment::IocSnapshotInput,
    lean_platform_bundle::{PlatformBundle, PlatformBundleSource, TenantPlatformPolicy},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use uuid::Uuid;

const KEY_ID: &str = "fixture-portable-1";
const SEED: [u8; 32] = [0x42; 32];
const GOLDEN_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nanosiem-core/tests/fixtures/portable-feed-bundle/v1"
);

fn tiny_mmdb() -> Vec<u8> {
    fn text(s: &str) -> Vec<u8> {
        [vec![0x40 | s.len() as u8], s.as_bytes().to_vec()].concat()
    }
    fn uint(n: u64, kind: u8) -> Vec<u8> {
        let bytes = n.to_be_bytes();
        let i = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        let mut out = if kind < 8 {
            vec![(kind << 5) | (8 - i) as u8]
        } else {
            vec![(8 - i) as u8, kind - 7]
        };
        out.extend(&bytes[i..]);
        out
    }
    fn map(pairs: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let mut out = vec![0xe0 | pairs.len() as u8];
        for (k, v) in pairs {
            out.extend(text(k));
            out.extend(v);
        }
        out
    }
    let us = map(vec![
        ("country", text("United States")),
        ("country_code", text("US")),
        ("asn", text("AS64500")),
    ]);
    let ca = map(vec![
        ("country", text("Canada")),
        ("country_code", text("CA")),
        ("asn", text("AS64501")),
    ]);
    let a = 18_u32;
    let b = a + us.len() as u32;
    let mut bytes = Vec::new();
    for pointer in [1, b, a, b] {
        bytes.extend(&pointer.to_be_bytes()[1..]);
    }
    bytes.extend([0; 16]);
    bytes.extend(us);
    bytes.extend(ca);
    bytes.extend(b"\xab\xcd\xefMaxMind.com");
    bytes.extend(map(vec![
        ("node_count", uint(2, 6)),
        ("record_size", uint(24, 5)),
        ("ip_version", uint(6, 5)),
        ("database_type", text("ipinfo_lite")),
        ("languages", vec![1, 4, 0x42, b'e', b'n']),
        ("binary_format_major_version", uint(2, 5)),
        ("binary_format_minor_version", uint(0, 5)),
        ("build_epoch", uint(1_799_999_000, 9)),
        ("description", map(vec![("en", text("fixture"))])),
    ]));
    bytes
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 28, 12, 0, 0).unwrap()
}
fn ring() -> KeyRing {
    let key = SigningKey::from_bytes(&SEED);
    KeyRing::from_hex(&[(KEY_ID, &hex::encode(key.verifying_key().as_bytes()))]).unwrap()
}

fn feed(
    id: &str,
    revision: i64,
    source: &[u8],
    rows: u64,
    age: Duration,
    window: Duration,
) -> (String, FeedEntry) {
    let upstream_at = t0() - age;
    (
        id.to_owned(),
        FeedEntry {
            revision,
            license_id: portable::portable_terms(id).unwrap().license_id.into(),
            terms_revision: match id {
                "ipinfo_lite" => "ipinfo-lite-cc-by-sa-4.0-reviewed-2026-09-21",
                "threatfox" => "threatfox-abusech-cc0-reviewed-2026-09-21",
                _ => "tor-bulk-exit-list-public-reviewed-2026-09-21",
            }
            .into(),
            upstream_at,
            produced_at: upstream_at + Duration::minutes(10),
            hard_expiry: upstream_at + window,
            row_count: rows,
            source_sha256: hex::encode(Sha256::digest(source)),
        },
    )
}

/// Build the golden container from a real NANPFB01 bundle in `dir`.
fn build(dir: &Path) -> (std::path::PathBuf, SignedDescriptor) {
    let mmdb = tiny_mmdb();
    let tor_source = b"185.220.101.1\n";
    let threatfox_source = b"45.9.148.3";
    let feeds: BTreeMap<String, FeedEntry> = [
        feed(
            "ipinfo_lite",
            2,
            &mmdb,
            2,
            Duration::days(1),
            Duration::days(14),
        ),
        feed(
            "threatfox",
            3,
            threatfox_source,
            1,
            Duration::hours(2),
            Duration::days(1),
        ),
        feed(
            "tor_exit_nodes",
            4,
            tor_source,
            1,
            Duration::hours(2),
            Duration::days(1),
        ),
    ]
    .into_iter()
    .collect();
    let rows = [
        IocSnapshotInput {
            ioc_value: "185.220.101.1".into(),
            ioc_type: "ip".into(),
            source_id: "tor_exit_nodes".into(),
            enrichment_name: "tor_exit_nodes".into(),
            threat_type: "tor_exit".into(),
            confidence_level: 100,
            ..Default::default()
        },
        IocSnapshotInput {
            ioc_value: "45.9.148.3".into(),
            ioc_type: "ip".into(),
            source_id: "threatfox".into(),
            enrichment_name: "threatfox".into(),
            threat_type: "botnet_cc".into(),
            malware: "win.cobalt_strike".into(),
            confidence_level: 75,
            data: json!({"ioc_type": "ip", "ioc_value": "45.9.148.3",
                "indicator_expires_at": "2026-11-27T12:00:00Z"}),
            ..Default::default()
        },
    ];
    let payload = dir.join("payload.nanpfb");
    PlatformBundle::publish_verified(
        &payload,
        Some(&mmdb),
        &rows,
        None,
        feeds.iter().map(|(k, f)| (k.clone(), f.revision)).collect(),
        feeds
            .iter()
            .map(|(k, f)| (k.clone(), f.hard_expiry))
            .collect(),
    )
    .unwrap();
    let out = dir.join("bundle.nanfeed");
    let signed = portable::seal(
        &payload,
        feeds,
        t0().timestamp_millis() as u64,
        t0(),
        KEY_ID,
        &SigningKey::from_bytes(&SEED),
        &ring(),
        &out,
    )
    .unwrap();
    (out, signed)
}

#[test]
fn portable_feed_bundle_golden() {
    let temp = tempfile::tempdir().unwrap();
    let (bundle, signed) = build(temp.path());
    let expected: [(&str, Vec<u8>); 4] = [
        ("bundle.nanfeed", fs::read(&bundle).unwrap()),
        ("descriptor.json", serde_json::to_vec(&signed).unwrap()),
        ("NOTICE", signed.descriptor.notice.clone().into_bytes()),
        (
            "fixture-keys.json",
            serde_json::to_vec_pretty(&BTreeMap::from([(
                KEY_ID,
                hex::encode(SigningKey::from_bytes(&SEED).verifying_key().as_bytes()),
            )]))
            .unwrap(),
        ),
    ];
    if std::env::var_os("NANO_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(GOLDEN_DIR).unwrap();
        for (name, bytes) in &expected {
            fs::write(Path::new(GOLDEN_DIR).join(name), bytes).unwrap();
        }
    }
    for (name, bytes) in &expected {
        let golden = fs::read(Path::new(GOLDEN_DIR).join(name)).unwrap();
        assert!(
            golden == *bytes,
            "golden {name} drifted; regenerate only for an intentional v1 change"
        );
    }
}

/// Verify → install into a `platform_bundle_dir` → default policy → the
/// unchanged hosted cell load path stamps geo/ASN, Tor and ThreatFox; expiry
/// stops new stamps only.
#[test]
fn verified_portable_bundle_stamps_through_the_hosted_cell_load_path() {
    let temp = tempfile::tempdir().unwrap();
    let (bundle, _) = build(temp.path());
    let verified = portable::verify_file(&bundle, &ring()).unwrap();
    verified.accept_after(None, t0()).unwrap();
    let cell_dir = temp.path().join("cell-bundles");
    fs::create_dir(&cell_dir).unwrap();
    let installed = verified.install_payload(&bundle, &cell_dir).unwrap();
    assert_eq!(
        fs::read(&installed).unwrap(),
        fs::read(temp.path().join("payload.nanpfb")).unwrap()
    );
    let descriptor = verified.descriptor();
    let digest = &descriptor.payload.sha256;

    let source = PlatformBundleSource::from_paths(None, Some(&cell_dir))
        .unwrap()
        .unwrap();
    let platform = source.open(digest).unwrap();
    let tenant = Uuid::new_v4();
    let policy = TenantPlatformPolicy::from_portable(tenant, &verified).unwrap();
    let policy_path = temp.path().join("policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let policy = TenantPlatformPolicy::read(&policy_path, tenant, digest).unwrap();
    assert_eq!(policy.revision, descriptor.sequence);

    let stamp = |now| {
        let mut event = json!({"src_endpoint": {"ip": "8.8.8.8"},
            "dst_endpoint": {"ip": "185.220.101.1"}, "observables": [{"value": "45.9.148.3"}]});
        let mut alt = json!({"src_endpoint": {"ip": "45.9.148.3"}});
        platform
            .stamp(event.as_object_mut().unwrap(), &policy, now)
            .unwrap();
        platform
            .stamp(alt.as_object_mut().unwrap(), &policy, now)
            .unwrap();
        (event, alt)
    };
    let (event, alt) = stamp(t0());
    assert_eq!(
        event["src_endpoint"]["location"]["country"], "US",
        "{event}"
    );
    assert_eq!(
        event["src_endpoint"]["autonomous_system"]["number"], 64500,
        "{event}"
    );
    let providers = |e: &serde_json::Value| {
        e.get("enrichments")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|x| x["provider"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    assert!(
        providers(&event).contains(&"platform/tor_exit_nodes".to_owned()),
        "{event}"
    );
    assert!(
        providers(&alt).contains(&"platform/threatfox".to_owned()),
        "{alt}"
    );

    // After the Tor/ThreatFox hard expiry: geo still stamps, IOC feeds stop.
    let late = descriptor.feeds["tor_exit_nodes"].hard_expiry;
    let (event, alt) = stamp(late);
    assert_eq!(event["src_endpoint"]["location"]["country"], "US");
    assert!(
        !providers(&event).contains(&"platform/tor_exit_nodes".to_owned()),
        "{event}"
    );
    assert!(
        !providers(&alt).contains(&"platform/threatfox".to_owned()),
        "{alt}"
    );

    // IPinfo also stops exactly at hard_expiry. Already-stamped values remain.
    let mut stamped = stamp(t0()).0;
    let geo_expiry = descriptor.feeds["ipinfo_lite"].hard_expiry;
    let (expired, _) = stamp(geo_expiry);
    assert!(
        expired["src_endpoint"].get("location").is_none(),
        "{expired}"
    );
    assert!(
        expired["src_endpoint"].get("autonomous_system").is_none(),
        "{expired}"
    );
    platform
        .stamp(stamped.as_object_mut().unwrap(), &policy, geo_expiry)
        .unwrap();
    assert_eq!(stamped["src_endpoint"]["location"]["country"], "US");
    assert_eq!(
        stamped["src_endpoint"]["autonomous_system"]["number"],
        64500
    );
}
