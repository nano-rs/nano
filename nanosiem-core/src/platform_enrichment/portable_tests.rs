// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use chrono::TimeZone;
use std::os::unix::fs::PermissionsExt;

const GOLDEN_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/portable-feed-bundle/v1"
);
pub(super) const FIXTURE_KEY_ID: &str = "fixture-portable-1";
pub(super) const FIXTURE_SEED: [u8; 32] = [0x42; 32];

fn key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_SEED)
}
fn ring() -> KeyRing {
    KeyRing::from_hex(&[(
        FIXTURE_KEY_ID,
        &hex::encode(key().verifying_key().as_bytes()),
    )])
    .unwrap()
}
fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 28, 12, 0, 0).unwrap()
}

fn entry(feed: &str, revision: i64) -> FeedEntry {
    let upstream_at = t0() - Duration::hours(2);
    FeedEntry {
        revision,
        license_id: portable_terms(feed).unwrap().license_id.into(),
        terms_revision: format!("{feed}-reviewed-2026-09-21").replace('_', "-"),
        upstream_at,
        produced_at: t0() - Duration::hours(1),
        hard_expiry: upstream_at + Duration::hours(20),
        row_count: 1,
        source_sha256: "ab".repeat(32),
    }
}

/// A minimal NANPFB01 file stating `feeds` (header + opaque sections).
fn payload(feeds: &BTreeMap<String, FeedEntry>, prefix_len: u64) -> Vec<u8> {
    let mmdb: &[u8] = if feeds.contains_key("ipinfo_lite") {
        b"MMDB-SECTION"
    } else {
        b""
    };
    let iocs: &[u8] = b"8.8.8.8\t{}\n";
    let header = serde_json::json!({
        "mmdb_len": mmdb.len(),
        "ioc_len": iocs.len(),
        "prefix_len": prefix_len,
        "prefix_rows": 0,
        "feed_revisions": feeds.iter().map(|(k, f)| (k.clone(), f.revision)).collect::<BTreeMap<_, _>>(),
        "feed_valid_until": feeds.iter().map(|(k, f)| (k.clone(), f.hard_expiry)).collect::<BTreeMap<_, _>>(),
    });
    let header = serde_json::to_vec(&header).unwrap();
    let mut out = b"NANPFB01".to_vec();
    out.extend((header.len() as u64).to_le_bytes());
    out.extend(header);
    out.extend(mmdb);
    out.extend(iocs);
    out.extend(vec![0u8; prefix_len as usize]);
    out
}

fn feeds(ids: &[(&str, i64)]) -> BTreeMap<String, FeedEntry> {
    ids.iter()
        .map(|(id, r)| ((*id).to_owned(), entry(id, *r)))
        .collect()
}

struct Sealed {
    _dir: tempfile::TempDir,
    path: PathBuf,
    signed: SignedDescriptor,
}
fn seal_with(feeds: BTreeMap<String, FeedEntry>, sequence: u64) -> Sealed {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("p.nanpfb");
    std::fs::write(&payload_path, payload(&feeds, 0)).unwrap();
    let path = dir.path().join("bundle.nanfeed");
    let signed = seal(
        &payload_path,
        feeds,
        sequence,
        t0(),
        FIXTURE_KEY_ID,
        &key(),
        &ring(),
        &path,
    )
    .unwrap();
    Sealed {
        _dir: dir,
        path,
        signed,
    }
}

/// Write an arbitrary (possibly invalid) container without `seal`'s checks.
fn raw_container(signed: &SignedDescriptor, payload: &[u8]) -> Vec<u8> {
    let json = serde_json::to_vec(signed).unwrap();
    let mut out = MAGIC.to_vec();
    out.extend((json.len() as u64).to_le_bytes());
    out.extend(json);
    out.extend(payload);
    out
}
/// Sign without validation, to build containers `sign` would refuse.
fn force_sign(mut d: Descriptor) -> SignedDescriptor {
    d.signer_key_id = FIXTURE_KEY_ID.into();
    let signature = hex::encode(key().sign(&d.canonical().unwrap()).to_bytes());
    SignedDescriptor {
        descriptor: d,
        signature,
    }
}

#[test]
fn seal_then_verify_roundtrip_carries_terms_notice_and_no_location() {
    let s = seal_with(
        feeds(&[("ipinfo_lite", 3), ("threatfox", 9), ("tor_exit_nodes", 4)]),
        7,
    );
    let v = verify_file(&s.path, &ring()).unwrap();
    let d = v.descriptor();
    assert_eq!(v.signed, s.signed);
    assert_eq!(d.format, "nano/feed-bundle");
    assert_eq!(d.payload.format, "NANPFB01");
    assert_eq!(d.feeds["ipinfo_lite"].license_id, "CC-BY-SA-4.0");
    assert_eq!(d.feeds["threatfox"].license_id, "CC0-1.0");
    assert!(d.notice.contains("CC BY-SA 4.0") && d.notice.contains("https://ipinfo.io"));
    let json = serde_json::to_string(&s.signed).unwrap();
    for location in [
        "bucket",
        "fencing_epoch",
        "object_key",
        "endpoint",
        "tenant",
    ] {
        assert!(!json.contains(location), "descriptor leaks {location}");
    }
    // The standalone descriptor (distribution `current.json`) verifies alone.
    assert_eq!(
        SignedDescriptor::from_json(json.as_bytes(), &ring()).unwrap(),
        s.signed
    );
}

#[test]
fn rotation_ring_accepts_any_listed_key_and_refuses_unlisted() {
    let s = seal_with(feeds(&[("threatfox", 1)]), 1);
    let other = SigningKey::from_bytes(&[9; 32]);
    let rotated = KeyRing::from_hex(&[
        ("next", &hex::encode(other.verifying_key().as_bytes())),
        (
            FIXTURE_KEY_ID,
            &hex::encode(key().verifying_key().as_bytes()),
        ),
    ])
    .unwrap();
    assert!(verify_file(&s.path, &rotated).is_ok());
    let without =
        KeyRing::from_hex(&[("next", &hex::encode(other.verifying_key().as_bytes()))]).unwrap();
    assert!(matches!(
        verify_file(&s.path, &without),
        Err(BundleError::UntrustedSigner)
    ));
    // Same id, different key: signature fails.
    let swapped = KeyRing::from_hex(&[(
        FIXTURE_KEY_ID,
        &hex::encode(other.verifying_key().as_bytes()),
    )])
    .unwrap();
    assert!(matches!(
        verify_file(&s.path, &swapped),
        Err(BundleError::BadSignature)
    ));
    // A publisher cannot sign with a key its consumers do not trust.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("p");
    std::fs::write(&p, payload(&feeds(&[("threatfox", 1)]), 0)).unwrap();
    let r = seal(
        &p,
        feeds(&[("threatfox", 1)]),
        1,
        t0(),
        "next",
        &key(),
        &rotated,
        &dir.path().join("o"),
    );
    assert!(matches!(r, Err(BundleError::UntrustedSigner)));
}

#[test]
fn production_ring_is_compiled_in_and_refuses_fixture_signatures() {
    let production = KeyRing::production();
    assert_eq!(production.0.len(), PRODUCTION_KEYS.len());
    assert!(production
        .0
        .contains_key("platform-ad038f5046fb19e51bf310e0"));
    let s = seal_with(feeds(&[("threatfox", 1)]), 1);
    assert!(matches!(
        verify_file(&s.path, &production),
        Err(BundleError::UntrustedSigner)
    ));
}

#[test]
fn any_tampering_is_refused() {
    let s = seal_with(feeds(&[("ipinfo_lite", 1), ("tor_exit_nodes", 1)]), 1);
    let good = std::fs::read(&s.path).unwrap();
    let check = |bytes: &[u8]| verify_reader(bytes, &ring());
    assert!(check(&good).is_ok());
    // Payload byte flip.
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert!(matches!(
        check(&flipped),
        Err(BundleError::PayloadMismatch(_))
    ));
    // Trailing and truncated bytes.
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        check(&trailing),
        Err(BundleError::PayloadMismatch(_))
    ));
    assert!(matches!(
        check(&good[..good.len() - 1]),
        Err(BundleError::PayloadMismatch(_))
    ));
    // Descriptor field changed after signing (extend expiry).
    let mut later = s.signed.clone();
    later
        .descriptor
        .feeds
        .get_mut("tor_exit_nodes")
        .unwrap()
        .hard_expiry += Duration::hours(1);
    let p = payload(&s.signed.descriptor.feeds, 0);
    assert!(matches!(
        check(&raw_container(&later, &p)),
        Err(BundleError::BadSignature)
    ));
    // Non-canonical signature encoding.
    let mut upper = s.signed.clone();
    upper.signature = upper.signature.to_uppercase();
    assert!(matches!(
        check(&raw_container(&upper, &p)),
        Err(BundleError::BadSignature)
    ));
    // Bad magic.
    let mut magic = good.clone();
    magic[0] = b'X';
    assert!(matches!(check(&magic), Err(BundleError::Invalid(_))));
}

#[test]
fn signature_failure_never_reads_the_payload() {
    struct DescriptorOnly(std::io::Cursor<Vec<u8>>);
    impl Read for DescriptorOnly {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                self.0.position() < self.0.get_ref().len() as u64,
                "read unverified payload"
            );
            self.0.read(buf)
        }
    }
    let s = seal_with(feeds(&[("threatfox", 1)]), 1);
    let mut forged = s.signed;
    forged.descriptor.sequence += 1;
    let head = raw_container(&forged, &[]);
    assert!(matches!(
        verify_reader(DescriptorOnly(std::io::Cursor::new(head)), &ring()),
        Err(BundleError::BadSignature)
    ));
}

#[test]
fn signed_path_components_are_refused_and_verified_state_is_immutable() {
    let s = seal_with(feeds(&[("threatfox", 1)]), 1);
    let v = verify_file(&s.path, &ring()).unwrap();
    let mut detached = v.signed().clone();
    detached
        .descriptor
        .feeds
        .get_mut("threatfox")
        .unwrap()
        .hard_expiry += Duration::days(1);
    assert_eq!(v.signed(), &s.signed);
    assert!(matches!(
        detached.verify(&ring()),
        Err(BundleError::BadSignature)
    ));
    // Even signed descriptors cannot supply an unpack path: only lowercase
    // SHA-256 is accepted, and no archive member names are interpreted.
    for digest in ["../outside", "/tmp/outside", "..\\outside", &"A".repeat(64)] {
        let mut d = s.signed.descriptor.clone();
        d.payload.sha256 = digest.into();
        let signed = force_sign(d);
        assert!(matches!(
            signed.verify(&ring()),
            Err(BundleError::Invalid("payload"))
        ));
    }
}

#[test]
fn payload_header_must_match_signed_revisions_expiries_and_feed_set() {
    let f = feeds(&[("threatfox", 2)]);
    let base = seal_with(f.clone(), 1).signed.descriptor;
    let resign = |payload: &[u8]| {
        let mut d = base.clone();
        d.payload.sha256 = hex::encode(Sha256::digest(payload));
        d.payload.bytes = payload.len() as u64;
        raw_container(&force_sign(d), payload)
    };
    // Revision differs from the signed entry.
    let p = payload(&feeds(&[("threatfox", 3)]), 0);
    assert!(matches!(
        verify_reader(&resign(&p)[..], &ring()),
        Err(BundleError::PayloadMismatch(_))
    ));
    // Expiry differs.
    let mut other = f.clone();
    other.get_mut("threatfox").unwrap().hard_expiry -= Duration::minutes(1);
    let p = payload(&other, 0);
    assert!(matches!(
        verify_reader(&resign(&p)[..], &ring()),
        Err(BundleError::PayloadMismatch(_))
    ));
    // A premium prefix (Synthient) section is never portable.
    let p = payload(&f, 64);
    assert!(matches!(
        verify_reader(&resign(&p)[..], &ring()),
        Err(BundleError::PayloadMismatch(_))
    ));
    // An extra feed in the payload header.
    let mut extra = f.clone();
    extra.insert("synthient".into(), entry("threatfox", 1));
    let p = payload(&extra, 0);
    assert!(matches!(
        verify_reader(&resign(&p)[..], &ring()),
        Err(BundleError::PayloadMismatch(_))
    ));
    // Not a NANPFB01 payload.
    let mut p = payload(&f, 0);
    p[0] = b'Z';
    assert!(matches!(
        verify_reader(&resign(&p)[..], &ring()),
        Err(BundleError::PayloadMismatch(_))
    ));
}

#[test]
fn descriptor_rules_refuse_non_portable_feeds_wrong_terms_and_notice() {
    let base = seal_with(feeds(&[("ipinfo_lite", 1)]), 1).signed.descriptor;
    let refused = |mutate: &dyn Fn(&mut Descriptor)| {
        let mut d = base.clone();
        mutate(&mut d);
        let p = payload(&d.feeds, 0);
        d.payload.sha256 = hex::encode(Sha256::digest(&p));
        d.payload.bytes = p.len() as u64;
        assert!(
            d.clone().sign(FIXTURE_KEY_ID, &key()).is_err(),
            "sign accepted {d:?}"
        );
        let r = verify_reader(&raw_container(&force_sign(d), &p)[..], &ring());
        assert!(matches!(r, Err(BundleError::Invalid(_))), "{r:?}");
    };
    refused(&|d| {
        let e = d.feeds.remove("ipinfo_lite").unwrap();
        d.feeds.insert("synthient".into(), e);
    });
    refused(&|d| d.feeds.get_mut("ipinfo_lite").unwrap().license_id = "proprietary".into());
    refused(&|d| d.notice = d.notice.replace("CC BY-SA 4.0", "CC BY 4.0"));
    refused(&|d| d.notice.clear());
    refused(&|d| {
        d.feeds
            .get_mut("ipinfo_lite")
            .unwrap()
            .terms_revision
            .clear()
    });
    refused(&|d| {
        let f = d.feeds.get_mut("ipinfo_lite").unwrap();
        f.hard_expiry = f.upstream_at + Duration::days(15);
    });
    refused(&|d| {
        let f = d.feeds.get_mut("ipinfo_lite").unwrap();
        f.hard_expiry = f.produced_at;
    });
    refused(&|d| {
        d.feeds.get_mut("ipinfo_lite").unwrap().produced_at = d.produced_at + Duration::seconds(1)
    });
    refused(&|d| d.feeds.get_mut("ipinfo_lite").unwrap().revision = 0);
    refused(&|d| d.format_version = 2);
    refused(&|d| d.sequence = 0);
    refused(&|d| d.feeds.clear());
    // Tor's hard expiry window is one day.
    let mut tor = feeds(&[("tor_exit_nodes", 1)]);
    let t = tor.get_mut("tor_exit_nodes").unwrap();
    t.hard_expiry = t.upstream_at + Duration::hours(25);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("p");
    std::fs::write(&p, payload(&tor, 0)).unwrap();
    assert!(seal(
        &p,
        tor,
        1,
        t0(),
        FIXTURE_KEY_ID,
        &key(),
        &ring(),
        &dir.path().join("o")
    )
    .is_err());
    // Unknown descriptor fields are refused (deny_unknown_fields).
    let mut json: serde_json::Value = serde_json::to_value(force_sign(base.clone())).unwrap();
    json["descriptor"]["bucket"] = "nano-platform-feeds".into();
    assert!(SignedDescriptor::from_json(&serde_json::to_vec(&json).unwrap(), &ring()).is_err());
}

#[test]
fn install_policy_refuses_rollback_substitution_regression_and_all_expired() {
    let old = seal_with(feeds(&[("threatfox", 5), ("tor_exit_nodes", 5)]), 10);
    let installed = old.signed.descriptor.clone();
    let now = t0();
    let v = |s: &Sealed| verify_file(&s.path, &ring()).unwrap();
    assert!(v(&old).accept_after(None, now).is_ok());
    assert!(
        v(&old).accept_after(Some(&installed), now).is_ok(),
        "reinstall is idempotent"
    );
    let older = seal_with(feeds(&[("threatfox", 6), ("tor_exit_nodes", 6)]), 9);
    assert!(matches!(
        v(&older).accept_after(Some(&installed), now),
        Err(BundleError::Rollback(_))
    ));
    let substitute = seal_with(feeds(&[("threatfox", 6), ("tor_exit_nodes", 6)]), 10);
    assert!(matches!(
        v(&substitute).accept_after(Some(&installed), now),
        Err(BundleError::Rollback(_))
    ));
    let regressed = seal_with(feeds(&[("threatfox", 6), ("tor_exit_nodes", 4)]), 11);
    assert!(matches!(
        v(&regressed).accept_after(Some(&installed), now),
        Err(BundleError::Rollback(_))
    ));
    let newer = seal_with(feeds(&[("threatfox", 6), ("tor_exit_nodes", 5)]), 11);
    assert!(v(&newer).accept_after(Some(&installed), now).is_ok());
    // Entirely expired: refused. Partly expired: accepted (expired feeds just stop stamping).
    let expiry = installed.feeds["tor_exit_nodes"].hard_expiry;
    assert!(matches!(
        v(&newer).accept_after(Some(&installed), expiry),
        Err(BundleError::Expired)
    ));
    let fresh = installed.freshness(expiry);
    assert!(fresh
        .iter()
        .all(|f| f.expired && f.age_seconds == 20 * 3600));
}

#[test]
fn install_payload_writes_sealed_content_addressed_nanpfb_idempotently() {
    let s = seal_with(feeds(&[("ipinfo_lite", 1), ("threatfox", 1)]), 1);
    let v = verify_file(&s.path, &ring()).unwrap();
    let cell = tempfile::tempdir().unwrap();
    let path = v.install_payload(&s.path, cell.path()).unwrap();
    let sha = &v.descriptor().payload.sha256;
    assert_eq!(path, cell.path().join(format!("platform-{sha}.nanpfb")));
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), *sha);
    assert_eq!(&bytes[..8], b"NANPFB01");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o444
    );
    assert_eq!(v.install_payload(&s.path, cell.path()).unwrap(), path);
    // A source swapped after verification is caught while copying.
    let other = tempfile::tempdir().unwrap();
    let mut changed = std::fs::read(&s.path).unwrap();
    *changed.last_mut().unwrap() ^= 1;
    std::fs::write(&s.path, changed).unwrap();
    assert!(matches!(
        v.install_payload(&s.path, other.path()),
        Err(BundleError::PayloadMismatch(_))
    ));
}

#[test]
fn file_verification_and_install_refuse_symlinks_nonregular_and_unsealed_files() {
    use std::os::unix::fs::symlink;
    let s = seal_with(feeds(&[("threatfox", 1)]), 1);
    let v = verify_file(&s.path, &ring()).unwrap();
    let cell = tempfile::tempdir().unwrap();
    let source_link = cell.path().join("source-link");
    symlink(&s.path, &source_link).unwrap();
    assert!(verify_file(&source_link, &ring()).is_err());
    assert!(v.install_payload(&source_link, cell.path()).is_err());
    assert!(verify_file(cell.path(), &ring()).is_err());

    // O_NONBLOCK lets the regular-file check refuse a FIFO without hanging.
    let fifo = cell.path().join("fifo");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: fifo_c is a valid NUL-terminated path within this test's tempdir.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    assert!(verify_file(&fifo, &ring()).is_err());

    let installed = v.install_payload(&s.path, cell.path()).unwrap();
    let saved = cell.path().join("saved");
    std::fs::rename(&installed, &saved).unwrap();
    symlink(&saved, &installed).unwrap();
    assert!(v.install_payload(&s.path, cell.path()).is_err());
    std::fs::remove_file(&installed).unwrap();
    std::fs::hard_link(&saved, &installed).unwrap();
    assert!(v.install_payload(&s.path, cell.path()).is_err());
    std::fs::remove_file(&installed).unwrap();
    std::fs::rename(&saved, &installed).unwrap();
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(v.install_payload(&s.path, cell.path()).is_err());
    std::fs::write(&installed, b"wrong payload").unwrap();
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert!(matches!(
        v.install_payload(&s.path, cell.path()),
        Err(BundleError::PayloadMismatch(_))
    ));
}

/// Golden v1 fixture (generated by the lake-worker
/// `portable_feed_bundle_golden` test from a real NANPFB01 bundle). Any
/// change to the encoding, canonical form or signature domain breaks this.
#[test]
fn golden_v1_fixture_verifies_and_is_pinned() {
    let path = Path::new(GOLDEN_DIR).join("bundle.nanfeed");
    let v = verify_file(&path, &ring()).unwrap();
    let descriptor = std::fs::read(Path::new(GOLDEN_DIR).join("descriptor.json")).unwrap();
    assert_eq!(
        SignedDescriptor::from_json(&descriptor, &ring()).unwrap(),
        v.signed
    );
    let notice = std::fs::read_to_string(Path::new(GOLDEN_DIR).join("NOTICE")).unwrap();
    assert_eq!(notice, v.descriptor().notice);
    assert_eq!(
        v.descriptor()
            .feeds
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["ipinfo_lite", "threatfox", "tor_exit_nodes"]
    );
    let keys: BTreeMap<String, String> = serde_json::from_slice(
        &std::fs::read(Path::new(GOLDEN_DIR).join("fixture-keys.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        keys[FIXTURE_KEY_ID],
        hex::encode(key().verifying_key().as_bytes())
    );
}
