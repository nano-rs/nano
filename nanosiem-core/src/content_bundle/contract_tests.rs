// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

pub(crate) const KEY_ID: &str = "fixture-content-1";

pub(crate) fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

pub(crate) fn ring() -> KeyRing {
    KeyRing::from_hex(&[(KEY_ID, &hex::encode(key().verifying_key().as_bytes()))]).unwrap()
}

pub(crate) fn sample_files() -> Files {
    [("parsers/okta/parser.yaml", "name: okta\n"), ("README.md", "nano parsers\n")]
        .iter()
        .map(|(p, c)| (p.to_string(), c.as_bytes().to_vec()))
        .collect()
}

pub(crate) fn sealed(channel: &str, sequence: u64, produced_at: DateTime<Utc>, files: &Files) -> (SignedContentDescriptor, Vec<u8>) {
    let payload = tree::pack(files).unwrap();
    let summary = tree::summarize(files);
    let commit = if channels::by_id(channel).unwrap().repo.is_empty() { String::new() } else { "a".repeat(40) };
    seal(
        SealInput { channel, sequence, produced_at, upstream: Upstream { commit, committed_at: produced_at - Duration::hours(1) } },
        &payload,
        &summary,
        KEY_ID,
        &key(),
        &ring(),
    )
    .unwrap()
}

#[test]
fn seal_then_verify_round_trips() {
    let now = Utc::now();
    let (signed, bytes) = sealed("parsers.main", 10, now, &sample_files());
    let v = verify_bytes(&bytes, &ring()).unwrap();
    assert_eq!(v.signed(), &signed);
    assert_eq!(v.files(), &sample_files());
    assert_eq!(v.descriptor().repo, "nano-rs/parsers");
    assert_eq!(v.descriptor().hard_expiry, now + VALIDITY);
}

#[test]
fn tampered_payload_byte_is_refused() {
    let (_, mut bytes) = sealed("rules.main", 10, Utc::now(), &sample_files());
    let last = bytes.len() - 5;
    bytes[last] ^= 0xff;
    assert!(matches!(verify_bytes(&bytes, &ring()), Err(ContentError::PayloadMismatch(_))));
}

#[test]
fn tampered_descriptor_is_refused() {
    let (signed, bytes) = sealed("rules.main", 10, Utc::now(), &sample_files());
    let mut forged = signed.clone();
    forged.descriptor.upstream.commit = "b".repeat(40);
    let json = serde_json::to_vec(&forged).unwrap();
    let len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
    let payload = &bytes[16 + len..];
    let mut out = MAGIC.to_vec();
    out.extend((json.len() as u64).to_le_bytes());
    out.extend(json);
    out.extend(payload);
    assert!(matches!(verify_bytes(&out, &ring()), Err(ContentError::BadSignature)));
}

#[test]
fn untrusted_signer_is_refused() {
    let (_, bytes) = sealed("rules.main", 10, Utc::now(), &sample_files());
    let other = SigningKey::from_bytes(&[7; 32]);
    let other_ring = KeyRing::from_hex(&[(KEY_ID, &hex::encode(other.verifying_key().as_bytes()))]).unwrap();
    assert!(matches!(verify_bytes(&bytes, &other_ring), Err(ContentError::BadSignature)));
    let unknown = KeyRing::from_hex(&[("someone-else", &hex::encode(other.verifying_key().as_bytes()))]).unwrap();
    assert!(matches!(verify_bytes(&bytes, &unknown), Err(ContentError::UntrustedSigner)));
}

#[test]
fn feed_signature_domain_cannot_be_replayed_as_content() {
    // A signature made over the same JSON under another domain does not verify.
    let (signed, _) = sealed("rules.main", 10, Utc::now(), &sample_files());
    let mut msg = b"nano/feed-bundle/descriptor/v1\0".to_vec();
    msg.extend(serde_json::to_vec(&signed.descriptor).unwrap());
    let replay = SignedContentDescriptor { descriptor: signed.descriptor.clone(), signature: hex::encode(key().sign(&msg).to_bytes()) };
    assert!(matches!(replay.verify(&ring()), Err(ContentError::BadSignature)));
}

#[test]
fn unknown_or_mismatched_channel_is_refused() {
    let (signed, _) = sealed("rules.main", 10, Utc::now(), &sample_files());
    let mut d = signed.descriptor.clone();
    d.channel = "rules.attacker".into();
    assert!(d.sign(KEY_ID, &key()).is_err(), "unknown channel cannot even be signed");
    let mut d = signed.descriptor.clone();
    d.repo = "evil/rules".into();
    assert!(d.sign(KEY_ID, &key()).is_err(), "repo must equal the registry");
}

#[test]
fn accept_after_refuses_rollback_substitution_and_expiry() {
    let now = Utc::now();
    let (_, new_bytes) = sealed("parsers.main", 20, now, &sample_files());
    let new = verify_bytes(&new_bytes, &ring()).unwrap();
    let (old_signed, _) = sealed("parsers.main", 30, now, &sample_files());
    assert!(matches!(new.accept_after(Some(&old_signed.descriptor), now, false), Err(ContentError::Rollback("sequence"))));
    let mut other = sample_files();
    other.insert("x".into(), b"y".to_vec());
    let (same_seq, _) = sealed("parsers.main", 20, now, &other);
    assert!(matches!(new.accept_after(Some(&same_seq.descriptor), now, false), Err(ContentError::Rollback(_))));
    assert!(new.accept_after(Some(new.descriptor()), now, false).is_ok());
    let (older, _) = sealed("parsers.main", 5, now, &sample_files());
    assert!(new.accept_after(Some(&older.descriptor), now, false).is_ok());
    // expired: refused online, accepted offline
    let later = now + VALIDITY + Duration::seconds(1);
    assert!(matches!(new.accept_after(None, later, false), Err(ContentError::Expired(_))));
    assert!(new.accept_after(None, later, true).is_ok());
    // another channel's installed descriptor
    let (rules, _) = sealed("rules.main", 1, now, &sample_files());
    assert!(new.accept_after(Some(&rules.descriptor), now, false).is_err());
}

#[test]
fn trailing_bytes_and_truncation_are_refused() {
    let (_, bytes) = sealed("playbooks.main", 10, Utc::now(), &sample_files());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(verify_bytes(&longer, &ring()).is_err());
    assert!(verify_bytes(&bytes[..bytes.len() - 1], &ring()).is_err());
}

#[test]
fn seal_refuses_a_key_outside_the_ring() {
    let files = sample_files();
    let payload = tree::pack(&files).unwrap();
    let other = SigningKey::from_bytes(&[9; 32]);
    let r = seal(
        SealInput { channel: "rules.main", sequence: 1, produced_at: Utc::now(), upstream: Upstream { commit: "a".repeat(40), committed_at: Utc::now() } },
        &payload,
        &tree::summarize(&files),
        KEY_ID,
        &other,
        &ring(),
    );
    assert!(matches!(r, Err(ContentError::UntrustedSigner)));
}

#[test]
fn production_ring_holds_the_platform_key_and_the_kms_key_only() {
    // Exactly these two entries: a rotation appends, it never adds a third key by accident.
    assert_eq!(
        CONTENT_PRODUCTION_KEYS,
        &[
            ("platform-ad038f5046fb19e51bf310e0", "54022ca65c169394eb131164b596d5b1265670289959604405be7da64dcdc516"),
            ("content-signing-v1", "85e132520acab941d01e0a43aa61ba75c411b7da905db46c8dc28ececd7cd4cd"),
        ]
    );
    let ring = production_key_ring();
    assert!(ring.key("platform-ad038f5046fb19e51bf310e0").is_some());
    // NAN-5283 overlap: the Cloud KMS content key is trusted beside the platform key.
    assert_eq!(
        ring.key("content-signing-v1").map(|k| hex::encode(k.as_bytes())).as_deref(),
        Some("85e132520acab941d01e0a43aa61ba75c411b7da905db46c8dc28ececd7cd4cd")
    );
    assert!(ring.key("content-dev-nan4955").is_none());
    assert!(ring.key("content-acceptance-nan4955").is_none());
    #[cfg(not(nano_content_acceptance))]
    {
        assert!(content_key_ring().key("content-dev-nan4955").is_none(), "normal builds never trust the dev key");
        assert!(content_key_ring().key("content-acceptance-nan4955").is_none(), "normal builds never trust the public RFC test key");
    }
}

/// Re-frame a container around `signed_json` with the original payload.
fn reframe(bytes: &[u8], signed_json: &[u8]) -> Vec<u8> {
    let len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
    let mut out = MAGIC.to_vec();
    out.extend((signed_json.len() as u64).to_le_bytes());
    out.extend(signed_json);
    out.extend(&bytes[16 + len..]);
    out
}

#[test]
fn missing_or_malformed_signature_is_refused() {
    let (signed, bytes) = sealed("rules.main", 10, Utc::now(), &sample_files());
    // No `signature` field at all: the container does not parse.
    let mut v = serde_json::to_value(&signed).unwrap();
    v.as_object_mut().unwrap().remove("signature");
    let out = reframe(&bytes, &serde_json::to_vec(&v).unwrap());
    assert!(matches!(verify_bytes(&out, &ring()), Err(ContentError::Invalid(_))));
    // Empty, truncated, non-hex and non-canonical (uppercase) signatures.
    let upper = signed.signature.to_uppercase();
    for sig in [String::new(), signed.signature[..64].to_string(), "zz".repeat(64), upper] {
        let forged = SignedContentDescriptor { descriptor: signed.descriptor.clone(), signature: sig.clone() };
        let out = reframe(&bytes, &serde_json::to_vec(&forged).unwrap());
        assert!(matches!(verify_bytes(&out, &ring()), Err(ContentError::BadSignature)), "{sig:?}");
        assert!(matches!(forged.verify(&ring()), Err(ContentError::BadSignature)), "{sig:?}");
    }
}

#[test]
fn validly_signed_format_downgrade_is_refused() {
    // Even a signature that verifies cannot carry an older (or newer) format.
    let (signed, bytes) = sealed("rules.main", 10, Utc::now(), &sample_files());
    let mut d = signed.descriptor.clone();
    d.format_version = FORMAT_VERSION - 1;
    let signature = hex::encode(key().sign(&d.canonical().unwrap()).to_bytes());
    let downgraded = SignedContentDescriptor { descriptor: d, signature };
    assert!(matches!(downgraded.verify(&ring()), Err(ContentError::Invalid(_))));
    let out = reframe(&bytes, &serde_json::to_vec(&downgraded).unwrap());
    assert!(matches!(verify_bytes(&out, &ring()), Err(ContentError::Invalid(_))));
}

#[test]
fn replay_of_an_older_sequence_is_refused_online_and_offline() {
    let now = Utc::now();
    let (installed, _) = sealed("rules.main", 50, now, &sample_files());
    let (_, old_bytes) = sealed("rules.main", 49, now, &sample_files());
    let old = verify_bytes(&old_bytes, &ring()).unwrap();
    for offline in [false, true] {
        assert!(
            matches!(old.accept_after(Some(&installed.descriptor), now, offline), Err(ContentError::Rollback("sequence"))),
            "offline={offline}"
        );
    }
}
