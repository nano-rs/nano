// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5283: rotating the content signing key with an overlap window.
//!
//! The app publishes each sequence under the current key (top level of the
//! metadata response, what every shipped release reads) and, during the
//! overlap, under the new key too (`alternates`). These tests walk the
//! phases from the install's side: an old release, a release that trusts both
//! keys, and the cutover.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};

use super::consumer::{parse_current, ChannelError, MAX_ALTERNATES};
use super::contract::{
    self, assemble, unsigned_descriptor, verify_bytes, ContentError, SealInput, SignedContentDescriptor, Upstream,
};
use super::tree;
use crate::platform_enrichment::portable::KeyRing;

const OLD_ID: &str = "fixture-content-1";
const NEW_ID: &str = "fixture-content-kms";

fn old_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32]) // the contract tests' fixture key
}
/// Stands in for the KMS key: signing happens outside `seal`.
fn new_key() -> SigningKey {
    SigningKey::from_bytes(&[0x43; 32])
}
fn hexkey(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().as_bytes())
}
/// What releases before the rotation trust.
fn old_ring() -> KeyRing {
    KeyRing::from_hex(&[(OLD_ID, &hexkey(&old_key()))]).unwrap()
}
/// What the overlap release trusts (appended, never replaced).
fn both_ring() -> KeyRing {
    KeyRing::from_hex(&[(OLD_ID, &hexkey(&old_key())), (NEW_ID, &hexkey(&new_key()))]).unwrap()
}
/// A later release that dropped the old key.
fn new_ring() -> KeyRing {
    KeyRing::from_hex(&[(NEW_ID, &hexkey(&new_key()))]).unwrap()
}

struct Publication {
    payload: Vec<u8>,
    old: (SignedContentDescriptor, Vec<u8>),
    new: (SignedContentDescriptor, Vec<u8>),
}

fn input(produced_at: DateTime<Utc>, sequence: u64) -> SealInput<'static> {
    SealInput {
        channel: "rules.main",
        sequence,
        produced_at,
        upstream: Upstream { commit: "b".repeat(40), committed_at: produced_at - Duration::hours(1) },
    }
}

/// One sequence signed twice, as the publisher does during the overlap: the
/// old key in process (`seal`), the new key remotely (`signing_message` →
/// signature → `assemble`).
fn dual(sequence: u64) -> Publication {
    let now = Utc::now();
    let files = super::contract::tests_support::sample_files();
    let payload = tree::pack(&files).unwrap();
    let summary = tree::summarize(&files);
    let old = contract::seal(input(now, sequence), &payload, &summary, OLD_ID, &old_key(), &both_ring()).unwrap();
    let (descriptor, message) =
        unsigned_descriptor(input(now, sequence), &payload, &summary).unwrap().signing_message(NEW_ID).unwrap();
    let signature = new_key().sign(&message).to_bytes(); // the KMS asymmetricSign response
    let new = assemble(descriptor, &signature, &payload, &both_ring()).unwrap();
    Publication { payload, old, new }
}

fn entry(signed: &SignedContentDescriptor, url: &str) -> serde_json::Value {
    serde_json::json!({ "descriptor": signed, "bundle_url": url, "bundle_sha256": signed.descriptor.payload.sha256 })
}

/// The route's response during the overlap: legacy fields untouched, the new
/// signature beside them.
fn overlap_body(p: &Publication) -> Vec<u8> {
    let mut body = entry(&p.old.0, "https://r2.example/old.nancontent");
    body["bundle_url_expires_in"] = 300.into();
    body["alternates"] = serde_json::json!([entry(&p.new.0, "https://r2.example/new.nancontent")]);
    serde_json::to_vec(&body).unwrap()
}

#[test]
fn both_signatures_cover_the_same_publication() {
    let p = dual(7);
    assert_eq!(p.old.0.descriptor.signer_key_id, OLD_ID);
    assert_eq!(p.new.0.descriptor.signer_key_id, NEW_ID);
    assert!(p.old.0.descriptor.same_content(&p.new.0.descriptor));
    assert_ne!(p.old.1, p.new.1, "each signer has its own container");
    assert!(p.old.1.ends_with(&p.payload) && p.new.1.ends_with(&p.payload), "one payload, two descriptors");
}

#[test]
fn an_old_release_reads_the_top_level_entry_and_ignores_alternates() {
    let p = dual(7);
    let r = parse_current(&overlap_body(&p), &old_ring(), "rules.main", false).unwrap();
    assert_eq!(r.signed, p.old.0);
    assert_eq!(r.bundle_url, "https://r2.example/old.nancontent");
    // What a pre-NAN-5283 release does with the same body: only `descriptor`.
    let v: serde_json::Value = serde_json::from_slice(&overlap_body(&p)).unwrap();
    let legacy = SignedContentDescriptor::from_json(&serde_json::to_vec(&v["descriptor"]).unwrap(), &old_ring()).unwrap();
    assert_eq!(legacy, p.old.0);
    assert!(verify_bytes(&p.old.1, &old_ring()).is_ok());
}

#[test]
fn the_overlap_release_takes_the_first_trusted_entry() {
    let p = dual(7);
    let r = parse_current(&overlap_body(&p), &both_ring(), "rules.main", false).unwrap();
    assert_eq!(r.signed, p.old.0, "the publisher's order decides; the top level comes first");
    assert!(verify_bytes(&p.new.1, &both_ring()).is_ok());
}

#[test]
fn a_release_that_dropped_the_old_key_uses_the_alternate() {
    let p = dual(7);
    let r = parse_current(&overlap_body(&p), &new_ring(), "rules.main", false).unwrap();
    assert_eq!(r.signed, p.new.0);
    assert_eq!(r.bundle_url, "https://r2.example/new.nancontent");
    assert!(matches!(verify_bytes(&p.old.1, &new_ring()), Err(ContentError::UntrustedSigner)));
}

#[test]
fn after_cutover_old_releases_refuse_which_is_why_cutover_waits_for_the_minimum_version() {
    let p = dual(7);
    let body = serde_json::to_vec(&entry(&p.new.0, "https://r2.example/new.nancontent")).unwrap();
    assert!(parse_current(&body, &both_ring(), "rules.main", false).is_ok());
    assert!(matches!(parse_current(&body, &old_ring(), "rules.main", false), Err(ChannelError::Refused(_))));
}

#[test]
fn only_an_untrusted_signer_moves_on_to_the_next_entry() {
    let p = dual(7);
    // A trusted top-level entry with a bad signature refuses the response even
    // though a valid alternate follows.
    let mut forged = p.old.0.clone();
    forged.descriptor.tree.files += 1;
    let mut body = entry(&forged, "https://r2.example/old");
    body["alternates"] = serde_json::json!([entry(&p.new.0, "https://r2.example/new")]);
    assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &both_ring(), "rules.main", false).is_err());
    // An alternate is held to the same checks as the top level.
    let mut body = entry(&p.old.0, "https://r2.example/old");
    let mut wrong_digest = entry(&p.new.0, "https://r2.example/new");
    wrong_digest["bundle_sha256"] = "00".repeat(32).into();
    body["alternates"] = serde_json::json!([wrong_digest]);
    assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).is_err());
    let mut body = entry(&p.old.0, "https://r2.example/old");
    body["alternates"] = serde_json::json!([entry(&p.new.0, "http://r2.example/new")]);
    assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).is_err());
    // Malformed alternates are refused, not skipped.
    let mut body = entry(&p.old.0, "https://r2.example/old");
    body["alternates"] = "nope".into();
    assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).is_err());
    // No trusted entry at all.
    let unknown = KeyRing::from_hex(&[("other", &hexkey(&SigningKey::from_bytes(&[0x44; 32])))]).unwrap();
    assert!(parse_current(&overlap_body(&p), &unknown, "rules.main", false).is_err());
}

#[test]
fn alternates_are_bounded() {
    let p = dual(7);
    let mut body = entry(&p.old.0, "https://r2.example/old");
    let filler = entry(&p.old.0, "https://r2.example/old");
    let mut list = vec![filler; MAX_ALTERNATES];
    list.push(entry(&p.new.0, "https://r2.example/new"));
    body["alternates"] = serde_json::Value::Array(list);
    // The new-key entry sits past the bound: a new-key-only ring finds nothing.
    assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).is_err());
}

#[test]
fn moving_between_signatures_of_one_sequence_is_not_a_substitution() {
    let p = dual(7);
    let new = verify_bytes(&p.new.1, &both_ring()).unwrap();
    let now = Utc::now();
    assert!(new.accept_after(Some(&p.old.0.descriptor), now, false).is_ok());
    let old = verify_bytes(&p.old.1, &both_ring()).unwrap();
    assert!(old.accept_after(Some(&p.new.0.descriptor), now, false).is_ok());
    // Different content under the same sequence is still refused.
    let mut other = p.old.0.descriptor.clone();
    other.upstream.commit = "c".repeat(40);
    assert!(matches!(new.accept_after(Some(&other), now, false), Err(ContentError::Rollback(_))));
}

#[test]
fn assemble_refuses_a_signature_the_ring_does_not_verify() {
    let now = Utc::now();
    let files = super::contract::tests_support::sample_files();
    let payload = tree::pack(&files).unwrap();
    let summary = tree::summarize(&files);
    let (descriptor, message) =
        unsigned_descriptor(input(now, 9), &payload, &summary).unwrap().signing_message(NEW_ID).unwrap();
    // Signed by the wrong key (a wrong KMS key version, say).
    let wrong = old_key().sign(&message).to_bytes();
    assert!(matches!(assemble(descriptor.clone(), &wrong, &payload, &both_ring()), Err(ContentError::BadSignature)));
    // A key id the ring does not hold.
    let sig = new_key().sign(&message).to_bytes();
    assert!(matches!(assemble(descriptor.clone(), &sig, &payload, &old_ring()), Err(ContentError::UntrustedSigner)));
    // Payload swapped after signing.
    let other = tree::pack(&super::contract::tests_support::sample_files().into_iter().take(1).collect()).unwrap();
    assert!(assemble(descriptor, &sig, &other, &both_ring()).is_err());
}

#[test]
fn an_alternate_cannot_downgrade_or_replay_and_cannot_be_unsigned() {
    // Top level untrusted, a trusted alternate of an OLDER sequence: parse takes
    // it, but the install policy refuses the rollback against what is installed.
    let installed = dual(8);
    let older = dual(7);
    let mut body = entry(&installed.old.0, "https://r2.example/old");
    body["alternates"] = serde_json::json!([entry(&older.new.0, "https://r2.example/new")]);
    let r = parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).unwrap();
    assert_eq!(r.signed.descriptor.sequence, 7);
    let v = verify_bytes(&older.new.1, &new_ring()).unwrap();
    assert!(matches!(
        v.accept_after(Some(&installed.new.0.descriptor), Utc::now(), false),
        Err(ContentError::Rollback("sequence"))
    ));
    assert!(matches!(
        v.accept_after(Some(&installed.old.0.descriptor), Utc::now(), true),
        Err(ContentError::Rollback("sequence"))
    ), "offline import refuses rollback too");
    // An alternate naming the trusted KMS key with no / a forged signature
    // refuses the whole response; it is never skipped as "untrusted".
    for signature in ["", &"00".repeat(64)] {
        let mut forged = installed.new.0.clone();
        forged.signature = signature.to_string();
        let mut body = entry(&installed.old.0, "https://r2.example/old");
        body["alternates"] = serde_json::json!([entry(&forged, "https://r2.example/new")]);
        assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).is_err());
    }
    // An unknown signer in an alternate is skipped; with nothing trusted left
    // the response is refused.
    let stranger = SigningKey::from_bytes(&[0x45; 32]);
    let (d, msg) = unsigned_descriptor(input(Utc::now(), 9), &installed.payload, &tree::summarize(&super::contract::tests_support::sample_files()))
        .unwrap()
        .signing_message("stranger")
        .unwrap();
    let strange = SignedContentDescriptor { descriptor: d, signature: hex::encode(stranger.sign(&msg).to_bytes()) };
    let mut body = entry(&installed.old.0, "https://r2.example/old");
    body["alternates"] = serde_json::json!([entry(&strange, "https://r2.example/s")]);
    assert!(parse_current(&serde_json::to_vec(&body).unwrap(), &new_ring(), "rules.main", false).is_err());
    // A container signed by one key can't stand in for the other's descriptor:
    // the download is compared with the announced signed descriptor verbatim.
    assert_ne!(verify_bytes(&installed.old.1, &both_ring()).unwrap().signed(), &installed.new.0);
}
