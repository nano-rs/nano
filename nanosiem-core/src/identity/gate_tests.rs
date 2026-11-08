// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for `identity::gate` (NAN-3483).

use super::*;
use crate::identity::normalizers::builtin_identity_normalizer;
use serde_json::json;

fn tagged(mut user: serde_json::Value, source: &str) -> serde_json::Value {
    user["kind"] = json!("identity");
    user["source"] = json!(source);
    user["provider_id"] = json!("okta-test");
    user
}

fn okta_user(id: &str) -> serde_json::Value {
    json!({
        "id": id, "status": "ACTIVE",
        "profile": {"login": format!("{id}@example.com"), "email": format!("{id}@example.com"),
                    "firstName": "Test", "lastName": "User"}
    })
}

fn builtin_gate(source: &str) -> IdentityRecordGate {
    let b = builtin_identity_normalizer(source).unwrap();
    IdentityRecordGate::new(source, NormalizerOrigin::Builtin, b.normalize_vrl).unwrap()
}

#[test]
fn every_builtin_compiles_into_a_gate() {
    for b in crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS {
        IdentityRecordGate::new(b.source, NormalizerOrigin::Builtin, b.normalize_vrl)
            .unwrap_or_else(|e| panic!("{}: {e}", b.source));
    }
}

#[test]
fn every_builtin_passes_the_user_registry_contract() {
    for b in crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS {
        crate::parsers::validate_enrichment_encoding_contract("identity", b.normalize_vrl)
            .unwrap_or_else(|e| panic!("{}: {e}", b.source));
    }
}

#[test]
fn okta_records_pass_the_okta_normalizer() {
    let gate = builtin_gate("okta");
    let mut tally = SyncTally::default();
    let records = vec![
        tagged(okta_user("00u1"), "okta"),
        tagged(okta_user("00u2"), "okta"),
    ];
    gate.tally(&records, &mut tally);
    assert_eq!(
        tally,
        SyncTally {
            total: 2,
            dead_lettered: 0,
            first_reason: None
        }
    );
    assert_eq!(verdict(&tally, &gate), SyncVerdict::Completed);
}

/// The CT106 failure: Okta records through the AD normalizer. Every one
/// is rejected, and the verdict is `failed` with the VRL's own reason.
#[test]
fn okta_records_through_the_ad_normalizer_all_dead_letter() {
    let gate = builtin_gate("ad");
    let mut tally = SyncTally::default();
    let records: Vec<_> = (0..3)
        .map(|i| tagged(okta_user(&format!("00u{i}")), "okta"))
        .collect();
    gate.tally(&records, &mut tally);
    assert_eq!(tally.total, 3);
    assert_eq!(tally.dead_lettered, 3);
    let reason = tally.first_reason.clone().unwrap();
    assert!(reason.contains("missing external_id"), "reason: {reason}");
    match verdict(&tally, &gate) {
        SyncVerdict::Failed(m) => {
            assert!(m.contains("all 3 records"), "{m}");
            assert!(m.contains("enrichment_normalize_ad (built-in)"), "{m}");
            assert!(m.contains("missing external_id"), "{m}");
        }
        other => panic!("expected failed, got {other:?}"),
    }
}

#[test]
fn some_dead_lettered_is_partial_with_counts() {
    let gate = builtin_gate("okta");
    let mut tally = SyncTally::default();
    let records = vec![
        tagged(okta_user("00u1"), "okta"),
        tagged(json!({"status": "ACTIVE", "profile": {}}), "okta"),
        tagged(okta_user("00u3"), "okta"),
    ];
    gate.tally(&records, &mut tally);
    assert_eq!(tally.synced(), 2);
    let v = verdict(&tally, &gate);
    assert_eq!(v.status(), "partial");
    let m = v.error().unwrap();
    assert!(
        m.starts_with("1 of 3 records dead-lettered by enrichment_normalize_okta"),
        "{m}"
    );
    assert!(m.contains("missing id"), "{m}");
}

/// NAN-3483 status alignment: Okta SUSPENDED stays `suspended`.
#[test]
fn okta_suspended_maps_to_suspended() {
    let b = builtin_identity_normalizer("okta").unwrap();
    let program = crate::parsers::CompiledNormalizer::compile(b.normalize_vrl).unwrap();
    let mut user = tagged(okta_user("00u9"), "okta");
    user["status"] = json!("SUSPENDED");
    let out = program.run(&user).unwrap();
    assert_eq!(out["account_status"], "suspended");
    assert_eq!(out["account_enabled"], 0);
    user["status"] = json!("DEPROVISIONED");
    assert_eq!(program.run(&user).unwrap()["account_status"], "disabled");
}

#[test]
fn empty_directory_is_completed() {
    let gate = builtin_gate("okta");
    assert_eq!(
        verdict(&SyncTally::default(), &gate),
        SyncVerdict::Completed
    );
}

#[test]
fn a_normalizer_that_does_not_compile_fails_loudly() {
    let err = IdentityRecordGate::new(
        "okta",
        NormalizerOrigin::Imported("okta_identity".into()),
        "this is not vrl (",
    )
    .unwrap_err();
    assert!(err.contains("source 'okta'"), "{err}");
    assert!(err.contains("imported parser okta_identity"), "{err}");
}
