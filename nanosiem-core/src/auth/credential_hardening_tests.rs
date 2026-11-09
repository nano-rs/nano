// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure unit coverage for the 2026-11-08 auth hardening (NAN-5036, NAN-5044).
//! The DB-backed halves live in `nanosiem-core/tests/credential_revocation_integration.rs`.

use super::api_key::{clamp_to_owner, OwnerClampMode};
use super::service::verify_or_burn;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|p| p.to_string()).collect()
}

// ---------------------------------------------------------------------------
// NAN-5044: api-key permissions are clamped to the owner's current set
// ---------------------------------------------------------------------------

#[test]
fn enforce_withholds_permissions_the_owner_lost() {
    let stored = s(&["search:view", "users:edit", "groups:edit"]);
    let owner = s(&["search:view", "alerts:view"]);
    let out = clamp_to_owner(&stored, &owner, OwnerClampMode::Enforce);
    assert_eq!(out.effective, s(&["search:view"]));
    assert_eq!(out.withheld, s(&["groups:edit", "users:edit"]));
}

#[test]
fn enforce_never_adds_owner_permissions_the_key_was_not_given() {
    let stored = s(&["search:view"]);
    let owner = s(&["search:view", "users:edit"]);
    let out = clamp_to_owner(&stored, &owner, OwnerClampMode::Enforce);
    assert_eq!(out.effective, s(&["search:view"]));
    assert!(out.withheld.is_empty());
}

#[test]
fn a_key_within_its_owner_is_unchanged() {
    let stored = s(&["users:create", "users:view"]);
    let owner = s(&["users:create", "users:view", "users:edit"]);
    let out = clamp_to_owner(&stored, &owner, OwnerClampMode::Enforce);
    assert_eq!(out.effective, stored);
    assert!(out.withheld.is_empty());
}

#[test]
fn audit_keeps_the_stored_set_but_reports_what_it_would_withhold() {
    let stored = s(&["search:view", "users:edit"]);
    let owner = s(&["search:view"]);
    let out = clamp_to_owner(&stored, &owner, OwnerClampMode::Audit);
    assert_eq!(out.effective, stored);
    assert_eq!(out.withheld, s(&["users:edit"]));
}

#[test]
fn a_fully_demoted_owner_leaves_the_key_with_nothing() {
    let out = clamp_to_owner(&s(&["users:edit"]), &[], OwnerClampMode::Enforce);
    assert!(out.effective.is_empty());
}

#[test]
fn clamp_mode_parse_fails_closed_to_enforce() {
    assert_eq!(OwnerClampMode::parse(Some("audit")), OwnerClampMode::Audit);
    assert_eq!(OwnerClampMode::parse(Some("enforce")), OwnerClampMode::Enforce);
    assert_eq!(OwnerClampMode::parse(Some("AUDIT")), OwnerClampMode::Enforce);
    assert_eq!(OwnerClampMode::parse(Some("")), OwnerClampMode::Enforce);
    assert_eq!(OwnerClampMode::parse(None), OwnerClampMode::Enforce);
}

// ---------------------------------------------------------------------------
// NAN-5036: every login rejection costs one real bcrypt verification
// ---------------------------------------------------------------------------

#[test]
fn dummy_hash_is_a_real_default_cost_bcrypt_hash() {
    // If the dummy were malformed, `verify_password` would error out
    // immediately and every "burn" would be free — the oracle would be back.
    let dummy = super::service::DUMMY_BCRYPT_HASH_FOR_TESTS;
    assert_eq!(dummy.len(), 60);
    assert!(dummy.starts_with(&format!("$2b${:02}$", bcrypt::DEFAULT_COST)));
    assert!(
        super::password::verify_password("anything", dummy).is_ok(),
        "the dummy hash must be verifiable (Ok(false)), not a parse error"
    );
}

#[tokio::test]
async fn passwordless_and_unusable_hashes_burn_a_full_bcrypt_and_fail() {
    for hash in [None, Some(""), Some("not-a-bcrypt-hash")] {
        let started = std::time::Instant::now();
        let ok = verify_or_burn("Correct-Horse-1", hash).await.unwrap();
        let elapsed = started.elapsed();
        assert!(!ok, "{hash:?} must never verify");
        // Cost-12 bcrypt is hundreds of ms; the pre-fix short-circuit was ~0.
        assert!(
            elapsed >= std::time::Duration::from_millis(20),
            "{hash:?} returned in {elapsed:?} — no bcrypt work was done (timing oracle)"
        );
    }
}

#[tokio::test]
async fn a_real_hash_still_verifies() {
    let hash = super::password::hash_password("Correct-Horse-1").unwrap();
    assert!(verify_or_burn("Correct-Horse-1", Some(&hash)).await.unwrap());
    assert!(!verify_or_burn("wrong", Some(&hash)).await.unwrap());
}
