// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the pure name-validation decisions in parser CRUD.
//!
//! Both guards here run before any database write and are split out as free
//! functions precisely so they can be exercised without a pool.

use uuid::Uuid;

use super::{identity_conflict, reserved_route_claim};

/// One `(id, name)` row as `ParserRepository::list_identities` returns it.
fn parser(id: u128, name: &str) -> (Uuid, String) {
    (Uuid::from_u128(id), name.to_string())
}

/// NAN-1124: names whose `safe_name` lands in the reserved `nano_` namespace
/// are rejected; everything else is allowed. `safe_name` lowercases and maps
/// non-alphanumerics to `_`, so spaces/dashes/case all normalize.
#[test]
fn reserves_nano_prefixed_route_claims() {
    for name in [
        "nano_enrich",
        "Nano Enrich",
        "nano enrich",
        "nano-enrich",
        "NANO_IDENTITY",
    ] {
        assert!(
            reserved_route_claim(name).is_some(),
            "expected '{name}' to be reserved (safe_name starts with nano_)"
        );
    }
    // Not reserved: no `nano_` prefix on the normalized route value.
    for name in [
        "Apache HTTP Server",
        "windows_event",
        "nanoenrich",
        "nano",
        "okta",
        "nginx",
    ] {
        assert!(
            reserved_route_claim(name).is_none(),
            "expected '{name}' to be allowed (safe_name does not start nano_)"
        );
    }
}

// ---------------------------------------------------------------------------
// NAN-2305: generated-identity uniqueness on create / rename
// ---------------------------------------------------------------------------

/// The defect: `log_sources.name` is UNIQUE on the raw string, so this create
/// was accepted. Both rows then generate `my_source.toml` and the route key
/// `my_source`, and one source silently stops being ingested.
#[test]
fn create_is_rejected_when_the_generated_identifier_is_taken() {
    let existing = [parser(1, "My Source")];

    let conflict = identity_conflict("my-source", &existing, None)
        .expect("a name generating a taken identifier must be rejected");

    assert!(conflict.contains("my_source"), "{conflict}");
    assert!(conflict.contains("My Source"), "{conflict}");
}

/// Every axis `safe_name` erases — case, spacing, punctuation — is a collision,
/// and none of them look like one to the operator picking the name.
#[test]
fn every_lossy_axis_is_treated_as_taken() {
    let existing = [parser(1, "My Source")];

    for candidate in ["my source", "MY SOURCE", "my_source", "My/Source", "my.source"] {
        assert!(
            identity_conflict(candidate, &existing, None).is_some(),
            "expected '{candidate}' to collide with 'My Source'"
        );
    }
}

/// A false positive fails a legitimate create, so distinct names must pass.
#[test]
fn distinct_names_are_accepted() {
    let existing = [parser(1, "My Source"), parser(2, "Apache HTTP Server")];

    for candidate in ["Okta System Log", "my-source-2", "Apache HTTP Server (OCSF)"] {
        assert!(
            identity_conflict(candidate, &existing, None).is_none(),
            "expected '{candidate}' to be accepted"
        );
    }
}

/// Renaming a source must not report it as conflicting with itself, or a
/// cosmetic rename (`My Source` → `My  Source`) would be impossible.
#[test]
fn rename_that_keeps_the_same_identifier_is_allowed() {
    let existing = [parser(1, "My Source")];
    let self_id = Uuid::from_u128(1);

    assert!(identity_conflict("My  Source", &existing, Some(self_id)).is_none());
    assert!(identity_conflict("my-source", &existing, Some(self_id)).is_none());
}

/// ...but a rename onto a DIFFERENT source's identifier is still a collision.
/// This is the likelier path in practice: the operator is editing one source
/// and has no reason to suspect the new name overlaps another.
#[test]
fn rename_onto_another_sources_identifier_is_rejected() {
    let existing = [parser(1, "My Source"), parser(2, "Apache HTTP Server")];
    let renaming = Uuid::from_u128(2);

    let conflict = identity_conflict("my-source", &existing, Some(renaming))
        .expect("rename onto another source's identifier must be rejected");
    assert!(conflict.contains("My Source"), "{conflict}");
}
