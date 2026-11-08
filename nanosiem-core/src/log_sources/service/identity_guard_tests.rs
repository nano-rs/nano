// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2311 — the generated-identity guard, on the service the API uses.

use crate::vector_naming::generated_identity_conflict;
use uuid::Uuid;

fn rows() -> Vec<(Uuid, String)> {
    vec![
        (Uuid::from_u128(1), "ZZ Validation Probe".to_string()),
        (Uuid::from_u128(2), "Apache HTTP Server".to_string()),
    ]
}

/// The case that returned `500 A database error occurred` against a live
/// tenant: two names that look different, one generated identifier.
#[test]
fn a_differently_punctuated_name_is_rejected_with_the_holder_named() {
    let detail = generated_identity_conflict("log source", "zz-validation-probe", &rows(), None)
        .expect("must be rejected — both names generate zz_validation_probe");

    assert!(
        detail.contains("zz_validation_probe"),
        "must name the generated identifier, since the two NAMES look different: {detail}"
    );
    assert!(
        detail.contains("ZZ Validation Probe"),
        "must name the conflicting source: {detail}"
    );
}

#[test]
fn case_and_spacing_variants_collide_too() {
    for candidate in ["zz validation probe", "ZZ_VALIDATION_PROBE", "zz.validation.probe"] {
        assert!(
            generated_identity_conflict("log source", candidate, &rows(), None).is_some(),
            "{candidate} generates zz_validation_probe and must be rejected"
        );
    }
}

#[test]
fn a_genuinely_distinct_name_is_allowed() {
    assert!(
        generated_identity_conflict("log source", "ZZ Validation Probe 2", &rows(), None).is_none()
    );
}

/// A rename that keeps the same stem must not be rejected as conflicting with
/// itself — otherwise "My Source" -> "My  Source" is unfixable.
#[test]
fn renaming_a_row_does_not_conflict_with_its_own_identity() {
    assert!(
        generated_identity_conflict(
            "log source",
            "ZZ  Validation  Probe",
            &rows(),
            Some(Uuid::from_u128(1)),
        )
        .is_none(),
        "excluding the row under edit must allow same-stem renames"
    );

    // ...but it must still collide with a DIFFERENT row.
    assert!(
        generated_identity_conflict(
            "log source",
            "apache-http-server",
            &rows(),
            Some(Uuid::from_u128(1)),
        )
        .is_some(),
        "excluding one row must not disable the check for the others"
    );
}
