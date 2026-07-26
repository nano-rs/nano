// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2160: `safety_validation` read-path compatibility.
//!
//! `tuning_proposals.safety_validation` is `jsonb NOT NULL DEFAULT '{}'`, so
//! the schema itself permits a value the read path used to reject. Every read
//! site (proposal list, proposal detail, and the three tuning-log queries that
//! nest a proposal) deserializes the column through `SafetyValidation`, so a
//! single legacy row anywhere in a page returned a tenant-wide 500:
//!
//! ```text
//! GET /api/tuning/proposals?limit=5   -> 200
//! GET /api/tuning/proposals?limit=200 -> 500 "Failed to deserialize safety_validation"
//! ```
//!
//! Verified against the live dev database on 2026-07-25: 21 of 168 proposal
//! rows were incomplete, in exactly the two shapes fixtured below. Fixing this
//! at the type means all six read sites are covered by construction.

use super::{SafetyCheck, SafetyValidation};

/// The database default. A row that never had safety validation run must read
/// as "not known to be safe" — never as safe, and never as an error that takes
/// the whole queue down with it.
#[test]
fn empty_object_reads_as_conservative_defaults() {
    let v: SafetyValidation = serde_json::from_value(serde_json::json!({})).expect(
        "the column's own DEFAULT '{}' must deserialize — strict parsing here \
         500s the entire proposal list",
    );
    assert!(!v.is_safe, "absent is_safe must fail closed");
    assert!(!v.critical_indicators_preserved);
    assert!(v.validation_checks.is_empty());
    assert!(v.warnings.is_empty());
}

/// The other live legacy shape. An explicitly present field is authoritative —
/// defaulting must not overwrite what the row actually recorded.
#[test]
fn partial_object_honours_present_fields_and_defaults_the_rest() {
    let v: SafetyValidation =
        serde_json::from_value(serde_json::json!({ "is_safe": true })).expect("legacy partial row");
    assert!(v.is_safe, "an explicit is_safe:true must survive the defaults");
    assert!(
        !v.critical_indicators_preserved,
        "absent critical_indicators_preserved must fail closed, not inherit is_safe"
    );
    assert!(v.validation_checks.is_empty());
    assert!(v.warnings.is_empty());
}

/// Compatibility must not silently weaken a complete record.
#[test]
fn fully_populated_object_is_unchanged() {
    let v: SafetyValidation = serde_json::from_value(serde_json::json!({
        "is_safe": false,
        "critical_indicators_preserved": true,
        "validation_checks": [
            { "check_name": "indicator_retention", "passed": true, "details": "all kept" }
        ],
        "warnings": ["narrows coverage"]
    }))
    .expect("complete row");
    assert!(!v.is_safe);
    assert!(v.critical_indicators_preserved);
    assert_eq!(v.validation_checks.len(), 1);
    assert_eq!(v.validation_checks[0].check_name, "indicator_retention");
    assert_eq!(v.warnings, vec!["narrows coverage".to_string()]);
}

/// Rows written after the fix still round-trip exactly, so the defaults only
/// ever apply to data that predates the field.
#[test]
fn write_then_read_round_trips() {
    let original = SafetyValidation {
        is_safe: true,
        critical_indicators_preserved: true,
        validation_checks: vec![SafetyCheck {
            check_name: "regex_scope".to_string(),
            passed: false,
            details: "widened".to_string(),
        }],
        warnings: vec!["review".to_string()],
    };
    let round_tripped: SafetyValidation =
        serde_json::from_value(serde_json::to_value(&original).expect("serialize"))
            .expect("deserialize");
    assert_eq!(round_tripped.is_safe, original.is_safe);
    assert_eq!(
        round_tripped.critical_indicators_preserved,
        original.critical_indicators_preserved
    );
    assert_eq!(round_tripped.validation_checks.len(), 1);
    assert!(!round_tripped.validation_checks[0].passed);
    assert_eq!(round_tripped.warnings, original.warnings);
}

/// A page mixing legacy and current rows is the actual failure the finding
/// reported — `limit=5` succeeded and `limit=200` did not, purely because of
/// which rows the page happened to contain. No single row may be able to fail
/// the batch.
#[test]
fn a_legacy_row_cannot_fail_the_page_it_appears_in() {
    let page = serde_json::json!([
        { "is_safe": true, "critical_indicators_preserved": true,
          "validation_checks": [], "warnings": [] },
        {},
        { "is_safe": true },
    ]);
    let rows: Vec<SafetyValidation> = page
        .as_array()
        .expect("array")
        .iter()
        .map(|row| {
            serde_json::from_value(row.clone())
                .expect("no row shape present in live data may fail the page")
        })
        .collect();
    assert_eq!(rows.len(), 3);
    assert!(rows[0].is_safe);
    assert!(!rows[1].is_safe);
    assert!(rows[2].is_safe);
}

/// `serde(default)` governs how a stored ROW is read — it must not leak into
/// the API contract. Nothing here is `skip_serializing_if`, so every response
/// still carries all four fields, and the schema has to keep saying so.
/// Without the `#[schema(required)]` attributes utoipa infers optionality from
/// the serde attribute and drops the entire `required` list, which would tell
/// every generated client that `is_safe` may be absent when it never is.
#[test]
fn the_read_side_default_does_not_weaken_the_response_schema() {
    use utoipa::PartialSchema;

    let schema = serde_json::to_value(SafetyValidation::schema()).expect("schema serializes");
    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .expect(
            "SafetyValidation lost its `required` list — serde(default) leaked \
             into the response contract; restore #[schema(required)]",
        );
    let required: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();

    for field in [
        "is_safe",
        "critical_indicators_preserved",
        "validation_checks",
        "warnings",
    ] {
        assert!(
            required.contains(&field),
            "{field} dropped from the response schema's required list"
        );
    }
}

/// The auto-apply gate in `tuning::repository::application` reads `is_safe`
/// straight off the raw JSON rather than through this type. Both readings must
/// agree, or a legacy row could auto-apply through one path while reading as
/// unsafe in the other.
#[test]
fn raw_json_auto_apply_gate_agrees_with_the_typed_default() {
    for raw in [
        serde_json::json!({}),
        serde_json::json!({ "is_safe": true }),
        serde_json::json!({ "is_safe": false }),
    ] {
        let gate_says_safe = raw.get("is_safe").and_then(serde_json::Value::as_bool) == Some(true);
        let typed: SafetyValidation = serde_json::from_value(raw.clone()).expect("deserialize");
        assert_eq!(
            gate_says_safe, typed.is_safe,
            "auto-apply gate and typed read disagree on {raw}"
        );
    }
}
