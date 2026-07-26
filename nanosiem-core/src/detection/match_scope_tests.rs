// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2071 pure-logic tests for the detection-match source scope: deny-set
//! normalization and the exact SQL predicate emitted for restricted vs
//! unrestricted callers. The DB-backed matrix (multi-source overlap, empty
//! stamp, mutation atomicity) lives in
//! `nanosiem-core/tests/detection_match_scope_integration.rs`.

use super::MatchScope;
use crate::auth::UNRESOLVED_SOURCE_SENTINEL;
use std::collections::BTreeSet;

fn deny(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| s.to_string()).collect()
}

/// The bind payload minus the NAN-2155 unresolved-provenance sentinel, so the
/// normalization assertions below stay about the CALLER's own deny set.
fn caller_denied(scope: &MatchScope) -> Vec<String> {
    let mut got: Vec<String> = scope
        .deny_bind_values()
        .iter()
        .filter(|v| v.as_str() != UNRESOLVED_SOURCE_SENTINEL)
        .cloned()
        .collect();
    got.sort();
    got
}

#[test]
fn empty_deny_set_is_unrestricted() {
    let scope = MatchScope::from_denied(&deny(&[]));
    assert!(scope.is_unrestricted());
    assert!(scope.deny_bind_values().is_empty());
}

#[test]
fn unrestricted_constructor_matches_empty_deny_set() {
    assert_eq!(
        MatchScope::unrestricted(),
        MatchScope::from_denied(&deny(&[]))
    );
}

#[test]
fn deny_values_are_trimmed_and_lowercased() {
    // detection_matches.source_types is stamped trimmed + lowercased, so a
    // deny value that differs only in case/whitespace MUST still overlap.
    let scope = MatchScope::from_denied(&deny(&["  Insider_Threat ", "AUDIT"]));
    assert_eq!(
        caller_denied(&scope),
        vec!["audit".to_string(), "insider_threat".to_string()]
    );
    assert!(!scope.is_unrestricted());
}

/// NAN-2155: a RESTRICTED caller's bind array also denies the
/// unresolved-provenance sentinel, so an aggregate match the engine could not
/// attribute to a source is hidden from them rather than being conflated with
/// the legitimately sourceless `'{}'` rows.
#[test]
fn restricted_caller_also_denies_the_unresolved_provenance_sentinel() {
    let scope = MatchScope::from_denied(&deny(&["insider_threat"]));
    assert!(scope
        .deny_bind_values()
        .iter()
        .any(|v| v == UNRESOLVED_SOURCE_SENTINEL));
}

/// The other half of the same invariant: an UNRESTRICTED caller must not get a
/// predicate at all. If the sentinel leaked into the empty case, every admin
/// read would start emitting a filter and unresolved rows would be invisible to
/// everyone — un-triageable rather than over-shared.
#[test]
fn unrestricted_caller_does_not_pick_up_the_sentinel() {
    let scope = MatchScope::from_denied(&deny(&[]));
    assert!(scope.is_unrestricted());
    assert!(!scope
        .deny_bind_values()
        .iter()
        .any(|v| v == UNRESOLVED_SOURCE_SENTINEL));
}

#[test]
fn blank_deny_values_are_dropped_and_cannot_fabricate_a_restriction() {
    // A registry row with a whitespace-only source_type must not flip an
    // otherwise-unrestricted caller into "restricted" (which would then also
    // bind an array containing '' and match nothing useful).
    let scope = MatchScope::from_denied(&deny(&["   ", ""]));
    assert!(scope.is_unrestricted());
}

#[test]
fn sql_predicate_is_an_overlap_negation_on_the_named_column() {
    let sql = MatchScope::sql_predicate("dm.source_types", 5);
    assert_eq!(
        sql,
        " AND ($5::text[] = '{}' OR NOT (dm.source_types && $5::text[]))"
    );
}

#[test]
fn sql_predicate_reuses_one_placeholder_for_both_arms() {
    // Both arms must reference the SAME parameter — a second placeholder would
    // shift every later bind by one and silently mis-bind the query.
    let sql = MatchScope::sql_predicate("source_types", 3);
    assert_eq!(sql.matches("$3").count(), 2);
    assert!(!sql.contains("$4"));
}

#[test]
fn sql_predicate_never_interpolates_the_deny_values() {
    // Deny values are bound parameters, never string-formatted into SQL.
    let scope = MatchScope::from_denied(&deny(&["'; DROP TABLE detection_matches; --"]));
    let sql = MatchScope::sql_predicate("source_types", 2);
    assert!(!sql.contains("DROP"));
    assert_eq!(caller_denied(&scope).len(), 1);
}
