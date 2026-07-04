// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression tests for the dict-path prevalence filter decision.
//!
//! The audit (P2) found that a dict-lookup MISS was treated as host_count 0,
//! which inverted the filter: a common artifact absent from the dict passed a
//! `host_count < N` rarity test. A miss must instead fail every comparison,
//! mirroring the JOIN path's NULL-drop semantics.

use super::prevalence_passes_filter;
use crate::query::PrevalenceOperator;

#[test]
fn dict_miss_fails_every_comparison() {
    // A miss (`None`) must be excluded regardless of operator — it is "common /
    // not tracked", never host_count 0.
    for op in [
        PrevalenceOperator::Lt,
        PrevalenceOperator::Lte,
        PrevalenceOperator::Gt,
        PrevalenceOperator::Gte,
        PrevalenceOperator::Eq,
        PrevalenceOperator::Ne,
    ] {
        assert!(
            !prevalence_passes_filter(None, &op, 3),
            "a dict miss must fail {op:?} (row dropped), not be treated as host_count 0"
        );
    }
}

#[test]
fn common_artifact_absent_from_dict_does_not_pass_rare_filter() {
    // The exact failure scenario: `| prevalence host_count < 3` on a common
    // artifact the dict omits. With the old `unwrap_or(0)` this returned true
    // (0 < 3). It must now be false.
    assert!(!prevalence_passes_filter(None, &PrevalenceOperator::Lt, 3));
}

#[test]
fn present_rare_artifact_passes_lt() {
    // A genuinely rare artifact (host_count 1) still passes `< 3`.
    assert!(prevalence_passes_filter(
        Some(1),
        &PrevalenceOperator::Lt,
        3
    ));
}

#[test]
fn present_common_artifact_fails_lt_passes_gte() {
    // host_count 50 is common: fails `< 3`, passes `>= 3`.
    assert!(!prevalence_passes_filter(
        Some(50),
        &PrevalenceOperator::Lt,
        3
    ));
    assert!(prevalence_passes_filter(
        Some(50),
        &PrevalenceOperator::Gte,
        3
    ));
}

#[test]
fn boundary_values_respect_operator_strictness() {
    // Boundary at the threshold: `<` excludes equality, `<=` includes it.
    assert!(!prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Lt,
        3
    ));
    assert!(prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Lte,
        3
    ));
    assert!(prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Eq,
        3
    ));
    assert!(!prevalence_passes_filter(
        Some(3),
        &PrevalenceOperator::Ne,
        3
    ));
}
