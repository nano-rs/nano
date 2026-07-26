// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2085 / NAN-2088 pure-logic matrix for the tuning-artifact visibility
//! gate. The DB-backed half (that the SQL predicate selects exactly the rows
//! `allows` accepts, across list/get/log paths) lives in
//! `nanosiem-core/tests/tuning_proposal_scope_integration.rs`.

use super::{
    derive_finding_source_manifest, merge_source_manifest, normalize_source_manifest,
    FindingProvenance, TuningScope,
};
use serde_json::json;
use std::collections::BTreeSet;

fn deny(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| s.to_string()).collect()
}

fn manifest(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

#[test]
fn unrestricted_reader_sees_everything_including_legacy_rows() {
    let scope = TuningScope::from_denied(&deny(&[]));
    assert!(scope.is_unrestricted());
    // Legacy proposal: no manifest, not complete. Still visible to a reader
    // with no restrictions at all — the gate must not become a global outage.
    assert!(scope.allows(&manifest(&[]), false));
    assert!(scope.allows(&manifest(&["insider_threat"]), true));
}

#[test]
fn system_scope_is_unrestricted() {
    let scope = TuningScope::system();
    assert!(scope.is_unrestricted());
    assert!(scope.allows(&manifest(&[]), false));
}

#[test]
fn restricted_reader_is_denied_a_legacy_proposal_with_no_provenance() {
    // The core fail-closed rule: pre-feature rows ('{}' + FALSE) carry text
    // that may have come from anywhere, so a restricted reader must not see it.
    let scope = TuningScope::from_denied(&deny(&["insider_threat"]));
    assert!(!scope.allows(&manifest(&[]), false));
}

#[test]
fn restricted_reader_is_denied_an_incomplete_manifest_even_when_disjoint() {
    // Producer could only partly account for its inputs: the values it DID
    // record are harmless, but the unaccounted remainder may not be.
    let scope = TuningScope::from_denied(&deny(&["insider_threat"]));
    assert!(!scope.allows(&manifest(&["apache"]), false));
}

#[test]
fn restricted_reader_sees_a_complete_disjoint_manifest() {
    let scope = TuningScope::from_denied(&deny(&["insider_threat"]));
    assert!(scope.allows(&manifest(&["apache", "windows_event"]), true));
}

#[test]
fn any_single_denied_contributor_hides_a_mixed_source_proposal() {
    // A proposal derived from several sources leaks if ANY contributor is
    // denied — the values are interleaved in one prose blob.
    let scope = TuningScope::from_denied(&deny(&["insider_threat"]));
    assert!(!scope.allows(
        &manifest(&["apache", "insider_threat", "windows_event"]),
        true
    ));
}

#[test]
fn manifest_comparison_is_case_and_whitespace_insensitive() {
    let scope = TuningScope::from_denied(&deny(&["Insider_Threat"]));
    assert!(!scope.allows(&manifest(&["  INSIDER_THREAT "]), true));
}

#[test]
fn implicit_audit_deny_hides_audit_derived_proposals() {
    // `effective_source_deny_set()` adds "audit" for callers without
    // `audit:view`; a proposal stamped from the audit stream must disappear.
    let scope = TuningScope::from_denied(&deny(&["audit"]));
    assert!(!scope.allows(&manifest(&["audit"]), true));
    assert!(scope.allows(&manifest(&["apache"]), true));
}

#[test]
fn blank_deny_values_do_not_fabricate_a_restriction() {
    let scope = TuningScope::from_denied(&deny(&["  ", ""]));
    assert!(scope.is_unrestricted());
    assert!(scope.allows(&manifest(&[]), false));
}

#[test]
fn sql_predicate_requires_completeness_and_disjointness() {
    assert_eq!(
        TuningScope::sql_predicate("tp.source_types", "tp.source_types_complete", 3),
        " AND tp.source_types_complete AND NOT (tp.source_types && $3::text[])"
    );
}

#[test]
fn sql_predicate_matches_the_pure_predicate_on_every_case() {
    // Guard against the SQL and the in-Rust gate drifting apart. Emulate what
    // Postgres evaluates for the emitted fragment and compare to `allows`.
    fn sql_result(deny_values: &[&str], manifest_values: &[&str], complete: bool) -> bool {
        if deny_values.is_empty() {
            return true; // predicate is not emitted at all
        }
        let denied: BTreeSet<&str> = deny_values.iter().copied().collect();
        let overlaps = manifest_values.iter().any(|m| denied.contains(m));
        complete && !overlaps
    }

    // All values already normalized so the emulation is faithful.
    let cases: &[(&[&str], &[&str], bool)] = &[
        (&[], &[], false),
        (&[], &["insider_threat"], true),
        (&["insider_threat"], &[], false),
        (&["insider_threat"], &[], true),
        (&["insider_threat"], &["apache"], false),
        (&["insider_threat"], &["apache"], true),
        (&["insider_threat"], &["insider_threat"], true),
        (&["insider_threat"], &["apache", "insider_threat"], true),
        (&["audit", "insider_threat"], &["apache"], true),
    ];

    for (deny_values, manifest_values, complete) in cases {
        let scope = TuningScope::from_denied(&deny(deny_values));
        assert_eq!(
            scope.allows(&manifest(manifest_values), *complete),
            sql_result(deny_values, manifest_values, *complete),
            "drift for deny={deny_values:?} manifest={manifest_values:?} complete={complete}"
        );
    }
}

#[test]
fn normalize_source_manifest_dedupes_sorts_and_lowercases() {
    let got = normalize_source_manifest(vec![" Apache ", "APACHE", "windows_event", "", "  "]);
    assert_eq!(got, vec!["apache".to_string(), "windows_event".to_string()]);
}

// ---------------------------------------------------------------------------
// NAN-2085: provenance comes from the finding's PERSISTED full origin manifest
// (`origin_source_types`), with the truncated sample only cross-checked — never
// from the synthetic outer `source_type='findings'` row.
// ---------------------------------------------------------------------------

fn manifest_of(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_persisted_origin_manifest_is_authoritative() {
    let sample_a = json!([{ "source_type": "windows_event", "src_ip": "10.0.0.1" }]);
    let origin_a = manifest_of(&["windows_event"]);
    let sample_b = json!([{ "source_type": "Apache" }]);
    let origin_b = manifest_of(&["apache"]);

    let (manifest, complete) = derive_finding_source_manifest(&[
        FindingProvenance {
            origin_source_types: Some(&origin_a),
            matched_events: &sample_a,
        },
        FindingProvenance {
            origin_source_types: Some(&origin_b),
            matched_events: &sample_b,
        },
    ]);
    assert_eq!(
        manifest,
        vec!["apache".to_string(), "windows_event".to_string()]
    );
    assert!(complete);
}

#[test]
fn a_truncated_sample_does_not_shrink_a_mixed_source_manifest() {
    // THE codex round-3 bug: `matched_events_sample` keeps only the first few
    // events, so a finding whose sampled events are all `apache` can still have
    // matched `insider_threat` later. The persisted manifest covers the full
    // match set and must win.
    let sample = json!([{ "source_type": "apache" }]);
    let origin = manifest_of(&["apache", "insider_threat"]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert_eq!(
        manifest,
        vec!["apache".to_string(), "insider_threat".to_string()]
    );
    assert!(complete);
    assert!(!TuningScope::from_denied(&deny(&["insider_threat"])).allows(&manifest, complete));
}

#[test]
fn a_sample_source_missing_from_the_origin_manifest_fails_closed() {
    // The two disagree and we cannot tell which is short.
    let sample = json!([{ "source_type": "insider_threat" }]);
    let origin = manifest_of(&["apache"]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert!(manifest.contains(&"insider_threat".to_string()));
    assert!(!complete);
}

#[test]
fn a_missing_origin_manifest_fails_closed_but_still_records_the_sample() {
    // Pre-NAN-1800 finding, or metadata that would not parse.
    let sample = json!([{ "source_type": "apache" }]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: None,
        matched_events: &sample,
    }]);
    assert_eq!(manifest, vec!["apache".to_string()]);
    assert!(!complete);
}

#[test]
fn an_empty_origin_manifest_fails_closed() {
    // The finding carried no source_type on any event — origin unknown.
    let sample = json!([{ "count": 12 }]);
    let origin: Vec<String> = Vec::new();
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert!(manifest.is_empty());
    assert!(!complete);
}

#[test]
fn one_unaccounted_finding_makes_the_whole_proposal_incomplete() {
    let good_sample = json!([{ "source_type": "apache" }]);
    let good_origin = manifest_of(&["apache"]);
    let legacy_sample = json!([{ "source_type": "windows_event" }]);
    let (manifest, complete) = derive_finding_source_manifest(&[
        FindingProvenance {
            origin_source_types: Some(&good_origin),
            matched_events: &good_sample,
        },
        FindingProvenance {
            origin_source_types: None,
            matched_events: &legacy_sample,
        },
    ]);
    assert_eq!(
        manifest,
        vec!["apache".to_string(), "windows_event".to_string()]
    );
    assert!(!complete);
}

#[test]
fn aggregate_stamp_in_the_sample_is_cross_checked_against_the_origin() {
    // Aggregate rules carry `_nano_source_types` instead of `source_type`; the
    // writer's manifest reads the same two forms, so they must agree.
    let sample = json!([{ "_nano_source_types": ["insider_threat", "apache"], "count": 12 }]);
    let origin = manifest_of(&["apache", "insider_threat"]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert_eq!(
        manifest,
        vec!["apache".to_string(), "insider_threat".to_string()]
    );
    assert!(complete);
}

#[test]
fn ocsf_nested_samples_populate_provenance_too() {
    let sample = json!([{ "source_type": "aws_cloudtrail", "src_endpoint.ip": "1.2.3.4" }]);
    let origin = manifest_of(&["aws_cloudtrail"]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert_eq!(manifest, vec!["aws_cloudtrail".to_string()]);
    assert!(complete);
}

#[test]
fn a_redacted_sample_still_trusts_the_persisted_origin() {
    // NAN-1800 empties `matched_events_sample` for restricted-origin findings
    // but keeps `origin_source_types` — provenance must survive that.
    let sample = json!([]);
    let origin = manifest_of(&["insider_threat"]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert_eq!(manifest, vec!["insider_threat".to_string()]);
    assert!(complete);
    assert!(!TuningScope::from_denied(&deny(&["insider_threat"])).allows(&manifest, complete));
}

#[test]
fn no_findings_is_incomplete_not_silently_unrestricted() {
    let (manifest, complete) = derive_finding_source_manifest(&[]);
    assert!(manifest.is_empty());
    assert!(!complete);
}

#[test]
fn derived_provenance_feeds_the_gate_end_to_end() {
    let sample = json!([{ "source_type": "insider_threat" }]);
    let origin = manifest_of(&["insider_threat"]);
    let (manifest, complete) = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert!(!TuningScope::from_denied(&deny(&["insider_threat"])).allows(&manifest, complete));
    assert!(TuningScope::from_denied(&deny(&["apache"])).allows(&manifest, complete));
}

// ---------------------------------------------------------------------------
// NAN-2085 (codex round 1): prior proposals reach the generation prompt, so
// their origins are contributors to the new proposal's manifest.
// ---------------------------------------------------------------------------

#[test]
fn history_contributors_are_unioned_into_the_manifest() {
    // Rule now fires only on `apache`, but the prompt still carries a prior
    // proposal derived from `insider_threat`; the model can echo its values.
    let sample = json!([{ "source_type": "apache" }]);
    let origin = manifest_of(&["apache"]);
    let base = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    assert!(base.1);

    let merged = merge_source_manifest(base, (&["insider_threat".to_string()], true));
    assert_eq!(
        merged.0,
        vec!["apache".to_string(), "insider_threat".to_string()]
    );
    assert!(merged.1);

    // …and the reader denied insider_threat now loses the new proposal too.
    let restricted = TuningScope::from_denied(&deny(&["insider_threat"]));
    assert!(!restricted.allows(&merged.0, merged.1));
}

#[test]
fn an_incomplete_history_contributor_makes_the_whole_manifest_incomplete() {
    // A legacy prior proposal has no provenance, so we cannot know what its
    // text (fed to the model) contained.
    let sample = json!([{ "source_type": "apache" }]);
    let origin = manifest_of(&["apache"]);
    let base = derive_finding_source_manifest(&[FindingProvenance {
        origin_source_types: Some(&origin),
        matched_events: &sample,
    }]);
    let merged = merge_source_manifest(base, (&[], false));
    assert_eq!(merged.0, vec!["apache".to_string()]);
    assert!(!merged.1, "an unaccounted contributor must fail closed");
    assert!(!TuningScope::from_denied(&deny(&["anything"])).allows(&merged.0, merged.1));
}

#[test]
fn merging_into_an_already_incomplete_manifest_stays_incomplete() {
    let merged = merge_source_manifest(
        (vec!["apache".to_string()], false),
        (&["windows_event".to_string()], true),
    );
    assert!(!merged.1);
}

#[test]
fn merged_contributors_are_normalized_and_deduped() {
    let merged = merge_source_manifest(
        (vec!["apache".to_string()], true),
        (&["  APACHE ".to_string(), "syslog".to_string()], true),
    );
    assert_eq!(merged.0, vec!["apache".to_string(), "syslog".to_string()]);
    assert!(merged.1);
}

#[test]
fn merging_two_empty_manifests_cannot_become_complete() {
    let merged = merge_source_manifest((Vec::new(), true), (&[], true));
    assert!(merged.0.is_empty());
    assert!(!merged.1);
}
