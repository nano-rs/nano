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

// ---------------------------------------------------------------------------
// NAN-1691 (P1-A): filter-form pushdown mapper. The `| prevalence <field> <op>
// N` count condition must translate to a dictGet-masked host-count WHERE
// predicate that yields the SAME row set as the in-memory `prevalence_passes_filter`
// (a dict miss / out-of-window entry — the 9999 sentinel — fails every operator).
// ---------------------------------------------------------------------------
mod filter_pushdown {
    use super::super::prevalence_filter_condition_to_sql;
    use crate::query::{
        PrevalenceCondition, PrevalenceField, PrevalenceOperator, PrevalenceThreshold,
    };

    fn cond(
        field: PrevalenceField,
        operator: PrevalenceOperator,
        threshold: PrevalenceThreshold,
    ) -> PrevalenceCondition {
        PrevalenceCondition {
            field,
            operator,
            threshold,
        }
    }

    #[test]
    fn hash_prevalence_maps_to_hp_host_count_alias_each_operator() {
        for (op, glyph) in [
            (PrevalenceOperator::Lt, "<"),
            (PrevalenceOperator::Lte, "<="),
            (PrevalenceOperator::Gt, ">"),
            (PrevalenceOperator::Gte, ">="),
            (PrevalenceOperator::Eq, "="),
            (PrevalenceOperator::Ne, "!="),
        ] {
            let sql = prevalence_filter_condition_to_sql(&cond(
                PrevalenceField::HashPrevalence,
                op,
                PrevalenceThreshold::Count(5),
            ))
            .expect("count field must push down");
            assert_eq!(sql, format!("(_hp_host_count < 9999 AND _hp_host_count {glyph} 5)"));
        }
    }

    #[test]
    fn domain_prevalence_maps_to_dp_host_count_alias() {
        let sql = prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::DomainPrevalence,
            PrevalenceOperator::Lte,
            PrevalenceThreshold::Count(3),
        ))
        .expect("count field must push down");
        assert_eq!(sql, "(_dp_host_count < 9999 AND _dp_host_count <= 3)");
    }

    #[test]
    fn every_operator_carries_the_9999_presence_guard() {
        // The `< 9999` guard is what makes a miss / out-of-window entry fail even
        // `>`, `>=`, `!=` — without it a sentinel 9999 row would spuriously pass and
        // diverge from the in-memory filter.
        for op in [
            PrevalenceOperator::Lt,
            PrevalenceOperator::Lte,
            PrevalenceOperator::Gt,
            PrevalenceOperator::Gte,
            PrevalenceOperator::Eq,
            PrevalenceOperator::Ne,
        ] {
            let sql = prevalence_filter_condition_to_sql(&cond(
                PrevalenceField::HashPrevalence,
                op,
                PrevalenceThreshold::Count(500),
            ))
            .unwrap();
            assert!(
                sql.contains("< 9999 AND"),
                "predicate must guard against the 9999 sentinel, got: {sql}"
            );
        }
    }

    #[test]
    fn timestamp_fields_do_not_push_down() {
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::HashFirstSeen,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Count(5),
        ))
        .is_none());
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::DomainFirstSeen,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Count(5),
        ))
        .is_none());
    }

    #[test]
    fn duration_threshold_does_not_push_down() {
        assert!(prevalence_filter_condition_to_sql(&cond(
            PrevalenceField::HashPrevalence,
            PrevalenceOperator::Lt,
            PrevalenceThreshold::Duration(std::time::Duration::from_secs(3600)),
        ))
        .is_none());
    }
}

// ---------------------------------------------------------------------------
// NAN-1691 (Fix 1): the residual in-memory filter's artifact selection must stay
// in lock-step with the pushdown. HashPrevalence keys on COALESCE(file_hash,
// process_hash), so a sysmon row carrying ONLY a process_hash matches a
// `hash_prevalence` filter on both paths.
// ---------------------------------------------------------------------------
mod coalesce_extraction {
    use super::super::{extract_prevalence_artifact, prevalence_filter_udm_concepts};
    use crate::query::PrevalenceField;
    use serde_json::json;

    #[test]
    fn hash_filter_coalesces_file_hash_then_process_hash() {
        // The COALESCE concept order the pushdown mirrors.
        assert_eq!(
            prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence),
            &["file_hash", "process_hash"]
        );
        assert_eq!(
            prevalence_filter_udm_concepts(&PrevalenceField::HashFirstSeen),
            &["file_hash", "process_hash"]
        );
    }

    #[test]
    fn domain_filter_keys_on_dest_host() {
        assert_eq!(
            prevalence_filter_udm_concepts(&PrevalenceField::DomainPrevalence),
            &["dest_host"]
        );
    }

    #[test]
    fn process_hash_only_row_matches_hash_filter() {
        // Sysmon-shaped row: no file_hash, only a process_hash. Before the fix the
        // in-memory path keyed on file_hash ONLY and skipped this row, diverging from
        // the pushdown. Now it must fall back to process_hash.
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "process_hash": "abc123", "process_name": "evil.exe" });
        assert_eq!(
            extract_prevalence_artifact(&row, &fields),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn file_hash_wins_when_both_present() {
        // COALESCE priority: file_hash before process_hash.
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "file_hash": "file_h", "process_hash": "proc_h" });
        assert_eq!(
            extract_prevalence_artifact(&row, &fields),
            Some("file_h".to_string())
        );
    }

    #[test]
    fn empty_file_hash_falls_back_to_process_hash() {
        // An empty-string file_hash is treated as absent (COALESCE skips it).
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "file_hash": "", "process_hash": "proc_h" });
        assert_eq!(
            extract_prevalence_artifact(&row, &fields),
            Some("proc_h".to_string())
        );
    }

    #[test]
    fn row_with_no_hash_yields_none() {
        let fields: Vec<String> = prevalence_filter_udm_concepts(&PrevalenceField::HashPrevalence)
            .iter()
            .map(|s| s.to_string())
            .collect();
        let row = json!({ "process_name": "evil.exe" });
        assert_eq!(extract_prevalence_artifact(&row, &fields), None);
    }
}
