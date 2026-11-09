// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5021: the cloud CTE builder gates the client's text itself, on both
//! branches, so no enforcement error can turn into an unscoped scan.

use super::super::npl_golden_corpus_tests::sql_only_service;
use super::*;
use crate::auth::{compose_viewer_scope, ScopeSet};
use chrono::{TimeZone, Utc};

fn range() -> TimeRange {
    TimeRange::new(
        Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 11, 1, 6, 0, 0).unwrap(),
    )
}

/// A low-privilege analyst: denied one restricted source, no audit:view.
fn analyst() -> ScopeSet {
    compose_viewer_scope(
        &ScopeSet::from_denied(std::collections::BTreeSet::from(["hr_payroll".to_string()])),
        false,
    )
}

fn assert_gated(sql: &str) {
    assert!(
        sql.contains("'hr_payroll'") && sql.contains("'audit'"),
        "cloud base CTE is missing the caller's source gate:\n{sql}"
    );
}

/// The reported trigger: the pretty-printer could not round-trip this valid
/// query, `enforce_source_scope` returned Err, and the cloud endpoints ran
/// the raw client text unscoped.
#[tokio::test]
async fn the_round_trip_trigger_is_gated_not_passed_through() {
    let svc = sql_only_service("udm");
    for q in [
        r#"error | fillnull value='a"b'"#,
        r#"* | cloud principal='x"y'"#,
        r#"source_type=hr_payroll OR source_type=audit"#,
        r#"* | append [ search source_type=hr_payroll ]"#,
    ] {
        let sql = svc
            .build_cloud_base_cte(q, &range(), &analyst())
            .unwrap_or_else(|e| panic!("{q}: {e}"));
        assert_gated(&sql);
    }
}

#[tokio::test]
async fn unparseable_text_takes_the_scoped_fallback_scan() {
    let svc = sql_only_service("udm");
    let sql = svc
        .build_cloud_base_cte("((( not nPL", &range(), &analyst())
        .expect("fallback scan");
    assert!(sql.contains("hr_payroll"), "{sql}");
}

#[tokio::test]
async fn text_an_entry_point_already_gated_is_not_double_wrapped() {
    let deny = analyst().deny_set().clone();
    let once = crate::search::query_processing::enforce_source_scope("error", &deny).unwrap();
    let svc = sql_only_service("udm");
    let sql = svc.build_cloud_base_cte(&once, &range(), &analyst()).unwrap();
    assert_eq!(sql.matches("'hr_payroll'").count(), 1, "{sql}");
}

#[tokio::test]
async fn an_unrestricted_caller_gets_the_query_verbatim() {
    let svc = sql_only_service("udm");
    let sql = svc
        .build_cloud_base_cte("error", &range(), &ScopeSet::unrestricted())
        .unwrap();
    assert!(!sql.contains("NOT IN"), "{sql}");
}

#[test]
fn no_caller_turns_a_scope_enforcement_error_into_an_unscoped_query() {
    // Tripwire over every non-test source file in the crate: an
    // `enforce_source_scope(..)` result must be propagated, never defaulted.
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.to_string_lossy().contains("test")
            {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
    let mut offenders = Vec::new();
    for file in files {
        let src = std::fs::read_to_string(&file).unwrap();
        for (idx, _) in src.match_indices("enforce_source_scope(") {
            let window: String = src[idx..].chars().take(240).collect();
            let call = window.split(';').next().unwrap_or_default();
            // `unwrap_or_else(|e| panic!(..))` in a test helper fails loudly; fine.
            if (call.contains(".unwrap_or") || call.contains(".ok()")) && !call.contains("panic!(") {
                offenders.push(format!("{}: {}", file.display(), call.lines().next().unwrap_or_default()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "source-scope enforcement errors swallowed (NAN-5021):\n{}",
        offenders.join("\n")
    );
}
