// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5226: only the injector's exact `source_type` spelling counts as the
//! scope gate. Plus the report-path guard settled for the 2026-11-10 scan (M7):
//! the gate survives the search service's text pipeline.

use super::*;
use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use std::collections::BTreeSet;

fn deny(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn window() -> TimeRange {
    let end = chrono::Utc::now();
    TimeRange {
        start: end - chrono::Duration::hours(1),
        end,
    }
}

fn scoped_sql(q: &str, deny_set: &BTreeSet<String>) -> String {
    let scoped = ScopedQuery::parse(q, deny_set).expect("scoped");
    ClickHouseSqlGenerator::new()
        .generate(scoped.query(), &window())
        .expect("sql")
}

#[test]
fn case_variant_audit_exclusion_is_not_accepted_as_the_gate() {
    let audit = deny(&["audit"]);
    for q in [
        "error SOURCE_TYPE!=\"audit\"",
        "error Source_Type!=\"audit\"",
        "error source_type!=\"AUDIT\"",
    ] {
        let sql = scoped_sql(q, &audit);
        assert!(
            sql.contains("lower(source_type) != 'audit'"),
            "{q}: the column gate must be injected, got: {sql}"
        );
    }
}

#[test]
fn case_variant_not_in_exclusion_is_not_accepted_as_the_gate() {
    let d = deny(&["audit", "hr_system"]);
    let sql = scoped_sql("error SOURCE_TYPE NOT IN (\"audit\", \"hr_system\")", &d);
    assert!(
        sql.contains("lower(source_type) NOT IN ('audit', 'hr_system')"),
        "column NOT IN gate must be injected, got: {sql}"
    );
}

#[test]
fn canonical_user_written_gate_stays_idempotent() {
    let audit = deny(&["audit"]);
    let scoped = ScopedQuery::parse("error source_type!=\"audit\"", &audit).expect("scoped");
    assert!(all_scans_gated(scoped.query(), &audit));
    let once = scoped.query().clone();
    let again = ScopedQuery::from_ast(once.clone(), &audit).expect("scoped");
    assert_eq!(again.query(), &once, "re-gating a gated tree must not wrap again");
}

#[test]
fn gate_field_is_exact() {
    assert!(is_gate_field("source_type"));
    for f in ["SOURCE_TYPE", "Source_Type", " source_type", "sourcetype"] {
        assert!(!is_gate_field(f), "{f:?} is not the gate field");
    }
}

/// Scan 2026-11-10, M7 (settled false positive): a report gates its query with
/// `enforce_non_audit_query`, and the search service then strips comments and
/// time modifiers, re-applies the owner's scope (empty for an unrestricted
/// owner) and re-parses. The gate must survive that pipeline on every scan.
#[test]
fn report_gate_survives_the_search_text_pipeline() {
    let audit = deny(&["audit"]);
    let now = chrono::Utc::now();
    for q in [
        "error",
        "message=\"a latest=b\"",
        "message=\"a earliest=-1d\" OR x=1",
        "user=/x\\// error",
        "error // trailing comment",
        "error | where a=\"latest=now\"",
        "error | rex field=message \"(?<x>latest=\\S+)\"",
        "x=\"earliest=-1d) OR (source_type=audit\"",
        "error | eval s=\"// x\"",
        "url=http://example earliest=-1h",
        "error SOURCE_TYPE!=\"audit\"",
        "error | append [ search b ]",
    ] {
        let gated = enforce_non_audit_query(q).unwrap_or_else(|e| panic!("{q}: {e}"));
        let (cleaned, _, _) = crate::search::service::extract_time_bounds_at(&gated, now)
            .unwrap_or_else(|e| panic!("{q}: {e}"));
        let unscoped_owner = enforce_source_scope(&cleaned, &BTreeSet::new()).expect("noop");
        let reparsed = parse_query(&unscoped_owner).unwrap_or_else(|e| panic!("{q}: {e}"));
        assert!(
            all_scans_gated(&reparsed, &audit),
            "{q}: gate lost after the search text pipeline: {unscoped_owner}"
        );
    }
}
