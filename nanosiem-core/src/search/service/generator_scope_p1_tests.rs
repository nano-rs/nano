// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793 review round 2 (P1): the prevalence pushdown and the OOM row
//! estimate generate their SQL under the caller's deny-set.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use super::*;
use crate::auth::{compose_viewer_scope, ScopeSet};
use chrono::{TimeZone, Utc};
use std::collections::BTreeSet;

fn range() -> TimeRange {
    TimeRange::new(
        Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 11, 1, 6, 0, 0).unwrap(),
    )
}

/// A viewer without `audit:view` and no other restriction: the row scope
/// denies `audit`, the artifact scope is unrestricted, so the prevalence
/// pushdown applies.
fn no_audit_view() -> ScopeSet {
    compose_viewer_scope(&ScopeSet::unrestricted(), false)
}

#[tokio::test]
async fn the_prevalence_pushdown_scopes_the_identity_build_side() {
    let svc = sql_only_service("udm");
    let sql = render(
        &svc,
        "* | resolve_identity field=src_ip | prevalence enrich=true",
        &no_audit_view(),
    )
    .await;
    assert!(sql.contains("prevalence"), "the pushdown must render: {sql}");
    assert!(sql.contains("identity_observations"), "{sql}");
    assert!(
        sql.contains("lower(source) != 'audit'"),
        "the identity_observations build side must exclude audit observations:\n{sql}"
    );
}

#[tokio::test]
async fn the_prevalence_base_count_scopes_the_identity_build_side() {
    let svc = sql_only_service("udm");
    let deny: BTreeSet<String> = ["audit".to_string()].into();
    let query = parse_query("* | resolve_identity field=src_ip | prevalence enrich=true").unwrap();
    let sql = svc
        .prevalence_base_count_sql(&query, &range(), crate::query::GeneratorScope::deny_set(&deny))
        .unwrap();
    assert!(sql.contains("lower(source) != 'audit'"), "{sql}");
}

#[tokio::test]
async fn the_oom_estimate_keeps_the_risk_origin_gate() {
    let svc = sql_only_service("udm");
    let scope = ScopeSet::from_denied(BTreeSet::from(["hr_payroll".to_string()]));
    let estimate = parse_query("user IN [dataset=risk score_24h > 0 | return entity]").unwrap();
    let sql = svc.estimate_sql(&estimate, &range(), &scope).unwrap();
    assert!(
        sql.contains("'__nano:unresolved_source__', 'hr_payroll'"),
        "the estimate's risk subsearch must exclude denied origins:\n{sql}"
    );
    let open = svc.estimate_sql(&estimate, &range(), &ScopeSet::unrestricted()).unwrap();
    assert!(!open.contains("hr_payroll"), "{open}");
}
