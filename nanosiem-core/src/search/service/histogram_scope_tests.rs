// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5793 review (P1): the histogram companion generates its base SQL with
//! the caller's deny-set, so a `[dataset=risk …]` subsearch in the base search
//! keeps its origin-manifest gate.

use super::npl_golden_corpus_tests::sql_only_service;
use super::*;
use chrono::{TimeZone, Utc};
use std::collections::BTreeSet;

#[tokio::test]
async fn a_risk_subsearch_in_the_histogram_base_keeps_the_origin_gate() {
    let svc = sql_only_service("udm");
    let query = parse_query("user IN [dataset=risk score_24h > 0 | return entity]").unwrap();
    let tr = TimeRange::new(
        Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 11, 1, 6, 0, 0).unwrap(),
    );
    let deny: BTreeSet<String> = ["hr_payroll".to_string()].into();
    let scoped = svc
        .histogram_base_sql(&query, &tr, crate::query::Dataset::Logs, &deny)
        .unwrap();
    assert!(
        scoped.contains("'__nano:unresolved_source__', 'hr_payroll'"),
        "the histogram's risk subsearch must exclude denied origins:\n{scoped}"
    );
    let open = svc
        .histogram_base_sql(&query, &tr, crate::query::Dataset::Logs, &BTreeSet::new())
        .unwrap();
    assert!(!open.contains("hr_payroll"), "{open}");
}
