// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::analyzer::tests::base_zero_metrics_fixture;

fn analysis() -> AnalysisResult {
    fallback_report(&base_zero_metrics_fixture())
}

#[test]
fn the_query_reads_unintentional_drops_from_the_right_table() {
    let single = drop_query(false);
    assert!(single.contains("FROM nanosiem.collector_errors WHERE"), "{single}");
    assert!(single.contains("level = 'ERROR'"));
    assert!(single.contains("startsWith(message, 'Events dropped')"));
    assert!(!single.to_uppercase().contains("PREWHERE"));
    // Clustered reads follow the shared table-name routing (as the log
    // source health page does for the same table).
    let table = TableNames::new(true).read_bare("collector_errors");
    assert!(drop_query(true).contains(&format!("FROM nanosiem.{table} WHERE")));
}

#[test]
fn no_drops_no_finding() {
    let mut a = analysis();
    let before = a.overall_score;
    ensure_pipeline_drop_findings(&mut a, &[]);
    ensure_pipeline_drop_findings(&mut a, &[DropRow { component_id: "x".into(), reports: 0 }]);
    assert!(!a.recommendations.iter().any(|r| r.title == PIPELINE_DROPS_TITLE));
    assert_eq!(a.overall_score, before);
}

#[test]
fn drops_raise_one_finding_naming_the_components() {
    let mut a = analysis();
    let rows = [
        DropRow { component_id: "clickhouse_ocsf_logs".into(), reports: 3 },
        DropRow { component_id: String::new(), reports: 1 },
    ];
    ensure_pipeline_drop_findings(&mut a, &rows);
    ensure_pipeline_drop_findings(&mut a, &rows);
    let found: Vec<_> = a.recommendations.iter().filter(|r| r.title == PIPELINE_DROPS_TITLE).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].priority, "high");
    assert!(found[0].description.contains("clickhouse_ocsf_logs (3 reports)"));
    assert!(found[0].description.contains("unknown component (1 reports)"));
    assert!(a.overall_score <= 69);
}
