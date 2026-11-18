// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5567: Vector dead-letter stores become a SIEM Health finding.

use super::*;
use crate::health::disk_monitor::{parse_vector_dead_letters, DiskHealthReport};
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::analyzer::tests::base_zero_metrics_fixture;

/// Shape of the nano.13 exporter page (`internal_metrics` namespace
/// `nanosiem_vector`).
const PAGE: &str = r#"# TYPE nanosiem_vector_component_dead_lettered_events_total counter
nanosiem_vector_component_dead_lettered_events_total{component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256"} 120 1794693403000
nanosiem_vector_component_dead_letter_bytes{component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256"} 2048 1794693403000
nanosiem_vector_component_dead_letter_discarded_events_total{component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256",reason="evicted"} 7 1794693403000
nanosiem_vector_component_dead_letter_discarded_events_total{component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256",reason="oversize"} 3 1794693403000
nanosiem_vector_component_dead_letter_bytes{component_id="clickhouse_ocsf_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256"} 0 1794693403000
nanosiem_vector_component_dead_letter_bytes{component_id="clickhouse_parser_health",component_kind="sink",component_type="clickhouse",host="828f11a0f256"} 512 1794693403000
nanosiem_vector_buffer_size_bytes{buffer_id="clickhouse_logs",buffer_type="disk",component_id="clickhouse_logs",component_kind="sink",component_type="clickhouse",host="828f11a0f256",stage="0"} 910 1794693403000
"#;

fn run(page: &str) -> AnalysisResult {
    let mut metrics = base_zero_metrics_fixture();
    let mut report = DiskHealthReport::new(vec![], vec![]);
    report.vector_dead_letters = parse_vector_dead_letters(page);
    metrics.disk = Some(report);
    let mut analysis = fallback_report(&metrics);
    analysis.overall_score = 100;
    ensure_vector_dead_letter_findings(&mut analysis, &metrics);
    ensure_vector_dead_letter_findings(&mut analysis, &metrics);
    analysis
}

#[test]
fn exporter_page_yields_only_sinks_with_something_to_report() {
    let found = parse_vector_dead_letters(PAGE);
    assert_eq!(found.len(), 2, "{found:?}");
    let logs = found.iter().find(|d| d.component_id == "clickhouse_logs").unwrap();
    assert_eq!(logs.dead_lettered_events, 120);
    assert_eq!(logs.held_bytes, 2048);
    assert_eq!(logs.discarded_events, 10, "discard reasons are summed");
    assert_eq!(logs.host.as_deref(), Some("828f11a0f256"));
    // Held bytes alone (batches from an earlier run) are reported.
    let parser = found.iter().find(|d| d.component_id == "clickhouse_parser_health").unwrap();
    assert_eq!(parser.held_bytes, 512);
    assert_eq!(parser.dead_lettered_events, 0);
}

#[test]
fn dead_letters_raise_one_high_finding_with_counts() {
    let analysis = run(PAGE);
    let found: Vec<_> = analysis.recommendations.iter().filter(|r| r.title == VECTOR_DEAD_LETTER_TITLE).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].priority, "high");
    let text = &found[0].description;
    assert!(text.contains("clickhouse_logs on 828f11a0f256 (2.0 KiB held, 120 events stored"), "{text}");
    assert!(text.contains("10 events discarded"), "{text}");
    assert!(
        text.ends_with(
            "This warning clears the next time Vector restarts (`docker compose restart vector`) after you replay and delete the files."
        ),
        "the store's bytes gauge is only rescanned at Vector startup: {text}"
    );
    assert!(text.contains("clickhouse_parser_health"), "{text}");
    assert!(!text.contains("clickhouse_ocsf_logs"), "{text}");
    assert!(analysis.overall_score <= 69);
}

#[test]
fn no_dead_letters_no_finding() {
    let analysis = run("nanosiem_vector_component_dead_letter_bytes{component_id=\"clickhouse_logs\"} 0\n");
    assert!(!analysis.recommendations.iter().any(|r| r.title == VECTOR_DEAD_LETTER_TITLE));
    assert_eq!(analysis.overall_score, 100);

    // An older Vector (no dead-letter metrics) and no disk report at all.
    assert!(parse_vector_dead_letters("nanosiem_vector_buffer_size_bytes{buffer_id=\"b\",buffer_type=\"disk\"} 5").is_empty());
    let mut metrics = base_zero_metrics_fixture();
    metrics.disk = None;
    let mut analysis = fallback_report(&metrics);
    analysis.overall_score = 100;
    ensure_vector_dead_letter_findings(&mut analysis, &metrics);
    assert_eq!(analysis.overall_score, 100);
}

#[test]
fn replayed_and_deleted_store_is_resolved_but_discards_still_report() {
    // Stored since start, files since deleted: resolved.
    let page = "nanosiem_vector_component_dead_lettered_events_total{component_id=\"clickhouse_logs\"} 5\n\
                nanosiem_vector_component_dead_letter_bytes{component_id=\"clickhouse_logs\"} 0\n";
    assert!(parse_vector_dead_letters(page).is_empty());
    // Discarded events are lost data: still reported with nothing held.
    let page = "nanosiem_vector_component_dead_letter_discarded_events_total{component_id=\"clickhouse_logs\",reason=\"oversize\"} 2\n";
    let found = parse_vector_dead_letters(page);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].host, None, "no host label: the scrape fills in the instance");
    assert_eq!(found[0].discarded_events, 2);
}

#[test]
fn stored_reports_without_the_field_still_deserialize() {
    let mut value = serde_json::to_value(DiskHealthReport::new(vec![], vec![])).unwrap();
    assert!(value.get("vector_dead_letters").is_none(), "skipped when empty");
    value.as_object_mut().unwrap().remove("vector_dead_letters");
    let report: DiskHealthReport = serde_json::from_value(value).unwrap();
    assert!(report.vector_dead_letters.is_empty());
}
