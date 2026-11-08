// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::observability::{MonitorComparator, MonitorTagFilter};

fn monitor(comparator: MonitorComparator) -> MetricMonitor {
    let now = Utc::now();
    MetricMonitor {
        id: uuid::Uuid::new_v4(),
        name: "disk".into(),
        metric_name: "node_filesystem_avail_bytes".into(),
        agg: "min".into(),
        service_name: None,
        group_by: None,
        filters: vec![],
        comparator,
        threshold: 10.0,
        window_secs: 300,
        eval_interval_secs: 60,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn payload_carries_filter_and_series_labels() {
    let mut m = monitor(MonitorComparator::Lt);
    m.group_by = Some("instance".into());
    m.filters.push(MonitorTagFilter {
        key: "mountpoint".into(),
        value: "/".into(),
    });
    let now = Utc::now();
    let payload = metric_payload(&m, "node-a", 9.0, now);
    assert_eq!(payload[0]["labels"]["instance"], "node-a");
    assert_eq!(payload[0]["labels"]["mountpoint"], "/");
    assert_eq!(payload[0]["evaluated_at"], now.to_rfc3339());
    // An empty series key is not a label.
    let ungrouped = metric_payload(&m, "", 9.0, now);
    assert!(ungrouped[0]["labels"].get("instance").is_none());
}

#[test]
fn breach_requires_known_finite_value() {
    use MonitorComparator::*;
    for (comparator, low, equal, high) in [
        (Gt, false, false, true),
        (Gte, false, true, true),
        (Lt, true, false, false),
        (Lte, true, true, false),
    ] {
        let m = monitor(comparator);
        assert_eq!(metric_breach(&m, Some(9.0)), low);
        assert_eq!(metric_breach(&m, Some(10.0)), equal);
        assert_eq!(metric_breach(&m, Some(11.0)), high);
        assert!(!metric_breach(&m, None));
        assert!(!metric_breach(&m, Some(f64::NAN)));
    }
}

#[test]
fn source_id_is_monitor_prefixed() {
    let id = uuid::Uuid::new_v4();
    assert_eq!(metric_monitor_source_id(id, "node-a"), format!("{id}:node-a"));
    assert_eq!(metric_monitor_source_id(id, ""), format!("{id}:"));
}

#[test]
fn sparse_counter_rate_golden() {
    let rows = vec![
        ("active".into(), Some(2.0)),
        ("one-sample".into(), None),
        ("absent".into(), None),
    ];
    let filtered = vec![
        ("active".into(), Some(5.0)),
        ("one-sample".into(), Some(1.0)),
        ("absent".into(), Some(0.0)),
    ];
    let base = vec![
        ("active".into(), Some(9.0)),
        ("one-sample".into(), Some(9.0)),
        ("absent".into(), Some(9.0)),
        ("new-group".into(), Some(2.0)),
        ("dead".into(), Some(0.0)),
        ("unknown".into(), None),
    ];
    assert_eq!(
        fill_missing_counter_rates(rows, filtered, base),
        vec![
            ("absent".into(), Some(0.0)),
            ("active".into(), Some(2.0)),
            ("new-group".into(), Some(0.0)),
            ("one-sample".into(), None),
        ]
    );
    assert_eq!(
        fill_missing_counter_rates(vec![("".into(), None)], vec![], vec![("".into(), Some(0.0))]),
        vec![("".into(), None)]
    );
    assert_eq!(
        fill_missing_counter_rates(vec![], vec![], vec![("".into(), Some(3.0))]),
        vec![("".into(), Some(0.0))]
    );
}

/// NAN-3894: partial (uncovered window) and no-data never breach, burn or
/// read as attained; partial wins over no-data.
#[test]
fn slo_partial_and_no_data_never_breach() {
    let partial = slo_evaluation(0.99, 0.0, false, true);
    assert_eq!(partial.status, "partial");
    assert!(!partial.known());
    assert_eq!(slo_evaluation(0.99, 1.0, true, true).status, "partial");
    let no_data = slo_evaluation(0.99, 1.0, true, false);
    assert_eq!(no_data.status, "no_data");
    assert!(!no_data.known());
    let bad = slo_evaluation(0.99, 0.98, false, false);
    assert_eq!(bad.status, "breaching");
    assert!(bad.known());
    assert!((bad.burn_rate - 2.0).abs() < 1e-9);
    assert!((bad.budget_remaining_pct + 100.0).abs() < 1e-6);
    assert_eq!(slo_evaluation(0.99, 0.992, false, false).status, "at_risk");
    assert_eq!(slo_evaluation(0.99, 0.999, false, false).status, "ok");
}
