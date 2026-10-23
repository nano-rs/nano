// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure decisions shared by dedicated and hosted observability evaluators.
use super::{MetricMonitor, SloDefinition};
use chrono::{DateTime, Utc};

pub fn metric_monitor_source_id(monitor_id: uuid::Uuid, series_key: &str) -> String {
    format!("{monitor_id}:{series_key}")
}

pub fn within_rearm(last: DateTime<Utc>, now: DateTime<Utc>, seconds: u64) -> bool {
    let elapsed = (now - last).num_seconds();
    elapsed < 0 || (elapsed as u64) < seconds
}

/// Fill only absent filtered counter series in groups whose base metric is
/// present. Existing NULL rates (e.g. one sample) and dead services stay unknown.
pub fn fill_missing_counter_rates(
    rows: Vec<(String, Option<f64>)>,
    filtered_counts: Vec<(String, Option<f64>)>,
    base_counts: Vec<(String, Option<f64>)>,
) -> Vec<(String, Option<f64>)> {
    let observed: std::collections::HashSet<_> = filtered_counts.into_iter()
        .filter(|(_, n)| n.is_some_and(|n| n.is_finite() && n > 0.0))
        .map(|(key, _)| key).collect();
    let mut result: std::collections::BTreeMap<_, _> = rows.into_iter().collect();
    for (key, count) in base_counts {
        if count.is_some_and(|n| n.is_finite() && n > 0.0) && !observed.contains(&key) {
            result.insert(key, Some(0.0));
        }
    }
    result.into_iter().collect()
}

pub fn metric_breach(monitor: &MetricMonitor, value: Option<f64>) -> bool {
    value.is_some_and(|v| v.is_finite() && monitor.comparator.breached(v, monitor.threshold))
}

pub fn metric_payload(
    monitor: &MetricMonitor,
    series: &str,
    value: f64,
    now: DateTime<Utc>,
) -> serde_json::Value {
    let mut labels = serde_json::Map::new();
    for filter in &monitor.filters {
        labels.insert(
            filter.key.clone(),
            serde_json::Value::String(filter.value.clone()),
        );
    }
    if let Some(group) = &monitor.group_by {
        if !series.is_empty() {
            labels.insert(group.clone(), serde_json::Value::String(series.to_owned()));
        }
    }
    serde_json::json!([{
        "labels": labels,
        "monitor_id": monitor.id.to_string(), "monitor_name": monitor.name,
        "metric_name": monitor.metric_name, "agg": monitor.agg,
        "service_name": monitor.service_name, "group_by": monitor.group_by,
        "series_key": series, "comparator": monitor.comparator.as_str(),
        "threshold": monitor.threshold, "value": value,
        "window_secs": monitor.window_secs, "evaluated_at": now.to_rfc3339()
    }])
}

#[derive(Debug, Clone, PartialEq)]
pub struct SloEvaluation {
    pub budget_remaining_pct: f64,
    pub burn_rate: f64,
    pub status: &'static str,
}

pub fn slo_evaluation(target: f64, current: f64, no_data: bool, partial: bool) -> SloEvaluation {
    let allowed = (1.0 - target).max(f64::EPSILON);
    let consumed = (1.0 - current).max(0.0);
    SloEvaluation {
        budget_remaining_pct: ((allowed - consumed) / allowed) * 100.0,
        burn_rate: consumed / allowed,
        status: if partial {
            "partial"
        } else if no_data {
            "no_data"
        } else if current < target {
            "breaching"
        } else if ((allowed - consumed) / allowed) * 100.0 < 25.0 {
            "at_risk"
        } else {
            "ok"
        },
    }
}

pub fn slo_payload(
    slo: &SloDefinition,
    current: f64,
    total: u64,
    now: DateTime<Utc>,
) -> serde_json::Value {
    let evaluation = slo_evaluation(slo.target, current, false, false);
    serde_json::json!([{
        "slo_id": slo.id.to_string(), "name": slo.name, "service": slo.service,
        "sli_kind": slo.sli_kind.as_str(), "target": slo.target, "current": current,
        "burn_rate": evaluation.burn_rate, "budget_remaining_pct": evaluation.budget_remaining_pct,
        "window_days": slo.window_days, "total_spans": total,
        "status": evaluation.status, "evaluated_at": now.to_rfc3339()
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_counter_rate_golden() {
        let rows = vec![("active".into(), Some(2.0)), ("one-sample".into(), None),
            ("absent".into(), None)];
        let filtered = vec![("active".into(), Some(5.0)), ("one-sample".into(), Some(1.0)),
            ("absent".into(), Some(0.0))];
        let base = vec![("active".into(), Some(9.0)), ("one-sample".into(), Some(9.0)),
            ("absent".into(), Some(9.0)), ("new-group".into(), Some(2.0)),
            ("dead".into(), Some(0.0)), ("unknown".into(), None)];
        assert_eq!(fill_missing_counter_rates(rows, filtered, base), vec![
            ("absent".into(), Some(0.0)), ("active".into(), Some(2.0)),
            ("new-group".into(), Some(0.0)), ("one-sample".into(), None)]);
        assert_eq!(fill_missing_counter_rates(vec![("".into(), None)], vec![],
            vec![("".into(), Some(0.0))]), vec![("".into(), None)]);
        assert_eq!(fill_missing_counter_rates(vec![], vec![],
            vec![("".into(), Some(3.0))]), vec![("".into(), Some(0.0))]);
    }

    #[test]
    fn no_data_and_partial_never_breach() {
        assert_eq!(slo_evaluation(0.99, 0.0, true, false).status, "no_data");
        assert_eq!(slo_evaluation(0.99, 0.0, false, true).status, "partial");
        let bad = slo_evaluation(0.99, 0.98, false, false);
        assert_eq!(bad.status, "breaching");
        assert!((bad.burn_rate - 2.0).abs() < 1e-9);
    }
    #[test]
    fn durable_rearm_boundary_and_future_clock() {
        let now = Utc::now();
        assert!(within_rearm(now + chrono::Duration::seconds(1), now, 60));
        assert!(within_rearm(now - chrono::Duration::seconds(59), now, 60));
        assert!(!within_rearm(now - chrono::Duration::seconds(60), now, 60));
        let id = uuid::Uuid::new_v4();
        assert_ne!(
            metric_monitor_source_id(id, "a:b"),
            metric_monitor_source_id(id, "a")
        );
    }
    #[test]
    fn monitor_comparators_reject_no_data_and_non_finite_values() {
        use crate::observability::MonitorComparator::*;
        let now = Utc::now();
        let mut monitor = MetricMonitor {
            id: uuid::Uuid::new_v4(),
            name: "test".into(),
            metric_name: "test.gauge".into(),
            agg: "avg".into(),
            service_name: None,
            group_by: None,
            filters: vec![],
            comparator: Gt,
            threshold: 10.0,
            window_secs: 60,
            eval_interval_secs: 30,
            enabled: true,
            created_by: None,
            created_at: now,
            updated_at: now,
        };
        monitor.group_by = Some("instance".into());
        monitor.filters.push(super::super::MonitorTagFilter {
            key: "mountpoint".into(),
            value: "/".into(),
        });
        let payload = metric_payload(&monitor, "node-a", 9.0, now);
        assert_eq!(payload[0]["labels"]["instance"], "node-a");
        assert_eq!(payload[0]["labels"]["mountpoint"], "/");
        for (comparator, low, equal, high) in [
            (Gt, false, false, true),
            (Gte, false, true, true),
            (Lt, true, false, false),
            (Lte, true, true, false),
        ] {
            monitor.comparator = comparator;
            assert_eq!(metric_breach(&monitor, Some(9.0)), low);
            assert_eq!(metric_breach(&monitor, Some(10.0)), equal);
            assert_eq!(metric_breach(&monitor, Some(11.0)), high);
            assert!(!metric_breach(&monitor, None));
            assert!(!metric_breach(&monitor, Some(f64::NAN)));
            assert!(!metric_breach(&monitor, Some(f64::INFINITY)));
        }
    }
}

/// Conservative free-space fraction within a monitor window. Missing or invalid
/// capacity is no-data, never a fabricated zero/free-space incident.
pub fn filesystem_ratios(
    available: Vec<(String, Option<f64>)>,
    capacity: Vec<(String, Option<f64>)>,
) -> Vec<(String, Option<f64>)> {
    let capacity: std::collections::HashMap<_, _> = capacity.into_iter().collect();
    available
        .into_iter()
        .map(|(key, value)| {
            let ratio = value
                .zip(capacity.get(&key).copied().flatten())
                .filter(|(free, size)| {
                    free.is_finite()
                        && size.is_finite()
                        && *free >= 0.0
                        && *size > 0.0
                        && free <= size
                })
                .map(|(free, size)| free / size);
            (key, ratio)
        })
        .collect()
}

#[cfg(test)]
mod filesystem_tests {
    use super::filesystem_ratios;
    #[test]
    fn ratios_match_nodes_and_require_fresh_positive_capacity() {
        let rows = filesystem_ratios(
            vec![
                ("small".into(), Some(6.38)),
                ("large".into(), Some(6.38)),
                ("missing".into(), Some(1.0)),
                ("zero".into(), Some(1.0)),
            ],
            vec![
                ("large".into(), Some(100.0)),
                ("small".into(), Some(40.0)),
                ("zero".into(), Some(0.0)),
            ],
        );
        assert!((rows[0].1.unwrap() - 0.1595).abs() < 1e-9);
        assert!(rows[1].1.unwrap() < 0.1);
        assert_eq!(rows[2].1, None);
        assert_eq!(rows[3].1, None);
    }
}
