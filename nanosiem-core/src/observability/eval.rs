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

pub fn metric_breach(monitor: &MetricMonitor, value: Option<f64>) -> bool {
    value.is_some_and(|v| v.is_finite() && monitor.comparator.breached(v, monitor.threshold))
}

pub fn metric_payload(
    monitor: &MetricMonitor,
    series: &str,
    value: f64,
    now: DateTime<Utc>,
) -> serde_json::Value {
    serde_json::json!([{
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
