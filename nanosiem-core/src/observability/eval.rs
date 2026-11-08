// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pure metric-monitor and SLO evaluation helpers (NAN-3975 / NAN-4031 /
//! NAN-3894), shared by the dedicated schedulers, the read path and the
//! lifecycle integration tests.
use chrono::{DateTime, Utc};

use super::{MetricMonitor, SloDefinition};

/// Stable identity for the incident belonging to a monitor and series.
///
/// The monitor id is a hyphenated UUID (never contains `:`), so the first `:`
/// separates the fixed prefix from the verbatim series key — the mapping is
/// injective. A no-`group_by` monitor yields `""` as the series key → `"<id>:"`.
pub fn metric_monitor_source_id(monitor_id: uuid::Uuid, series_key: &str) -> String {
    format!("{monitor_id}:{series_key}")
}

/// Time-based re-arm (NAN-1563): `true` while the newest alert at `last` is
/// within `seconds` of `now` (skip raising). A future `last` (clock skew)
/// counts as within the window, erring toward dedup rather than a storm.
pub fn within_rearm(last: DateTime<Utc>, now: DateTime<Utc>, seconds: u64) -> bool {
    let elapsed = (now - last).num_seconds();
    elapsed < 0 || (elapsed as u64) < seconds
}

/// A known, finite sample that crosses the threshold. No-data never breaches.
pub fn metric_breach(monitor: &MetricMonitor, value: Option<f64>) -> bool {
    value.is_some_and(|v| v.is_finite() && monitor.comparator.breached(v, monitor.threshold))
}

/// Breach/observation payload stored in the alert's `matched_events`. The
/// lifecycle orders observations by `evaluated_at`, and `labels` carries the
/// monitor's filters plus the grouped series so the console can show which
/// node/mountpoint the incident belongs to.
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
        "window_secs": monitor.window_secs, "evaluated_at": now.to_rfc3339(),
    }])
}

/// NAN-4031: fill only absent filtered counter series in groups whose base
/// metric is present. A sparse label (e.g. `status=500`) need not exist before
/// its first event, so "no filtered rows while the base metric reports" is a
/// proven zero rate. Existing NULL rates (e.g. one sample) and dead services
/// (no base rows) stay unknown.
pub fn fill_missing_counter_rates(
    rows: Vec<(String, Option<f64>)>,
    filtered_counts: Vec<(String, Option<f64>)>,
    base_counts: Vec<(String, Option<f64>)>,
) -> Vec<(String, Option<f64>)> {
    let observed: std::collections::HashSet<_> = filtered_counts
        .into_iter()
        .filter(|(_, n)| n.is_some_and(|n| n.is_finite() && n > 0.0))
        .map(|(key, _)| key)
        .collect();
    let mut result: std::collections::BTreeMap<_, _> = rows.into_iter().collect();
    for (key, count) in base_counts {
        if count.is_some_and(|n| n.is_finite() && n > 0.0) && !observed.contains(&key) {
            result.insert(key, Some(0.0));
        }
    }
    result.into_iter().collect()
}

/// Budget / burn / status for one SLO evaluation (NAN-3894). The scheduler
/// and the list endpoint both use this, so alerting and the console agree.
#[derive(Debug, Clone, PartialEq)]
pub struct SloEvaluation {
    pub budget_remaining_pct: f64,
    pub burn_rate: f64,
    /// `ok` | `at_risk` | `breaching` | `no_data` | `partial`.
    pub status: &'static str,
}

impl SloEvaluation {
    /// Attainment, budget and burn are only meaningful for a fully covered
    /// window with traffic; `partial` and `no_data` report none of them.
    pub fn known(&self) -> bool {
        !matches!(self.status, "partial" | "no_data")
    }
}

/// `partial` (the target service's telemetry does not cover the window) wins
/// over everything: an uncovered window must never read as attained, burning
/// or breaching. `no_data` (zero traffic, O17) is next.
pub fn slo_evaluation(target: f64, current: f64, no_data: bool, partial: bool) -> SloEvaluation {
    // Error budget: allowed failure fraction is (1 - target); consumed is
    // (1 - current). Burn 1.0 = on track to exhaust the budget at window end.
    let allowed = (1.0 - target).max(f64::EPSILON);
    let consumed = (1.0 - current).max(0.0);
    let budget_remaining_pct = ((allowed - consumed) / allowed) * 100.0;
    let status = if partial {
        "partial"
    } else if no_data {
        "no_data"
    } else if current < target {
        "breaching"
    } else if budget_remaining_pct < 25.0 {
        "at_risk"
    } else {
        "ok"
    };
    SloEvaluation {
        budget_remaining_pct,
        burn_rate: consumed / allowed,
        status,
    }
}

/// Breach payload stored in a `kind:"slo"` alert's `matched_events`.
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
        "burn_rate": evaluation.burn_rate,
        "budget_remaining_pct": evaluation.budget_remaining_pct,
        "window_days": slo.window_days, "total_spans": total,
        "status": evaluation.status, "evaluated_at": now.to_rfc3339(),
    }])
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod tests;
