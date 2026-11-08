// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902 review: the max-lag gauge must stay ONE unlabelled series however
//! often the worst rule changes (a per-rule label leaked a series per rule).

use std::sync::{Arc, Mutex};

use chrono::Utc;
use metrics::{Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};

use super::{record_schedule_lag, LaggingRule, ScheduleLagSummary};

#[derive(Default)]
struct KeyRecorder {
    gauges: Arc<Mutex<Vec<Key>>>,
}

impl Recorder for KeyRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
        Counter::noop()
    }
    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        self.gauges.lock().unwrap().push(key.clone());
        Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

fn summary(worst_rule: &str, max_lag_secs: i64) -> ScheduleLagSummary {
    ScheduleLagSummary {
        total: 1,
        behind_schedule: 1,
        over_2x_interval: 1,
        max_lag_secs,
        p95_lag_secs: max_lag_secs,
        behind_grace_secs: 30,
        degraded: true,
        worst: vec![LaggingRule {
            rule_id: worst_rule.to_string(),
            rule_name: worst_rule.to_string(),
            lag_secs: max_lag_secs,
            interval_secs: Some(60),
            over_2x_interval: true,
        }],
        measured_at: Utc::now(),
    }
}

#[test]
fn max_lag_gauge_is_unlabelled_as_the_worst_rule_rotates() {
    let recorder = KeyRecorder::default();
    let gauges = Arc::clone(&recorder.gauges);
    metrics::with_local_recorder(&recorder, || {
        for (rule, lag) in [("rule_a", 300), ("rule_b", 400), ("rule_c", 500)] {
            record_schedule_lag(&summary(rule, lag));
        }
    });
    let gauges = gauges.lock().unwrap();
    let max_lag: Vec<&Key> = gauges
        .iter()
        .filter(|key| key.name() == "nanosiem_detection_schedule_lag_max_seconds")
        .collect();
    assert_eq!(max_lag.len(), 3, "one registration per record call");
    assert!(
        max_lag.iter().all(|key| key.labels().next().is_none()),
        "max-lag gauge must carry no labels: {max_lag:?}"
    );
}
