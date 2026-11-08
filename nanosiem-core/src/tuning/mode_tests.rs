// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn defaults_to_on() {
    assert_eq!(AiTuningMode::default(), AiTuningMode::On);
}

#[test]
fn round_trips_and_rejects_unknown_names() {
    for mode in AiTuningMode::ALL {
        assert_eq!(AiTuningMode::parse(mode.as_str()), Some(mode));
        assert_eq!(
            serde_json::to_value(mode).unwrap(),
            serde_json::json!(mode.as_str())
        );
    }
    assert_eq!(AiTuningMode::parse("manual_only"), None);
    assert_eq!(AiTuningMode::parse("ON"), None);
    assert!(serde_json::from_value::<AiTuningMode>(serde_json::json!("disabled")).is_err());
}

#[test]
fn capability_matrix() {
    use AiTuningMode::*;
    assert!(On.collects_metrics() && On.automatic_proposals() && On.wizard_allowed());
    assert!(
        Manual.collects_metrics() && !Manual.automatic_proposals() && Manual.wizard_allowed()
    );
    assert!(!Off.collects_metrics() && !Off.automatic_proposals() && !Off.wizard_allowed());
}

#[test]
fn dedicated_scheduler_tasks_honour_the_mode() {
    use AiTuningMode::*;
    use TuningTask::*;
    let all = [Metrics, Baselines, Breaches, SilentRules, Notifications];
    for task in all {
        assert!(task.allowed(On), "{task:?} runs when on");
        assert!(
            !task.allowed(Off),
            "{task:?} never runs when off (metrics included)"
        );
    }
    assert!(Metrics.allowed(Manual));
    assert!(Baselines.allowed(Manual));
    assert!(!Breaches.allowed(Manual), "manual: no automatic proposals");
    assert!(
        !SilentRules.allowed(Manual),
        "manual: no automatic proposals"
    );
    assert!(!Notifications.allowed(Manual), "manual: no notifications");
}
