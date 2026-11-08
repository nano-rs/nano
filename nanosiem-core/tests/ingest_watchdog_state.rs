// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use nanosiem_core::ingest_watchdog::{
    IngestWatchdogConfig, WatchdogDecision, WatchdogMode, WatchdogSample, WatchdogState,
};

fn calm() -> WatchdogSample {
    WatchdogSample {
        pending_async_inserts: 0,
        oldest_flush_age_seconds: 0,
        running_queries: 10,
        memory_usage_bytes: 100,
        memory_limit_bytes: 1_000,
        refreshes_running: 0,
        disabled_views: vec![],
    }
}

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}

#[test]
fn four_consecutive_hot_samples_stop_views() {
    let config = IngestWatchdogConfig::default();
    let mut state = WatchdogState::default();
    let mut hot = calm();
    hot.pending_async_inserts = 2_000;

    for tick in 0..3 {
        assert_eq!(
            state.observe(&hot, at(tick * 30), &config),
            WatchdogDecision::None
        );
    }
    assert_eq!(
        state.observe(&hot, at(90), &config),
        WatchdogDecision::StopViews
    );
    assert!(state.shedding);
}

#[test]
fn calm_restore_requires_twenty_samples_and_fifteen_minutes() {
    let config = IngestWatchdogConfig::default();
    let mut state = WatchdogState::default();
    state.mode = WatchdogMode::Auto;
    state.shedding = true;
    state.last_transition = Some(at(0));
    let mut disabled = calm();
    disabled.disabled_views = vec!["ip_enrichment_dict_refresh".into()];

    for tick in 1..=20 {
        assert_eq!(
            state.observe(&disabled, at(tick * 30), &config),
            WatchdogDecision::None,
            "twenty calm samples are only ten minutes; anti-flap still applies"
        );
    }
    for tick in 21..30 {
        assert_eq!(
            state.observe(&disabled, at(tick * 30), &config),
            WatchdogDecision::None
        );
    }
    assert_eq!(
        state.observe(&disabled, at(15 * 60), &config),
        WatchdogDecision::StartViews
    );
    assert!(!state.shedding);
}

#[test]
fn human_disabled_view_enters_manual_mode_and_never_auto_starts() {
    let config = IngestWatchdogConfig::default();
    let mut state = WatchdogState::default();
    let mut disabled = calm();
    disabled.disabled_views = vec!["user_registry_dict_refresh".into()];

    assert_eq!(
        state.observe(&disabled, at(0), &config),
        WatchdogDecision::RecordObservedManualStop
    );
    assert_eq!(state.mode, WatchdogMode::Manual);
    assert!(state.shedding);
    for tick in 1..=100 {
        assert_eq!(
            state.observe(&disabled, at(tick * 30), &config),
            WatchdogDecision::None
        );
    }
}

#[test]
fn manual_stop_is_reapplied_after_clickhouse_restart() {
    let config = IngestWatchdogConfig::default();
    let mut state = WatchdogState::default();
    state.mode = WatchdogMode::Manual;
    state.shedding = true;
    state.last_transition = Some(at(0));

    assert_eq!(
        state.observe(&calm(), at(30), &config),
        WatchdogDecision::ReapplyManualStopAfterRestart
    );
    assert!(state.shedding);
    assert_eq!(state.mode, WatchdogMode::Manual);
}

#[test]
fn clickhouse_restart_during_owned_stop_triggers_immediate_catch_up() {
    let config = IngestWatchdogConfig::default();
    let mut state = WatchdogState::default();
    state.mode = WatchdogMode::Auto;
    state.shedding = true;
    state.last_transition = Some(at(0) - ChronoDuration::minutes(1));

    assert_eq!(
        state.observe(&calm(), at(0), &config),
        WatchdogDecision::CatchUpAfterRestart
    );
    assert!(!state.shedding);
}

#[test]
fn hot_thresholds_match_incident_contract() {
    let config = IngestWatchdogConfig::default();
    let mut sample = calm();
    assert!(sample.hot_reasons(&config).is_empty());

    sample.oldest_flush_age_seconds = 61;
    assert_eq!(sample.hot_reasons(&config).len(), 1);
    sample.oldest_flush_age_seconds = 0;
    sample.running_queries = 1_500;
    assert_eq!(sample.hot_reasons(&config).len(), 1);
    sample.running_queries = 0;
    sample.memory_usage_bytes = 501;
    assert_eq!(sample.hot_reasons(&config).len(), 1);
}

#[test]
fn degraded_coverage_is_never_counted_as_calm() {
    let config = IngestWatchdogConfig::default();
    let mut state = WatchdogState::default();
    state.shedding = true;
    state.last_transition = Some(at(0) - ChronoDuration::minutes(20));
    for tick in 1..=40 {
        assert_eq!(
            state.observe_with_coverage(&calm(), false, at(tick * 30), &config),
            WatchdogDecision::None
        );
    }
    assert_eq!(state.calm_streak, 0);
    assert!(state.shedding);
}
