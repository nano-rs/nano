// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5976: the v2.0.37 RC1 CT122 upgrade. One MEMORY_LIMIT_EXCEEDED at
//! 13:23:39Z while the upgrade restarted ClickHouse (rollout window
//! 13:20:38Z to 13:28:02Z, nothing in the 24 h before) took Ingestion from
//! 100 to 80 and the report to CRITICAL for a day.

use super::*;
use crate::siem_health::analyzer::{insert_integrity_recommendations, score_ingestion};
use crate::siem_health::types::{
    DictionaryCheck, ErrorCounterSample, IngestionMetrics, SourceVolumeMetric,
};

fn at(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text).unwrap().with_timezone(&Utc)
}

/// The gate's `clickhouse_errors_before`, as the upgrade records it.
fn baseline(json: serde_json::Value) -> Option<ErrorBaseline> {
    Some(serde_json::from_value(json).unwrap())
}

fn clean_baseline() -> Option<ErrorBaseline> {
    // CT122's baseline: the counter existed (an OOM two days earlier) but
    // nothing in the 24 h before the upgrade.
    baseline(serde_json::json!({
        "captured_at": "2026-11-26T13:20:38Z",
        "errors": {"MEMORY_LIMIT_EXCEEDED": {"value": 3, "last_at": "2026-11-24T09:00:00Z"}},
        "failed_dictionaries": 0
    }))
}

fn ct122_window(baseline: Option<ErrorBaseline>) -> RecordedWindows {
    RecordedWindows {
        windows: vec![UpgradeRolloutWindow {
            run_id: "upgrade-20261126T132038Z-70a30bf1".into(),
            starts_at: at("2026-11-26T13:20:38Z"),
            ends_at: at("2026-11-26T13:28:02Z"),
            baseline,
        }],
    }
}

/// A node's sample whose last occurrence was at `last_at` (ClickHouse clock).
fn sample(host: &str, name: &str, value: u64, last_at: &str) -> ErrorCounterSample {
    ErrorCounterSample {
        host: host.into(),
        name: name.into(),
        value,
        last_error_unix: at(last_at).timestamp() as u64,
    }
}

fn dictionaries_ok() -> Option<DictionaryCheck> {
    Some(DictionaryCheck { hosts: vec!["ch-1".into(), "ch-2".into()], unhealthy: 0 })
}

/// The CT122 ingestion metrics: healthy sources, one OOM last seen at
/// `last_at` on the single ClickHouse node, no failing dictionary.
fn ingestion_with_oom(last_at: &str) -> IngestionMetrics {
    let ii = InsertIntegrityMetrics {
        probes_available: true,
        memory_limit_errors: 1,
        error_counter_samples: vec![sample("ch-1", "MEMORY_LIMIT_EXCEEDED", 1, last_at)],
        dictionary_check: dictionaries_ok(),
        ..Default::default()
    };
    IngestionMetrics {
        source_volumes: vec![SourceVolumeMetric {
            source_type: "linux_syslog".into(),
            count_24h: 1523,
            count_prior_24h: 1500,
            change_pct: 1.5,
        }],
        total_events_24h: 1523,
        total_events_prior_24h: 1500,
        silent_sources: vec![],
        removed_sources: vec![],
        insert_integrity: ii,
    }
}

fn has_memory_finding(ii: &InsertIntegrityMetrics) -> bool {
    insert_integrity_recommendations(ii)
        .iter()
        .any(|r| r.title == "ClickHouse is hitting its memory limit")
}

#[test]
fn an_error_inside_the_recorded_rollout_window_is_shown_but_not_scored() {
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    // The bug: counted as a live problem.
    assert_eq!(score_ingestion(&m), 80);
    assert!(has_memory_finding(&m.insert_integrity));

    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));

    assert_eq!(score_ingestion(&m), 100);
    assert!(!has_memory_finding(&m.insert_integrity));
    assert_eq!(m.insert_integrity.memory_limit_errors, 0);
    assert_eq!(
        m.insert_integrity.upgrade_transient_errors,
        vec![UpgradeTransientError {
            name: "MEMORY_LIMIT_EXCEEDED".into(),
            count: 1,
            last_at: at("2026-11-26T13:23:39Z"),
            upgrade_run_id: "upgrade-20261126T132038Z-70a30bf1".into(),
        }]
    );
}

#[test]
fn an_error_after_the_rollout_window_still_counts() {
    // A real OOM later the same day moves last_error_time past the window.
    let mut m = ingestion_with_oom("2026-11-26T14:10:00Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
    assert!(m.insert_integrity.upgrade_transient_errors.is_empty());
    assert_eq!(score_ingestion(&m), 80);
    assert!(has_memory_finding(&m.insert_integrity));

    // And one before the window started (but inside the 24 h probe).
    let mut m = ingestion_with_oom("2026-11-26T13:20:37Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

#[test]
fn no_recorded_window_leaves_the_report_unchanged() {
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    let before = format!("{:?}", m.insert_integrity);
    set_aside_upgrade_transients(&mut m.insert_integrity, &RecordedWindows::default());
    assert_eq!(format!("{:?}", m.insert_integrity), before);
    assert_eq!(score_ingestion(&m), 80);
}

#[test]
fn an_error_already_happening_before_the_upgrade_still_counts() {
    // The gate's rule: an error seen in the 24 h before the upgrade was not
    // caused by it, even if it fired again during the rollout.
    let active = baseline(serde_json::json!({
        "captured_at": "2026-11-26T13:20:38Z",
        "errors": {"MEMORY_LIMIT_EXCEEDED": {"value": 9, "last_at": "2026-11-26T08:00:00Z"}}
    }));
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(active));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

#[test]
fn a_window_without_a_baseline_excuses_nothing() {
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(None));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

#[test]
fn a_baseline_without_the_error_is_clean() {
    let empty = baseline(serde_json::json!({
        "captured_at": "2026-11-26T13:20:38Z", "errors": {}
    }));
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(empty));
    assert_eq!(m.insert_integrity.memory_limit_errors, 0);
}

#[test]
fn a_failing_or_unchecked_dictionary_on_any_node_keeps_every_error_counted() {
    let cases = [
        // r2's single number could not tell these apart.
        Some(DictionaryCheck { hosts: vec!["ch-1".into()], unhealthy: 1 }),
        // Probe failed.
        None,
        // Review r2 P2-1: ch-1 showed no dictionary rows (SHOW DICTIONARIES
        // grant missing, NAN-1437): unchecked, not healthy.
        Some(DictionaryCheck { hosts: vec!["ch-2".into()], unhealthy: 0 }),
    ];
    for check in cases {
        let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
        m.insert_integrity.dictionary_check = check.clone();
        set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
        assert_eq!(m.insert_integrity.memory_limit_errors, 1, "{check:?}");
    }
    // Review r2 P2-1: a logs dictionary flagged by dict_is_unhealthy (a
    // degraded CACHE dict, LOADED with a last_exception) also keeps it.
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    m.insert_integrity.failed_logs_dictionaries =
        vec![crate::siem_health::types::FailedDictionary {
            name: "nanosiem.hash_prevalence_dict".into(),
            last_exception: "Code: 510. CACHE_DICTIONARY_UPDATE_FAIL".into(),
        }];
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

/// Review P2-1 (r1): on a cluster, one node's OOM inside the window must not
/// excuse another node's OOM outside it (r1 summed values and took the
/// cluster-wide max(last_error_time)).
#[test]
fn one_node_outside_the_window_keeps_the_whole_counter_scored() {
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    let ii = &mut m.insert_integrity;
    ii.memory_limit_errors = 3;
    ii.error_counter_samples = vec![
        // Node B: a real OOM before a later resume window...
        sample("ch-2", "MEMORY_LIMIT_EXCEEDED", 2, "2026-11-26T14:10:00Z"),
        sample("ch-1", "MEMORY_LIMIT_EXCEEDED", 1, "2026-11-26T13:23:39Z"),
    ];
    let mut recorded = ct122_window(clean_baseline());
    // ...and node A's latest inside the main window; even with a second
    // window later, node B's 14:10 is in none of them.
    recorded.windows.push(UpgradeRolloutWindow {
        run_id: "upgrade-20261126T132038Z-70a30bf1".into(),
        starts_at: at("2026-11-26T14:30:00Z"),
        ends_at: at("2026-11-26T14:40:00Z"),
        baseline: clean_baseline(),
    });
    set_aside_upgrade_transients(ii, &recorded);
    assert_eq!(ii.memory_limit_errors, 3);
    assert!(ii.upgrade_transient_errors.is_empty());

    // Both nodes inside: set aside, with the full count.
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    let ii = &mut m.insert_integrity;
    ii.memory_limit_errors = 3;
    ii.error_counter_samples = vec![
        sample("ch-2", "MEMORY_LIMIT_EXCEEDED", 2, "2026-11-26T13:22:00Z"),
        sample("ch-1", "MEMORY_LIMIT_EXCEEDED", 1, "2026-11-26T13:23:39Z"),
    ];
    set_aside_upgrade_transients(ii, &ct122_window(clean_baseline()));
    assert_eq!(ii.memory_limit_errors, 0);
    assert_eq!(ii.upgrade_transient_errors[0].count, 3);
    assert_eq!(ii.upgrade_transient_errors[0].last_at, at("2026-11-26T13:23:39Z"));
}

/// A counter whose per-node samples do not add up to the scored count is
/// never set aside (a node could be summed without being judged).
#[test]
fn samples_that_do_not_cover_the_count_keep_it_scored() {
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    m.insert_integrity.memory_limit_errors = 2;
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 2);
}

/// Review P2-2 (r1) / r2: the error time is ClickHouse's own last_error_time
/// read in the same query (no derived "now"), and the window is shrunk by a
/// margin so seconds of skew can only make SIEM Health count more.
#[test]
fn skew_near_the_window_edges_only_ever_counts_more() {
    // 10 s before the window end: r1 excused it.
    let mut m = ingestion_with_oom("2026-11-26T13:27:52Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
    // 10 s after the window start: same at the other end.
    let mut m = ingestion_with_oom("2026-11-26T13:20:48Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

/// Review r2: an unknown time (no last_error_time) excuses nothing.
#[test]
fn an_unknown_error_time_keeps_the_counter_scored() {
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    m.insert_integrity.error_counter_samples[0].last_error_unix = 0;
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(clean_baseline()));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

/// A baseline entry without a time cannot show the error was quiet before.
#[test]
fn a_baseline_entry_without_a_time_counts_as_active() {
    let unknown = baseline(serde_json::json!({
        "captured_at": "2026-11-26T13:20:38Z",
        "errors": {"MEMORY_LIMIT_EXCEEDED": {"value": 2, "last_at": null}}
    }));
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &ct122_window(unknown));
    assert_eq!(m.insert_integrity.memory_limit_errors, 1);
}

/// Review r2 P2-3: a report that still scores an error freezes every
/// recorded run, so no later window can excuse it; nothing is frozen when
/// nothing is scored.
#[test]
fn a_scored_error_freezes_the_recorded_runs() {
    let mut m = ingestion_with_oom("2026-11-26T14:10:00Z");
    let recorded = ct122_window(clean_baseline());
    set_aside_upgrade_transients(&mut m.insert_integrity, &recorded);
    assert_eq!(
        runs_to_freeze(&m.insert_integrity, &recorded),
        vec!["upgrade-20261126T132038Z-70a30bf1".to_string()]
    );
    let mut m = ingestion_with_oom("2026-11-26T13:23:39Z");
    set_aside_upgrade_transients(&mut m.insert_integrity, &recorded);
    assert!(runs_to_freeze(&m.insert_integrity, &recorded).is_empty());
}

#[test]
fn a_resume_restart_window_counts_like_the_main_one() {
    // A --resume's nano-jobs restart is recorded as its own row.
    let mut recorded = ct122_window(clean_baseline());
    recorded.windows.push(UpgradeRolloutWindow {
        run_id: "upgrade-20261126T132038Z-70a30bf1".into(),
        starts_at: at("2026-11-26T14:00:00Z"),
        ends_at: at("2026-11-26T14:06:00Z"),
        baseline: clean_baseline(),
    });
    let mut m = ingestion_with_oom("2026-11-26T14:02:00Z");
    let ii = &mut m.insert_integrity;
    ii.cache_dictionary_update_fails = 4;
    // The dictionary error kept firing after the window: it still counts.
    ii.error_counter_samples
        .push(sample("ch-1", "CACHE_DICTIONARY_UPDATE_FAIL", 4, "2026-11-26T14:30:00Z"));
    set_aside_upgrade_transients(ii, &recorded);
    assert_eq!(ii.memory_limit_errors, 0);
    assert_eq!(ii.cache_dictionary_update_fails, 4);
}

#[test]
fn the_internal_samples_are_never_stored_in_a_report() {
    let m = ingestion_with_oom("2026-11-26T13:23:39Z");
    let json = serde_json::to_value(&m.insert_integrity).unwrap();
    assert!(json.get("error_counter_samples").is_none());
    assert!(json.get("failing_dictionaries_any_node").is_none());
    // Nothing set aside: the new field stays out of the stored metrics.
    assert!(json.get("upgrade_transient_errors").is_none());
    // A report stored before NAN-5976 still deserializes.
    let old: InsertIntegrityMetrics = serde_json::from_value(serde_json::json!({
        "probes_available": true, "logs_inserts_1h": 0, "new_parts_1h": 0,
        "memory_limit_errors": 1, "cache_dictionary_update_fails": 0,
        "failed_logs_dictionaries": [], "async_insert_failures_1h": null,
        "last_async_insert_error": null
    }))
    .unwrap();
    assert!(old.upgrade_transient_errors.is_empty());
}
