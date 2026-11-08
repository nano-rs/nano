// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4988: SIEM Health visibility for refreshable-view shedding.

use super::*;

fn watchdog(action: &str, mode: &str) -> IngestWatchdogHealth {
    IngestWatchdogHealth {
        node: "clickhouse-shard-1".into(),
        action: action.into(),
        mode: mode.into(),
        reason: "oldest_flush_age_seconds=61 (limit 60)".into(),
        event_age_secs: 30,
        disabled_views: vec!["ip_enrichment_dict_refresh".into()],
        replicas: Vec::new(),
    }
}

#[test]
fn automatic_shedding_is_a_high_health_finding() {
    let metrics = InsertIntegrityMetrics {
        ingest_watchdog: vec![watchdog("auto_stop", "auto")],
        ..Default::default()
    };

    let recommendations = insert_integrity_recommendations(&metrics);
    let finding = recommendations
        .iter()
        .find(|recommendation| recommendation.title.contains("Refreshable views"))
        .expect("watchdog finding");
    assert_eq!(finding.priority, "high");
    assert!(finding.description.contains("ip_enrichment_dict_refresh"));
    assert!(finding.description.contains("twenty calm samples"));
}

#[test]
fn production_auto_stop_journal_flows_through_collector_and_analyzer() {
    let stopped = crate::ingest_watchdog::OwnedView {
        replica: "clickhouse-shard-1-replica-1".into(),
        endpoint: "http://clickhouse-shard-1-replica-1:8123".into(),
        database: "nanosiem".into(),
        view: "ip_enrichment_dict_refresh".into(),
    };
    assert!(crate::ingest_watchdog::journal_disabled_views(
        "auto_stop",
        "intent",
        &crate::ingest_watchdog::WatchdogSample::default(),
        std::slice::from_ref(&stopped),
    )
    .is_empty());
    let disabled_views = crate::ingest_watchdog::journal_disabled_views(
        "auto_stop",
        "completed",
        &crate::ingest_watchdog::WatchdogSample::default(),
        &[stopped],
    );
    assert_eq!(
        disabled_views,
        vec!["clickhouse-shard-1-replica-1|nanosiem|ip_enrichment_dict_refresh"]
    );

    let health = crate::siem_health::collector::watchdog_health_from_row(
        crate::siem_health::collector::WatchdogHealthRow {
            node: "clickhouse-shard-1".into(),
            action: "auto_stop".into(),
            mode: "auto".into(),
            reason: "pending_async_inserts=2000 (limit 2000)".into(),
            age: 0,
            disabled_views,
        },
    );
    let metrics = InsertIntegrityMetrics {
        ingest_watchdog: vec![health],
        ..Default::default()
    };
    let finding = insert_integrity_recommendations(&metrics)
        .into_iter()
        .find(|recommendation| recommendation.title.contains("Refreshable views"))
        .expect("real auto-stop journal produces a SIEM Health finding");
    assert_eq!(finding.priority, "high");
    assert!(finding.description.contains("ip_enrichment_dict_refresh"));
    assert!(finding.description.contains("Primary ingest remains running"));
}

#[test]
fn manual_shedding_says_the_watchdog_will_never_restart_views() {
    let metrics = InsertIntegrityMetrics {
        ingest_watchdog: vec![watchdog("manual_stop_reapplied", "manual")],
        ..Default::default()
    };

    let recommendations = insert_integrity_recommendations(&metrics);
    let finding = recommendations
        .iter()
        .find(|recommendation| recommendation.title.contains("Refreshable views"))
        .expect("manual watchdog finding");
    assert!(finding.description.contains("will never restart"));
    assert!(finding.description.contains("manual-start"));
}

#[test]
fn pre_watchdog_health_reports_remain_compatible() {
    let mut old_report = serde_json::to_value(InsertIntegrityMetrics::default()).unwrap();
    old_report
        .as_object_mut()
        .unwrap()
        .remove("ingest_watchdog");
    let metrics: InsertIntegrityMetrics = serde_json::from_value(old_report).expect("old report");
    assert!(metrics.ingest_watchdog.is_empty());
}

#[test]
fn unreachable_replica_is_a_visible_health_finding() {
    let mut state = watchdog("none", "auto");
    state.disabled_views.clear();
    state.replicas.push(IngestWatchdogReplicaHealth {
        replica: "replica-2".into(),
        endpoint: "http://replica-2:8123".into(),
        reachable: false,
        error: "connection refused".into(),
        hot: false,
        sample_age_secs: 30,
    });
    let metrics = InsertIntegrityMetrics {
        ingest_watchdog: vec![state],
        ..Default::default()
    };
    let finding = insert_integrity_recommendations(&metrics)
        .into_iter()
        .find(|recommendation| recommendation.title.contains("coverage"))
        .expect("coverage finding");
    assert_eq!(finding.priority, "high");
    assert!(finding.description.contains("replica-2"));
}
