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
        stale: false,
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

/// NAN-5296: a flush stuck past five minutes is a critical finding and drags
/// the ingestion score, independent of the (unwritable) watchdog journal.
#[test]
fn stuck_async_flush_is_a_critical_health_finding() {
    let calm = InsertIntegrityMetrics::default();
    assert!(!insert_integrity_recommendations(&calm)
        .iter()
        .any(|recommendation| recommendation.title.contains("Async-insert flushes are stuck")));

    let stuck = InsertIntegrityMetrics {
        stuck_async_flushes: 2,
        longest_async_flush_secs: 34_211,
        ..Default::default()
    };
    let recommendations = insert_integrity_recommendations(&stuck);
    let finding = recommendations
        .iter()
        .find(|recommendation| recommendation.title.contains("Async-insert flushes are stuck"))
        .expect("stuck-flush finding");
    assert_eq!(finding.priority, "critical");
    assert!(finding.description.contains("2 AsyncInsertFlush queries"));
    assert!(finding.description.contains("longest 34211s"));
    assert!(finding.description.contains("migration 198"));
}

fn replica(name: &str, reachable: bool, hot: bool, age: u64, stale: bool) -> IngestWatchdogReplicaHealth {
    IngestWatchdogReplicaHealth {
        replica: name.into(),
        endpoint: format!("http://{name}:8123"),
        reachable,
        error: String::new(),
        hot,
        sample_age_secs: age,
        stale,
    }
}

fn ingestion(ii: InsertIntegrityMetrics) -> IngestionMetrics {
    IngestionMetrics {
        source_volumes: vec![SourceVolumeMetric {
            source_type: "windows_event".to_string(),
            count_24h: 1_000,
            count_prior_24h: 1_000,
            change_pct: 0.0,
        }],
        total_events_24h: 1_000,
        total_events_prior_24h: 1_000,
        silent_sources: vec![],
        removed_sources: vec![],
        insert_integrity: ii,
    }
}

/// NAN-5819: a last-known-good row (reachable, calm) whose sample is past the
/// staleness bound is reported as stale, never as covered or calm.
#[test]
fn stale_last_known_good_replica_is_shown_as_stale() {
    let with = |r: IngestWatchdogReplicaHealth| {
        let mut state = watchdog("none", "auto");
        state.disabled_views.clear();
        state.replicas.push(r);
        InsertIntegrityMetrics { ingest_watchdog: vec![state], ..Default::default() }
    };
    let fresh = with(replica("replica-1", true, false, 25, false));
    let stale = with(replica("replica-1", true, false, 3_600, true));

    assert!(!insert_integrity_recommendations(&fresh)
        .iter()
        .any(|r| r.title.contains("watchdog replica")));
    let finding = insert_integrity_recommendations(&stale)
        .into_iter()
        .find(|r| r.title == "Ingest watchdog replica status is stale")
        .expect("stale finding");
    assert_eq!(finding.priority, "high");
    assert!(finding.description.contains("clickhouse-shard-1/replica-1 (last sample 3600 s ago)"));
    // Not double-reported as unreachable.
    assert!(!insert_integrity_recommendations(&stale)
        .iter()
        .any(|r| r.title.contains("coverage is degraded")));
    // The score treats it as missing coverage, like an unreachable replica.
    let unreachable = with(replica("replica-1", false, false, 25, false));
    assert_eq!(score_ingestion(&ingestion(stale)), score_ingestion(&ingestion(unreachable)));
    assert!(score_ingestion(&ingestion(fresh.clone())) > score_ingestion(&ingestion(with(replica("replica-1", true, false, 3_600, true)))));
}

/// NAN-5819: the collector marks a row stale past the bound, not at it.
#[test]
fn collector_marks_rows_past_the_bound_stale() {
    let row = |age| crate::siem_health::collector::WatchdogReplicaHealthRow {
        node: "n".into(),
        replica: "r".into(),
        endpoint: "e".into(),
        reachable: true,
        error: String::new(),
        hot: false,
        age,
    };
    assert!(!crate::siem_health::collector::replica_health_from_row(row(120), 120).stale);
    assert!(crate::siem_health::collector::replica_health_from_row(row(121), 120).stale);
}

/// NAN-5819: reports stored before the field deserialize as not stale.
#[test]
fn replica_rows_without_stale_deserialize() {
    let old = serde_json::json!({
        "replica": "r", "endpoint": "e", "reachable": true, "error": "", "hot": false, "sample_age_secs": 5
    });
    let parsed: IngestWatchdogReplicaHealth = serde_json::from_value(old).unwrap();
    assert!(!parsed.stale);
}
