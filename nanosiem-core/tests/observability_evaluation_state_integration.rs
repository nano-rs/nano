// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3894 durable monitor / SLO evaluation state against the REAL migrated
//! schema (migrations 292 + 295). Each test creates its own definitions and
//! deletes them at the end (state rows cascade).
//!
//! `DATABASE_URL=… NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 cargo test -p nanosiem-core
//! --test observability_evaluation_state_integration -- --ignored`
mod common;

use chrono::{Duration, Utc};
use nanosiem_core::observability::{
    eval::slo_evaluation,
    evaluation_state::{
        admit_slo_alert, list_current_metric_monitor_state, list_fresh_slo_evaluations,
        record_slo_evaluation, MONITOR_SERIES_SAMPLE,
    },
    metric_alert_lifecycle::apply_evaluation,
    MetricMonitorRepository, MonitorComparator, SloRepository, SloSliKind,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn slo_state_is_fenced_on_time_and_definition() {
    let pool = common::migrated_pool().await;
    let repo = SloRepository::new(pool.clone());
    let slo = repo
        .create("lane-f slo", "checkout", SloSliKind::Availability, 0.99, 7, None, None)
        .await
        .unwrap();
    let mine = |rows: Vec<nanosiem_core::observability::evaluation_state::SloEvaluationRecord>| {
        rows.into_iter().filter(|r| r.slo_id == slo.id).collect::<Vec<_>>()
    };

    let now = Utc::now();
    let breaching = slo_evaluation(slo.target, 0.98, false, false);
    assert!(record_slo_evaluation(&pool, &slo, 0.98, 1000, false, &breaching, now).await.unwrap());
    let rows = mine(list_fresh_slo_evaluations(&pool).await.unwrap());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "breaching");
    assert_eq!(rows[0].current, Some(0.98));
    assert_eq!(rows[0].total, 1000);
    assert!((rows[0].burn_fast.unwrap() - 2.0).abs() < 1e-9);

    // An older (slow) evaluation never overwrites a newer one.
    let healthy = slo_evaluation(slo.target, 1.0, false, false);
    let older = now - Duration::seconds(30);
    assert!(!record_slo_evaluation(&pool, &slo, 1.0, 10, false, &healthy, older).await.unwrap());
    assert_eq!(mine(list_fresh_slo_evaluations(&pool).await.unwrap())[0].status, "breaching");

    // Partial stores no figures.
    let partial = slo_evaluation(slo.target, 0.5, false, true);
    let later = now + Duration::seconds(30);
    assert!(record_slo_evaluation(&pool, &slo, 0.5, 10, false, &partial, later).await.unwrap());
    let row = &mine(list_fresh_slo_evaluations(&pool).await.unwrap())[0];
    assert_eq!(row.status, "partial");
    assert_eq!((row.current, row.budget_remaining_pct, row.burn_fast), (None, None, None));

    // An edit invalidates the cached result, and a result computed against
    // the old definition is dropped rather than written.
    let edited = repo
        .update(slo.id, "lane-f slo", "checkout", SloSliKind::Availability, 0.999, 7, None)
        .await
        .unwrap();
    assert!(mine(list_fresh_slo_evaluations(&pool).await.unwrap()).is_empty());
    let much_later = now + Duration::seconds(60);
    assert!(!record_slo_evaluation(&pool, &slo, 1.0, 10, false, &healthy, much_later).await.unwrap());
    assert!(record_slo_evaluation(&pool, &edited, 1.0, 10, false, &healthy, much_later).await.unwrap());
    assert_eq!(mine(list_fresh_slo_evaluations(&pool).await.unwrap())[0].status, "ok");

    // Stale results age out of the read.
    sqlx::query("UPDATE observability_slo_evaluations SET evaluated_at = NOW() - INTERVAL '11 minutes' WHERE slo_id = $1")
        .bind(slo.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(mine(list_fresh_slo_evaluations(&pool).await.unwrap()).is_empty());

    // Deleting the SLO cascades; a late write for a deleted SLO is a no-op.
    assert!(repo.delete(slo.id).await.unwrap());
    assert!(!record_slo_evaluation(&pool, &edited, 1.0, 10, false, &healthy, much_later + Duration::seconds(1)).await.unwrap());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn monitor_state_serves_the_current_series_inventory() {
    let pool = common::migrated_pool().await;
    let repo = MetricMonitorRepository::new(pool.clone());
    let monitor = repo
        .create(
            "lane-f disk",
            "system.filesystem.utilization",
            "max",
            None,
            Some("host.name"),
            &[],
            MonitorComparator::Gt,
            0.9,
            300,
            60,
            true,
            None,
        )
        .await
        .unwrap();
    let mine = |rows: Vec<nanosiem_core::observability::evaluation_state::MetricMonitorEvaluation>| {
        rows.into_iter()
            .filter(|r| r.monitor_id == monitor.id)
            .map(|r| (r.series_key, r.value, r.no_data))
            .collect::<Vec<_>>()
    };

    // Saved but never evaluated: no rows ("Awaiting evaluation").
    assert!(mine(list_current_metric_monitor_state(&pool).await.unwrap().1).is_empty());

    // An evaluation that returns no series at all is recorded as no-data.
    let t0 = Utc::now() - Duration::seconds(120);
    apply_evaluation(&pool, &monitor, vec![], t0).await.unwrap();
    assert_eq!(
        mine(list_current_metric_monitor_state(&pool).await.unwrap().1),
        vec![(String::new(), None, true)]
    );

    // Two series report (healthy): only the newest evaluation is served.
    let t1 = t0 + Duration::seconds(60);
    apply_evaluation(
        &pool,
        &monitor,
        vec![("node-a".into(), Some(0.5)), ("node-b".into(), None)],
        t1,
    )
    .await
    .unwrap();
    assert_eq!(
        mine(list_current_metric_monitor_state(&pool).await.unwrap().1),
        vec![("node-a".into(), Some(0.5), false), ("node-b".into(), None, true)]
    );

    // Disabling hides the monitor's state (paused, not "healthy").
    sqlx::query("UPDATE observability_metric_monitors SET enabled = false WHERE id = $1")
        .bind(monitor.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(mine(list_current_metric_monitor_state(&pool).await.unwrap().1).is_empty());

    // Series the evaluator stopped returning a day ago are retired.
    let alerts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM alerts WHERE kind = 'metric_monitor' AND starts_with(source_id, $1)",
    )
    .bind(format!("{}:", monitor.id))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(alerts, 0, "healthy and no-data samples never open an incident");
    let t2 = t1 + Duration::days(2);
    apply_evaluation(&pool, &monitor, vec![("node-a".into(), Some(0.4))], t2).await.unwrap();
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT series_key FROM observability_metric_monitor_state WHERE monitor_id = $1 ORDER BY series_key",
    )
    .bind(monitor.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(keys, vec!["node-a".to_string()]);

    assert!(repo.delete(monitor.id).await.unwrap());
}

async fn grouped_monitor(pool: &sqlx::PgPool, name: &str) -> nanosiem_core::observability::MetricMonitor {
    MetricMonitorRepository::new(pool.clone())
        .create(
            name,
            "system.filesystem.utilization",
            "max",
            None,
            Some("host.name"),
            &[],
            MonitorComparator::Gt,
            0.9,
            300,
            60,
            true,
            None,
        )
        .await
        .unwrap()
}

async fn monitor_alerts(pool: &sqlx::PgPool, monitor: uuid::Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM alerts WHERE kind = 'metric_monitor' AND starts_with(source_id, $1)",
    )
    .bind(format!("{monitor}:"))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Codex P1-1: evaluator A records a breach at t1, evaluator B then records a
/// healthy result at t2, and A resumes to raise its alert. Admission re-checks
/// that A's result is still current in the same transaction as the re-arm
/// check and the insert, so A raises nothing; a genuinely current breach
/// raises exactly one alert and the re-arm window holds after it.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn superseded_slo_breach_raises_no_alert() {
    let pool = common::migrated_pool().await;
    let repo = SloRepository::new(pool.clone());
    let slo = repo
        .create("lane-f interleave", "checkout", SloSliKind::Availability, 0.99, 7, None, None)
        .await
        .unwrap();
    let alerts = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM alerts WHERE kind = 'slo' AND source_id = $1")
            .bind(slo.id.to_string())
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let now = Utc::now();
    let (t1, t2, t3) = (now - Duration::seconds(30), now - Duration::seconds(20), now - Duration::seconds(10));
    let breach = slo_evaluation(slo.target, 0.9, false, false);
    let healthy = slo_evaluation(slo.target, 1.0, false, false);
    let payload = serde_json::json!([{ "status": "breaching" }]);

    // A: breaching result persisted at t1 ...
    assert!(record_slo_evaluation(&pool, &slo, 0.9, 100, false, &breach, t1).await.unwrap());
    // ... B: newer healthy result persisted at t2 ...
    assert!(record_slo_evaluation(&pool, &slo, 1.0, 100, false, &healthy, t2).await.unwrap());
    // ... A resumes: superseded, no alert.
    assert!(admit_slo_alert(&pool, &slo, t1, 3600, &payload).await.unwrap().is_none());
    assert_eq!(alerts().await, 0, "a superseded breach must not raise");

    // A current breach raises once; a second admission is within re-arm.
    assert!(record_slo_evaluation(&pool, &slo, 0.9, 100, false, &breach, t3).await.unwrap());
    assert!(admit_slo_alert(&pool, &slo, t3, 3600, &payload).await.unwrap().is_some());
    assert!(admit_slo_alert(&pool, &slo, t3, 3600, &payload).await.unwrap().is_none());
    assert_eq!(alerts().await, 1);

    // A current but non-breaching result never raises (re-arm off).
    let t4 = now;
    assert!(record_slo_evaluation(&pool, &slo, 1.0, 100, false, &healthy, t4).await.unwrap());
    assert!(admit_slo_alert(&pool, &slo, t4, 0, &payload).await.unwrap().is_none());
    assert_eq!(alerts().await, 1);

    sqlx::query("DELETE FROM alerts WHERE kind = 'slo' AND source_id = $1")
        .bind(slo.id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    assert!(repo.delete(slo.id).await.unwrap());
}

/// Codex P1-2: B's EMPTY result at t2 lands first; A's older result at t1
/// with a breaching `node-a` (no cursor of its own yet) must be dropped
/// whole — no incident, no state row — and the console keeps B's no-data.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn newer_empty_result_fences_older_series_writes() {
    let pool = common::migrated_pool().await;
    let monitor = grouped_monitor(&pool, "lane-f fence").await;
    let t1 = Utc::now() - Duration::seconds(60);
    let t2 = t1 + Duration::seconds(30);

    assert!(apply_evaluation(&pool, &monitor, vec![], t2).await.unwrap().is_empty());
    let opened = apply_evaluation(&pool, &monitor, vec![("node-a".into(), Some(0.99))], t1)
        .await
        .unwrap();
    assert!(opened.is_empty(), "stale breach opened an incident");
    assert_eq!(monitor_alerts(&pool, monitor.id).await, 0);
    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT series_key FROM observability_metric_monitor_state WHERE monitor_id = $1",
    )
    .bind(monitor.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(keys, vec![String::new()], "the stale node-a cursor must not be written");
    let (summaries, _) = list_current_metric_monitor_state(&pool).await.unwrap();
    let mine = summaries.iter().find(|s| s.monitor_id == monitor.id).unwrap();
    assert_eq!((mine.series, mine.breaching, mine.no_data), (1, 0, 1));

    // A genuinely newer breach still opens.
    let t3 = t2 + Duration::seconds(30);
    let opened = apply_evaluation(&pool, &monitor, vec![("node-a".into(), Some(0.99))], t3)
        .await
        .unwrap();
    assert_eq!(opened.len(), 1);
    // An equal-generation replay is dropped (no second incident).
    assert!(apply_evaluation(&pool, &monitor, vec![("node-b".into(), Some(0.99))], t3)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(monitor_alerts(&pool, monitor.id).await, 1);

    sqlx::query("DELETE FROM alerts WHERE kind = 'metric_monitor' AND starts_with(source_id, $1)")
        .bind(format!("{}:", monitor.id))
        .execute(&pool)
        .await
        .unwrap();
    assert!(MetricMonitorRepository::new(pool.clone()).delete(monitor.id).await.unwrap());
}

/// Codex P2-4: a breach that sorts after 10 050 healthy series is still the
/// monitor's status. The summary covers every current series; the sample is
/// capped per monitor, breaching first, and flagged truncated.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn summary_reports_a_breach_past_ten_thousand_healthy_series() {
    let pool = common::migrated_pool().await;
    let monitor = grouped_monitor(&pool, "lane-f wide").await;
    let now = Utc::now() - Duration::seconds(10);
    let mut results: Vec<(String, Option<f64>)> =
        (0..10_050).map(|i| (format!("node-{i:05}"), Some(0.1))).collect();
    results.push(("zz-last".into(), Some(0.99)));
    let opened = apply_evaluation(&pool, &monitor, results, now).await.unwrap();
    assert_eq!(opened.len(), 1);

    let (summaries, sample) = list_current_metric_monitor_state(&pool).await.unwrap();
    let summary = summaries.iter().find(|s| s.monitor_id == monitor.id).unwrap();
    assert_eq!((summary.series, summary.breaching, summary.no_data), (10_051, 1, 0));
    assert!(summary.truncated);
    let mine: Vec<_> = sample.iter().filter(|r| r.monitor_id == monitor.id).collect();
    assert_eq!(mine.len() as i64, MONITOR_SERIES_SAMPLE);
    assert_eq!(mine[0].series_key, "zz-last", "breaching series sorts first");
    assert!(mine[0].breaching);

    sqlx::query("DELETE FROM alerts WHERE kind = 'metric_monitor' AND starts_with(source_id, $1)")
        .bind(format!("{}:", monitor.id))
        .execute(&pool)
        .await
        .unwrap();
    assert!(MetricMonitorRepository::new(pool.clone()).delete(monitor.id).await.unwrap());
}
