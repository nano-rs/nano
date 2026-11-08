// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3975 metric-monitor incident lifecycle against the REAL migrated
//! `alerts` table (single-tenant: `tenant = None`). Everything runs inside one
//! transaction that is rolled back, so no rows survive the test.
//!
//! Gated like the other DB suites: `#[ignore]`d — run with a disposable
//! Postgres, `DATABASE_URL=… NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 cargo test
//! -p nanosiem-core --test metric_alert_lifecycle_integration -- --ignored`.
mod common;

use chrono::{DateTime, Duration, Utc};
use nanosiem_core::observability::{
    eval::metric_monitor_source_id,
    metric_alert_lifecycle::{observe, reconcile, retire_unlabelled},
};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

fn payload(at: DateTime<Utc>, value: f64) -> serde_json::Value {
    json!([{ "evaluated_at": at.to_rfc3339(), "value": value }])
}

async fn open_ids(tx: &mut Transaction<'_, Postgres>, monitor: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM alerts WHERE kind='metric_monitor' AND status <> 'closed' \
         AND starts_with(source_id, $1) ORDER BY created_at, id",
    )
    .bind(format!("{monitor}:"))
    .fetch_all(&mut **tx)
    .await
    .unwrap()
}

async fn count_for(tx: &mut Transaction<'_, Postgres>, monitor: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM alerts WHERE kind='metric_monitor' AND starts_with(source_id, $1)",
    )
    .bind(format!("{monitor}:"))
    .fetch_one(&mut **tx)
    .await
    .unwrap()
}

/// A breach that persists across many evaluations (hours) stays ONE incident,
/// keeps its original start and acknowledged status, and only the opening
/// returns an id (= one notification).
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn persistent_breach_stays_one_incident_across_evaluations() {
    let pool = common::migrated_pool().await;
    let mut tx = pool.begin().await.unwrap();
    let monitor = Uuid::new_v4();
    let source = metric_monitor_source_id(monitor, "node-a");
    let start = Utc::now() - Duration::hours(8);

    reconcile(&mut tx, None, monitor).await.unwrap();
    let id = observe(&mut tx, None, &source, true, &payload(start, 9.0), start)
        .await
        .unwrap()
        .expect("first breach opens an incident");
    sqlx::query("UPDATE alerts SET status='acknowledged' WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();

    // One evaluation per minute for 7 hours: the old 1h re-arm opened 7 more.
    let mut notifications = 0;
    for minute in 1..=420 {
        let at = start + Duration::minutes(minute);
        reconcile(&mut tx, None, monitor).await.unwrap();
        if observe(&mut tx, None, &source, true, &payload(at, 6.0), at)
            .await
            .unwrap()
            .is_some()
        {
            notifications += 1;
        }
    }
    assert_eq!(notifications, 0, "updates must not re-notify");
    assert_eq!(count_for(&mut tx, monitor).await, 1);
    let row: (String, DateTime<Utc>, serde_json::Value) =
        sqlx::query_as("SELECT status, created_at, matched_events FROM alerts WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(row.0, "acknowledged");
    assert_eq!(row.1.timestamp_micros(), start.timestamp_micros());
    assert_eq!(row.2[0]["value"], 6.0);
    tx.rollback().await.unwrap();
}

/// A healthy sample closes the incident; no-data does not; a later breach
/// opens a NEW incident; a slow older evaluation can neither overwrite, close
/// nor reopen.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn healthy_sample_recovers_and_stale_evaluations_are_fenced() {
    let pool = common::migrated_pool().await;
    let mut tx = pool.begin().await.unwrap();
    let monitor = Uuid::new_v4();
    let source = metric_monitor_source_id(monitor, "");
    let t0 = Utc::now() - Duration::hours(2);
    let id = observe(&mut tx, None, &source, true, &payload(t0, 95.0), t0)
        .await
        .unwrap()
        .unwrap();

    // No-data is never passed to observe (the scheduler skips None), so the
    // incident simply stays open across a gap.
    assert_eq!(open_ids(&mut tx, monitor).await, vec![id]);

    // A slower OLD leader's healthy sample cannot resolve a newer observation.
    let t1 = t0 + Duration::minutes(10);
    observe(&mut tx, None, &source, true, &payload(t1, 96.0), t1)
        .await
        .unwrap();
    observe(&mut tx, None, &source, false, &payload(t0, 10.0), t0)
        .await
        .unwrap();
    assert_eq!(open_ids(&mut tx, monitor).await, vec![id]);

    // Condition clears → closed with closed_at = evaluation time.
    let t2 = t1 + Duration::minutes(1);
    assert_eq!(
        observe(&mut tx, None, &source, false, &payload(t2, 10.0), t2)
            .await
            .unwrap(),
        None
    );
    let (status, closed_at): (String, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT status, closed_at FROM alerts WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(status, "closed");
    assert_eq!(closed_at.unwrap().timestamp_micros(), t2.timestamp_micros());

    // An older breach evaluated after recovery must not reopen.
    assert_eq!(
        observe(&mut tx, None, &source, true, &payload(t1, 96.0), t1)
            .await
            .unwrap(),
        None
    );
    assert!(open_ids(&mut tx, monitor).await.is_empty());

    // A genuinely new breach opens a fresh incident.
    let t3 = t2 + Duration::minutes(1);
    let reopened = observe(&mut tx, None, &source, true, &payload(t3, 97.0), t3)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(reopened, id);
    assert_eq!(open_ids(&mut tx, monitor).await, vec![reopened]);
    tx.rollback().await.unwrap();
}

/// Legacy hourly duplicates (from the old re-arm) collapse to the earliest
/// incident carrying the latest payload; history is closed, not deleted. The
/// unlabelled fleet incident retires once labelled series arrive. Another
/// monitor's incidents are untouched.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn reconcile_collapses_legacy_duplicates_and_retires_unlabelled() {
    let pool = common::migrated_pool().await;
    let mut tx = pool.begin().await.unwrap();
    let monitor = Uuid::new_v4();
    let other_monitor = Uuid::new_v4();
    let source = metric_monitor_source_id(monitor, "node-a");
    let base = Utc::now() - Duration::hours(5);
    let mut legacy = Vec::new();
    for hour in 0..4 {
        let at = base + Duration::hours(hour);
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO alerts (id, kind, source_id, severity, status, created_at, matched_events) \
             VALUES ($1, 'metric_monitor', $2, 'high', 'new', $3, $4)",
        )
        .bind(id)
        .bind(&source)
        .bind(at)
        .bind(payload(at, 10.0 - hour as f64))
        .execute(&mut *tx)
        .await
        .unwrap();
        legacy.push(id);
    }
    let other = observe(
        &mut tx,
        None,
        &metric_monitor_source_id(other_monitor, "node-a"),
        true,
        &payload(base, 1.0),
        base,
    )
    .await
    .unwrap()
    .unwrap();

    reconcile(&mut tx, None, monitor).await.unwrap();
    reconcile(&mut tx, None, monitor).await.unwrap(); // idempotent
    assert_eq!(open_ids(&mut tx, monitor).await, vec![legacy[0]]);
    assert_eq!(count_for(&mut tx, monitor).await, 4, "history is kept");
    let latest: serde_json::Value =
        sqlx::query_scalar("SELECT matched_events FROM alerts WHERE id=$1")
            .bind(legacy[0])
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(latest[0]["value"], 7.0);
    assert_eq!(open_ids(&mut tx, other_monitor).await, vec![other]);

    // A breach observed after reconcile updates the keeper, never a 5th row.
    let now = base + Duration::hours(5);
    assert_eq!(
        observe(&mut tx, None, &source, true, &payload(now, 5.0), now)
            .await
            .unwrap(),
        None
    );
    assert_eq!(count_for(&mut tx, monitor).await, 4);

    let empty = metric_monitor_source_id(monitor, "");
    let fleet = observe(&mut tx, None, &empty, true, &payload(now, 1.0), now)
        .await
        .unwrap()
        .unwrap();
    retire_unlabelled(&mut tx, None, monitor, now + Duration::seconds(1))
        .await
        .unwrap();
    let (status, reason): (String, Option<String>) = sqlx::query_as(
        "SELECT status, matched_events->0->>'resolution_reason' FROM alerts WHERE id=$1",
    )
    .bind(fleet)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(status, "closed");
    assert_eq!(reason.as_deref(), Some("replaced_by_labelled_series"));
    assert_eq!(open_ids(&mut tx, monitor).await, vec![legacy[0]]);
    tx.rollback().await.unwrap();
}

async fn insert_monitor(pool: &sqlx::PgPool, comparator: &str, threshold: f64) -> nanosiem_core::observability::MetricMonitor {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO observability_metric_monitors \
         (id, name, metric_name, agg, comparator, threshold, window_secs, eval_interval_secs) \
         VALUES ($1, 'lane-a cursor', 'requests_total', 'rate', $2, $3, 300, 60)",
    )
    .bind(id)
    .bind(comparator)
    .bind(threshold)
    .execute(pool)
    .await
    .unwrap();
    let now = Utc::now();
    nanosiem_core::observability::MetricMonitor {
        id,
        name: "lane-a cursor".into(),
        metric_name: "requests_total".into(),
        agg: "rate".into(),
        service_name: None,
        group_by: None,
        filters: vec![],
        comparator: nanosiem_core::observability::MonitorComparator::from_str(comparator).unwrap(),
        threshold,
        window_secs: 300,
        eval_interval_secs: 60,
        enabled: true,
        created_by: None,
        created_at: now,
        updated_at: now,
    }
}

async fn cleanup_monitor(pool: &sqlx::PgPool, monitor: Uuid) {
    sqlx::query("DELETE FROM alerts WHERE kind='metric_monitor' AND starts_with(source_id, $1)")
        .bind(format!("{monitor}:"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM observability_metric_monitors WHERE id = $1")
        .bind(monitor)
        .execute(pool)
        .await
        .unwrap();
}

async fn open_count(pool: &sqlx::PgPool, monitor: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM alerts WHERE kind='metric_monitor' AND status <> 'closed' \
         AND starts_with(source_id, $1)",
    )
    .bind(format!("{monitor}:"))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Codex P2: the evaluator applies results AFTER the ClickHouse query, with
/// no transaction held across it. The durable per-series cursor is what keeps
/// ordering: a healthy result that touched no incident still advances it, so
/// an OLDER breaching result arriving later (a slow evaluator across a jobs
/// leader failover) cannot open an incident.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn older_result_cannot_reopen_after_a_newer_recovery() {
    use nanosiem_core::observability::metric_alert_lifecycle::apply_evaluation;
    let pool = common::migrated_pool().await;
    let monitor = insert_monitor(&pool, "gt", 10.0).await;
    let t0 = Utc::now() - Duration::minutes(10);

    // Newer evaluation (t0+2m) is healthy and lands first: no incident, but
    // the cursor records it.
    let opened = apply_evaluation(&pool, &monitor, vec![("".into(), Some(1.0))], t0 + Duration::minutes(2))
        .await
        .unwrap();
    assert!(opened.is_empty());
    // The slower, older evaluation (t0+1m) saw a breach. It must not open.
    let opened = apply_evaluation(&pool, &monitor, vec![("".into(), Some(50.0))], t0 + Duration::minutes(1))
        .await
        .unwrap();
    assert!(opened.is_empty(), "stale breach opened an incident");
    assert_eq!(open_count(&pool, monitor.id).await, 0);

    // A genuinely newer breach opens exactly one incident and notifies once.
    let opened = apply_evaluation(&pool, &monitor, vec![("".into(), Some(50.0))], t0 + Duration::minutes(3))
        .await
        .unwrap();
    assert_eq!(opened.len(), 1);
    let again = apply_evaluation(&pool, &monitor, vec![("".into(), Some(60.0))], t0 + Duration::minutes(4))
        .await
        .unwrap();
    assert!(again.is_empty(), "an update must not re-notify");
    assert_eq!(open_count(&pool, monitor.id).await, 1);

    // No-data advances the cursor but neither resolves nor opens.
    apply_evaluation(&pool, &monitor, vec![("".into(), None)], t0 + Duration::minutes(5))
        .await
        .unwrap();
    assert_eq!(open_count(&pool, monitor.id).await, 1);
    let (no_data, evaluated_at): (bool, chrono::DateTime<Utc>) = sqlx::query_as(
        "SELECT no_data, evaluated_at FROM observability_metric_monitor_state WHERE monitor_id = $1",
    )
    .bind(monitor.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(no_data);
    assert_eq!(evaluated_at.timestamp_micros(), (t0 + Duration::minutes(5)).timestamp_micros());

    // A stale healthy result (older than the no-data cursor) cannot resolve.
    apply_evaluation(&pool, &monitor, vec![("".into(), Some(1.0))], t0 + Duration::minutes(4))
        .await
        .unwrap();
    assert_eq!(open_count(&pool, monitor.id).await, 1);
    // A newer healthy result recovers it.
    apply_evaluation(&pool, &monitor, vec![("".into(), Some(1.0))], t0 + Duration::minutes(6))
        .await
        .unwrap();
    assert_eq!(open_count(&pool, monitor.id).await, 0);

    cleanup_monitor(&pool, monitor.id).await;
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM observability_metric_monitor_state WHERE monitor_id = $1",
    )
    .bind(monitor.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0, "state cascades with the monitor definition");
}

/// Keeper choice is by workflow state, then earliest.
#[test]
fn keeper_prefers_case_linked_then_worked_then_earliest() {
    use nanosiem_core::observability::metric_alert_lifecycle::{choose_keeper, IncidentWorkflow};
    let t = Utc::now();
    let row = |minute: i64, ack: bool, assigned: bool, case: bool| IncidentWorkflow {
        id: Uuid::new_v4(),
        created_at: t + Duration::minutes(minute),
        acknowledged: ack,
        assigned,
        case_linked: case,
    };
    assert_eq!(choose_keeper(&[row(0, false, false, false), row(1, false, false, false)]), Some(0));
    assert_eq!(choose_keeper(&[row(0, false, false, false), row(1, true, false, false)]), Some(1));
    assert_eq!(choose_keeper(&[row(0, false, false, false), row(1, false, true, false), row(2, true, false, false)]), Some(1));
    assert_eq!(choose_keeper(&[row(0, true, true, false), row(1, false, false, true)]), Some(1));
    assert_eq!(choose_keeper(&[]), None);
}
