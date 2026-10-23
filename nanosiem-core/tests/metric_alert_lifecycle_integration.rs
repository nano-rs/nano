// SPDX-License-Identifier: AGPL-3.0-or-later
//! Run on the train's disposable PostgreSQL, never production.
mod common;
use chrono::{Duration, Utc};
use nanosiem_core::observability::{eval::metric_monitor_source_id, metric_alert_lifecycle::*};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1"]
async fn incident_updates_recovers_reopens_and_repairs_duplicates_with_tenant_fences() {
    let pool = common::migrated_pool().await;
    let mut tx = pool.begin().await.unwrap();
    // A transaction-local fixture cannot affect real alerts, and exercises the
    // same SQL with both dedicated (no tenant predicate) and hosted scopes.
    sqlx::query("CREATE TEMP TABLE alerts (id uuid PRIMARY KEY, tenant_id uuid, kind text, rule_id uuid, source_id text, severity text, status text DEFAULT 'new', matched_events jsonb, created_at timestamptz, closed_at timestamptz) ON COMMIT DROP")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("CREATE TEMP TABLE observability_metric_monitors (tenant_id uuid, name text, metric_name text, agg text, threshold double precision, comparator text, group_by text, filters jsonb, updated_at timestamptz) ON COMMIT DROP")
        .execute(&mut *tx).await.unwrap();
    let tenant = Uuid::new_v4();
    let foreign = Uuid::new_v4();
    for owner in [tenant, foreign] {
        sqlx::query("INSERT INTO observability_metric_monitors VALUES ($1,'Node disk low (<10 GiB free on /)','node_filesystem_avail_bytes','min',10737418240,'lt','instance','[]',now())")
            .bind(owner).execute(&mut *tx).await.unwrap();
    }
    repair_default_grouping(&mut tx, Some(tenant))
        .await
        .unwrap();
    repair_default_grouping(&mut tx, Some(tenant))
        .await
        .unwrap();
    let definition: (String, f64, serde_json::Value) = sqlx::query_as("SELECT metric_name,threshold,filters FROM observability_metric_monitors WHERE tenant_id=$1")
        .bind(tenant).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(definition.0, "node_filesystem_avail_ratio");
    assert_eq!(definition.1, 0.1);
    assert_eq!(definition.2, json!([{"key":"mountpoint","value":"/"}]));
    let foreign_metric: String = sqlx::query_scalar(
        "SELECT metric_name FROM observability_metric_monitors WHERE tenant_id=$1",
    )
    .bind(foreign)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(foreign_metric, "node_filesystem_avail_bytes");
    let monitor = Uuid::new_v4();
    let source = metric_monitor_source_id(monitor, "node-a");
    let start = Utc::now() - Duration::hours(8);
    let payload = |at: chrono::DateTime<Utc>, value: f64| json!([{"evaluated_at":at.to_rfc3339(),"value":value}]);
    reconcile(&mut tx, Some(tenant), monitor).await.unwrap();
    let id = observe(
        &mut tx,
        Some(tenant),
        &source,
        true,
        &payload(start, 9.0),
        start,
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query("UPDATE alerts SET status='acknowledged' WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let now = start + Duration::hours(7);
    assert_eq!(
        observe(
            &mut tx,
            Some(tenant),
            &source,
            true,
            &payload(now, 6.0),
            now
        )
        .await
        .unwrap(),
        None
    );
    let row: (String, chrono::DateTime<Utc>, serde_json::Value) =
        sqlx::query_as("SELECT status,created_at,matched_events FROM alerts WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(row.0, "acknowledged");
    assert_eq!(row.1.timestamp_micros(), start.timestamp_micros());
    assert_eq!(row.2[0]["value"], 6.0);
    // A slower old leader cannot overwrite the latest value or resolve it.
    observe(
        &mut tx,
        Some(tenant),
        &source,
        false,
        &payload(start, 20.0),
        start,
    )
    .await
    .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM alerts WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(status, "acknowledged");
    observe(
        &mut tx,
        Some(tenant),
        &source,
        false,
        &payload(now + Duration::seconds(1), 20.0),
        now + Duration::seconds(1),
    )
    .await
    .unwrap();
    assert_eq!(
        observe(
            &mut tx,
            Some(tenant),
            &source,
            true,
            &payload(now, 6.0),
            now
        )
        .await
        .unwrap(),
        None
    );
    let reopened = observe(
        &mut tx,
        Some(tenant),
        &source,
        true,
        &payload(now + Duration::seconds(2), 5.0),
        now + Duration::seconds(2),
    )
    .await
    .unwrap()
    .unwrap();
    assert_ne!(id, reopened);

    // Legacy hourly duplicates: retain earliest start, latest value, and do not
    // consolidate another tenant's coincident source id.
    let other = observe(
        &mut tx,
        Some(foreign),
        &source,
        true,
        &payload(now, 4.0),
        now,
    )
    .await
    .unwrap()
    .unwrap();
    let duplicate = Uuid::new_v4();
    sqlx::query("INSERT INTO alerts (id,tenant_id,kind,source_id,status,created_at,matched_events) VALUES ($1,$2,'metric_monitor',$3,'new',$4,$5)")
        .bind(duplicate).bind(tenant).bind(&source).bind(now + Duration::seconds(3)).bind(payload(now + Duration::seconds(3), 3.0)).execute(&mut *tx).await.unwrap();
    reconcile(&mut tx, Some(tenant), monitor).await.unwrap();
    reconcile(&mut tx, Some(tenant), monitor).await.unwrap(); // idempotent
    let open: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM alerts WHERE tenant_id=$1 AND status!='closed'")
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    assert_eq!(open, vec![reopened]);
    let value: serde_json::Value =
        sqlx::query_scalar("SELECT matched_events FROM alerts WHERE id=$1")
            .bind(reopened)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(value[0]["value"], 3.0);
    let status: String = sqlx::query_scalar("SELECT status FROM alerts WHERE id=$1")
        .bind(other)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(status, "new");
    let empty = metric_monitor_source_id(monitor, "");
    let legacy = observe(&mut tx, Some(tenant), &empty, true, &payload(now, 1.0), now)
        .await
        .unwrap()
        .unwrap();
    retire_unlabelled(&mut tx, Some(tenant), monitor, now + Duration::seconds(4))
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM alerts WHERE id=$1")
        .bind(legacy)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(status, "closed");
    // Dedicated installations have no tenant column requirement in the SQL.
    let dedicated = metric_monitor_source_id(Uuid::new_v4(), "node-b");
    assert!(
        observe(&mut tx, None, &dedicated, true, &payload(now, 2.0), now)
            .await
            .unwrap()
            .is_some()
    );
    tx.rollback().await.unwrap();
}
