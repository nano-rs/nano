// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5785 review (round 3): a bulk delete's security-critical audit rows
//! are recorded in ONE batched outbox insert, not one serial durable write
//! per event. Against migrated PostgreSQL:
//!
//! * a 1,000-event batch (a max-size bulk delete: one delete row and one
//!   flagged-alert row per source) lands in one call, due for the drainer,
//!   and a re-run is idempotent;
//! * with the outbox stalled (a lock held on the table), a bounded call times
//!   out and records NOTHING (the insert is one atomic statement, so a
//!   cancelled or timed-out batch never leaves half of itself), and the same
//!   batch records in full once the stall clears.
//!
//! Ignored in ordinary unit runs; the pg-integration-tests lane runs it with
//! `--ignored --test-threads=1`. Rows are removed by event id afterwards.

mod common;

use std::time::{Duration, Instant};

use nanosiem_core::audit::{AuditEvent, AuditSource, SecurityAuditOutbox, LOG_SOURCE_DELETED, SYSTEM_HEALTH_SOURCE_REMOVED};
use sqlx::PgPool;
use uuid::Uuid;

fn batch(n: usize, marker: &str) -> Vec<AuditEvent> {
    let actor = Uuid::now_v7();
    (0..n)
        .map(|i| {
            let action = if i % 2 == 0 { LOG_SOURCE_DELETED } else { SYSTEM_HEALTH_SOURCE_REMOVED };
            AuditEvent::builder(AuditSource::LogSource, action)
                .actor(Some(actor), Some("NAN-5785 deleter".to_string()))
                .resource("log_source", Some(Uuid::now_v7()), Some(format!("{marker}-{i}")))
                .build()
        })
        .collect()
}

async fn recorded(pool: &PgPool, events: &[AuditEvent]) -> (i64, i64) {
    let ids: Vec<Uuid> = events.iter().map(|e| e.event_id).collect();
    sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE next_attempt_at <= NOW())
         FROM security_audit_events WHERE event_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_one(pool)
    .await
    .expect("count outbox rows")
}

async fn remove(pool: &PgPool, events: &[AuditEvent]) {
    let ids: Vec<Uuid> = events.iter().map(|e| e.event_id).collect();
    sqlx::query("DELETE FROM security_audit_events WHERE event_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await
        .expect("clean outbox rows");
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn a_bulk_delete_audit_batch_is_one_idempotent_insert() {
    let pool = common::migrated_pool().await;
    let outbox = SecurityAuditOutbox::new(pool.clone());
    let events = batch(1_000, &format!("nan5785-batch-{}", Uuid::now_v7().simple()));

    let started = Instant::now();
    outbox.enqueue_batch(&events).await.expect("batch insert");
    let took = started.elapsed();
    let first = recorded(&pool, &events).await;
    outbox.enqueue_batch(&events).await.expect("re-run");
    let again = recorded(&pool, &events).await;
    let stored_action: String =
        sqlx::query_scalar("SELECT event->>'action' FROM security_audit_events WHERE event_id = $1")
            .bind(events[1].event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    remove(&pool, &events).await;

    assert_eq!(first, (1_000, 1_000), "every row recorded and due for the drainer");
    assert_eq!(again, (1_000, 1_000), "idempotent on event_id");
    assert_eq!(stored_action, SYSTEM_HEALTH_SOURCE_REMOVED, "the stored event is the full event");
    assert!(took < Duration::from_secs(5), "one statement, not 1,000 round trips: {took:?}");
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn a_stalled_outbox_times_out_the_batch_without_a_partial_write() {
    let pool = common::migrated_pool().await;
    let outbox = SecurityAuditOutbox::new(pool.clone());
    let events = batch(200, &format!("nan5785-stall-{}", Uuid::now_v7().simple()));

    // Stall the outbox: a lock that blocks every INSERT until released.
    let mut stall = pool.begin().await.expect("begin stall");
    sqlx::query("LOCK TABLE security_audit_events IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *stall)
        .await
        .expect("lock outbox");
    let started = Instant::now();
    let stalled = tokio::time::timeout(Duration::from_millis(750), outbox.enqueue_batch(&events)).await;
    let waited = started.elapsed();
    stall.rollback().await.expect("release stall");
    let during = recorded(&pool, &events).await;

    outbox.enqueue_batch(&events).await.expect("batch after the stall clears");
    let after = recorded(&pool, &events).await;
    remove(&pool, &events).await;

    assert!(stalled.is_err(), "the bounded call gives up instead of hanging");
    assert!(waited < Duration::from_secs(2), "bounded by its timeout: {waited:?}");
    assert_eq!(during.0, 0, "a timed-out batch records nothing (atomic, cancellation-safe)");
    assert_eq!(after, (200, 200), "the whole batch records once the outbox recovers");
}
