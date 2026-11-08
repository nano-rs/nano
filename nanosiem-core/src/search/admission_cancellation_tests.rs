// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4915: `AdmissionController::acquire` must be cancellation-safe. The
//! batch hand-off drops a queued `acquire` at its 45 s budget, and an SSE
//! client can disconnect while queued. Neither may leave an admission slot
//! counted with no permit to release it.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use uuid::Uuid;

fn controller(global: u32) -> Arc<AdmissionController> {
    let c = Arc::new(AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: global,
        per_user_limit: 100,
        max_queue_depth: 100,
        queue_timeout_ms: 60_000,
    }));
    c.start_drain_loop();
    c
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

async fn assert_baseline(c: &AdmissionController) {
    let stats = c.stats().await;
    assert_eq!(stats.active_adhoc, 0, "leaked global slot(s): {stats:?}");
    assert!(stats.per_user_counts.is_empty(), "leaked per-user slot(s): {stats:?}");
    assert_eq!(stats.queued, 0, "abandoned waiters still queued: {stats:?}");
}

#[tokio::test]
async fn timed_out_queued_waiters_never_leak_slots() {
    let c = controller(2);
    let holder = Uuid::now_v7();
    let p1 = c.acquire("hold-1", holder, QueryPriority::Interactive).await.unwrap();
    let p2 = c.acquire("hold-2", holder, QueryPriority::Interactive).await.unwrap();

    // Five hand-off-style waiters: each future is dropped by an outer timeout
    // while parked in the queue (exactly what the 45 s hand-off does).
    for i in 0..5 {
        let c = c.clone();
        let r = tokio::time::timeout(
            Duration::from_millis(50),
            c.acquire(&format!("waiter-{i}"), Uuid::now_v7(), QueryPriority::Interactive),
        )
        .await;
        assert!(r.is_err(), "waiter {i} should still have been queued");
    }
    assert_eq!(c.stats().await.queued, 0, "dropped waiters are removed from the queue");

    drop(p1);
    drop(p2);
    settle().await;
    assert_baseline(&c).await;

    // Full capacity is available again: both slots admit immediately.
    let a = c.acquire("after-1", holder, QueryPriority::Interactive).await.unwrap();
    let b = c.acquire("after-2", holder, QueryPriority::Interactive).await.unwrap();
    drop((a, b));
    settle().await;
    assert_baseline(&c).await;
}

#[tokio::test]
async fn waiters_with_closed_receivers_are_purged_not_admitted() {
    let c = controller(1);
    let holder = Uuid::now_v7();
    let permit = c.acquire("hold", holder, QueryPriority::Interactive).await.unwrap();

    let waiter = {
        let c = c.clone();
        tokio::spawn(async move {
            c.acquire("contended", Uuid::now_v7(), QueryPriority::Interactive).await
        })
    };
    // Wait until the waiter is parked in the queue.
    for _ in 0..50 {
        if lock_queue(&c.queue).len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Disarm-free variant of a contended drop: push a waiter whose receiver
    // is already closed (as if its guard never got to run) and cancel the
    // live one. Neither may be admitted.
    lock_queue(&c.queue).push(QueuedSearch {
        seq: 0,
        job_id: "closed".into(),
        subject: Uuid::now_v7(),
        priority: QueryPriority::Interactive,
        lane: AdmissionLane::Primary,
        class: QueryClass::Human,
        principal_tag: 0,
        tx: oneshot::channel().0,
    });
    waiter.abort();
    let _ = waiter.await;

    // Releasing the slot must not hand it to the dead waiter.
    drop(permit);
    settle().await;
    assert_baseline(&c).await;
}

#[tokio::test]
async fn admitted_waiter_gets_a_permit_and_the_permit_releases_both_counters() {
    let c = controller(1);
    let holder = Uuid::now_v7();
    let queued_user = Uuid::now_v7();
    let permit = c.acquire("hold", holder, QueryPriority::Interactive).await.unwrap();
    let waiter = {
        let c = c.clone();
        tokio::spawn(async move { c.acquire("queued", queued_user, QueryPriority::Interactive).await })
    };
    settle().await;
    drop(permit);
    let admitted = waiter.await.unwrap().expect("queued waiter admitted");
    let stats = c.stats().await;
    assert_eq!(stats.active_adhoc, 1);
    assert_eq!(
        stats.per_user_counts,
        vec![(queued_user.to_string(), 1)],
        "drain counts the per-user slot the permit's Drop will release"
    );
    drop(admitted);
    settle().await;
    assert_baseline(&c).await;
}

/// Same guarantee for the cluster-wide Redis counters. Needs a throwaway Redis
/// at `REDIS_URL` (it SETs/DELs the admission keys).
#[tokio::test]
#[ignore = "requires a throwaway Redis at REDIS_URL; run with --ignored"]
async fn redis_counters_return_to_baseline_after_cancelled_waiters() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL");
    let client = redis::Client::open(url).unwrap();
    let mut conn = redis::aio::ConnectionManager::new(client).await.unwrap();
    let _: () = redis::cmd("DEL").arg(REDIS_GLOBAL_KEY).query_async(&mut conn).await.unwrap();

    let c = controller(1);
    c.set_redis(conn.clone()).await;
    let holder = Uuid::now_v7();
    let permit = c.acquire("hold", holder, QueryPriority::Interactive).await.unwrap();

    let mut waiter_users = Vec::new();
    for i in 0..4 {
        let user = Uuid::now_v7();
        waiter_users.push(user);
        let r = tokio::time::timeout(
            Duration::from_millis(80),
            c.acquire(&format!("w-{i}"), user, QueryPriority::Interactive),
        )
        .await;
        assert!(r.is_err());
    }
    // One waiter is admitted and then released normally, exercising the
    // drain → permit → Drop path end to end against Redis.
    let queued_user = Uuid::now_v7();
    let waiter = {
        let c = c.clone();
        tokio::spawn(async move { c.acquire("live", queued_user, QueryPriority::Interactive).await })
    };
    settle().await;
    drop(permit);
    let admitted = waiter.await.unwrap().expect("live waiter admitted");
    drop(admitted);
    tokio::time::sleep(Duration::from_millis(300)).await; // Drop's release is spawned

    let global: i64 = redis::cmd("ZCARD").arg(REDIS_GLOBAL_KEY).query_async(&mut conn).await.unwrap();
    assert_eq!(global, 0, "Redis global admission lease leaked");
    for user in waiter_users.iter().chain([&holder, &queued_user]) {
        let v: i64 = redis::cmd("ZCARD").arg(redis_user_key(*user)).query_async(&mut conn).await.unwrap();
        assert_eq!(v, 0, "Redis per-user lease leaked for {user}");
    }
    assert_baseline(&c).await;
}
