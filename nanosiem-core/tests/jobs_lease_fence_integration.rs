// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933: the jobs lease epoch fence on a live Postgres.
//!
//! Two production `LeaderElection`s on one lock: exactly one leads; every
//! acquisition bumps `leader_lease_epochs`; a takeover's bump waits for the
//! old leader's in-flight guarded transaction (so a guarded write either
//! commits before the successor starts or is refused); a stale epoch is
//! refused afterwards. `#[ignore]`d: pg-integration lane only.
mod common;

use nanosiem_core::leader::{FenceError, LeaderElection, LeaderFence, LeaderHooks, LeaderTiming};
use nanosiem_core::shutdown::ShutdownToken;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Default)]
struct Flag {
    leading: Arc<AtomicBool>,
    epoch: Arc<AtomicI64>,
}

impl LeaderHooks for Flag {
    async fn elected(&mut self, epoch: i64) {
        self.epoch.store(epoch, Ordering::SeqCst);
        self.leading.store(true, Ordering::SeqCst);
    }
    async fn stepped_down(&mut self) {
        self.leading.store(false, Ordering::SeqCst);
    }
}

const FAST: LeaderTiming = LeaderTiming {
    heartbeat: Duration::from_secs(1),
    database_timeout: Duration::from_secs(1),
    retry: Duration::from_secs(1),
    stale_after: Some(Duration::from_secs(4)),
};

async fn wait_for(limit: Duration, what: &str, done: impl Fn() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn takeover_bumps_the_epoch_after_in_flight_guarded_writes_and_refuses_stale_ones() {
    let pool = common::migrated_pool().await;
    let lock_id: i64 = 0x4e53_0000_0000 | i64::from(rand_suffix());

    let start = |name: &str| {
        let fence = LeaderFence::armed(lock_id);
        let flag = Flag::default();
        let shutdown = ShutdownToken::new();
        let handle = LeaderElection::new(pool.clone(), lock_id)
            .with_timing(FAST)
            .with_fence(fence.clone(), name)
            .spawn_with(shutdown.clone(), flag.clone());
        (fence, flag, shutdown, handle)
    };

    let (fence_a, flag_a, stop_a, handle_a) = start("node-a");
    wait_for(Duration::from_secs(10), "A to lead", || flag_a.leading.load(Ordering::SeqCst)).await;
    let (fence_b, flag_b, stop_b, handle_b) = start("node-b");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!flag_b.leading.load(Ordering::SeqCst), "exactly one leader");
    let epoch_a = flag_a.epoch.load(Ordering::SeqCst);
    assert_eq!(fence_a.epoch(), Some(epoch_a));
    assert_eq!(fence_b.epoch(), None);

    // A starts a guarded leader-only write and is then stopped mid-transaction.
    let stale = LeaderFence::pinned(lock_id, epoch_a);
    let mut in_flight = pool.begin().await.unwrap();
    stale.guard(&mut in_flight).await.expect("current epoch passes");
    stop_a.cancel();
    handle_a.await.unwrap();
    assert_eq!(fence_a.epoch(), None, "a stepped-down leader's fence closes");

    // B has the lock but its epoch bump waits on A's in-flight transaction.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!flag_b.leading.load(Ordering::SeqCst), "successor must not start before the old write settles");
    in_flight.commit().await.unwrap();
    wait_for(Duration::from_secs(10), "B to lead", || flag_b.leading.load(Ordering::SeqCst)).await;
    let epoch_b = flag_b.epoch.load(Ordering::SeqCst);
    assert_eq!(epoch_b, epoch_a + 1);

    // The resumed old leader is refused; the new one passes.
    let mut late = pool.begin().await.unwrap();
    assert!(matches!(
        stale.guard(&mut late).await,
        Err(FenceError::Superseded { held, current: Some(current) }) if held == epoch_a && current == epoch_b
    ));
    late.rollback().await.ok();
    assert!(!stale.still_leader(&pool).await);
    assert!(fence_b.still_leader(&pool).await);
    let mut ok = pool.begin().await.unwrap();
    fence_b.guard(&mut ok).await.unwrap();
    ok.commit().await.unwrap();
    // A closed fence (never elected / stepped down) refuses outright.
    let mut closed = pool.begin().await.unwrap();
    assert!(matches!(fence_a.guard(&mut closed).await, Err(FenceError::NotLeader)));
    closed.rollback().await.ok();

    let history: Vec<(i64, String)> = sqlx::query_as(
        "SELECT epoch, holder FROM leader_lease_history WHERE lock_id = $1 ORDER BY epoch",
    )
    .bind(lock_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(history, vec![(epoch_a, "node-a".into()), (epoch_b, "node-b".into())]);

    stop_b.cancel();
    handle_b.await.unwrap();
    for table in ["leader_lease_history", "leader_lease_epochs"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE lock_id = $1"))
            .bind(lock_id)
            .execute(&pool)
            .await
            .ok();
    }
}

fn rand_suffix() -> u32 {
    uuid::Uuid::new_v4().as_u128() as u32 & 0x7fff_ffff
}

// ---- NAN-4933 codex review: guarded side effects (disk pressure, synthetics).

use nanosiem_core::settings::{fifo_drop_loop, DiskPressureError, DropLoopOutcome, PartitionDropper, PartitionSnapshot};
use std::sync::Mutex;

async fn seed_epoch(pool: &sqlx::PgPool) -> i64 {
    let lock_id: i64 = 0x4e53_0000_0000 | i64::from(rand_suffix());
    sqlx::query("INSERT INTO leader_lease_epochs (lock_id, epoch, holder) VALUES ($1, 1, 'test-leader')")
        .bind(lock_id)
        .execute(pool)
        .await
        .unwrap();
    lock_id
}

async fn bump_epoch(pool: &sqlx::PgPool, lock_id: i64) {
    sqlx::query("UPDATE leader_lease_epochs SET epoch = epoch + 1, holder = 'successor' WHERE lock_id = $1")
        .bind(lock_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Fake ClickHouse partitions: usage stays high; optionally simulates a
/// takeover (epoch bump by the successor) right after the first drop, i.e.
/// the leader was paused mid-loop and superseded before its next iteration.
struct FakePartitions {
    pool: sqlx::PgPool,
    lock_id: i64,
    usage_after: Mutex<Vec<f64>>,
    dropped: Mutex<Vec<String>>,
    supersede_after_first: bool,
    drop_delay: Duration,
}

#[async_trait::async_trait]
impl PartitionDropper for FakePartitions {
    async fn partition_snapshot(&self, _today: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        Ok(PartitionSnapshot {
            oldest_before_today: Some(format!("202610{:02}", self.dropped.lock().unwrap().len() + 1)),
            newest: Some("20261104".to_string()),
        })
    }
    async fn usage(&self) -> Result<f64, DiskPressureError> {
        let n = self.dropped.lock().unwrap().len();
        Ok(self.usage_after.lock().unwrap().get(n).copied().unwrap_or(0.95))
    }
    async fn drop_partition(&self, date: &str) -> Result<Vec<String>, DiskPressureError> {
        tokio::time::sleep(self.drop_delay).await;
        self.dropped.lock().unwrap().push(date.to_owned());
        Ok(vec!["ocsf_logs".to_owned()])
    }
    async fn dropped(&self, _date: &str, _tables: &[String]) {
        if self.supersede_after_first && self.dropped.lock().unwrap().len() == 1 {
            bump_epoch(&self.pool, self.lock_id).await;
        }
    }
}

fn fake(pool: &sqlx::PgPool, lock_id: i64, supersede: bool, delay: Duration, usage: Vec<f64>) -> FakePartitions {
    FakePartitions {
        pool: pool.clone(),
        lock_id,
        usage_after: Mutex::new(usage),
        dropped: Mutex::new(Vec::new()),
        supersede_after_first: supersede,
        drop_delay: delay,
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn a_superseded_leader_resuming_mid_drop_loop_drops_nothing_more() {
    let pool = common::migrated_pool().await;
    let lock_id = seed_epoch(&pool).await;
    let fence = LeaderFence::pinned(lock_id, 1);
    let parts = fake(&pool, lock_id, true, Duration::ZERO, vec![]);
    let outcome = fifo_drop_loop(&parts, &fence, &pool, 0.70, 5, Duration::ZERO, "20261104").await;
    assert_eq!(outcome, DropLoopOutcome::Superseded);
    assert_eq!(parts.dropped.lock().unwrap().len(), 1, "no extra partition after the takeover");
    sqlx::query("DELETE FROM leader_lease_epochs WHERE lock_id = $1").bind(lock_id).execute(&pool).await.ok();
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn the_drop_loop_rechecks_pressure_before_every_drop() {
    let pool = common::migrated_pool().await;
    let lock_id = seed_epoch(&pool).await;
    let fence = LeaderFence::pinned(lock_id, 1);
    // High before the first drop, relieved before the second.
    let parts = fake(&pool, lock_id, false, Duration::ZERO, vec![0.92, 0.65]);
    let outcome = fifo_drop_loop(&parts, &fence, &pool, 0.70, 5, Duration::ZERO, "20261104").await;
    assert_eq!(outcome, DropLoopOutcome::Relieved);
    assert_eq!(parts.dropped.lock().unwrap().len(), 1);
    sqlx::query("DELETE FROM leader_lease_epochs WHERE lock_id = $1").bind(lock_id).execute(&pool).await.ok();
}

/// The guard is held across the destructive call: a successor's epoch bump
/// waits until the in-flight drop (or synthetic publication) finishes.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn a_takeover_waits_for_an_in_flight_guarded_side_effect() {
    let pool = common::migrated_pool().await;
    let lock_id = seed_epoch(&pool).await;
    let fence = LeaderFence::pinned(lock_id, 1);
    let parts = fake(&pool, lock_id, false, Duration::from_secs(3), vec![0.95, 0.95]);
    let drop_loop = async { fifo_drop_loop(&parts, &fence, &pool, 0.70, 1, Duration::ZERO, "20261104").await };
    let takeover = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = std::time::Instant::now();
        bump_epoch(&pool, lock_id).await;
        started.elapsed()
    };
    let (outcome, waited) = tokio::join!(drop_loop, takeover);
    assert_eq!(outcome, DropLoopOutcome::MaxDrops);
    assert!(waited >= Duration::from_secs(2), "the epoch bump must wait for the drop, waited {waited:?}");

    // Synthetic publication uses the same guard: once superseded it is refused.
    let published = fence.run_guarded(&pool, || async { "published" }).await;
    assert!(matches!(published, Err(FenceError::Superseded { .. })));
    sqlx::query("DELETE FROM leader_lease_epochs WHERE lock_id = $1").bind(lock_id).execute(&pool).await.ok();
}
