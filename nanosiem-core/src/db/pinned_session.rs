// SPDX-License-Identifier: AGPL-3.0-or-later

//! Slots for pooled PostgreSQL connections pinned by a session advisory lock
//! (NAN-5892).
//!
//! Some background work holds one pooled connection for its whole run: the
//! session advisory lock that fences it lives on that session, across long
//! network and ClickHouse I/O (the MITRE catalog sync, the platform feed and
//! content channel installs, the daily usage report). Right after nano-jobs
//! starts, its leader schedulers all run at once. On a small install
//! (PostgreSQL limited to 512 MiB, a jobs pool of 4) those pins took every
//! connection, so ordinary queries waited: about 30 slow-acquire warnings and
//! a few acquire timeouts in the first minute.
//!
//! Work that pins a connection takes a [`PinnedSlot`] first. A process may pin
//! at most [`pinned_slot_limit`] connections of its pool at once, which always
//! leaves a reserve for short queries; the rest of the pinned work waits for a
//! slot WITHOUT holding a connection, so the boot burst runs one after another
//! instead of starving the pool. The pool and PostgreSQL's `max_connections`
//! are unchanged (NAN-5822's memory budget still holds).
//!
//! The wait is bounded ([`PINNED_SLOT_MAX_WAIT`]): past it the work goes ahead
//! without a slot, so a nested pin or a stuck holder can slow work down but
//! never deadlock it.
//!
//! Only background work waits (NAN-5892 review): the gate is OFF unless the
//! process turns it on with [`enable_background_gate`], which only nano-jobs
//! does (its leader schedulers are the boot burst). In nano-api the same code
//! runs inside HTTP handlers (content and feed imports, MITRE sync), where a
//! wait would turn a fast 409 into a hang past the edge's timeout, so there
//! [`pinned_slot`] returns at once and the handler goes on as before.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Longest a pinned task waits for a slot before going ahead without one.
pub const PINNED_SLOT_MAX_WAIT: Duration = Duration::from_secs(120);

static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static BACKGROUND_GATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Turn the pinned-connection gate on for this process. Called once by the
/// nano-jobs binary; never by a process that serves requests.
pub fn enable_background_gate() {
    BACKGROUND_GATE.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn gate_enabled() -> bool {
    BACKGROUND_GATE.load(std::sync::atomic::Ordering::SeqCst)
}

/// How many connections of a `pool_max`-wide pool may be pinned at once:
/// everything but a reserve of a third of the pool (at least 2) for short
/// queries, and never fewer than 1. A 20-wide pool keeps its historical
/// headroom (14, far above the handful of pins that ever overlap); the 4-wide
/// jobs pool of a 512 MiB PostgreSQL pins at most 2.
pub fn pinned_slot_limit(pool_max: u32) -> usize {
    let reserve = (pool_max / 3).max(2);
    pool_max.saturating_sub(reserve).max(1) as usize
}

/// A slot for one pinned connection; release it by dropping it, after the
/// pinned connection itself.
#[derive(Debug)]
#[must_use = "the slot is released when dropped"]
pub struct PinnedSlot {
    _permit: Option<OwnedSemaphorePermit>,
}

impl PinnedSlot {
    /// Whether a slot was granted (false after [`PINNED_SLOT_MAX_WAIT`]).
    pub fn granted(&self) -> bool {
        self._permit.is_some()
    }
}

/// Wait for a pinned-connection slot. The limit comes from the first pool
/// asked for one in this process (each service has one main pool). Returns
/// at once, without a slot, unless [`enable_background_gate`] was called.
pub async fn pinned_slot(pool: &PgPool) -> PinnedSlot {
    if !gate_enabled() {
        return PinnedSlot { _permit: None };
    }
    acquire_within(slots_for(pool), PINNED_SLOT_MAX_WAIT).await
}

/// A slot for a second connection pinned by work that already holds one
/// (NAN-5892 review: the MITRE apply inside a content-channel install). It
/// waits like [`pinned_slot`] when the process has room for two pins; in a
/// one-slot process the outer pin holds the only slot, so waiting would only
/// wait on itself and it goes ahead at once.
pub async fn nested_pinned_slot(pool: &PgPool) -> PinnedSlot {
    if !gate_enabled() || pinned_slot_limit(pool.options().get_max_connections()) < 2 {
        return PinnedSlot { _permit: None };
    }
    acquire_within(slots_for(pool), PINNED_SLOT_MAX_WAIT).await
}

fn slots_for(pool: &PgPool) -> &'static Arc<Semaphore> {
    SLOTS.get_or_init(|| {
        Arc::new(Semaphore::new(pinned_slot_limit(pool.options().get_max_connections())))
    })
}

async fn acquire_within(slots: &Arc<Semaphore>, max_wait: Duration) -> PinnedSlot {
    if let Ok(permit) = Arc::clone(slots).try_acquire_owned() {
        return PinnedSlot { _permit: Some(permit) };
    }
    tracing::debug!("waiting for a pinned PostgreSQL connection slot");
    match tokio::time::timeout(max_wait, Arc::clone(slots).acquire_owned()).await {
        Ok(Ok(permit)) => PinnedSlot { _permit: Some(permit) },
        // The semaphore is never closed; a timeout goes ahead unthrottled.
        _ => {
            tracing::info!(
                waited_secs = max_wait.as_secs(),
                "no pinned PostgreSQL connection slot came free; going ahead without one"
            );
            PinnedSlot { _permit: None }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_always_leaves_a_reserve_for_short_queries() {
        // (pool, pins): the tiers resource-sizing.sh plans (NAN-5822) and the
        // historical 20-wide pools.
        for (pool, pins) in [(1, 1), (2, 1), (3, 1), (4, 2), (5, 3), (6, 4), (8, 6), (10, 7), (17, 12), (20, 14)] {
            assert_eq!(pinned_slot_limit(pool), pins, "pool {pool}");
            if pool >= 3 {
                assert!(pool as usize - pins >= 2, "pool {pool} keeps 2 free");
            }
        }
    }

    /// NAN-5892 review: a process that serves requests never turned the gate
    /// on, so a handler gets past `pinned_slot` at once even when the slot
    /// pool is exhausted.
    #[tokio::test(start_paused = true)]
    async fn a_request_handler_never_waits_on_a_slot() {
        assert!(!gate_enabled(), "only nano-jobs turns the gate on");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .unwrap();
        // Exhaust the (one-slot) pool's slots as a background holder would.
        let _held = Arc::clone(slots_for(&pool)).try_acquire_many_owned(1).unwrap();
        let started = tokio::time::Instant::now();
        let slot = pinned_slot(&pool).await;
        let nested = nested_pinned_slot(&pool).await;
        assert!(!slot.granted() && !nested.granted());
        assert_eq!(started.elapsed(), Duration::ZERO, "no wait at all");
    }

    #[tokio::test(start_paused = true)]
    async fn pinned_work_waits_for_a_slot_and_never_deadlocks() {
        let slots = Arc::new(Semaphore::new(1));
        let first = acquire_within(&slots, Duration::from_secs(5)).await;
        assert!(first.granted());
        // A second pin waits; when the first ends it gets the slot.
        let waiter = tokio::spawn({
            let slots = Arc::clone(&slots);
            async move { acquire_within(&slots, Duration::from_secs(5)).await.granted() }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(first);
        assert!(waiter.await.unwrap());
        // A holder that never lets go only delays the next pin.
        let _held = acquire_within(&slots, Duration::from_secs(5)).await;
        let late = acquire_within(&slots, Duration::from_secs(5)).await;
        assert!(!late.granted(), "goes ahead without a slot after the wait");
    }
}
