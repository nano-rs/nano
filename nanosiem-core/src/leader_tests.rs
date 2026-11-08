// SPDX-License-Identifier: AGPL-3.0-or-later
//! Lease election proofs (ported from main's NAN-4699 suite) plus the
//! NAN-4933 epoch fence, on a fake lock table with a paused tokio clock.
use super::*;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

#[tokio::test]
async fn cancelled_election_returns_owned_handle_without_connecting() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:9/nanosiem")
        .unwrap();
    let election = LeaderElection::new(pool, lock_ids::API_SCHEDULER);
    let shutdown = ShutdownToken::new();
    shutdown.cancel();

    let (mut leadership, handle) = election.start(shutdown);
    tokio::time::timeout(std::time::Duration::from_secs(1), handle)
        .await
        .expect("cancelled election task must stop")
        .expect("election task must not panic");

    assert!(!*leadership.borrow());
    while leadership.changed().await.is_ok() {
        assert!(!*leadership.borrow());
    }
}

#[tokio::test]
async fn hard_timeout_bounds_a_blackholed_heartbeat() {
    let result = hard_timeout(
        std::time::Duration::from_millis(5),
        std::future::pending::<()>(),
    )
    .await;
    assert!(result.is_err());
}

#[test]
fn lock_key_parts_match_pg_locks() {
    assert_eq!(lock_key_parts(lock_ids::API_SCHEDULER), (0x4e53, 0x4c45_4144));
    assert_eq!(lock_key_parts(0x1_ffff_ffff), (1, 0xffff_ffff));
}

#[test]
fn jobs_lease_bounds() {
    let t = LeaderTiming::JOBS;
    t.validate().unwrap();
    assert_eq!(t.self_fence_bound(), Duration::from_secs(5));
    assert!(t.takeover_bound().unwrap() <= Duration::from_secs(30), "{:?}", t.takeover_bound());
    assert!(t.stale_after.unwrap() >= t.self_fence_bound() * 2);
    // A pre-lease jobs leader renews every 15 s: during the first roll the new
    // standby must never see it as stale.
    assert!(t.stale_after.unwrap() > LeaderTiming::DEFAULT.heartbeat + Duration::from_secs(2));
    assert_eq!(LeaderTiming::DEFAULT.stale_after, None);
    LeaderTiming::DEFAULT.validate().unwrap();
    let unsafe_stale = LeaderTiming {
        stale_after: Some(Duration::from_secs(6)),
        ..LeaderTiming::JOBS
    };
    assert!(unsafe_stale.validate().is_err());
}

#[test]
fn disabled_fence_always_passes_and_armed_fence_starts_closed() {
    let disabled = LeaderFence::disabled();
    assert!(!disabled.is_armed());
    assert_eq!(disabled.epoch(), None);
    let armed = LeaderFence::armed(7);
    assert!(armed.is_armed());
    assert_eq!(armed.epoch(), None);
    armed.set(3);
    assert_eq!(armed.clone().epoch(), Some(3));
    armed.set(0);
    assert_eq!(armed.epoch(), None);
}

// ---- A fake lock table with a fake clock (tokio paused time). ----

#[derive(Default)]
struct FakeDb {
    /// (session id, last renew) of the holder, as the server sees it.
    holder: Option<(u64, Instant)>,
    next_session: u64,
    terminated: HashSet<u64>,
    evictions: usize,
    epoch: i64,
    epoch_history: Vec<(i64, String)>,
}

#[derive(Clone)]
struct FakeStore {
    db: Arc<Mutex<FakeDb>>,
    /// This client cannot reach the database: every call hangs, and its
    /// sessions' close never reaches the server.
    partitioned: Arc<AtomicBool>,
}

struct FakeSession {
    id: u64,
    db: Arc<Mutex<FakeDb>>,
    partitioned: Arc<AtomicBool>,
}

impl Drop for FakeSession {
    fn drop(&mut self) {
        if self.partitioned.load(Ordering::SeqCst) {
            return;
        }
        let mut db = self.db.lock().unwrap();
        if db.holder.map(|(id, _)| id) == Some(self.id) {
            db.holder = None;
        }
    }
}

impl FakeStore {
    fn new(db: &Arc<Mutex<FakeDb>>) -> Self {
        Self {
            db: Arc::clone(db),
            partitioned: Arc::new(AtomicBool::new(false)),
        }
    }
    async fn reachable(&self) {
        if self.partitioned.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }
}

impl LeaseStore for FakeStore {
    type Session = FakeSession;

    async fn probe(&self, _lock_id: i64, stale_after: Duration) -> Result<LockProbe, String> {
        self.reachable().await;
        let db = self.db.lock().unwrap();
        Ok(match db.holder {
            None => LockProbe::Free,
            Some((_, last)) if last.elapsed() >= stale_after => LockProbe::Stale,
            Some(_) => LockProbe::Held,
        })
    }

    async fn evict_stale(&self, _lock_id: i64, stale_after: Duration) -> Result<bool, String> {
        self.reachable().await;
        let mut db = self.db.lock().unwrap();
        match db.holder {
            Some((id, last)) if last.elapsed() >= stale_after => {
                db.holder = None;
                db.terminated.insert(id);
                db.evictions += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn open(&self) -> Result<FakeSession, String> {
        self.reachable().await;
        let mut db = self.db.lock().unwrap();
        db.next_session += 1;
        Ok(FakeSession {
            id: db.next_session,
            db: Arc::clone(&self.db),
            partitioned: Arc::clone(&self.partitioned),
        })
    }

    async fn try_lock(&self, session: &mut FakeSession, _lock_id: i64) -> Result<bool, String> {
        self.reachable().await;
        let mut db = self.db.lock().unwrap();
        match db.holder {
            None => {
                db.holder = Some((session.id, Instant::now()));
                Ok(true)
            }
            Some((id, _)) => Ok(id == session.id),
        }
    }

    async fn renew(&self, session: &mut FakeSession) -> Result<(), String> {
        self.reachable().await;
        let mut db = self.db.lock().unwrap();
        if db.terminated.contains(&session.id) {
            return Err("terminating connection due to administrator command".into());
        }
        match db.holder {
            Some((id, _)) if id == session.id => {
                db.holder = Some((id, Instant::now()));
                Ok(())
            }
            _ => Err("lock lost".into()),
        }
    }

    async fn bump_epoch(
        &self,
        session: &mut FakeSession,
        _lock_id: i64,
        holder: &str,
    ) -> Result<i64, String> {
        self.reachable().await;
        let mut db = self.db.lock().unwrap();
        if db.holder.map(|(id, _)| id) != Some(session.id) {
            return Err("not the lock holder".into());
        }
        db.epoch += 1;
        let epoch = db.epoch;
        db.epoch_history.push((epoch, holder.to_owned()));
        Ok(epoch)
    }
}

/// Records when each instance's singletons start and stop, and how many run at once.
#[derive(Clone, Default)]
struct Ledger {
    events: Arc<Mutex<Vec<(&'static str, &'static str, Instant, i64)>>>,
    running: Arc<AtomicUsize>,
    max_running: Arc<AtomicUsize>,
}

impl Ledger {
    fn at(&self, who: &str, what: &str) -> Option<Instant> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|(w, e, _, _)| *w == who && *e == what)
            .map(|(_, _, t, _)| *t)
    }
}

struct Singletons {
    who: &'static str,
    ledger: Ledger,
    leading: Arc<AtomicBool>,
}

impl LeaderHooks for Singletons {
    async fn elected(&mut self, epoch: i64) {
        let now = self.ledger.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.ledger.max_running.fetch_max(now, Ordering::SeqCst);
        self.leading.store(true, Ordering::SeqCst);
        self.ledger
            .events
            .lock()
            .unwrap()
            .push((self.who, "start", Instant::now(), epoch));
    }
    async fn stepped_down(&mut self) {
        self.ledger.running.fetch_sub(1, Ordering::SeqCst);
        self.leading.store(false, Ordering::SeqCst);
        self.ledger
            .events
            .lock()
            .unwrap()
            .push((self.who, "stop", Instant::now(), 0));
    }
}

struct Instance {
    store: FakeStore,
    shutdown: ShutdownToken,
    leading: Arc<AtomicBool>,
    fence: LeaderFence,
    handle: tokio::task::JoinHandle<()>,
}

fn spawn_instance(who: &'static str, db: &Arc<Mutex<FakeDb>>, ledger: &Ledger) -> Instance {
    let store = FakeStore::new(db);
    let shutdown = ShutdownToken::new();
    let leading = Arc::new(AtomicBool::new(false));
    let fence = LeaderFence::armed(7);
    let hooks = FencedHooks {
        inner: Singletons {
            who,
            ledger: ledger.clone(),
            leading: Arc::clone(&leading),
        },
        fence: Some((fence.clone(), who.to_owned())),
    };
    let handle = tokio::spawn(run_election(
        store.clone(),
        7,
        LeaderTiming::JOBS,
        shutdown.clone(),
        hooks,
    ));
    Instance {
        store,
        shutdown,
        leading,
        fence,
        handle,
    }
}

async fn advance_until(limit: Duration, done: impl Fn() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() <= limit, "condition not reached within {limit:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    start.elapsed()
}

async fn leader_and_standby() -> (Arc<Mutex<FakeDb>>, Ledger, Instance, Instance) {
    let db = Arc::new(Mutex::new(FakeDb::default()));
    let ledger = Ledger::default();
    let a = spawn_instance("A", &db, &ledger);
    let leading = Arc::clone(&a.leading);
    advance_until(Duration::from_secs(1), || leading.load(Ordering::SeqCst)).await;
    let b = spawn_instance("B", &db, &ledger);
    // B stays a standby while A renews.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(a.leading.load(Ordering::SeqCst));
    assert!(!b.leading.load(Ordering::SeqCst));
    (db, ledger, a, b)
}

#[tokio::test(start_paused = true)]
async fn takeover_after_the_leader_is_cut_off_is_bounded_and_fenced() {
    let (db, ledger, a, b) = leader_and_standby().await;
    assert_eq!(a.fence.epoch(), Some(1));
    assert_eq!(b.fence.epoch(), None);
    // A's node is lost / partitioned: its renews hang and its session never
    // closes server-side (the TCP peer is gone).
    let cut = Instant::now();
    a.store.partitioned.store(true, Ordering::SeqCst);
    let b_leading = Arc::clone(&b.leading);
    let took = advance_until(Duration::from_secs(30), || b_leading.load(Ordering::SeqCst)).await;

    let a_stop = ledger.at("A", "stop").expect("A fenced itself");
    let b_start = ledger.at("B", "start").expect("B took over");
    assert!(
        a_stop.duration_since(cut) <= LeaderTiming::JOBS.self_fence_bound(),
        "{:?}",
        a_stop.duration_since(cut)
    );
    assert!(b_start > a_stop);
    assert!(
        b_start.duration_since(a_stop) >= Duration::from_secs(10),
        "margin {:?}",
        b_start.duration_since(a_stop)
    );
    assert!(took <= LeaderTiming::JOBS.takeover_bound().unwrap(), "took {took:?}");
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1, "two leaders ran singletons at once");
    assert_eq!(db.lock().unwrap().evictions, 1);
    assert!(!a.leading.load(Ordering::SeqCst));
    // The epoch advanced with the takeover; A's fence is closed, B's is the new epoch.
    assert_eq!(a.fence.epoch(), None);
    assert_eq!(b.fence.epoch(), Some(2));
    assert_eq!(
        db.lock().unwrap().epoch_history,
        vec![(1, "A".to_string()), (2, "B".to_string())]
    );

    // A stays fenced: it never leads again while B holds the lease.
    a.store.partitioned.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(!a.leading.load(Ordering::SeqCst));
    assert!(b.leading.load(Ordering::SeqCst));
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn graceful_stop_hands_over_within_one_retry_after_tasks_stop() {
    let (db, ledger, a, b) = leader_and_standby().await;
    let stopped = Instant::now();
    a.shutdown.cancel();
    a.handle.await.unwrap();
    let b_leading = Arc::clone(&b.leading);
    let took = advance_until(Duration::from_secs(30), || b_leading.load(Ordering::SeqCst)).await;
    assert!(took <= LeaderTiming::JOBS.retry + Duration::from_millis(200), "took {took:?}");
    assert!(ledger.at("A", "stop").unwrap() >= stopped);
    assert!(ledger.at("B", "start").unwrap() >= ledger.at("A", "stop").unwrap());
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);
    assert_eq!(db.lock().unwrap().epoch, 2);
}

#[tokio::test(start_paused = true)]
async fn a_crashed_leader_whose_session_closes_is_replaced_within_one_retry() {
    let (_db, ledger, a, b) = leader_and_standby().await;
    // Process killed on a live node: the kernel closes the socket, the server
    // releases the lock, and no step-down hook runs in the dead process.
    a.handle.abort();
    let _ = a.handle.await;
    ledger.running.fetch_sub(1, Ordering::SeqCst);
    let b_leading = Arc::clone(&b.leading);
    let took = advance_until(Duration::from_secs(30), || b_leading.load(Ordering::SeqCst)).await;
    assert!(took <= LeaderTiming::JOBS.retry + Duration::from_millis(200), "took {took:?}");
}

#[tokio::test(start_paused = true)]
async fn a_reachable_leader_keeps_the_lease_indefinitely() {
    let (db, ledger, a, b) = leader_and_standby().await;
    tokio::time::sleep(Duration::from_secs(4 * 3600)).await;
    assert!(a.leading.load(Ordering::SeqCst));
    assert!(!b.leading.load(Ordering::SeqCst));
    assert_eq!(db.lock().unwrap().evictions, 0);
    assert_eq!(ledger.events.lock().unwrap().len(), 1);
    assert_eq!(db.lock().unwrap().epoch, 1);
}

#[tokio::test(start_paused = true)]
async fn the_standby_holds_no_session_between_probes() {
    let (db, _ledger, _a, _b) = leader_and_standby().await;
    assert_eq!(db.lock().unwrap().next_session, 1);
}

// ---- NAN-4933 review P1: renewal runs concurrently with a slow elected hook.

struct SlowStart {
    inner: Singletons,
    startup: Duration,
}

impl LeaderHooks for SlowStart {
    async fn elected(&mut self, epoch: i64) {
        // Scheduler startup that takes longer than the 20 s stale threshold.
        tokio::time::sleep(self.startup).await;
        self.inner.elected(epoch).await;
    }
    async fn stepped_down(&mut self) {
        // Only roll back what actually started.
        if self.inner.leading.load(Ordering::SeqCst) {
            self.inner.stepped_down().await;
        }
    }
}

fn spawn_slow(who: &'static str, db: &Arc<Mutex<FakeDb>>, ledger: &Ledger, startup: Duration) -> Instance {
    let store = FakeStore::new(db);
    let shutdown = ShutdownToken::new();
    let leading = Arc::new(AtomicBool::new(false));
    let fence = LeaderFence::armed(7);
    let hooks = FencedHooks {
        inner: SlowStart {
            inner: Singletons { who, ledger: ledger.clone(), leading: Arc::clone(&leading) },
            startup,
        },
        fence: Some((fence.clone(), who.to_owned())),
    };
    let handle = tokio::spawn(run_election(store.clone(), 7, LeaderTiming::JOBS, shutdown.clone(), hooks));
    Instance { store, shutdown, leading, fence, handle }
}

#[tokio::test(start_paused = true)]
async fn a_slow_scheduler_startup_keeps_renewing_and_is_never_evicted() {
    let db = Arc::new(Mutex::new(FakeDb::default()));
    let ledger = Ledger::default();
    let a = spawn_slow("A", &db, &ledger, Duration::from_secs(45));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b = spawn_instance("B", &db, &ledger);
    // Well past the 20 s stale threshold while A is still starting.
    tokio::time::sleep(Duration::from_secs(40)).await;
    assert!(!b.leading.load(Ordering::SeqCst), "standby took over during a slow startup");
    assert_eq!(db.lock().unwrap().evictions, 0, "a renewing leader was evicted");
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(a.leading.load(Ordering::SeqCst));
    assert!(!b.leading.load(Ordering::SeqCst));
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);
    assert_eq!(db.lock().unwrap().epoch, 1, "no second epoch");
}

#[tokio::test(start_paused = true)]
async fn a_lease_lost_during_startup_closes_the_fence_and_rolls_startup_back() {
    let db = Arc::new(Mutex::new(FakeDb::default()));
    let ledger = Ledger::default();
    let a = spawn_slow("A", &db, &ledger, Duration::from_secs(45));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.fence.epoch(), Some(1));
    let b = spawn_instance("B", &db, &ledger);
    // A is cut off mid-startup: its next renew hangs and times out.
    a.store.partitioned.store(true, Ordering::SeqCst);
    let fence_a = a.fence.clone();
    advance_until(LeaderTiming::JOBS.self_fence_bound() + Duration::from_secs(1), || fence_a.epoch().is_none()).await;
    // B takes over by eviction while A's startup is still running...
    let b_leading = Arc::clone(&b.leading);
    advance_until(Duration::from_secs(40), || b_leading.load(Ordering::SeqCst)).await;
    assert_eq!(b.fence.epoch(), Some(2));
    // ...and when A's startup returns it is rolled back at once.
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(!a.leading.load(Ordering::SeqCst), "A must stop what its late startup began");
    assert_eq!(a.fence.epoch(), None);
    let events = ledger.events.lock().unwrap().clone();
    let a_start = events.iter().find(|(w, e, _, _)| *w == "A" && *e == "start").map(|(_, _, t, _)| *t).unwrap();
    let a_stop = events.iter().find(|(w, e, _, _)| *w == "A" && *e == "stop").map(|(_, _, t, _)| *t).unwrap();
    assert_eq!(a_start, a_stop, "rolled back in the same instant its startup returned");
}
