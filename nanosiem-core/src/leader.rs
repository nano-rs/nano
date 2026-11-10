// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL advisory lock-based leader election (a PG lease)
//!
//! Ensures exactly one replica runs leader-only tasks. Uses `pg_try_advisory_lock`
//! on a dedicated session: if the leader process dies, PostgreSQL closes the
//! session and releases the lock automatically, allowing another instance to
//! take over.
//!
//! IMPORTANT: the lock session is opened OUTSIDE the pool. Advisory locks are
//! session-level: returning a pooled connection would keep the lock, and the
//! next attempt would deadlock against itself.
//!
//! Used by both the Jobs service (scheduler leadership) and the Search service
//! (active/standby traffic gating).
//!
//! # Lease mode (NAN-4933, port of main's NAN-4699 step 4: jobs at two replicas)
//!
//! [`LeaderTiming::JOBS`] turns the lock into a lease with bounded takeover:
//!
//! - **renew** every `heartbeat` (2 s) on the lock's own session, each bounded by
//!   `database_timeout` (3 s). A renew that fails or times out ends leadership:
//!   the leader's tasks are stopped and awaited ([`LeaderHooks::stepped_down`])
//!   BEFORE the session (and so the lock) is dropped. A leader cut off from
//!   PostgreSQL therefore stops its singletons within `heartbeat +
//!   database_timeout` (5 s) of its last good renew.
//! - **standby** probes the lock every `retry` (2 s) over the ordinary
//!   application pool, so a standby holds NO direct session until it takes
//!   over. It opens one only when the lock is free.
//! - **stale holder**: a hard node loss leaves the holder's backend open until
//!   TCP notices (minutes to hours). A holder whose session has been idle (no
//!   renew) for `stale_after` (20 s: four times the self-fence bound, and above
//!   the 15 s renew interval of a pre-lease jobs image, so the first roll onto
//!   this image never evicts the old leader) is terminated with
//!   `pg_terminate_backend` (same login, no extra privilege) and the standby
//!   takes the lock. Takeover after a hard death: at most
//!   `stale_after + retry + 2 x database_timeout` = 28 s. A graceful stop or a
//!   crash with the node up closes the session at once: takeover within
//!   `retry` (2 s).
//!
//! # Epoch fence (NAN-4933)
//!
//! A leader that was frozen (SIGSTOP, VM pause, a GC-like stall) longer than
//! `stale_after` is evicted while its tasks are suspended mid-flight; when it
//! resumes, those tasks run until its next renew fails. To close that window,
//! an election with a [`LeaderFence`] bumps `leader_lease_epochs.epoch` on the
//! lock session at every acquisition (before any leader task starts), and
//! leader-only writes either check the epoch at their tick
//! ([`LeaderFence::still_leader`]) or, for the writes that must never
//! duplicate, take `FOR SHARE` on the epoch row inside their own transaction
//! ([`LeaderFence::guard`]). The bump's row lock waits for any in-flight
//! guarded transaction of the old leader, so a guarded write either commits
//! before the new leader starts or is refused.
//!
//! The lease lives in PostgreSQL, not a Kubernetes Lease, on purpose: every
//! singleton it fences is PostgreSQL work, so PostgreSQL reachability is
//! exactly the condition under which a leader can make progress.

use sqlx::{Connection, PgConnection, PgPool};
use std::future::Future;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::shutdown::ShutdownToken;

/// Well-known lock IDs for each service.
pub mod lock_ids {
    /// API scheduler leader (`NSLEAD` in hex) — used for tuning + enrichment sync.
    pub const API_SCHEDULER: i64 = 0x4e53_4c45_4144;
    /// Search active/standby leader (`NSSEAC` in hex).
    pub const SEARCH_ACTIVE: i64 = 0x4e53_5345_4143;
    /// Signal processor leader (`NSSGPR` in hex) — serial watermark processing.
    pub const SIGNAL_PROCESSOR: i64 = 0x4e53_5349_4750;
    /// Disk pressure monitor leader (`NSDISC` in hex).
    pub const DISK_PRESSURE: i64 = 0x4e53_4449_534b;
    /// Schema migrator (`NSMIGR` in hex). Held for a whole migrator run so
    /// several app hosts starting at once apply PostgreSQL and ClickHouse
    /// migrations exactly once, one host at a time (NAN-5213).
    pub const SCHEMA_MIGRATOR: i64 = 0x4e53_4d49_4752;
    /// Online licence check-in and usage report (`NSLICN` in hex): only one
    /// process reports at a time (NAN-5213).
    pub const LICENSE_USAGE_REPORT: i64 = 0x4e53_4c49_434e;
}

/// The election's clock. `LEADER_HEARTBEAT_SECS`, `LEADER_HEARTBEAT_TIMEOUT_SECS`,
/// `LEADER_RETRY_SECS` and `LEADER_STALE_SECS` override it
/// ([`LeaderTiming::with_env_overrides`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaderTiming {
    /// Renew interval while leading.
    pub heartbeat: Duration,
    /// Bound on every database call of the election (connect, lock, renew, probe).
    pub database_timeout: Duration,
    /// Standby poll interval, and the back-off after a failure.
    pub retry: Duration,
    /// Lease mode: a holder idle this long is evicted. `None`: no probe, no
    /// eviction (the pre-lease behavior, kept for search).
    pub stale_after: Option<Duration>,
}

impl LeaderTiming {
    /// Search's active/standby gate (unchanged since NAN-1781).
    pub const DEFAULT: Self = Self {
        heartbeat: Duration::from_secs(15),
        database_timeout: Duration::from_secs(5),
        retry: Duration::from_secs(15),
        stale_after: None,
    };
    /// Jobs' singleton lease (see the module docs).
    pub const JOBS: Self = Self {
        heartbeat: Duration::from_secs(2),
        database_timeout: Duration::from_secs(3),
        retry: Duration::from_secs(2),
        stale_after: Some(Duration::from_secs(20)),
    };

    /// Longest a leader that can no longer renew keeps leading.
    pub fn self_fence_bound(&self) -> Duration {
        self.heartbeat + self.database_timeout
    }

    /// Longest a standby waits to lead after the holder's last renew (lease mode).
    pub fn takeover_bound(&self) -> Option<Duration> {
        self.stale_after
            .map(|stale| stale + self.retry + self.database_timeout * 2)
    }

    /// A stale threshold must leave the old leader time to fence itself first:
    /// at least twice its self-fence bound.
    pub fn validate(&self) -> Result<(), String> {
        if self.heartbeat.is_zero() || self.database_timeout.is_zero() || self.retry.is_zero() {
            return Err("leader heartbeat, timeout and retry must be positive".into());
        }
        if let Some(stale) = self.stale_after {
            if stale < self.self_fence_bound() * 2 {
                return Err(format!(
                    "LEADER_STALE_SECS {}s must be at least twice heartbeat + timeout ({}s)",
                    stale.as_secs(),
                    self.self_fence_bound().as_secs()
                ));
            }
        }
        Ok(())
    }

    /// The env overrides on top of `self`; an invalid combination keeps `self`.
    pub fn with_env_overrides(self) -> Self {
        let secs = |key: &str, default: Duration| {
            Duration::from_secs(parse_env(key, default.as_secs()))
        };
        let overridden = Self {
            heartbeat: secs("LEADER_HEARTBEAT_SECS", self.heartbeat),
            database_timeout: secs("LEADER_HEARTBEAT_TIMEOUT_SECS", self.database_timeout)
                .max(Duration::from_secs(1)),
            retry: secs("LEADER_RETRY_SECS", self.retry),
            stale_after: self.stale_after.map(|stale| secs("LEADER_STALE_SECS", stale)),
        };
        match overridden.validate() {
            Ok(()) => overridden,
            Err(error) => {
                tracing::error!(%error, "Leader election: ignoring invalid LEADER_* overrides");
                self
            }
        }
    }
}

/// What the holder of a lock looks like from a standby (lease mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockProbe {
    /// Nobody holds it.
    Free,
    /// Held by a session that renewed within `stale_after` (or one this login cannot inspect).
    Held,
    /// Held by a session idle for at least `stale_after`.
    Stale,
}

/// The database side of an election, abstracted so the election can be tested
/// with a fake clock and a fake lock table.
pub trait LeaseStore: Send + Sync + 'static {
    /// The dedicated session that holds the lock; dropping it releases the lock.
    type Session: Send + 'static;
    fn probe(
        &self,
        lock_id: i64,
        stale_after: Duration,
    ) -> impl Future<Output = Result<LockProbe, String>> + Send;
    /// Terminate the holder only if it is still idle for `stale_after`. `true` when one was signalled.
    fn evict_stale(
        &self,
        lock_id: i64,
        stale_after: Duration,
    ) -> impl Future<Output = Result<bool, String>> + Send;
    fn open(&self) -> impl Future<Output = Result<Self::Session, String>> + Send;
    fn try_lock(
        &self,
        session: &mut Self::Session,
        lock_id: i64,
    ) -> impl Future<Output = Result<bool, String>> + Send;
    fn renew(&self, session: &mut Self::Session) -> impl Future<Output = Result<(), String>> + Send;
    /// Advance and return the lease epoch on the lock session (fenced elections).
    fn bump_epoch(
        &self,
        session: &mut Self::Session,
        lock_id: i64,
        holder: &str,
    ) -> impl Future<Output = Result<i64, String>> + Send;
}

/// What the election does on a change of leadership. `stepped_down` must not
/// return before every leader-only task has stopped: the lock is released only
/// after it returns.
pub trait LeaderHooks: Send + 'static {
    /// `epoch` is the fenced lease epoch, or 0 for an unfenced election.
    fn elected(&mut self, epoch: i64) -> impl Future<Output = ()> + Send;
    fn stepped_down(&mut self) -> impl Future<Output = ()> + Send;
}

// ---------------------------------------------------------------------------
// Epoch fence
// ---------------------------------------------------------------------------

/// A leader-only write was attempted by an instance that no longer holds the
/// current lease epoch.
#[derive(Debug, thiserror::Error)]
pub enum FenceError {
    #[error("leader lease epoch {held} is no longer current (now {current:?}); write refused")]
    Superseded { held: i64, current: Option<i64> },
    #[error("not the leader; write refused")]
    NotLeader,
    #[error("leader fence check failed: {0}")]
    Database(#[from] sqlx::Error),
}

/// Shared handle to this process's lease epoch. Cheap to clone.
///
/// `disabled()` (the API, single-node jobs, tests) always passes; an armed
/// fence passes only while this process holds the current epoch.
#[derive(Clone, Debug)]
pub struct LeaderFence {
    inner: Option<Arc<FenceState>>,
}

#[derive(Debug)]
struct FenceState {
    lock_id: i64,
    /// 0 = not leading.
    epoch: AtomicI64,
}

impl LeaderFence {
    /// No election: every check passes (explicit single-node deployments).
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// A fence for the election on `lock_id`, not leading until elected.
    pub fn armed(lock_id: i64) -> Self {
        Self {
            inner: Some(Arc::new(FenceState {
                lock_id,
                epoch: AtomicI64::new(0),
            })),
        }
    }

    /// A fence pinned to `epoch`: what a leader frozen past its eviction still
    /// believes it holds. For fencing proofs and drills.
    #[doc(hidden)]
    pub fn pinned(lock_id: i64, epoch: i64) -> Self {
        let fence = Self::armed(lock_id);
        fence.set(epoch);
        fence
    }

    pub fn is_armed(&self) -> bool {
        self.inner.is_some()
    }

    /// The epoch this process leads under, if any.
    pub fn epoch(&self) -> Option<i64> {
        match &self.inner {
            None => None,
            Some(state) => Some(state.epoch.load(Ordering::SeqCst)).filter(|e| *e > 0),
        }
    }

    pub(crate) fn set(&self, epoch: i64) {
        if let Some(state) = &self.inner {
            state.epoch.store(epoch, Ordering::SeqCst);
        }
    }

    /// Strict fence: run inside the caller's transaction, before its writes.
    /// `FOR SHARE` makes a concurrent takeover's epoch bump wait for this
    /// transaction, so a write that passes commits before the new leader starts.
    pub async fn guard(&self, conn: &mut PgConnection) -> Result<(), FenceError> {
        let Some(state) = &self.inner else {
            return Ok(());
        };
        let held = state.epoch.load(Ordering::SeqCst);
        if held == 0 {
            return Err(FenceError::NotLeader);
        }
        let current: Option<i64> =
            sqlx::query_scalar("SELECT epoch FROM leader_lease_epochs WHERE lock_id = $1 FOR SHARE")
                .bind(state.lock_id)
                .fetch_optional(&mut *conn)
                .await?;
        if current == Some(held) {
            Ok(())
        } else {
            Err(FenceError::Superseded { held, current })
        }
    }

    /// Run `work` while holding the strict guard: a transaction holding
    /// `FOR SHARE` on the epoch row stays open until `work` finishes, so a
    /// takeover's epoch bump cannot complete while the work is in flight, and
    /// a superseded instance is refused before the work starts. For side
    /// effects outside this transaction (ClickHouse DDL, alerts, webhooks)
    /// that must never run on two leaders. Disabled fence: just runs `work`.
    pub async fn run_guarded<T, F, Fut>(&self, pool: &PgPool, work: F) -> Result<T, FenceError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        if self.inner.is_none() {
            return Ok(work().await);
        }
        let mut tx = pool.begin().await?;
        self.guard(&mut tx).await?;
        let out = work().await;
        // Commit only releases the share lock; nothing was written.
        tx.commit().await?;
        Ok(out)
    }

    /// Tick gate: whether this process still holds the current epoch (no lock
    /// taken). A database error counts as "no" so a cut-off leader idles.
    pub async fn still_leader(&self, pool: &PgPool) -> bool {
        let Some(state) = &self.inner else {
            return true;
        };
        let held = state.epoch.load(Ordering::SeqCst);
        if held == 0 {
            return false;
        }
        match sqlx::query_scalar::<_, i64>("SELECT epoch FROM leader_lease_epochs WHERE lock_id = $1")
            .bind(state.lock_id)
            .fetch_optional(pool)
            .await
        {
            Ok(Some(current)) if current == held => true,
            Ok(current) => {
                tracing::warn!(held, ?current, "leader lease epoch superseded; skipping leader-only tick");
                false
            }
            Err(error) => {
                tracing::warn!(%error, "leader fence check failed; skipping leader-only tick");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Election
// ---------------------------------------------------------------------------

/// Leader election using PostgreSQL session-level advisory locks.
///
/// One instance holds the lock and acts as the leader; all others are standby.
pub struct LeaderElection {
    pool: PgPool,
    lock_id: i64,
    timing: LeaderTiming,
    fence: Option<(LeaderFence, String)>,
}

impl LeaderElection {
    pub fn new(pool: PgPool, lock_id: i64) -> Self {
        Self {
            pool,
            lock_id,
            timing: LeaderTiming::DEFAULT.with_env_overrides(),
            fence: None,
        }
    }

    /// Replace the timing (already env-resolved by the caller, if wanted).
    pub fn with_timing(mut self, timing: LeaderTiming) -> Self {
        self.timing = timing;
        self
    }

    /// Bump the lease epoch on every acquisition and keep `fence` in step.
    /// `holder` names this instance in `leader_lease_epochs` (node id).
    pub fn with_fence(mut self, fence: LeaderFence, holder: impl Into<String>) -> Self {
        self.fence = Some((fence, holder.into()));
        self
    }

    pub fn timing(&self) -> LeaderTiming {
        self.timing
    }

    /// Spawn the election loop, reporting leadership on a `watch` channel.
    ///
    /// The returned handle resolves only after cancellation has closed the
    /// dedicated PostgreSQL connection and therefore released any advisory lock.
    pub fn start(
        &self,
        shutdown: ShutdownToken,
    ) -> (watch::Receiver<bool>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = watch::channel(false);
        (rx, self.spawn_with(shutdown, WatchHooks(tx)))
    }

    /// Spawn the election loop with `hooks` run on every change of leadership
    /// (the leader's tasks stop before its lock is released).
    pub fn spawn_with<H: LeaderHooks>(
        &self,
        shutdown: ShutdownToken,
        hooks: H,
    ) -> tokio::task::JoinHandle<()> {
        let store = PgLeaseStore {
            app_pool: self.pool.clone(),
        };
        tokio::spawn(run_election(
            store,
            self.lock_id,
            self.timing,
            shutdown,
            FencedHooks {
                inner: hooks,
                fence: self.fence.clone(),
            },
        ))
    }
}

struct WatchHooks(watch::Sender<bool>);

impl LeaderHooks for WatchHooks {
    async fn elected(&mut self, _epoch: i64) {
        let _ = self.0.send(true);
    }
    async fn stepped_down(&mut self) {
        let _ = self.0.send(false);
    }
}

/// Keeps the [`LeaderFence`] in step: armed with the epoch before the inner
/// `elected`, disarmed after the inner `stepped_down`.
struct FencedHooks<H> {
    inner: H,
    fence: Option<(LeaderFence, String)>,
}

impl<H: LeaderHooks> FencedHooks<H> {
    fn holder(&self) -> Option<&str> {
        self.fence.as_ref().map(|(_, holder)| holder.as_str())
    }
}

impl<H: LeaderHooks> LeaderHooks for FencedHooks<H> {
    async fn elected(&mut self, epoch: i64) {
        if let Some((fence, _)) = &self.fence {
            fence.set(epoch);
        }
        self.inner.elected(epoch).await;
    }
    async fn stepped_down(&mut self) {
        self.inner.stepped_down().await;
        if let Some((fence, _)) = &self.fence {
            fence.set(0);
        }
    }
}

/// `pg_advisory_lock(bigint)` is recorded in `pg_locks` as classid = high 32
/// bits, objid = low 32 bits, objsubid = 1.
fn lock_key_parts(lock_id: i64) -> (i64, i64) {
    let key = lock_id as u64;
    ((key >> 32) as u32 as i64, (key & 0xffff_ffff) as u32 as i64)
}

const HOLDER_FILTER: &str = "l.locktype = 'advisory' AND l.granted AND l.objsubid = 1 \
     AND l.classid::bigint = $1 AND l.objid::bigint = $2 \
     AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())";

struct PgLeaseStore {
    /// Ordinary application pool: probes and evictions. The lock session is a
    /// dedicated connection opened with the same options.
    app_pool: PgPool,
}

impl LeaseStore for PgLeaseStore {
    type Session = PgConnection;

    async fn probe(&self, lock_id: i64, stale_after: Duration) -> Result<LockProbe, String> {
        let (classid, objid) = lock_key_parts(lock_id);
        let holder: Option<(Option<String>, Option<f64>)> = sqlx::query_as(&format!(
            "SELECT a.state, EXTRACT(EPOCH FROM (clock_timestamp() - a.state_change))::float8 \
               FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid WHERE {HOLDER_FILTER} LIMIT 1"
        ))
        .bind(classid)
        .bind(objid)
        .fetch_optional(&self.app_pool)
        .await
        .map_err(|error| error.to_string())?;
        Ok(match holder {
            None => LockProbe::Free,
            Some((Some(state), Some(quiet)))
                if state == "idle" && quiet >= stale_after.as_secs_f64() =>
            {
                LockProbe::Stale
            }
            Some(_) => LockProbe::Held,
        })
    }

    async fn evict_stale(&self, lock_id: i64, stale_after: Duration) -> Result<bool, String> {
        let (classid, objid) = lock_key_parts(lock_id);
        // One statement: the idle re-check and the signal see the same row, so a
        // holder that renewed since the probe is never terminated.
        let signalled: Option<bool> = sqlx::query_scalar(&format!(
            "SELECT pg_terminate_backend(a.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid \
              WHERE {HOLDER_FILTER} AND a.state = 'idle' \
                AND a.state_change < clock_timestamp() - make_interval(secs => $3) LIMIT 1"
        ))
        .bind(classid)
        .bind(objid)
        .bind(stale_after.as_secs_f64())
        .fetch_optional(&self.app_pool)
        .await
        .map_err(|error| error.to_string())?;
        Ok(signalled == Some(true))
    }

    async fn open(&self) -> Result<Self::Session, String> {
        // Outside the pool: dropping the connection releases the lock.
        PgConnection::connect_with(&self.app_pool.connect_options())
            .await
            .map_err(|error| error.to_string())
    }

    async fn try_lock(&self, session: &mut Self::Session, lock_id: i64) -> Result<bool, String> {
        sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_id)
            .fetch_one(&mut *session)
            .await
            .map_err(|error| error.to_string())
    }

    async fn renew(&self, session: &mut Self::Session) -> Result<(), String> {
        sqlx::query("SELECT 1")
            .execute(&mut *session)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn bump_epoch(
        &self,
        session: &mut Self::Session,
        lock_id: i64,
        holder: &str,
    ) -> Result<i64, String> {
        // Runs on the lock session, so only the lock holder can bump. The row
        // lock waits for any old leader's in-flight `FOR SHARE` guard.
        let mut tx = session.begin().await.map_err(|e| e.to_string())?;
        let epoch: i64 = sqlx::query_scalar(
            "INSERT INTO leader_lease_epochs (lock_id, epoch, holder, acquired_at) \
             VALUES ($1, 1, $2, now()) \
             ON CONFLICT (lock_id) DO UPDATE SET epoch = leader_lease_epochs.epoch + 1, \
               holder = EXCLUDED.holder, acquired_at = now() \
             RETURNING epoch",
        )
        .bind(lock_id)
        .bind(holder)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        sqlx::query(
            "INSERT INTO leader_lease_history (lock_id, epoch, holder, acquired_at) \
             VALUES ($1, $2, $3, now())",
        )
        .bind(lock_id)
        .bind(epoch)
        .bind(holder)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(epoch)
    }
}

/// Renew the lock session every heartbeat until a renew fails (`false`) or
/// shutdown (`true`).
async fn renew_until_lost<S: LeaseStore>(
    store: &S,
    session: &mut S::Session,
    lock: &str,
    timing: LeaderTiming,
    shutdown: &ShutdownToken,
) -> bool {
    loop {
        if !sleep_or_stop(shutdown, timing.heartbeat).await {
            return true;
        }
        match bounded(shutdown, timing.database_timeout, store.renew(session)).await {
            None => return true,
            Some(Ok(())) => tracing::trace!(%lock, "Leader election: renewed"),
            Some(Err(error)) => {
                tracing::error!(%lock, %error, "Leader election: renew failed; stepping down");
                return false;
            }
        }
    }
}

async fn sleep_or_stop(shutdown: &ShutdownToken, duration: Duration) -> bool {
    shutdown
        .run_until_cancelled(tokio::time::sleep(duration))
        .await
        .is_some()
}

/// A database call, cancellable on shutdown (`None`) and bounded by `timeout`.
async fn bounded<T>(
    shutdown: &ShutdownToken,
    timeout: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Option<Result<T, String>> {
    shutdown
        .run_until_cancelled(hard_timeout(timeout, future))
        .await
        .map(|result| {
            result.unwrap_or_else(|_| Err(format!("timed out after {}s", timeout.as_secs())))
        })
}

/// The election loop. Leadership ends on a failed or late renew, or on
/// shutdown; either way `hooks.stepped_down()` completes before the session
/// holding the lock is dropped.
async fn run_election<S: LeaseStore, H: LeaderHooks>(
    store: S,
    lock_id: i64,
    timing: LeaderTiming,
    shutdown: ShutdownToken,
    mut hooks: FencedHooks<H>,
) {
    let timeout = timing.database_timeout;
    let lock = format!("0x{lock_id:X}");
    'election: loop {
        if shutdown.is_cancelled() {
            break;
        }
        if let Some(stale_after) = timing.stale_after {
            match bounded(&shutdown, timeout, store.probe(lock_id, stale_after)).await {
                None => break,
                Some(Ok(LockProbe::Free)) => {}
                Some(Ok(LockProbe::Held)) => {
                    tracing::debug!(%lock, "Leader election: another instance is leader");
                    if !sleep_or_stop(&shutdown, timing.retry).await {
                        break;
                    }
                    continue;
                }
                Some(Ok(LockProbe::Stale)) => {
                    match bounded(&shutdown, timeout, store.evict_stale(lock_id, stale_after))
                        .await
                    {
                        None => break,
                        Some(Ok(true)) => tracing::warn!(
                            %lock,
                            stale_secs = stale_after.as_secs(),
                            "Leader election: terminated a leader session that stopped renewing; taking over"
                        ),
                        Some(Ok(false)) => {}
                        Some(Err(error)) => tracing::warn!(
                            %lock, %error, "Leader election: stale leader eviction failed"
                        ),
                    }
                }
                Some(Err(error)) => {
                    tracing::warn!(%lock, %error, "Leader election: probe failed");
                    if !sleep_or_stop(&shutdown, timing.retry).await {
                        break;
                    }
                    continue;
                }
            }
        }

        let mut session = match bounded(&shutdown, timeout, store.open()).await {
            None => break,
            Some(Ok(session)) => session,
            Some(Err(error)) => {
                tracing::warn!(%lock, %error, "Leader election: failed to open dedicated connection");
                if !sleep_or_stop(&shutdown, timing.retry).await {
                    break;
                }
                continue;
            }
        };
        let acquired =
            match bounded(&shutdown, timeout, store.try_lock(&mut session, lock_id)).await {
                None => {
                    drop(session);
                    break;
                }
                Some(Ok(acquired)) => acquired,
                Some(Err(error)) => {
                    tracing::warn!(%lock, %error, "Leader election: lock query failed");
                    false
                }
            };
        if !acquired {
            // Drop closes the dedicated connection: no lock leak, and a standby
            // keeps no direct session between attempts.
            drop(session);
            tracing::debug!(%lock, retry_secs = timing.retry.as_secs(), "Leader election: not acquired");
            if !sleep_or_stop(&shutdown, timing.retry).await {
                break;
            }
            continue;
        }

        // Fenced: advance the epoch before any leader task can start.
        let epoch = match hooks.holder().map(str::to_owned) {
            None => 0,
            Some(holder) => {
                match bounded(&shutdown, timeout, store.bump_epoch(&mut session, lock_id, &holder))
                    .await
                {
                    None => {
                        drop(session);
                        break;
                    }
                    Some(Ok(epoch)) => epoch,
                    Some(Err(error)) => {
                        tracing::error!(%lock, %error, "Leader election: lease epoch bump failed; releasing the lock");
                        drop(session);
                        if !sleep_or_stop(&shutdown, timing.retry).await {
                            break;
                        }
                        continue;
                    }
                }
            }
        };

        // --- We are the leader ---
        tracing::info!(%lock, epoch, "Leader election: this instance is now the leader");
        // NAN-4933 (review P1): renew from the moment the epoch is acquired,
        // CONCURRENTLY with the elected hook. A slow scheduler startup (a
        // watermark load, a slow pool) must never leave the lock session idle
        // long enough for a standby to evict it as stale. If a renew fails
        // while the hook is still starting tasks, the fence closes at once
        // (fenced writes refuse) and startup is rolled back (stepped_down)
        // the moment the hook returns, before the lock is released.
        let fence = hooks.fence.as_ref().map(|(fence, _)| fence.clone());
        let cancelled = {
            let renewals = renew_until_lost(&store, &mut session, &lock, timing, &shutdown);
            tokio::pin!(renewals);
            let elected = hooks.elected(epoch);
            tokio::pin!(elected);
            tokio::select! {
                biased;
                () = &mut elected => renewals.await,
                cancelled = &mut renewals => {
                    if let Some(fence) = &fence {
                        fence.set(0);
                    }
                    if !cancelled {
                        tracing::error!(%lock, "Leader election: lease lost while leader tasks were starting; rolling them back");
                    }
                    elected.await;
                    cancelled
                }
            }
        };
        // Fencing: every leader-only task stops (and is awaited) BEFORE the
        // lock can pass to another instance.
        hooks.stepped_down().await;
        drop(session);
        if cancelled || shutdown.is_cancelled() {
            break 'election;
        }
        tracing::info!(%lock, retry_secs = timing.retry.as_secs(), "Leader election: leadership lost, will retry");
        if !sleep_or_stop(&shutdown, timing.retry).await {
            break;
        }
    }
    tracing::info!(%lock, "Leader election stopped and advisory lock released");
}

async fn hard_timeout<F: Future>(
    timeout: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(timeout, future).await
}

fn parse_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
#[path = "leader_tests.rs"]
mod tests;
