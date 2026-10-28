// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL advisory lock-based leader election (a PG lease)
//!
//! Ensures exactly one replica runs leader-only tasks. Uses `pg_try_advisory_lock`
//! on a dedicated session: if the leader pod crashes, PostgreSQL closes the
//! session and releases the lock automatically, allowing another instance to
//! take over.
//!
//! Ownership uses the bounded direct-session pool and closes its checkout on
//! drop. It must never return a session still carrying a lock to an idle pool.
//!
//! Used by both the Jobs service (scheduler leadership) and the Search service
//! (active/standby traffic gating).
//!
//! # Lease mode (NAN-4699 step 4, jobs at two replicas)
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
//!   application pool (the transaction pool on 6432), so a standby holds NO
//!   direct session until it takes over. It opens one only when the lock is free.
//! - **stale holder**: a hard node loss leaves the holder's backend open until
//!   TCP notices (minutes to hours, and longer behind a proxy). A holder whose
//!   session has been idle (no renew) for `stale_after` (20 s: four times the
//!   self-fence bound, and above the 15 s renew interval of a pre-lease jobs
//!   image, so the first roll onto this image never evicts the old leader) is
//!   terminated with `pg_terminate_backend` (same login, so no extra
//!   privilege) and the standby takes the lock. Takeover after a hard death: at
//!   most `stale_after + retry + 2 x database_timeout` = 28 s.
//!   A graceful stop (roll, drain) or a crash with the node up closes the
//!   session at once: takeover within `retry` (2 s).
//!
//! The lease lives in PostgreSQL, not a Kubernetes Lease, on purpose: every
//! singleton it fences is PostgreSQL work, so PostgreSQL reachability is
//! exactly the condition under which a leader can make progress, and a
//! Kubernetes API outage (AU 2026-10-27, hours) neither stops the leader nor
//! lets a second one start.

use sqlx::PgPool;
use std::future::Future;
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
    /// NAN-4729: the hosted shared-schema convergence worker's leader
    /// (`NSCV` in the high 32 bits); the low 32 bits are the FNV-1a hash of
    /// the application region, so two regions that ever shared one database
    /// never stand by for each other. See [`shared_convergence`].
    pub const SHARED_CONVERGENCE_NAMESPACE: i64 = 0x4e53_4356;

    /// The convergence leader lock of `application_region`.
    pub fn shared_convergence(application_region: &str) -> i64 {
        let mut hash: u32 = 0x811c_9dc5;
        for byte in application_region.bytes() {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        (SHARED_CONVERGENCE_NAMESPACE << 32) | i64::from(hash)
    }
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
    /// eviction (the pre-NAN-4699 behavior, kept for search).
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
    /// NAN-4699 step 4: jobs' singleton lease (see the module docs).
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
        let secs = |key: &str, default: Duration| Duration::from_secs(parse_env(key, default.as_secs()));
        let overridden = Self {
            heartbeat: secs("LEADER_HEARTBEAT_SECS", self.heartbeat),
            database_timeout: secs("LEADER_HEARTBEAT_TIMEOUT_SECS", self.database_timeout).max(Duration::from_secs(1)),
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
    fn probe(&self, lock_id: i64, stale_after: Duration) -> impl Future<Output = Result<LockProbe, String>> + Send;
    /// Terminate the holder only if it is still idle for `stale_after`. `true` when one was signalled.
    fn evict_stale(&self, lock_id: i64, stale_after: Duration) -> impl Future<Output = Result<bool, String>> + Send;
    fn open(&self) -> impl Future<Output = Result<Self::Session, String>> + Send;
    fn try_lock(&self, session: &mut Self::Session, lock_id: i64) -> impl Future<Output = Result<bool, String>> + Send;
    fn renew(&self, session: &mut Self::Session) -> impl Future<Output = Result<(), String>> + Send;
}

/// What the election does on a change of leadership. `stepped_down` must not
/// return before every leader-only task has stopped: the lock is released only
/// after it returns.
pub trait LeaderHooks: Send + 'static {
    fn elected(&mut self) -> impl Future<Output = ()> + Send;
    fn stepped_down(&mut self) -> impl Future<Output = ()> + Send;
}

/// Leader election using PostgreSQL session-level advisory locks.
///
/// One instance holds the lock and acts as the leader; all others are standby.
pub struct LeaderElection {
    pool: PgPool,
    lock_id: i64,
    timing: LeaderTiming,
    session_pool: Option<PgPool>,
}

impl LeaderElection {
    pub fn new(pool: PgPool, lock_id: i64) -> Self {
        Self { pool, lock_id, timing: LeaderTiming::DEFAULT.with_env_overrides(), session_pool: None }
    }

    /// NAN-4729: hold the lock on sessions from this DIRECT pool (same login
    /// and database as `pool`, never the 6432 transaction pooler) instead of
    /// the process-wide `NANOSIEM_SESSION_DATABASE_URL` lane. For a process
    /// whose credentials are files, not URLs (the convergence worker).
    pub fn with_session_pool(mut self, session_pool: PgPool) -> Result<Self, String> {
        let direct = session_pool.connect_options();
        let app = self.pool.connect_options();
        if direct.get_port() == 6432 {
            return Err("leader session pool must be a direct session, not the transaction pooler".into());
        }
        if direct.get_host() != app.get_host()
            || direct.get_database() != app.get_database()
            || direct.get_username() != app.get_username()
        {
            return Err("leader session pool must use the application pool's endpoint, database and login".into());
        }
        self.session_pool = Some(session_pool);
        Ok(self)
    }

    /// Replace the timing (already env-resolved by the caller, if wanted).
    pub fn with_timing(mut self, timing: LeaderTiming) -> Self {
        self.timing = timing;
        self
    }

    pub fn timing(&self) -> LeaderTiming {
        self.timing
    }

    /// Spawn the election loop, reporting leadership on a `watch` channel.
    ///
    /// The returned handle resolves only after cancellation has closed the
    /// dedicated PostgreSQL connection and therefore released any advisory lock.
    ///
    /// Every dedicated-connection database operation is both cancellable on
    /// shutdown (NAN-1778 graceful shutdown) and hard-timeout bounded so a
    /// blackholed connection cannot pin leadership forever (NAN-1781 fencing).
    pub fn start(
        &self,
        shutdown: ShutdownToken,
    ) -> (watch::Receiver<bool>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = watch::channel(false);
        (rx, self.spawn_with(shutdown, WatchHooks(tx)))
    }

    /// Spawn the election loop with `hooks` run on every change of leadership
    /// (NAN-4699: the leader's tasks stop before its lock is released).
    pub fn spawn_with<H: LeaderHooks>(&self, shutdown: ShutdownToken, hooks: H) -> tokio::task::JoinHandle<()> {
        // In the staged/legacy direct deployment, leadership must not consume
        // the application's only checkout (a max-1 app pool would deadlock).
        // Pooled deployments share the explicit bounded session exception.
        let session_pool = if let Some(explicit) = &self.session_pool {
            explicit.clone()
        } else if self.pool.connect_options().get_port() == 6432 {
            self.pool.clone()
        } else {
            crate::db::connection_budget::pool_options(2)
                .acquire_timeout(self.pool.options().get_acquire_timeout())
                .connect_lazy_with((*self.pool.connect_options()).clone())
        };
        let store = PgLeaseStore { app_pool: self.pool.clone(), session_pool };
        match DrillSwitch::from_env(&self.timing) {
            Some(switch) => tokio::spawn(run_election(PartitionDrill::new(store, switch), self.lock_id, self.timing, shutdown, hooks)),
            None => tokio::spawn(run_election(store, self.lock_id, self.timing, shutdown, hooks)),
        }
    }
}

struct WatchHooks(watch::Sender<bool>);

impl LeaderHooks for WatchHooks {
    async fn elected(&mut self) {
        let _ = self.0.send(true);
    }
    async fn stepped_down(&mut self) {
        let _ = self.0.send(false);
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
    /// Ordinary application pool (the transaction pool on 6432): probes and evictions.
    app_pool: PgPool,
    /// Where the dedicated lock session comes from.
    session_pool: PgPool,
}

impl LeaseStore for PgLeaseStore {
    type Session = sqlx::pool::PoolConnection<sqlx::Postgres>;

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
            Some((Some(state), Some(quiet))) if state == "idle" && quiet >= stale_after.as_secs_f64() => LockProbe::Stale,
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
        crate::db::pooler::session_connection(&self.session_pool).await.map_err(|error| {
            crate::db::connection_budget::warn_connect_refusal(&error, "leader-election");
            error.to_string()
        })
    }

    async fn try_lock(&self, session: &mut Self::Session, lock_id: i64) -> Result<bool, String> {
        sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_id)
            .fetch_one(&mut **session)
            .await
            .map_err(|error| error.to_string())
    }

    async fn renew(&self, session: &mut Self::Session) -> Result<(), String> {
        sqlx::query("SELECT 1")
            .execute(&mut **session)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

// ---- NAN-4730: the coded one-node-loss drill hook (lease mode only). ----
//
// A hard node loss leaves the leader's lock session open server-side with the
// holder silent: no renew, no Terminate, no FIN. Nothing outside the process
// reproduces that on the region clusters: Calico (iptables dataplane) accepts
// RELATED,ESTABLISHED flows before any policy, so a deny policy never cuts the
// open lock session, and Kubernetes NetworkPolicy is allow-only anyway. Deleting
// a node is not a drill. So the drill switch lives here: while it is on, every
// election call toward PostgreSQL hangs (as on a partitioned node: the existing
// `database_timeout` bound turns the next renew into the self-fence), and a
// session the election drops is PARKED open instead of closed, so the server
// keeps the lock until the standby's stale eviction (`pg_terminate_backend`)
// removes it: exactly the path a dead node exercises.
//
// The switch is a file (`LEADER_DRILL_FILE`, a downward-API projection of ONE
// pod annotation, `nanosiem.io/leader-drill`), read on every election call:
//   `partition until=<unix seconds> id=<drill id>`
// It is on only before `until`, and never for a window longer than
// `LEADER_DRILL_MAX_WINDOW` from when the switch file was WRITTEN (its mtime,
// set by the kubelet's projection on this node's clock) or from now, so a drill
// whose operator vanished ends by itself, and a switch refused as too long never
// arms later as its `until` comes within reach (not even after a restart).
// Leader-only work is untouched by the switch: the election's own self-fence
// stops it, as it would on a real partition.

/// Env var naming the drill switch file. Unset: no drill hook at all.
pub const LEADER_DRILL_FILE_ENV: &str = "LEADER_DRILL_FILE";
/// Longest partition a switch may ask for; a longer one is refused (stays off).
pub const LEADER_DRILL_MAX_WINDOW: Duration = Duration::from_secs(300);

/// What the drill switch asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrillState {
    Off,
    Partition { id: String, until_unix: u64 },
}

/// Parse the switch content at `now_unix`, written (file mtime) at `written_unix`.
/// Empty (no annotation) or expired: `Off`.
pub fn parse_drill_switch(content: &str, now_unix: u64, written_unix: Option<u64>) -> Result<DrillState, String> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(DrillState::Off);
    }
    let mut words = content.split_whitespace();
    let (Some("partition"), Some(until), Some(id), None) = (words.next(), words.next(), words.next(), words.next()) else {
        return Err("expected `partition until=<unix seconds> id=<drill id>`".into());
    };
    let until_unix: u64 = until
        .strip_prefix("until=")
        .and_then(|value| value.parse().ok())
        .ok_or("until= must be unix seconds")?;
    let id = id.strip_prefix("id=").unwrap_or("");
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("id= must be 1-64 of [A-Za-z0-9_-]".into());
    }
    let Some(written_unix) = written_unix else {
        return Err("the switch file has no modification time".into());
    };
    if until_unix.saturating_sub(written_unix) > LEADER_DRILL_MAX_WINDOW.as_secs() {
        return Err(format!(
            "window {}s from when the switch was written exceeds {}s",
            until_unix.saturating_sub(written_unix),
            LEADER_DRILL_MAX_WINDOW.as_secs()
        ));
    }
    if until_unix <= now_unix {
        return Ok(DrillState::Off);
    }
    if until_unix - now_unix > LEADER_DRILL_MAX_WINDOW.as_secs() {
        return Err(format!("window {}s exceeds {}s", until_unix - now_unix, LEADER_DRILL_MAX_WINDOW.as_secs()));
    }
    Ok(DrillState::Partition { id: id.to_string(), until_unix })
}

/// The drill switch file and the wall clock its `until` is read against.
pub struct DrillSwitch {
    path: std::path::PathBuf,
    now_unix: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl DrillSwitch {
    pub fn new(path: impl Into<std::path::PathBuf>, now_unix: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self { path: path.into(), now_unix: Box::new(now_unix) }
    }

    /// Armed only in lease mode with `LEADER_DRILL_FILE` set (deployments render it on jobs only).
    pub fn from_env(timing: &LeaderTiming) -> Option<Self> {
        timing.stale_after?;
        let path = std::env::var(LEADER_DRILL_FILE_ENV).ok().filter(|path| !path.trim().is_empty())?;
        tracing::info!(%path, "Leader election drill hook armed (off until its switch is set)");
        Some(Self::new(path, || {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        }))
    }

    /// A missing or unreadable file is `Off` (no annotation projected yet).
    fn read(&self) -> (String, Result<DrillState, String>) {
        let content = std::fs::read_to_string(&self.path).unwrap_or_default();
        let written = std::fs::metadata(&self.path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let state = parse_drill_switch(&content, (self.now_unix)(), written);
        (content, state)
    }
}

#[derive(Default)]
struct DrillRuntime {
    /// The drill id while partitioned.
    engaged: Option<String>,
    /// Last switch content refused, so a bad switch is logged once.
    refused: Option<String>,
    /// Last role line: (leading, when). The drill reads the leader from recent lines, not from a rotated boot log.
    role: Option<(bool, tokio::time::Instant)>,
}

/// How often an armed hook restates its role (and at once on a change).
const DRILL_ROLE_EVERY: Duration = Duration::from_secs(60);

/// A [`LeaseStore`] with the drill switch in front (see the NAN-4730 notes above).
pub struct PartitionDrill<S: LeaseStore> {
    inner: S,
    switch: DrillSwitch,
    runtime: std::sync::Mutex<DrillRuntime>,
    engaged: std::sync::Arc<std::sync::atomic::AtomicBool>,
    parked: std::sync::Arc<std::sync::Mutex<Vec<S::Session>>>,
}

/// A lock session that is parked open, not closed, if dropped while partitioned.
pub struct DrillSession<T: Send + 'static> {
    inner: Option<T>,
    engaged: std::sync::Arc<std::sync::atomic::AtomicBool>,
    parked: std::sync::Arc<std::sync::Mutex<Vec<T>>>,
}

impl<T: Send + 'static> Drop for DrillSession<T> {
    fn drop(&mut self) {
        let Some(session) = self.inner.take() else { return };
        if self.engaged.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::warn!("Leader election drill: lock session parked open (no close sent)");
            self.parked.lock().unwrap_or_else(|e| e.into_inner()).push(session);
        }
    }
}

impl<S: LeaseStore> PartitionDrill<S> {
    pub fn new(inner: S, switch: DrillSwitch) -> Self {
        Self {
            inner,
            switch,
            runtime: std::sync::Mutex::new(DrillRuntime::default()),
            engaged: Default::default(),
            parked: Default::default(),
        }
    }

    /// Read the switch, log any transition, close parked sessions when it turns off. `true`: partitioned.
    fn partitioned(&self) -> bool {
        let (content, state) = self.switch.read();
        let mut runtime = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        let state = match state {
            Ok(state) => {
                runtime.refused = None;
                state
            }
            Err(error) => {
                if runtime.refused.as_deref() != Some(content.as_str()) {
                    tracing::warn!(%error, "Leader election drill: ignoring the drill switch");
                    runtime.refused = Some(content);
                }
                DrillState::Off
            }
        };
        match (state, runtime.engaged.clone()) {
            (DrillState::Partition { id, until_unix }, None) => {
                tracing::warn!(drill_id = %id, until_unix,
                    "Leader election drill: partition engaged; this instance goes silent toward PostgreSQL");
                self.engaged.store(true, std::sync::atomic::Ordering::SeqCst);
                runtime.engaged = Some(id);
                true
            }
            (DrillState::Partition { .. }, Some(_)) => true,
            (DrillState::Off, Some(id)) => {
                self.engaged.store(false, std::sync::atomic::Ordering::SeqCst);
                runtime.engaged = None;
                let parked = std::mem::take(&mut *self.parked.lock().unwrap_or_else(|e| e.into_inner()));
                tracing::info!(drill_id = %id, parked = parked.len(),
                    "Leader election drill: partition cleared; parked sessions closed");
                drop(parked);
                false
            }
            (DrillState::Off, None) => false,
        }
    }

    /// A renew is only ever made by the leader, a probe only by a standby: say which, at most once a minute.
    fn note_role(&self, leading: bool) {
        let mut runtime = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        let now = tokio::time::Instant::now();
        if matches!(runtime.role, Some((was, at)) if was == leading && now.duration_since(at) < DRILL_ROLE_EVERY) {
            return;
        }
        runtime.role = Some((leading, now));
        tracing::info!(role = if leading { "leader" } else { "standby" }, "Leader election drill hook: role");
    }

    /// A partitioned call never answers; the election's `database_timeout` bounds it.
    async fn reachable(&self) {
        if self.partitioned() {
            std::future::pending::<()>().await;
        }
    }
}

impl<S: LeaseStore> LeaseStore for PartitionDrill<S> {
    type Session = DrillSession<S::Session>;

    async fn probe(&self, lock_id: i64, stale_after: Duration) -> Result<LockProbe, String> {
        self.reachable().await;
        self.note_role(false);
        self.inner.probe(lock_id, stale_after).await
    }

    async fn evict_stale(&self, lock_id: i64, stale_after: Duration) -> Result<bool, String> {
        self.reachable().await;
        self.inner.evict_stale(lock_id, stale_after).await
    }

    async fn open(&self) -> Result<Self::Session, String> {
        self.reachable().await;
        let session = self.inner.open().await?;
        Ok(DrillSession { inner: Some(session), engaged: self.engaged.clone(), parked: self.parked.clone() })
    }

    async fn try_lock(&self, session: &mut Self::Session, lock_id: i64) -> Result<bool, String> {
        self.reachable().await;
        let inner = session.inner.as_mut().ok_or("drill session already released")?;
        self.inner.try_lock(inner, lock_id).await
    }

    async fn renew(&self, session: &mut Self::Session) -> Result<(), String> {
        self.reachable().await;
        self.note_role(true);
        let inner = session.inner.as_mut().ok_or("drill session already released")?;
        self.inner.renew(inner).await
    }
}

/// Sleep unless shutdown is requested first; `false` = stop.
async fn sleep_or_stop(shutdown: &ShutdownToken, duration: Duration) -> bool {
    shutdown.run_until_cancelled(tokio::time::sleep(duration)).await.is_some()
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
        .map(|result| result.unwrap_or_else(|_| Err(format!("timed out after {}s", timeout.as_secs()))))
}

/// The election loop. Leadership ends on a failed or late renew, or on
/// shutdown; either way `hooks.stepped_down()` completes before the session
/// holding the lock is dropped.
pub async fn run_election<S: LeaseStore, H: LeaderHooks>(
    store: S,
    lock_id: i64,
    timing: LeaderTiming,
    shutdown: ShutdownToken,
    mut hooks: H,
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
                    match bounded(&shutdown, timeout, store.evict_stale(lock_id, stale_after)).await {
                        None => break,
                        Some(Ok(true)) => tracing::warn!(
                            %lock,
                            stale_secs = stale_after.as_secs(),
                            "Leader election: terminated a leader session that stopped renewing; taking over"
                        ),
                        Some(Ok(false)) => {}
                        Some(Err(error)) => tracing::warn!(%lock, %error, "Leader election: stale leader eviction failed"),
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
        let acquired = match bounded(&shutdown, timeout, store.try_lock(&mut session, lock_id)).await {
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

        // --- We are the leader ---
        tracing::info!(%lock, "Leader election: this instance is now the leader");
        hooks.elected().await;
        let cancelled = loop {
            if !sleep_or_stop(&shutdown, timing.heartbeat).await {
                break true;
            }
            match bounded(&shutdown, timeout, store.renew(&mut session)).await {
                None => break true,
                Some(Ok(())) => tracing::trace!(%lock, "Leader election: renewed"),
                Some(Err(error)) => {
                    tracing::error!(%lock, %error, "Leader election: renew failed; stepping down");
                    break false;
                }
            }
        };
        // NAN-4699 fencing: every leader-only task stops (and is awaited)
        // BEFORE the lock can pass to another instance.
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
mod tests {
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
        // 0x4e53_4c45_4144: classid 0x4e53, objid 0x4c45_4144.
        assert_eq!(lock_key_parts(lock_ids::API_SCHEDULER), (0x4e53, 0x4c45_4144));
        // objid is an unsigned 32-bit oid.
        assert_eq!(lock_key_parts(0x1_ffff_ffff), (1, 0xffff_ffff));
    }

    #[test]
    fn shared_convergence_lock_is_per_region_and_outside_other_ids() {
        let east = lock_ids::shared_convergence("us-east-iad-1-prod");
        let uk = lock_ids::shared_convergence("uk-lon-1");
        assert_ne!(east, uk);
        assert_eq!(east, lock_ids::shared_convergence("us-east-iad-1-prod"));
        assert_eq!(lock_key_parts(east).0, lock_ids::SHARED_CONVERGENCE_NAMESPACE);
        assert!(east > 0);
        for other in [lock_ids::API_SCHEDULER, lock_ids::SEARCH_ACTIVE, lock_ids::SIGNAL_PROCESSOR, lock_ids::DISK_PRESSURE] {
            assert_ne!(lock_key_parts(other).0, lock_ids::SHARED_CONVERGENCE_NAMESPACE);
        }
        // FNV-1a("") is the offset basis.
        assert_eq!(lock_ids::shared_convergence("") & 0xffff_ffff, 0x811c_9dc5);
    }

    #[tokio::test]
    async fn explicit_session_pool_must_be_direct_and_same_identity() {
        let pool_at = |port: u16, user: &str| {
            PgPoolOptions::new().connect_lazy_with(
                sqlx::postgres::PgConnectOptions::new().host("db.invalid").port(port).username(user).database("nano"),
            )
        };
        let pooled_app = pool_at(6432, "nano_shared_convergence_worker");
        assert!(LeaderElection::new(pooled_app.clone(), 7)
            .with_session_pool(pool_at(6432, "nano_shared_convergence_worker"))
            .is_err());
        assert!(LeaderElection::new(pooled_app.clone(), 7)
            .with_session_pool(pool_at(5432, "nano_shared_provider_adapter"))
            .is_err());
        assert!(LeaderElection::new(pooled_app, 7)
            .with_session_pool(pool_at(5432, "nano_shared_convergence_worker"))
            .is_ok());
    }

    #[test]
    fn jobs_lease_bounds() {
        let t = LeaderTiming::JOBS;
        t.validate().unwrap();
        assert_eq!(t.self_fence_bound(), Duration::from_secs(5));
        // Takeover after a hard death stays under the 30 s target.
        assert!(t.takeover_bound().unwrap() <= Duration::from_secs(30), "{:?}", t.takeover_bound());
        // The old leader fences itself well before anyone may evict it.
        assert!(t.stale_after.unwrap() >= t.self_fence_bound() * 2);
        // A pre-lease jobs leader renews every 15 s (DEFAULT): during the first
        // roll the new standby must never see it as stale.
        assert!(t.stale_after.unwrap() > LeaderTiming::DEFAULT.heartbeat + Duration::from_secs(2));
        // Search keeps its pre-lease behavior.
        assert_eq!(LeaderTiming::DEFAULT.stale_after, None);
        LeaderTiming::DEFAULT.validate().unwrap();
        let unsafe_stale = LeaderTiming { stale_after: Some(Duration::from_secs(6)), ..LeaderTiming::JOBS };
        assert!(unsafe_stale.validate().is_err());
    }

    // ---- A fake lock table with a fake clock (tokio paused time). ----

    #[derive(Default)]
    struct FakeDb {
        /// (session id, last renew) of the holder, as the server sees it.
        holder: Option<(u64, Instant)>,
        next_session: u64,
        terminated: HashSet<u64>,
        evictions: usize,
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
            Self { db: Arc::clone(db), partitioned: Arc::new(AtomicBool::new(false)) }
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
            Ok(FakeSession { id: db.next_session, db: Arc::clone(&self.db), partitioned: Arc::clone(&self.partitioned) })
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
    }

    /// Records when each instance's singletons start and stop, and how many run at once.
    #[derive(Clone, Default)]
    struct Ledger {
        events: Arc<Mutex<Vec<(&'static str, &'static str, Instant)>>>,
        running: Arc<AtomicUsize>,
        max_running: Arc<AtomicUsize>,
    }

    impl Ledger {
        fn at(&self, who: &str, what: &str) -> Option<Instant> {
            self.events.lock().unwrap().iter().find(|(w, e, _)| *w == who && *e == what).map(|(_, _, t)| *t)
        }
    }

    struct Singletons {
        who: &'static str,
        ledger: Ledger,
        leading: Arc<AtomicBool>,
    }

    impl LeaderHooks for Singletons {
        async fn elected(&mut self) {
            let now = self.ledger.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.ledger.max_running.fetch_max(now, Ordering::SeqCst);
            self.leading.store(true, Ordering::SeqCst);
            self.ledger.events.lock().unwrap().push((self.who, "start", Instant::now()));
        }
        async fn stepped_down(&mut self) {
            self.ledger.running.fetch_sub(1, Ordering::SeqCst);
            self.leading.store(false, Ordering::SeqCst);
            self.ledger.events.lock().unwrap().push((self.who, "stop", Instant::now()));
        }
    }

    struct Instance {
        store: FakeStore,
        shutdown: ShutdownToken,
        leading: Arc<AtomicBool>,
        handle: tokio::task::JoinHandle<()>,
    }

    fn spawn_instance(who: &'static str, db: &Arc<Mutex<FakeDb>>, ledger: &Ledger) -> Instance {
        let store = FakeStore::new(db);
        let shutdown = ShutdownToken::new();
        let leading = Arc::new(AtomicBool::new(false));
        let hooks = Singletons { who, ledger: ledger.clone(), leading: Arc::clone(&leading) };
        let handle = tokio::spawn(run_election(store.clone(), 7, LeaderTiming::JOBS, shutdown.clone(), hooks));
        Instance { store, shutdown, leading, handle }
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
        // A's node is lost / partitioned: its renews hang and its session never
        // closes server-side (the TCP peer is gone).
        let cut = Instant::now();
        a.store.partitioned.store(true, Ordering::SeqCst);
        let b_leading = Arc::clone(&b.leading);
        let took = advance_until(Duration::from_secs(30), || b_leading.load(Ordering::SeqCst)).await;

        let a_stop = ledger.at("A", "stop").expect("A fenced itself");
        let b_start = ledger.at("B", "start").expect("B took over");
        // A stops its singletons within heartbeat + timeout of its last renew.
        assert!(a_stop.duration_since(cut) <= LeaderTiming::JOBS.self_fence_bound(), "{:?}", a_stop.duration_since(cut));
        // B starts only after A stopped, and within the takeover bound.
        assert!(b_start > a_stop);
        // The fence comes well before the eviction (15 s nominal), not merely first.
        assert!(b_start.duration_since(a_stop) >= Duration::from_secs(10), "margin {:?}", b_start.duration_since(a_stop));
        assert!(took <= LeaderTiming::JOBS.takeover_bound().unwrap(), "took {took:?}");
        assert!(took >= LeaderTiming::JOBS.stale_after.unwrap() - LeaderTiming::JOBS.heartbeat);
        assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1, "two leaders ran singletons at once");
        assert_eq!(db.lock().unwrap().evictions, 1);
        assert!(!a.leading.load(Ordering::SeqCst));

        // A stays fenced: it never leads again while B holds the lease.
        a.store.partitioned.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(!a.leading.load(Ordering::SeqCst));
        assert!(b.leading.load(Ordering::SeqCst));
        assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn graceful_stop_hands_over_within_one_retry_after_tasks_stop() {
        let (_db, ledger, a, b) = leader_and_standby().await;
        let stopped = Instant::now();
        a.shutdown.cancel();
        a.handle.await.unwrap();
        let b_leading = Arc::clone(&b.leading);
        let took = advance_until(Duration::from_secs(30), || b_leading.load(Ordering::SeqCst)).await;
        assert!(took <= LeaderTiming::JOBS.retry + Duration::from_millis(200), "took {took:?}");
        assert!(ledger.at("A", "stop").unwrap() >= stopped);
        assert!(ledger.at("B", "start").unwrap() >= ledger.at("A", "stop").unwrap());
        assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);
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
        // AU 2026-10-27: the Kubernetes API was down for hours while PostgreSQL
        // stayed up. Leadership depends on PostgreSQL only, so the leader keeps
        // running its singletons and the standby never starts a second set.
        let (db, ledger, a, b) = leader_and_standby().await;
        tokio::time::sleep(Duration::from_secs(4 * 3600)).await;
        assert!(a.leading.load(Ordering::SeqCst));
        assert!(!b.leading.load(Ordering::SeqCst));
        assert_eq!(db.lock().unwrap().evictions, 0);
        assert_eq!(ledger.events.lock().unwrap().len(), 1);
    }

    // ---- NAN-4730: the drill switch, through the production wrapper. ----

    const DRILL_NOW: u64 = 1_800_000_000;

    struct DrillInstance {
        leading: Arc<AtomicBool>,
        switch: tempfile::NamedTempFile,
        clock: Arc<std::sync::atomic::AtomicU64>,
        _shutdown: ShutdownToken,
    }

    fn spawn_drill_instance(who: &'static str, db: &Arc<Mutex<FakeDb>>, ledger: &Ledger) -> DrillInstance {
        let switch = tempfile::NamedTempFile::new().unwrap();
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(DRILL_NOW));
        let read_clock = Arc::clone(&clock);
        let store = PartitionDrill::new(
            FakeStore::new(db),
            DrillSwitch::new(switch.path(), move || read_clock.load(Ordering::SeqCst)),
        );
        let shutdown = ShutdownToken::new();
        let leading = Arc::new(AtomicBool::new(false));
        let hooks = Singletons { who, ledger: ledger.clone(), leading: Arc::clone(&leading) };
        tokio::spawn(run_election(store, 7, LeaderTiming::JOBS, shutdown.clone(), hooks));
        DrillInstance { leading, switch, clock, _shutdown: shutdown }
    }

    /// Write the switch as the kubelet's projection does: content, mtime = this instance's clock.
    fn set_switch(instance: &DrillInstance, content: &str) {
        std::fs::write(instance.switch.path(), content).unwrap();
        let written = std::time::UNIX_EPOCH + Duration::from_secs(instance.clock.load(Ordering::SeqCst));
        std::fs::File::options().write(true).open(instance.switch.path()).unwrap().set_modified(written).unwrap();
    }

    async fn drill_leader_and_standby() -> (Arc<Mutex<FakeDb>>, Ledger, DrillInstance, DrillInstance) {
        let db = Arc::new(Mutex::new(FakeDb::default()));
        let ledger = Ledger::default();
        let a = spawn_drill_instance("A", &db, &ledger);
        let leading = Arc::clone(&a.leading);
        advance_until(Duration::from_secs(1), || leading.load(Ordering::SeqCst)).await;
        let b = spawn_drill_instance("B", &db, &ledger);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(a.leading.load(Ordering::SeqCst) && !b.leading.load(Ordering::SeqCst));
        assert_eq!(db.lock().unwrap().evictions, 0, "an off switch changes nothing");
        (db, ledger, a, b)
    }

    #[tokio::test(start_paused = true)]
    async fn drill_partition_holds_the_session_open_and_the_standby_evicts_it() {
        let (db, ledger, a, b) = drill_leader_and_standby().await;
        let cut = Instant::now();
        set_switch(&a, &format!("partition until={} id=nan4730-t1\n", DRILL_NOW + 120));
        let b_leading = Arc::clone(&b.leading);
        let took = advance_until(Duration::from_secs(40), || b_leading.load(Ordering::SeqCst)).await;

        let a_stop = ledger.at("A", "stop").expect("A fenced itself");
        let b_start = ledger.at("B", "start").expect("B took over");
        // Engaged at A's next renew (within one heartbeat), fenced by that renew's timeout.
        assert!(a_stop.duration_since(cut) <= LeaderTiming::JOBS.heartbeat + LeaderTiming::JOBS.self_fence_bound());
        assert!(b_start > a_stop);
        // The session stayed open: B had to evict it (a closed session would hand over within one retry).
        assert_eq!(db.lock().unwrap().evictions, 1);
        assert!(took >= LeaderTiming::JOBS.stale_after.unwrap() - LeaderTiming::JOBS.heartbeat, "took {took:?}");
        assert!(took <= LeaderTiming::JOBS.takeover_bound().unwrap() + LeaderTiming::JOBS.heartbeat, "took {took:?}");
        assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1, "two leaders ran singletons at once");

        // Restore: A closes its parked session, rejoins as a standby and never leads while B holds.
        set_switch(&a, "");
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(!a.leading.load(Ordering::SeqCst));
        assert!(b.leading.load(Ordering::SeqCst));
        assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);
        assert_eq!(db.lock().unwrap().evictions, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn drill_partition_ends_by_itself_at_until() {
        let (db, _ledger, a, b) = drill_leader_and_standby().await;
        set_switch(&a, &format!("partition until={} id=nan4730-t2", DRILL_NOW + 30));
        let b_leading = Arc::clone(&b.leading);
        advance_until(Duration::from_secs(40), || b_leading.load(Ordering::SeqCst)).await;
        // The operator vanished: the window passes and A rejoins with no one clearing the switch.
        a.clock.store(DRILL_NOW + 31, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(!a.leading.load(Ordering::SeqCst) && b.leading.load(Ordering::SeqCst));
        // A probes again (its calls answer): the next eviction count stays 1 and B keeps renewing.
        assert_eq!(db.lock().unwrap().evictions, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bad_drill_switch_changes_nothing() {
        let (db, ledger, a, b) = drill_leader_and_standby().await;
        for bad in [
            format!("partition until={} id=x", DRILL_NOW + 301),   // window too long
            format!("partition until={} id=x", DRILL_NOW - 1),     // expired
            format!("partition until={} id=bad/id", DRILL_NOW + 60),
            "partition".to_string(),
            "freeze until=1 id=x".to_string(),
        ] {
            set_switch(&a, &bad);
            tokio::time::sleep(Duration::from_secs(40)).await;
        }
        assert!(a.leading.load(Ordering::SeqCst) && !b.leading.load(Ordering::SeqCst));
        assert_eq!(db.lock().unwrap().evictions, 0);
        assert_eq!(ledger.events.lock().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_switch_refused_as_too_long_never_arms_later() {
        let (db, ledger, a, b) = drill_leader_and_standby().await;
        set_switch(&a, &format!("partition until={} id=stale", DRILL_NOW + 600));
        tokio::time::sleep(Duration::from_secs(10)).await;
        // 400 s later `until` is 200 s away: still refused (it was written asking for 600 s).
        a.clock.store(DRILL_NOW + 400, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(a.leading.load(Ordering::SeqCst) && !b.leading.load(Ordering::SeqCst));
        assert_eq!(db.lock().unwrap().evictions, 0);
        assert_eq!(ledger.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn drill_switch_grammar() {
        let now = DRILL_NOW;
        let w = Some(now);
        assert_eq!(parse_drill_switch("", now, w), Ok(DrillState::Off));
        assert_eq!(parse_drill_switch("  \n", now, None), Ok(DrillState::Off));
        assert_eq!(
            parse_drill_switch(&format!("partition until={} id=NAN-4730_a1", now + 300), now, w),
            Ok(DrillState::Partition { id: "NAN-4730_a1".into(), until_unix: now + 300 })
        );
        assert_eq!(parse_drill_switch(&format!("partition until={now} id=a"), now, w), Ok(DrillState::Off));
        assert!(parse_drill_switch(&format!("partition until={} id=a", now + 301), now, w).is_err());
        assert!(parse_drill_switch(&format!("partition until={} id=a extra", now + 10), now, w).is_err());
        assert!(parse_drill_switch(&format!("partition id=a until={}", now + 10), now, w).is_err());
        assert!(parse_drill_switch(&format!("partition until={} id={}", now + 10, "a".repeat(65)), now, w).is_err());
        // The window counts from when the switch was written, not only from now.
        assert!(parse_drill_switch(&format!("partition until={} id=a", now + 100), now, Some(now - 250)).is_err());
        assert!(parse_drill_switch(&format!("partition until={} id=a", now + 100), now, None).is_err());
        // A switch from the future (clock skew) still never exceeds the window from now.
        assert!(parse_drill_switch(&format!("partition until={} id=a", now + 400), now, Some(now + 200)).is_err());
    }

    #[test]
    fn drill_hook_is_lease_mode_only() {
        // Search's DEFAULT timing never arms it, whatever the env says.
        assert!(DrillSwitch::from_env(&LeaderTiming::DEFAULT).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn the_standby_holds_no_session_between_probes() {
        let (db, _ledger, _a, _b) = leader_and_standby().await;
        // Only A's session was ever opened: B probes over the application pool
        // and opens a direct session only when the lock is free.
        assert_eq!(db.lock().unwrap().next_session, 1);
    }
}
