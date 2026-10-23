// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Postgres-backed writer lease of one tenant on one lake cell
//! (NAN-4052, full lake-cell HA).
//!
//! A lake cell runs two pods and exactly one of them runs the tenant's
//! writers. The pods' peer lease (`nanosiem_lake_cell::handover`) decides who
//! starts them, but two pods that cannot reach each other both claimed after
//! its TTL and fenced each other through the storage fences (edge-log DO
//! lease, part-log conditional create) in a restart loop. Data stayed safe,
//! ingest stalled.
//!
//! This lease is the authority (`public.lake_cell_writer_leases`, migration
//! 9013980), reached through the tenant's own `publish` data-path login (the
//! credential exchange's `erasure_ledger`; the database binds the tenant):
//!
//! - **acquire** before ingest opens the edge log or the part log. A lease
//!   held by another pod generation ends the process as *standby*
//!   ([`WriterStandby`], exit [`nanosiem_lake_cell::contract::WRITER_STANDBY_EXIT_CODE`]);
//!   the supervisor waits and retries without counting a crash, and nothing
//!   was opened that could fence the live writer.
//! - Every acquisition moves the **epoch** up; **renew** is a compare-and-set
//!   on `(holder, epoch)`, so a writer whose lease was taken can never extend
//!   it again.
//! - The writer may commit only while its **local deadline** holds: the
//!   instant a renew was *sent*, plus the TTL, minus a safety margin. The
//!   server set the expiry at or after that instant, so no other pod can
//!   acquire before the deadline passes. The part log checks it before every
//!   append ([`crate::parts::part_log::AppendGate`]); a failed CAS or a
//!   passed deadline makes the lease *lost* and ingest exits as standby.
//! - A graceful drain **releases** the lease (after the final flush) so the
//!   peer takes over within one poll instead of one TTL.
//!
//! Postgres unreachable for longer than the margin stops the writer
//! (fail closed); the edge log keeps the backlog, nothing is lost.

use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

/// Default lease TTL. The renew runs every TTL/4 and the writer stops at
/// TTL - TTL/5 after a renew was sent, so two consecutive failed renews are
/// absorbed.
pub const DEFAULT_TTL: Duration = Duration::from_secs(10);
/// Bounds the database accepts (`p_ttl_ms BETWEEN 1000 AND 600000`).
pub const MIN_TTL: Duration = Duration::from_secs(2);
pub const MAX_TTL: Duration = Duration::from_secs(600);
/// Every lease call is bounded (the renew must never outlive the deadline).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// The safety margin subtracted from the TTL for the local deadline (clock
/// rate drift, an append already in flight).
pub fn margin(ttl: Duration) -> Duration {
    (ttl / 5).max(Duration::from_millis(200))
}

/// How often the holder renews.
pub fn renew_every(ttl: Duration) -> Duration {
    (ttl / 4).max(Duration::from_millis(250))
}

/// Which lease, and who asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseKey {
    pub cell_id: String,
    /// The pod generation (`<cell>/<boot id>`).
    pub holder: String,
}

impl LeaseKey {
    /// The shapes the database accepts (`9013980`); anything else runs
    /// without a lease rather than failing every acquisition.
    pub fn valid(&self) -> bool {
        let cell_ok = !self.cell_id.is_empty()
            && self.cell_id.len() <= 128
            && self.cell_id.as_bytes()[0].is_ascii_alphanumeric()
            && self.cell_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        let holder_ok = !self.holder.is_empty()
            && self.holder.len() <= 160
            && self.holder.as_bytes()[0].is_ascii_alphanumeric()
            && self.holder.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/'));
        cell_ok && holder_ok
    }
}

/// What an acquisition found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acquire {
    Acquired { epoch: u64 },
    Held { holder: String, epoch: u64, remaining: Duration },
}

/// The lease table, behind its three accessors.
#[async_trait::async_trait]
pub trait LeaseStore: Send + Sync {
    /// Take the lease when it is free (expired) or already `key.holder`'s,
    /// with the next epoch.
    async fn acquire(&self, key: &LeaseKey, ttl: Duration) -> Result<Acquire>;
    /// Extend it while `(holder, epoch)` still own it; `false` = lost.
    async fn renew(&self, key: &LeaseKey, epoch: u64, ttl: Duration) -> Result<bool>;
    /// Expire it now while `(holder, epoch)` still own it.
    async fn release(&self, key: &LeaseKey, epoch: u64) -> Result<bool>;
}

/// Another pod generation holds the lease: this process stays standby.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterStandby {
    pub holder: String,
    pub epoch: u64,
    pub remaining: Duration,
}

impl std::fmt::Display for WriterStandby {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "writer lease held by {} (epoch {}, {} ms left); standing by", self.holder, self.epoch, self.remaining.as_millis())
    }
}

impl std::error::Error for WriterStandby {}

/// The lease this process held is gone (taken, expired locally, released).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseLost {
    pub epoch: u64,
    pub reason: String,
}

impl std::fmt::Display for LeaseLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "writer lease epoch {} lost: {}", self.epoch, self.reason)
    }
}

impl std::error::Error for LeaseLost {}

/// Whether `error` means "stop as standby" (the supervisor's quiet exit).
pub fn is_standby(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<WriterStandby>().is_some() || cause.downcast_ref::<LeaseLost>().is_some())
}

/// `undefined_function` (42883): the database predates migration 9013980,
/// so the cell writes on the peer lease alone (an image rolled before its
/// migration never wedges).
pub fn lease_functions_missing(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<sqlx::Error>().and_then(|e| e.as_database_error()).and_then(|e| e.code()).as_deref() == Some("42883")
    })
}

/// The outcome of one renew attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renewed {
    Ok,
    /// The CAS failed or the deadline passed: the lease is lost for good.
    Lost(String),
    /// The call failed; the lease holds until the deadline.
    Transient(String),
}

/// A held lease: the writer's epoch and its commit deadline.
pub struct WriterLease {
    key: LeaseKey,
    epoch: u64,
    ttl: Duration,
    store: Arc<dyn LeaseStore>,
    state: Mutex<State>,
}

struct State {
    valid_until: Instant,
    lost: Option<String>,
}

impl std::fmt::Debug for WriterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterLease").field("key", &self.key).field("epoch", &self.epoch).field("ttl", &self.ttl).finish_non_exhaustive()
    }
}

impl WriterLease {
    /// Acquire, or fail with [`WriterStandby`] when another generation holds it.
    pub async fn acquire(store: Arc<dyn LeaseStore>, key: LeaseKey, ttl: Duration) -> Result<Arc<Self>> {
        anyhow::ensure!((MIN_TTL..=MAX_TTL).contains(&ttl), "writer lease TTL {} ms out of range", ttl.as_millis());
        let sent = Instant::now();
        let outcome = tokio::time::timeout(CALL_TIMEOUT, store.acquire(&key, ttl))
            .await
            .context("writer lease acquire timed out")?
            .context("writer lease acquire")?;
        match outcome {
            Acquire::Acquired { epoch } => {
                tracing::info!(cell = %key.cell_id, holder = %key.holder, epoch, ttl_ms = ttl.as_millis() as u64, "writer lease acquired");
                Ok(Arc::new(Self { key, epoch, ttl, store, state: Mutex::new(State { valid_until: Self::deadline(sent, ttl), lost: None }) }))
            }
            Acquire::Held { holder, epoch, remaining } => Err(WriterStandby { holder, epoch, remaining }.into()),
        }
    }

    fn deadline(sent: Instant, ttl: Duration) -> Instant {
        sent + ttl.saturating_sub(margin(ttl))
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn key(&self) -> &LeaseKey {
        &self.key
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// May the writer commit now?
    pub fn check(&self) -> std::result::Result<(), LeaseLost> {
        let mut state = self.lock();
        if let Some(reason) = &state.lost {
            return Err(LeaseLost { epoch: self.epoch, reason: reason.clone() });
        }
        if Instant::now() >= state.valid_until {
            let reason = "not renewed before its deadline".to_string();
            state.lost = Some(reason.clone());
            return Err(LeaseLost { epoch: self.epoch, reason });
        }
        Ok(())
    }

    /// Why the lease is gone, if it is.
    pub fn lost(&self) -> Option<LeaseLost> {
        self.check().err()
    }

    fn mark_lost(&self, reason: &str) -> bool {
        let mut state = self.lock();
        if state.lost.is_some() {
            return false;
        }
        state.lost = Some(reason.to_string());
        true
    }

    /// One renew: CAS on `(holder, epoch)`; on success the deadline moves to
    /// `sent + ttl - margin`.
    pub async fn renew_once(&self) -> Renewed {
        if let Err(lost) = self.check() {
            return Renewed::Lost(lost.reason);
        }
        let sent = Instant::now();
        let result = tokio::time::timeout(CALL_TIMEOUT, self.store.renew(&self.key, self.epoch, self.ttl)).await;
        match result {
            Ok(Ok(true)) => {
                let mut state = self.lock();
                if state.lost.is_none() {
                    state.valid_until = state.valid_until.max(Self::deadline(sent, self.ttl));
                }
                Renewed::Ok
            }
            Ok(Ok(false)) => {
                let reason = "another pod generation took the lease".to_string();
                self.mark_lost(&reason);
                Renewed::Lost(reason)
            }
            Ok(Err(error)) => self.transient(format!("{error:#}")),
            Err(_) => self.transient("renew timed out".into()),
        }
    }

    fn transient(&self, error: String) -> Renewed {
        match self.check() {
            Ok(()) => Renewed::Transient(error),
            Err(lost) => Renewed::Lost(format!("{}; last renew error: {error}", lost.reason)),
        }
    }

    /// Renew every [`renew_every`] until the lease is lost or released;
    /// `on_lost` runs once with the reason (it is never called after a
    /// release).
    pub async fn run(self: Arc<Self>, on_lost: impl FnOnce(LeaseLost) + Send) {
        let every = renew_every(self.ttl);
        let mut failing = 0_u32;
        loop {
            tokio::time::sleep(every).await;
            match self.renew_once().await {
                Renewed::Ok => {
                    if failing > 0 {
                        tracing::info!(epoch = self.epoch, failures = failing, "writer lease renew recovered");
                    }
                    failing = 0;
                }
                Renewed::Transient(error) => {
                    failing += 1;
                    tracing::warn!(epoch = self.epoch, failures = failing, %error, "writer lease renew failed; holding until the deadline");
                }
                Renewed::Lost(reason) => {
                    if self.lock().lost.as_deref() == Some(RELEASED) {
                        return;
                    }
                    tracing::warn!(epoch = self.epoch, %reason, "writer lease lost; this writer stops");
                    on_lost(LeaseLost { epoch: self.epoch, reason });
                    return;
                }
            }
        }
    }

    /// Stop committing, then expire the lease so the peer takes over now.
    /// Best effort: a failed release only costs the peer one TTL.
    pub async fn release(&self) {
        if !self.mark_lost(RELEASED) {
            return;
        }
        match tokio::time::timeout(CALL_TIMEOUT, self.store.release(&self.key, self.epoch)).await {
            Ok(Ok(released)) => tracing::info!(epoch = self.epoch, released, "writer lease released"),
            Ok(Err(error)) => tracing::warn!(epoch = self.epoch, error = %format!("{error:#}"), "writer lease release failed; the peer waits one TTL"),
            Err(_) => tracing::warn!(epoch = self.epoch, "writer lease release timed out; the peer waits one TTL"),
        }
    }
}

const RELEASED: &str = "released on drain";

/// NAN-4129: the renewer of a held lease, started right after
/// [`WriterLease::acquire`], not when the ingest loop starts.
///
/// Ingest setup (SlateDB and prevalence opens, the edge-log open, the part
/// log load) can outlast the TTL on a slow node: on us-central-dfw-1 it took
/// about 9.2 s against an 8 s deadline. A renewer that only starts afterwards
/// lost every lease before the first renew. This one renews in the background
/// from the moment the lease is held, through setup and the run loop. It is
/// stopped by [`LeaseRenewer::stop`] or by dropping it, so a setup that fails
/// or is dropped takes its renewer down with it.
///
/// A loss is published once on [`LeaseRenewer::lost_signal`]. Setup races
/// against it ([`abort_setup_on_loss`]), and the run loop terminates on it. A
/// release never fires it.
pub struct LeaseRenewer {
    lease: Arc<WriterLease>,
    lost: tokio::sync::watch::Receiver<Option<LeaseLost>>,
    task: tokio::task::JoinHandle<()>,
    started: Instant,
}

impl std::fmt::Debug for LeaseRenewer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseRenewer").field("lease", &self.lease).field("finished", &self.task.is_finished()).finish_non_exhaustive()
    }
}

type RenewFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

impl LeaseRenewer {
    /// Start renewing on the cell refresh runtime (`cell_refresh`), like the
    /// credential refresher: a long merge on the ingest runtime never delays a
    /// renew past the deadline.
    pub fn start(lease: Arc<WriterLease>) -> Self {
        Self::start_with(lease, crate::cell_refresh::spawn_prioritized)
    }

    /// [`Self::start`] with an explicit spawner (tests: `tokio::spawn` on a
    /// paused clock).
    pub fn start_with(lease: Arc<WriterLease>, spawn: impl FnOnce(RenewFuture) -> tokio::task::JoinHandle<()>) -> Self {
        let (tx, lost) = tokio::sync::watch::channel(None);
        let task = spawn(Box::pin(lease.clone().run(move |lost| {
            let _ = tx.send(Some(lost));
        })));
        Self { lease, lost, task, started: Instant::now() }
    }

    pub fn lease(&self) -> &Arc<WriterLease> {
        &self.lease
    }

    /// How long ago the renewer started (about the time since acquisition).
    pub fn held_for(&self) -> Duration {
        self.started.elapsed()
    }

    /// Resolves with the loss once the renewer declares the lease lost. It
    /// stays pending forever after a release or once the renewer is stopped.
    /// The future is `'static`, so a setup that owns the renewer can still
    /// race against it.
    pub fn lost_signal(&self) -> impl std::future::Future<Output = LeaseLost> + Send + 'static {
        let mut lost = self.lost.clone();
        async move {
            // Clone out of the (non-Send) watch guard before any await.
            let seen = lost.wait_for(Option::is_some).await.ok().and_then(|value| value.clone());
            match seen {
                Some(lost) => lost,
                // The renewer ended without a loss (release, stop).
                None => std::future::pending().await,
            }
        }
    }

    /// A setup checkpoint: an error ([`LeaseLost`], a standby error) when
    /// the lease is gone, so nothing past `phase` runs without it.
    pub fn ensure_held(&self, phase: &str) -> Result<()> {
        self.lease.check().map_err(|lost| {
            tracing::warn!(epoch = lost.epoch, reason = %lost.reason, phase, "cell writer lease lost during ingest setup; aborting setup (standby)");
            anyhow::Error::from(lost)
        })
    }

    /// Stop renewing (teardown). The lease then lapses at its deadline
    /// unless it was released first.
    pub fn stop(&self) {
        self.task.abort();
    }

    /// Whether the renew task has ended (stopped, lost, or released).
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

impl Drop for LeaseRenewer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Run `setup` while `lost` (a [`LeaseRenewer::lost_signal`]) has not fired.
/// A loss drops the setup future at once (nothing past that point runs) and
/// returns a standby error ([`is_standby`]).
pub async fn abort_setup_on_loss<T>(
    lost: Option<impl std::future::Future<Output = LeaseLost>>,
    setup: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let Some(lost) = lost else { return setup.await };
    tokio::select! {
        biased;
        lost = lost => {
            tracing::warn!(epoch = lost.epoch, reason = %lost.reason, "cell writer lease lost during ingest setup; setup aborted (standby)");
            Err(lost.into())
        }
        result = setup => result,
    }
}

impl crate::parts::part_log::AppendGate for WriterLease {
    fn check_append(&self) -> Result<()> {
        self.check().map_err(anyhow::Error::from)
    }
}

/// [`LeaseStore`] on the tenant's `publish` data-path login.
pub struct PgLeaseStore {
    tenant_id: String,
    slot: super::lean_erasure::ErasureLedgerSlot,
    pool: Mutex<Option<(String, sqlx::PgPool)>>,
}

impl PgLeaseStore {
    pub fn new(tenant_id: &str, slot: super::lean_erasure::ErasureLedgerSlot) -> Self {
        Self { tenant_id: tenant_id.to_string(), slot, pool: Mutex::new(None) }
    }

    /// The pool for the current login (re-made when a refresh changed it).
    fn pool(&self) -> Result<sqlx::PgPool> {
        let credential = self.slot.get().context("no lake publish login delivered")?;
        credential.validate(&self.tenant_id, chrono::Utc::now())?;
        let mut guard = self.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((url, pool)) = guard.as_ref() {
            if *url == credential.database_url {
                return Ok(pool.clone());
            }
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .min_connections(0)
            .acquire_timeout(CALL_TIMEOUT)
            .idle_timeout(Duration::from_secs(120))
            .connect_lazy(&credential.database_url)
            .context("writer lease login unusable")?;
        *guard = Some((credential.database_url, pool.clone()));
        Ok(pool)
    }
}

fn ttl_ms(ttl: Duration) -> i32 {
    ttl.as_millis().clamp(MIN_TTL.as_millis(), MAX_TTL.as_millis()) as i32
}

// Every call runs on the cell refresh runtime (`cell_refresh::priority_runtime`),
// where the pool's connection lives too: a long merge on the ingest runtime
// never delays a renew past the deadline.
#[async_trait::async_trait]
impl LeaseStore for PgLeaseStore {
    async fn acquire(&self, key: &LeaseKey, ttl: Duration) -> Result<Acquire> {
        let (pool, key) = (self.pool()?, key.clone());
        crate::cell_refresh::run_prioritized(async move {
            let (acquired, epoch, holder, remaining_ms): (bool, i64, String, i64) =
                sqlx::query_as("SELECT acquired, epoch, holder, remaining_ms FROM nano_shared.acquire_lake_cell_writer_lease($1, $2, $3)")
                    .bind(&key.cell_id)
                    .bind(&key.holder)
                    .bind(ttl_ms(ttl))
                    .fetch_one(&pool)
                    .await
                    .context("acquire_lake_cell_writer_lease")?;
            let epoch = u64::try_from(epoch).ok().filter(|e| *e > 0).context("writer lease epoch is invalid")?;
            Ok(if acquired {
                Acquire::Acquired { epoch }
            } else {
                Acquire::Held { holder, epoch, remaining: Duration::from_millis(remaining_ms.max(0) as u64) }
            })
        })
        .await
    }

    async fn renew(&self, key: &LeaseKey, epoch: u64, ttl: Duration) -> Result<bool> {
        let (pool, key) = (self.pool()?, key.clone());
        crate::cell_refresh::run_prioritized(async move {
            sqlx::query_scalar("SELECT nano_shared.renew_lake_cell_writer_lease($1, $2, $3, $4)")
                .bind(&key.cell_id)
                .bind(&key.holder)
                .bind(epoch as i64)
                .bind(ttl_ms(ttl))
                .fetch_one(&pool)
                .await
                .context("renew_lake_cell_writer_lease")
        })
        .await
    }

    async fn release(&self, key: &LeaseKey, epoch: u64) -> Result<bool> {
        let (pool, key) = (self.pool()?, key.clone());
        crate::cell_refresh::run_prioritized(async move {
            sqlx::query_scalar("SELECT nano_shared.release_lake_cell_writer_lease($1, $2, $3)")
                .bind(&key.cell_id)
                .bind(&key.holder)
                .bind(epoch as i64)
                .fetch_one(&pool)
                .await
                .context("release_lake_cell_writer_lease")
        })
        .await
    }
}

/// An in-memory [`LeaseStore`] with the database's exact semantics, on the
/// tokio clock (tests pause it). `partition(holder)` makes every call of that
/// holder fail as if Postgres were unreachable from its pod.
#[derive(Default)]
pub struct MemLeaseStore {
    inner: Mutex<MemInner>,
}

#[derive(Default)]
struct MemInner {
    row: std::collections::HashMap<String, MemRow>,
    partitioned: std::collections::HashSet<String>,
}

#[derive(Clone)]
struct MemRow {
    holder: String,
    epoch: u64,
    expires_at: Instant,
}

impl MemLeaseStore {
    pub fn partition(&self, holder: &str, cut: bool) {
        let mut inner = self.inner.lock().unwrap();
        if cut {
            inner.partitioned.insert(holder.to_string());
        } else {
            inner.partitioned.remove(holder);
        }
    }

    fn reach(&self, holder: &str) -> Result<std::sync::MutexGuard<'_, MemInner>> {
        let inner = self.inner.lock().unwrap();
        anyhow::ensure!(!inner.partitioned.contains(holder), "connection refused (partitioned)");
        Ok(inner)
    }

    /// The current `(holder, epoch)` of a cell's lease.
    pub fn current(&self, cell: &str) -> Option<(String, u64)> {
        self.inner.lock().unwrap().row.get(cell).map(|r| (r.holder.clone(), r.epoch))
    }
}

#[async_trait::async_trait]
impl LeaseStore for MemLeaseStore {
    async fn acquire(&self, key: &LeaseKey, ttl: Duration) -> Result<Acquire> {
        let mut inner = self.reach(&key.holder)?;
        let now = Instant::now();
        let row = inner.row.get(&key.cell_id).cloned();
        match row {
            Some(row) if row.expires_at > now && row.holder != key.holder => {
                Ok(Acquire::Held { holder: row.holder, epoch: row.epoch, remaining: row.expires_at - now })
            }
            other => {
                let epoch = other.map_or(1, |row| row.epoch + 1);
                inner.row.insert(key.cell_id.clone(), MemRow { holder: key.holder.clone(), epoch, expires_at: now + ttl });
                Ok(Acquire::Acquired { epoch })
            }
        }
    }

    async fn renew(&self, key: &LeaseKey, epoch: u64, ttl: Duration) -> Result<bool> {
        let mut inner = self.reach(&key.holder)?;
        let now = Instant::now();
        match inner.row.get_mut(&key.cell_id) {
            Some(row) if row.holder == key.holder && row.epoch == epoch => {
                row.expires_at = now + ttl;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn release(&self, key: &LeaseKey, epoch: u64) -> Result<bool> {
        let mut inner = self.reach(&key.holder)?;
        let now = Instant::now();
        match inner.row.get_mut(&key.cell_id) {
            Some(row) if row.holder == key.holder && row.epoch == epoch && row.expires_at > now => {
                row.expires_at = now;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::AppendGate;

    const TTL: Duration = Duration::from_secs(10);

    fn key(holder: &str) -> LeaseKey {
        LeaseKey { cell_id: "cell-a".into(), holder: format!("cell-a/{holder}") }
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_cas_renew_and_steal_after_expiry() {
        let store = Arc::new(MemLeaseStore::default());
        let a = WriterLease::acquire(store.clone(), key("a"), TTL).await.unwrap();
        assert_eq!(a.epoch(), 1);
        // Held: the other pod stands by and learns who holds it.
        let err = WriterLease::acquire(store.clone(), key("b"), TTL).await.unwrap_err();
        assert!(is_standby(&err));
        let standby = err.downcast_ref::<WriterStandby>().unwrap();
        assert_eq!((standby.holder.as_str(), standby.epoch), ("cell-a/a", 1));
        // CAS renew: right holder + epoch only.
        assert_eq!(a.renew_once().await, Renewed::Ok);
        assert!(!store.renew(&key("b"), 1, TTL).await.unwrap(), "another holder cannot renew");
        assert!(!store.renew(&key("a"), 2, TTL).await.unwrap(), "a wrong epoch cannot renew");
        // A stops renewing: B takes it only after the server expiry, with the
        // next epoch, and A's next renew fails the CAS.
        tokio::time::advance(TTL - Duration::from_millis(1)).await;
        assert!(WriterLease::acquire(store.clone(), key("b"), TTL).await.is_err());
        tokio::time::advance(Duration::from_millis(2)).await;
        let b = WriterLease::acquire(store.clone(), key("b"), TTL).await.unwrap();
        assert_eq!(b.epoch(), 2);
        assert!(matches!(a.renew_once().await, Renewed::Lost(_)));
        assert!(a.check_append().is_err());
        assert!(b.check_append().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn the_same_pod_reacquires_with_a_new_epoch_and_fences_its_predecessor() {
        let store = Arc::new(MemLeaseStore::default());
        let old = WriterLease::acquire(store.clone(), key("a"), TTL).await.unwrap();
        let new = WriterLease::acquire(store.clone(), key("a"), TTL).await.unwrap();
        assert_eq!((old.epoch(), new.epoch()), (1, 2));
        assert!(matches!(old.renew_once().await, Renewed::Lost(_)), "the old generation cannot renew");
        assert_eq!(new.renew_once().await, Renewed::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn the_local_deadline_runs_out_before_anyone_else_can_acquire() {
        let store = Arc::new(MemLeaseStore::default());
        let a = WriterLease::acquire(store.clone(), key("a"), TTL).await.unwrap();
        store.partition("cell-a/a", true);
        // Renews fail transiently while the deadline holds...
        tokio::time::advance(renew_every(TTL)).await;
        assert!(matches!(a.renew_once().await, Renewed::Transient(_)));
        assert!(a.check().is_ok());
        // ...and the writer is stopped strictly before the server expiry.
        tokio::time::advance(TTL - margin(TTL) - renew_every(TTL)).await;
        assert!(a.check().is_err(), "deadline passed: no more commits");
        assert!(WriterLease::acquire(store.clone(), key("b"), TTL).await.is_err(), "server lease still live");
        tokio::time::advance(margin(TTL)).await;
        assert!(WriterLease::acquire(store.clone(), key("b"), TTL).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn release_hands_over_at_once_and_stops_commits() {
        let store = Arc::new(MemLeaseStore::default());
        let a = WriterLease::acquire(store.clone(), key("a"), TTL).await.unwrap();
        a.release().await;
        assert!(a.check_append().is_err());
        let b = WriterLease::acquire(store.clone(), key("b"), TTL).await.unwrap();
        assert_eq!(b.epoch(), 2);
    }

    /// Two pods that cannot see each other (the peer lease says "nobody
    /// writes" on both sides) both start ingest. Exactly one writes at any
    /// instant; the loser stands by instead of fencing, and when the holder
    /// itself loses Postgres the other takes over after one TTL with a higher
    /// epoch. No instant has two committers.
    #[tokio::test(start_paused = true)]
    async fn two_partitioned_pods_never_commit_at_once() {
        let store = Arc::new(MemLeaseStore::default());
        let lost_a = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a = WriterLease::acquire(store.clone(), key("a"), TTL).await.unwrap();
        tokio::spawn(a.clone().run({
            let lost_a = lost_a.clone();
            move |_| lost_a.store(true, std::sync::atomic::Ordering::SeqCst)
        }));
        let mut b: Option<Arc<WriterLease>> = None;
        let mut standby_attempts = 0;
        let step = Duration::from_millis(500);
        for tick in 0..240 {
            // At 30 s pod A loses Postgres (its node's network degrades).
            if tick == 60 {
                store.partition("cell-a/a", true);
            }
            // Pod B's supervisor retries ingest every 2 s while standby.
            if b.is_none() && tick % 4 == 0 {
                match WriterLease::acquire(store.clone(), key("b"), TTL).await {
                    Ok(lease) => b = Some(lease),
                    Err(error) => {
                        assert!(is_standby(&error));
                        standby_attempts += 1;
                    }
                }
            }
            if let Some(b) = &b {
                let _ = b.renew_once().await;
            }
            let committers = [a.check().is_ok(), b.as_ref().is_some_and(|b| b.check().is_ok())];
            assert!(committers.iter().filter(|c| **c).count() <= 1, "two committers at tick {tick}");
            tokio::time::advance(step).await;
            tokio::task::yield_now().await;
        }
        assert!(standby_attempts > 10, "B stood by while A held the lease");
        assert!(lost_a.load(std::sync::atomic::Ordering::SeqCst), "A noticed it lost the lease");
        let b = b.expect("B took over");
        assert_eq!(b.epoch(), 2);
        assert!(b.check().is_ok());
        assert_eq!(store.current("cell-a"), Some(("cell-a/b".into(), 2)));
    }

    /// Counts renew calls, delegating to [`MemLeaseStore`].
    #[derive(Default)]
    struct CountingStore {
        inner: MemLeaseStore,
        renews: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl LeaseStore for CountingStore {
        async fn acquire(&self, key: &LeaseKey, ttl: Duration) -> Result<Acquire> {
            self.inner.acquire(key, ttl).await
        }
        async fn renew(&self, key: &LeaseKey, epoch: u64, ttl: Duration) -> Result<bool> {
            self.renews.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.renew(key, epoch, ttl).await
        }
        async fn release(&self, key: &LeaseKey, epoch: u64) -> Result<bool> {
            self.inner.release(key, epoch).await
        }
    }

    const CELL_TTL: Duration = Duration::from_secs(8);

    async fn sleep_in_steps(total: Duration) {
        let step = Duration::from_millis(100);
        let mut left = total;
        while !left.is_zero() {
            let now = step.min(left);
            tokio::time::sleep(now).await;
            left -= now;
        }
    }

    /// NAN-4129: a setup that takes longer than the TTL (TX: ~9.2 s against
    /// 8 s) keeps the lease, because renewing starts at acquisition.
    #[tokio::test(start_paused = true)]
    async fn setup_slower_than_the_ttl_keeps_the_lease() {
        let store = Arc::new(MemLeaseStore::default());
        let lease = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
        let renewer = LeaseRenewer::start_with(lease.clone(), tokio::spawn);
        let wrote = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let setup = {
            let (renewer, wrote) = (&renewer, wrote.clone());
            async move {
                sleep_in_steps(Duration::from_millis(4_700)).await; // the state open
                renewer.ensure_held("prevalence open")?;
                sleep_in_steps(Duration::from_millis(4_500)).await; // the rest of setup
                renewer.ensure_held("setup done")?;
                renewer.lease().check_append()?;
                wrote.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        };
        abort_setup_on_loss(Some(renewer.lost_signal()), setup).await.expect("setup keeps the lease");
        assert!(wrote.load(std::sync::atomic::Ordering::SeqCst));
        // And it stays held well past several TTLs.
        sleep_in_steps(CELL_TTL * 3).await;
        assert!(lease.check().is_ok());
        assert_eq!(store.current("cell-a"), Some(("cell-a/a".into(), 1)));
        assert!(WriterLease::acquire(store.clone(), key("b"), CELL_TTL).await.is_err(), "the peer stays standby");
    }

    /// The pre-fix shape: a renewer started only after a 9.2 s setup loses
    /// the lease before its first renew.
    #[tokio::test(start_paused = true)]
    async fn a_renewer_started_after_slow_setup_is_too_late() {
        let store = Arc::new(MemLeaseStore::default());
        let lease = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
        sleep_in_steps(Duration::from_millis(9_200)).await;
        assert!(lease.check().is_err(), "deadline acquire + TTL - TTL/5 passed during setup");
    }

    /// A renew that fails during setup aborts setup before its write: the
    /// setup future is dropped, the error is a standby, nothing is written.
    #[tokio::test(start_paused = true)]
    async fn a_renew_failure_during_setup_aborts_without_writing() {
        let store = Arc::new(MemLeaseStore::default());
        let lease = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
        let renewer = LeaseRenewer::start_with(lease.clone(), tokio::spawn);
        // Postgres is unreachable from this pod for the whole setup.
        store.partition("cell-a/a", true);
        let wrote = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let setup = {
            let wrote = wrote.clone();
            let lease = lease.clone();
            async move {
                sleep_in_steps(Duration::from_secs(20)).await;
                // Only reached when not aborted; the gate also refuses.
                if lease.check_append().is_ok() {
                    wrote.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                wrote.fetch_add(100, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        };
        let started = Instant::now();
        let error = abort_setup_on_loss(Some(renewer.lost_signal()), setup).await.unwrap_err();
        assert!(is_standby(&error), "{error:#}");
        assert_eq!(wrote.load(std::sync::atomic::Ordering::SeqCst), 0, "setup never reached its write");
        assert!(started.elapsed() < Duration::from_secs(20), "aborted mid-setup, not after it");
        assert!(lease.check().is_err());
        assert!(renewer.ensure_held("after").is_err());
        // The loss was declared no later than one renew period plus one call
        // after the deadline, and strictly before the server expiry passed
        // for anyone else.
        assert!(started.elapsed() <= CELL_TTL - margin(CELL_TTL) + renew_every(CELL_TTL) + CALL_TIMEOUT);
    }

    /// The CAS failing during setup (another generation took the lease)
    /// aborts setup too.
    #[tokio::test(start_paused = true)]
    async fn a_lease_taken_during_setup_aborts_it() {
        let store = Arc::new(MemLeaseStore::default());
        let lease = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
        let renewer = LeaseRenewer::start_with(lease.clone(), tokio::spawn);
        // The same pod re-acquires (a newer generation): epoch 2 fences epoch 1.
        let _newer = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
        let setup = async {
            sleep_in_steps(Duration::from_secs(30)).await;
            Ok(())
        };
        let error = abort_setup_on_loss(Some(renewer.lost_signal()), setup).await.unwrap_err();
        assert!(is_standby(&error));
        assert!(error.to_string().contains("another pod generation"), "{error:#}");
    }

    /// Teardown (stop or drop) stops renewing: no more renew calls, and the
    /// lease lapses so the peer can take it after the TTL.
    #[tokio::test(start_paused = true)]
    async fn teardown_stops_the_renewer() {
        for drop_it in [false, true] {
            let store = Arc::new(CountingStore::default());
            let lease = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
            let renewer = LeaseRenewer::start_with(lease.clone(), tokio::spawn);
            sleep_in_steps(CELL_TTL).await;
            let renews = store.renews.load(std::sync::atomic::Ordering::SeqCst);
            assert!(renews >= 3, "renewing while held ({renews})");
            let lost = renewer.lost_signal();
            if drop_it {
                drop(renewer);
            } else {
                renewer.stop();
                tokio::task::yield_now().await;
                assert!(renewer.is_finished());
            }
            sleep_in_steps(CELL_TTL * 2).await;
            assert_eq!(store.renews.load(std::sync::atomic::Ordering::SeqCst), renews, "no renew after teardown");
            assert!(lease.check().is_err(), "the lease lapses at its deadline");
            let peer = WriterLease::acquire(store.clone(), key("b"), CELL_TTL).await.unwrap();
            assert_eq!(peer.epoch(), 2);
            // A stopped renewer never reports a loss.
            assert!(tokio::time::timeout(Duration::from_secs(1), lost).await.is_err());
        }
    }

    /// A release on drain never fires the loss signal.
    #[tokio::test(start_paused = true)]
    async fn a_release_does_not_signal_a_loss() {
        let store = Arc::new(MemLeaseStore::default());
        let lease = WriterLease::acquire(store.clone(), key("a"), CELL_TTL).await.unwrap();
        let renewer = LeaseRenewer::start_with(lease.clone(), tokio::spawn);
        let lost = renewer.lost_signal();
        lease.release().await;
        sleep_in_steps(CELL_TTL).await;
        assert!(renewer.is_finished());
        assert!(tokio::time::timeout(Duration::from_secs(1), lost).await.is_err());
    }

    #[test]
    fn keys_outside_the_database_shape_are_refused_locally() {
        assert!(key("0198f0c2-7b1e-7000-8000-000000000001").valid());
        assert!(!LeaseKey { cell_id: "cell a".into(), holder: "x".into() }.valid());
        assert!(!LeaseKey { cell_id: "cell-a".into(), holder: "".into() }.valid());
        assert!(!LeaseKey { cell_id: "-cell".into(), holder: "x".into() }.valid());
    }

    #[test]
    fn the_deadline_leaves_room_for_two_failed_renews() {
        for ttl in [Duration::from_secs(2), DEFAULT_TTL, Duration::from_secs(30)] {
            assert!(ttl - margin(ttl) >= renew_every(ttl) * 3, "{ttl:?}");
        }
    }
}
