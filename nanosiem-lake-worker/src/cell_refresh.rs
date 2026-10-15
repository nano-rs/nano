// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential refresh for long-running lean-cell children (NAN-3017).
//!
//! Every tenant process gets its storage/bearer credentials from the cell
//! credential exchange, and every one of them expires (R2 read credentials
//! after `LAKE_CELL_CREDENTIAL_TTL_SECONDS`, 6 h by default; owner bearers
//! after 10 min). A process that lives longer than its credential must
//! re-exchange: it asks the supervisor for a fresh single-use bootstrap token
//! (`ControlChannel::request_secrets`), the supervisor answers with
//! `Event::Secrets`, and the service's `TenantService::secrets` hook runs the
//! exchange and swaps the result into its live stores.
//!
//! [`CredentialRefresher`] is the one scheduler for that loop, shared by
//! `ingest[T]`, `query[T]` and `detect[T]`:
//! - a refresh is due at [`REFRESH_AT_FRACTION`] of the credential lifetime;
//! - transient failures use jittered backoff until expiry; a 401/403 is final;
//! - a reader that was refused by the store (`PermissionDenied`) asks for an
//!   immediate refresh ([`CredentialRefresher::request_now`]) and waits for
//!   the next credential generation ([`CredentialRefresher::wait_newer`]);
//! - past the expiry safety margin, [`CredentialRefresher::run`] returns
//!   an error so the process exits and the supervisor respawns it with a
//!   fresh bootstrap (the manual mitigation, automated);
//! - an owner `lake-parts:sign` 401 (`cell_bearer_expired`) is the signer's
//!   `PermissionDenied`: [`RefreshingSigner`] asks for an immediate refresh,
//!   waits for it and retries the sign once.
//!
//! The scheduler and the exchange that answers it must run CONCURRENTLY with
//! the work that uses the credential. detect[T] once polled both only between
//! finding drains, so a drain longer than 2/3 of the 600 s owner bearer
//! signed with the expired startup bearer (401) and killed the process.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::part_ingest::cell::{OwnerSignRefused, EXPIRY_SKEW, REFRESH_ANSWER_TIMEOUT, REFRESH_AT_FRACTION, REFRESH_BACKOFF_S};
use crate::parts::provenance::{Ed25519Signature, PartSigner, ProvenanceRecord};

/// The supervisor's minimum spacing between two mints for one process
/// (`nanosiem_lake_cell::supervisor::REFRESH_MIN_INTERVAL`). A request inside
/// it is dropped by the supervisor, so an urgent request waits it out.
pub const SUPERVISOR_REFRESH_MIN_INTERVAL: chrono::Duration = chrono::Duration::seconds(60);

/// How often the refresher re-checks its schedule without a wake.
const POLL: Duration = Duration::from_secs(5);

/// The owner's ceiling on an owner bearer's lifetime
/// (the platform `LAKE_CELL_OWNER_SIGN_MAX_TTL_SECONDS`): no `lake-parts:sign`
/// or `lake-parts:delete` bearer verifies longer than this after its mint.
pub const OWNER_BEARER_MAX_LIFETIME: chrono::Duration = chrono::Duration::seconds(600);

/// The schedule for an owner bearer whose exchange named no usable
/// `expires_at`: treated as living 450 s, so it is re-exchanged every 225 s.
pub const OWNER_BEARER_FALLBACK_LIFETIME: chrono::Duration = chrono::Duration::seconds(450);

/// How long a signer refused with 401 waits for the urgent re-exchange: the
/// supervisor's mint spacing, a lost-answer timeout and the exchange itself.
pub const URGENT_REFRESH_WAIT: Duration = Duration::from_secs(60 + 90 + 15);

/// When an owner bearer (`owner_sign` / `owner_delete`) must be treated as
/// expired, from the exchange's `expires_at` taken at receipt (`now`).
/// Absent or unparseable: [`OWNER_BEARER_FALLBACK_LIFETIME`]. Never later
/// than [`OWNER_BEARER_MAX_LIFETIME`] from now, whatever the exchange says:
/// the owner refuses such a bearer by then anyway.
pub fn owner_bearer_expiry(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(at) => at.with_timezone(&chrono::Utc).min(now + OWNER_BEARER_MAX_LIFETIME),
        Err(_) => {
            tracing::warn!(expires_at, "owner bearer has no usable expires_at; re-exchanging on the conservative schedule");
            now + OWNER_BEARER_FALLBACK_LIFETIME
        }
    }
}

/// The credential refresh's own OS thread and current-thread runtime.
///
/// The exchange POST and the refresh schedule must never wait behind the
/// tenant's work: on ingest's two-worker runtime a CPU-heavy task (the
/// lake-part GC fold, a lean test tenant 2026-09-29) delayed the exchange POST
/// by minutes after the supervisor minted the 180 s bootstrap token, so the
/// token expired, the owner-sign bearer lapsed and ingest wedged. `None`
/// only if the thread could not be started (then callers run inline).
pub fn priority_runtime() -> Option<&'static tokio::runtime::Handle> {
    static RUNTIME: std::sync::OnceLock<Option<tokio::runtime::Handle>> = std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel();
            let spawned = std::thread::Builder::new().name("cell-refresh".into()).spawn(move || {
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => {
                        let _ = tx.send(Some(runtime.handle().clone()));
                        // Process lifetime.
                        runtime.block_on(std::future::pending::<()>());
                    }
                    Err(_) => {
                        let _ = tx.send(None);
                    }
                }
            });
            match spawned {
                Ok(_) => rx.recv().ok().flatten(),
                Err(error) => {
                    tracing::error!(%error, "could not start the credential refresh thread; refreshing on the service runtime");
                    None
                }
            }
        })
        .as_ref()
}

/// Run `future` on [`priority_runtime`] and wait for it from any runtime.
pub async fn run_prioritized<T: Send + 'static>(
    future: impl std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
) -> anyhow::Result<T> {
    match priority_runtime() {
        Some(handle) => handle.spawn(future).await.map_err(|join| anyhow::anyhow!("credential refresh task failed: {join}"))?,
        None => future.await,
    }
}

/// Spawn `future` on [`priority_runtime`] (the caller's runtime if it is
/// unavailable).
pub fn spawn_prioritized<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match priority_runtime() {
        Some(handle) => handle.spawn(future),
        None => tokio::spawn(future),
    }
}

/// The refresh schedule for one credential set.
pub(crate) struct RefreshState {
    pub(crate) issued: chrono::DateTime<chrono::Utc>,
    pub(crate) expires: chrono::DateTime<chrono::Utc>,
    /// A `RefreshSecrets` is in flight.
    pub(crate) outstanding: bool,
    pub(crate) requested_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Transient failures so far, and when the next retry may be asked.
    pub(crate) failures: usize,
    pub(crate) retry_at: Option<chrono::DateTime<chrono::Utc>>,
    /// A 401/403 or an expired credential: stop and respawn.
    pub(crate) given_up: bool,
}

impl RefreshState {
    pub(crate) fn fresh(expires: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            issued: chrono::Utc::now(),
            expires,
            outstanding: false,
            requested_at: None,
            failures: 0,
            retry_at: None,
            given_up: false,
        }
    }

    pub(crate) fn expired(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        now >= self.refresh_deadline()
    }

    fn refresh_deadline(&self) -> chrono::DateTime<chrono::Utc> {
        // Preserve the 30 s production margin without treating a short-lived
        // credential as expired immediately on receipt.
        let lifetime_ms = (self.expires - self.issued).num_milliseconds().max(0);
        self.expires - EXPIRY_SKEW.min(chrono::Duration::milliseconds(lifetime_ms / 20))
    }

    fn at_risk(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        let lifetime = (self.expires - self.issued).num_milliseconds().max(0);
        now >= self.expires - chrono::Duration::milliseconds(lifetime / 10)
    }

    /// Is a refresh request due now?
    pub(crate) fn due(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.given_up {
            return false;
        }
        if self.outstanding {
            // An unanswered request is lost after the timeout.
            return self.requested_at.is_some_and(|at| now >= at + REFRESH_ANSWER_TIMEOUT);
        }
        if let Some(at) = self.retry_at {
            return now >= at;
        }
        let lifetime = (self.expires - self.issued).num_milliseconds().max(0) as f64;
        now >= self.issued + chrono::Duration::milliseconds((lifetime * REFRESH_AT_FRACTION) as i64)
    }

    /// Record a failed exchange; transient failures keep retrying until expiry.
    pub(crate) fn failed(&mut self, now: chrono::DateTime<chrono::Utc>, is_final: bool) -> bool {
        self.outstanding = false;
        if is_final || self.expired(now) {
            self.given_up = true;
            return false;
        }
        // 60–75, 75–90, then 90–105 seconds: never faster than the
        // supervisor's mint limit. Independent randomness avoids fleet herds.
        let jitter = (uuid::Uuid::new_v4().as_u128() % 16) as i64;
        let base = REFRESH_BACKOFF_S[0] as i64 + (self.failures.min(2) as i64 * 15);
        self.retry_at = Some((now + chrono::Duration::seconds(base + jitter)).min(self.refresh_deadline()));
        self.failures = self.failures.saturating_add(1);
        true
    }
}

/// Who delivers a fresh bootstrap secret: the supervisor control channel in
/// a cell, a fake in tests.
#[async_trait::async_trait]
pub trait SecretRequester: Send + Sync {
    async fn request_secrets(&self) -> std::io::Result<()>;
}

#[async_trait::async_trait]
impl SecretRequester for nanosiem_lake_cell::child::ControlChannel {
    async fn request_secrets(&self) -> std::io::Result<()> {
        nanosiem_lake_cell::child::ControlChannel::request_secrets(self).await
    }
}

/// The shared refresh scheduler (see the module docs).
pub struct CredentialRefresher {
    state: Mutex<RefreshState>,
    /// A reader was refused by the store: ask now, not at half of the TTL.
    urgent: AtomicBool,
    /// When the last request went to the supervisor (its rate limit).
    last_request: Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    wake: tokio::sync::Notify,
    /// Bumped after every successful swap.
    generation: tokio::sync::watch::Sender<u64>,
    /// Schedule re-check interval ([`POLL`]; shortened by tests).
    poll_ms: std::sync::atomic::AtomicU64,
    /// Urgent-request spacing ([`SUPERVISOR_REFRESH_MIN_INTERVAL`]; tests only).
    min_interval_ms: std::sync::atomic::AtomicU64,
}

impl CredentialRefresher {
    pub fn new(expires: chrono::DateTime<chrono::Utc>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RefreshState::fresh(expires)),
            urgent: AtomicBool::new(false),
            last_request: Mutex::new(None),
            wake: tokio::sync::Notify::new(),
            generation: tokio::sync::watch::channel(0).0,
            poll_ms: std::sync::atomic::AtomicU64::new(POLL.as_millis() as u64),
            min_interval_ms: std::sync::atomic::AtomicU64::new(SUPERVISOR_REFRESH_MIN_INTERVAL.num_milliseconds() as u64),
        })
    }

    /// Tests: space urgent requests this far apart (the real supervisor
    /// enforces [`SUPERVISOR_REFRESH_MIN_INTERVAL`]).
    pub fn set_min_request_interval(&self, interval: Duration) {
        self.min_interval_ms.store(interval.as_millis() as u64, Ordering::Relaxed);
    }

    /// Tests: re-check the schedule this often.
    pub fn set_poll(&self, poll: Duration) {
        self.poll_ms.store(poll.as_millis() as u64, Ordering::Relaxed);
    }

    /// The credential generation currently installed (0 = the startup one).
    pub fn generation(&self) -> u64 {
        *self.generation.borrow()
    }

    pub fn expires_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.state.lock().expect("refresh lock").expires
    }

    /// `(expired, given_up)` now.
    pub fn status(&self) -> (bool, bool) {
        let state = self.state.lock().expect("refresh lock");
        (state.expired(chrono::Utc::now()), state.given_up)
    }

    /// No replacement arrived before the final 10% of the lifetime.
    pub fn at_risk(&self) -> bool {
        self.state.lock().expect("refresh lock").at_risk(chrono::Utc::now())
    }

    /// A store refused a read: refresh as soon as the supervisor allows.
    pub fn request_now(&self) {
        self.urgent.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// The exchange succeeded and every store holds the new credential.
    pub fn refreshed(&self, expires: chrono::DateTime<chrono::Utc>) {
        *self.state.lock().expect("refresh lock") = RefreshState::fresh(expires);
        self.urgent.store(false, Ordering::SeqCst);
        self.generation.send_modify(|generation| *generation += 1);
    }

    /// The exchange failed; returns whether another attempt is scheduled.
    pub fn failed(&self, is_final: bool) -> bool {
        self.state.lock().expect("refresh lock").failed(chrono::Utc::now(), is_final)
    }

    /// Wait up to `timeout` for a generation newer than `seen`.
    pub async fn wait_newer(&self, seen: u64, timeout: Duration) -> bool {
        let mut receiver = self.generation.subscribe();
        tokio::time::timeout(timeout, receiver.wait_for(|generation| *generation > seen))
            .await
            .is_ok_and(|changed| changed.is_ok())
    }

    /// Claim a request slot if one is due now (scheduled or urgent).
    pub(crate) fn take_due(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        let mut state = self.state.lock().expect("refresh lock");
        let mut last = self.last_request.lock().expect("refresh lock");
        if state.expired(now) {
            return false;
        }
        let allowed = last.is_none_or(|at| now >= at + chrono::Duration::milliseconds(self.min_interval_ms.load(Ordering::Relaxed) as i64));
        if !allowed {
            return false;
        }
        if state.outstanding && state.due(now) {
            tracing::warn!(expires_at = %state.expires, "credential refresh received no bootstrap answer; retrying");
            state.failed(now, false);
        }
        let scheduled = state.due(now);
        // Urgent: never while one is in flight or refresh gave up, never
        // inside the supervisor's rate limit (it would drop the request
        // silently) nor before a scheduled 503 backoff elapsed.
        let urgent = self.urgent.load(Ordering::SeqCst)
            && !state.outstanding
            && !state.given_up
            && state.retry_at.is_none_or(|at| now >= at);
        if !(scheduled || urgent) {
            return false;
        }
        self.urgent.store(false, Ordering::SeqCst);
        state.outstanding = true;
        state.requested_at = Some(now);
        *last = Some(now);
        true
    }

    fn request_failed(&self) {
        self.failed(false);
    }

    /// Drive the schedule until expiry (then exit so the supervisor respawns).
    pub async fn run(self: Arc<Self>, requester: impl SecretRequester) -> anyhow::Result<()> {
        self.drive(requester, false).await
    }

    /// [`Self::run`], but `Err` as soon as refresh gives up (a final 401/403
    /// such as "bootstrap token is spent"), even while the current credential
    /// is still valid. No later refresh will
    /// be attempted, so waiting for expiry only delays the respawn; ingest[T]
    /// once sat wedged for 20+ min in exactly that state.
    pub async fn run_until_given_up(self: Arc<Self>, requester: impl SecretRequester) -> anyhow::Result<()> {
        self.drive(requester, true).await
    }

    async fn drive(self: Arc<Self>, requester: impl SecretRequester, stop_when_given_up: bool) -> anyhow::Result<()> {
        let mut warned_at_risk = false;
        loop {
            let at_risk = self.at_risk();
            if at_risk && !warned_at_risk {
                tracing::error!(expires_at = %self.expires_at(), "credential refresh has not succeeded before the final 10% of lifetime");
            }
            warned_at_risk = at_risk;
            if self.take_due(chrono::Utc::now()) {
                if let Err(error) = requester.request_secrets().await {
                    tracing::warn!(%error, "could not request a fresh bootstrap secret; retrying");
                    self.request_failed();
                }
            }
            match self.status() {
                (true, _) => anyhow::bail!("credentials expired before a replacement arrived"),
                (false, true) if stop_when_given_up => anyhow::bail!("credential refresh gave up (final refusal)"),
                _ => {}
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(self.poll_ms.load(Ordering::Relaxed))) => {}
                _ = self.wake.notified() => {}
            }
        }
    }
}

/// True when the owner refused a `lake-parts:sign` bearer (HTTP 401,
/// `cell_bearer_expired`) anywhere in the error chain.
pub fn is_owner_bearer_rejected(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<OwnerSignRefused>().is_some_and(OwnerSignRefused::is_bearer_rejected))
}

/// A [`PartSigner`] whose bearer the refresh path swaps in place, made
/// self-healing: a 401 from the owner asks for an immediate re-exchange,
/// waits for the next credential generation and retries the sign ONCE. A
/// refresh that does not arrive in time returns the (non-fatal) sign error;
/// the caller's batch stays in its outbox for the next pass.
pub struct RefreshingSigner {
    inner: Arc<dyn PartSigner>,
    refresher: Arc<CredentialRefresher>,
    wait: Duration,
}

impl RefreshingSigner {
    pub fn new(inner: Arc<dyn PartSigner>, refresher: Arc<CredentialRefresher>) -> Self {
        Self { inner, refresher, wait: URGENT_REFRESH_WAIT }
    }

    /// Tests: wait this long for the urgent refresh.
    pub fn with_wait(mut self, wait: Duration) -> Self {
        self.wait = wait;
        self
    }
}

#[async_trait::async_trait]
impl PartSigner for RefreshingSigner {
    fn key_id(&self) -> &str {
        self.inner.key_id()
    }

    async fn sign(&self, tenant_id: &str, records: &[ProvenanceRecord]) -> anyhow::Result<Vec<Ed25519Signature>> {
        let seen = self.refresher.generation();
        match self.inner.sign(tenant_id, records).await {
            Err(error) if is_owner_bearer_rejected(&error) => {
                tracing::warn!(error = %format!("{error:#}"), generation = seen,
                    "owner refused the sign bearer; re-exchanging now and retrying once");
                // A refresh that landed while the call was in flight already
                // swapped the bearer: retry at once.
                if self.refresher.generation() == seen {
                    self.refresher.request_now();
                    if !self.refresher.wait_newer(seen, self.wait).await {
                        return Err(error.context("owner-sign bearer rejected and no fresh credential arrived in time"));
                    }
                }
                self.inner.sign(tenant_id, records).await
            }
            other => other,
        }
    }

    async fn sign_counts(&self, tenant_id: &str, records: &[crate::parts::count_record::CountRecord]) -> anyhow::Result<Vec<Ed25519Signature>> {
        let seen = self.refresher.generation();
        match self.inner.sign_counts(tenant_id, records).await {
            Err(error) if is_owner_bearer_rejected(&error) => {
                if self.refresher.generation() == seen {
                    self.refresher.request_now();
                    if !self.refresher.wait_newer(seen, self.wait).await {
                        return Err(error.context("owner-sign bearer rejected and no fresh credential arrived in time"));
                    }
                }
                self.inner.sign_counts(tenant_id, records).await
            }
            other => other,
        }
    }
}

/// True when any error in the chain is an object-store `PermissionDenied`
/// (an expired or revoked credential), from opendal or `object_store`.
pub fn is_permission_denied(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<opendal::Error>().is_some_and(|e| e.kind() == opendal::ErrorKind::PermissionDenied)
    }) || format!("{error:#}").contains("PermissionDenied")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct Counting(AtomicUsize);

    #[async_trait::async_trait]
    impl SecretRequester for Arc<Counting> {
        async fn request_secrets(&self) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn urgent_request_respects_in_flight_and_the_supervisor_rate_limit() {
        let now = chrono::Utc::now();
        let refresher = CredentialRefresher::new(now + chrono::Duration::hours(6));
        assert!(!refresher.take_due(now), "nothing due an instant after issue");
        refresher.request_now();
        assert!(refresher.take_due(now), "a refused read asks at once");
        refresher.request_now();
        assert!(!refresher.take_due(now + chrono::Duration::seconds(1)), "one request in flight at a time");
        refresher.refreshed(now + chrono::Duration::hours(6));
        refresher.request_now();
        assert!(!refresher.take_due(now + chrono::Duration::seconds(30)), "inside the supervisor's 60 s limit");
        assert!(refresher.take_due(now + chrono::Duration::seconds(61)), "the urgent flag survives the wait");
    }

    #[test]
    fn transient_retries_are_jittered_and_continue_until_expiry() {
        let now = chrono::Utc::now();
        let mut state = RefreshState::fresh(now + chrono::Duration::hours(6));
        state.issued = now;
        for failure in 0..32 {
            assert!(state.failed(now, false));
            let delay = (state.retry_at.unwrap() - now).num_seconds();
            let base = 60 + failure.min(2) * 15;
            assert!((base..=base + 15).contains(&delay));
        }
        assert!(!state.at_risk(now + chrono::Duration::minutes(323)));
        assert!(state.at_risk(now + chrono::Duration::minutes(324)));
        assert!(!state.failed(state.expires - EXPIRY_SKEW, false));
        assert!(state.given_up);
    }

    #[test]
    fn retries_continue_through_the_ninety_percent_warning_window() {
        let issued = chrono::Utc::now();
        let mut state = RefreshState::fresh(issued + chrono::Duration::seconds(600));
        state.issued = issued;
        let mut now = issued + chrono::Duration::seconds(300);
        assert!(state.due(now));
        while state.failed(now, false) {
            now = state.retry_at.unwrap();
            assert!(now <= issued + chrono::Duration::seconds(570));
            assert!(!state.due(now - chrono::Duration::milliseconds(1)));
            assert!(state.due(now));
        }
        assert!(state.at_risk(now));
        assert!(state.expired(now));
        assert!(state.failures >= 3, "several attempts precede the safety margin");
    }

    #[test]
    fn a_lost_mint_answer_backs_off_and_all_requests_respect_spacing() {
        let now = chrono::Utc::now();
        let refresher = CredentialRefresher::new(now + chrono::Duration::minutes(10));
        refresher.state.lock().unwrap().issued = now;
        assert!(!refresher.take_due(now + chrono::Duration::seconds(299)));
        let requested = now + chrono::Duration::seconds(300);
        assert!(refresher.take_due(requested));
        assert!(!refresher.take_due(requested + REFRESH_ANSWER_TIMEOUT));
        let retry = refresher.state.lock().unwrap().retry_at.unwrap();
        assert!(retry >= requested + REFRESH_ANSWER_TIMEOUT + chrono::Duration::seconds(60));
        assert!(!refresher.take_due(retry - chrono::Duration::milliseconds(1)));
        assert!(refresher.take_due(retry));
        // Even an immediately failed exchange cannot bypass mint spacing.
        refresher.state.lock().unwrap().failed(retry, false);
        assert!(!refresher.take_due(retry + chrono::Duration::seconds(59)));
        refresher.refreshed(now + chrono::Duration::hours(6));
        assert!(!refresher.at_risk());
    }

    #[tokio::test]
    async fn an_unanswered_refresh_cannot_lapse_silently() {
        let refresher = CredentialRefresher::new(chrono::Utc::now() - chrono::Duration::seconds(1));
        let result = refresher.run(Arc::new(Counting::default())).await;
        assert!(result.is_err(), "expiry exits even if no exchange reported failure");
    }

    #[tokio::test]
    async fn short_ttl_is_refreshed_before_expiry_and_wakes_waiters() {
        let refresher = CredentialRefresher::new(chrono::Utc::now() + chrono::Duration::seconds(3));
        refresher.set_poll(Duration::from_millis(50));
        let counting = Arc::new(Counting::default());
        let task = tokio::spawn(refresher.clone().run(counting.clone()));
        // Due at half of the 3 s TTL, i.e. ~1.5 s in: before expiry.
        tokio::time::timeout(Duration::from_secs(5), async {
            while counting.0.load(Ordering::SeqCst) == 0 { tokio::time::sleep(Duration::from_millis(20)).await; }
        }).await.expect("refresh requested before expiry");
        let seen = refresher.generation();
        let waiter = { let r = refresher.clone(); tokio::spawn(async move { r.wait_newer(seen, Duration::from_secs(5)).await }) };
        refresher.refreshed(chrono::Utc::now() + chrono::Duration::hours(6));
        assert!(waiter.await.unwrap(), "readers waiting on a refused read see the new generation");
        assert!(!refresher.status().0);
        task.abort();
    }

    #[tokio::test]
    async fn a_final_refusal_stops_the_strict_schedule_before_expiry() {
        // "401 bootstrap token is spent" with hours of credential left: the
        // strict runner ends at once instead of waiting for expiry.
        let refresher = CredentialRefresher::new(chrono::Utc::now() + chrono::Duration::hours(6));
        refresher.set_poll(Duration::from_millis(50));
        let counting = Arc::new(Counting::default());
        let task = tokio::spawn(refresher.clone().run_until_given_up(counting.clone()));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!task.is_finished(), "a healthy schedule keeps running");
        assert!(!refresher.failed(true), "401 is final");
        let result = tokio::time::timeout(Duration::from_secs(2), task).await.expect("strict runner ends promptly").unwrap();
        assert!(result.is_err());
        // The lenient runner (query/detect) still waits for expiry.
        let lenient = tokio::time::timeout(Duration::from_millis(300), refresher.clone().run(counting)).await;
        assert!(lenient.is_err(), "run() keeps going until the credential expires");
    }

    #[tokio::test]
    async fn expired_and_given_up_exits_for_a_respawn() {
        let refresher = CredentialRefresher::new(chrono::Utc::now() - chrono::Duration::seconds(1));
        assert!(!refresher.failed(true), "403 is final");
        let counting = Arc::new(Counting::default());
        refresher.set_poll(Duration::from_millis(50));
        let result = tokio::time::timeout(Duration::from_secs(2), refresher.run(counting)).await.unwrap();
        assert!(result.is_err());
    }
}
