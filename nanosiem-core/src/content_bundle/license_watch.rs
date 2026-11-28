// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5769: re-check the enterprise channels when the install's license
//! changes, instead of waiting for the next hourly poll.
//!
//! A fresh install runs its first content check about 20 s after boot,
//! usually before the operator imports the license. Enterprise channels
//! (`soar-catalog`) are then skipped for lack of a license. That skip is not a
//! clean check for those channels, so the jobs leader keeps watching:
//!
//! - **License changed** ([`credential::LICENSE_CHANGED_CHANNEL`]): an import,
//!   a renewal or a check-in that newly admits the install raises a NOTIFY on
//!   whichever replica handled it. The leader re-checks the enterprise
//!   channels at once.
//! - **Local probe**: while no license is available, the leader re-resolves
//!   the credential (one PostgreSQL row read, never a platform request) every
//!   [`CheckTiming::licence_probe_min`], backing off to
//!   [`CheckTiming::licence_probe_max`]. A NOTIFY lost to a dropped listener
//!   is therefore picked up within minutes.
//!
//! An enterprise channel is fetched from the platform only when a credential
//! exists and differs from the one the last check used, or after a license
//! change when the last enterprise check was not clean. An unlicensed install
//! never contacts the platform for an enterprise channel.
//!
//! Air-gap: the consumer loop returns before any of this starts. Multi-replica:
//! every replica may listen, but only the fenced leader acts.
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::credential::{self, CredentialOrigin, DistributionCredential};
use crate::shutdown::ShutdownToken;

/// Delay before the first scheduled check after the consumer starts.
pub const FIRST_CHECK_SECS: u64 = 20;
/// First local license probe after a check skipped for lack of a license.
pub const LICENCE_PROBE_MIN_SECS: u64 = 15;
/// Longest gap between local license probes on an unlicensed install.
pub const LICENCE_PROBE_MAX_SECS: u64 = 300;

/// The consumer loop's timings. Production uses [`Default`]; tests shorten
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckTiming {
    pub first_check: Duration,
    pub licence_probe_min: Duration,
    pub licence_probe_max: Duration,
}

impl Default for CheckTiming {
    fn default() -> Self {
        Self {
            first_check: Duration::from_secs(FIRST_CHECK_SECS),
            licence_probe_min: Duration::from_secs(LICENCE_PROBE_MIN_SECS),
            licence_probe_max: Duration::from_secs(LICENCE_PROBE_MAX_SECS),
        }
    }
}

/// A digest of the credential an enterprise check presents (`None`: no
/// license). Compared, never logged or stored.
pub type Fingerprint = Option<[u8; 32]>;

pub fn fingerprint(resolved: &Result<(DistributionCredential, CredentialOrigin), String>) -> Fingerprint {
    let (credential, _) = resolved.as_ref().ok()?;
    let mut h = Sha256::new();
    match credential {
        DistributionCredential::SignedLicense(bytes) => {
            h.update(b"license\0");
            h.update(bytes);
        }
        DistributionCredential::Enrollment { deployment_id, token, licence_origin } => {
            h.update(b"enrollment\0");
            for part in [deployment_id, token, licence_origin] {
                h.update((part.len() as u64).to_be_bytes());
                h.update(part.as_bytes());
            }
        }
    }
    Some(h.finalize().into())
}

/// When the leader re-checks the enterprise channels between polls.
#[derive(Debug)]
pub struct EnterpriseWatch {
    timing: CheckTiming,
    /// The credential the last enterprise check ran with. `None`: no check
    /// yet (the first scheduled check is due shortly and covers it).
    last: Option<Fingerprint>,
    /// The last enterprise check presented a license and every enterprise
    /// channel succeeded.
    clean: bool,
    probe_every: Duration,
    probe_at: Option<Instant>,
}

impl EnterpriseWatch {
    pub fn new(timing: CheckTiming) -> Self {
        Self { timing, last: None, clean: false, probe_every: timing.licence_probe_min, probe_at: None }
    }

    /// When the next local license probe is due (`None`: no probe pending).
    pub fn probe_at(&self) -> Option<Instant> {
        self.probe_at
    }

    /// Whether the last enterprise check was clean.
    pub fn clean(&self) -> bool {
        self.clean
    }

    fn unlicensed(&self) -> bool {
        self.last == Some(None)
    }

    fn schedule_probe(&mut self, now: Instant) {
        self.probe_at = Some(now + self.probe_every);
        self.probe_every = (self.probe_every * 2).min(self.timing.licence_probe_max);
    }

    /// Record a check that covered the enterprise channels: `fp` is the
    /// credential it presented, `ok` whether every enterprise channel
    /// succeeded. A check without a license is never clean, and schedules a
    /// local probe instead of waiting for the next poll.
    pub fn checked(&mut self, fp: Fingerprint, ok: bool, now: Instant) {
        let still_unlicensed = self.unlicensed() && fp.is_none();
        self.last = Some(fp);
        self.clean = ok && fp.is_some();
        if fp.is_none() {
            if !still_unlicensed {
                self.probe_every = self.timing.licence_probe_min;
            }
            self.schedule_probe(now);
        } else {
            self.probe_every = self.timing.licence_probe_min;
            self.probe_at = None;
        }
    }

    /// Whether a probe (`woken == false`) or a license-changed signal
    /// (`woken == true`) that resolved `fp_now` should check the enterprise
    /// channels now.
    pub fn wants_check(&self, fp_now: Fingerprint, woken: bool) -> bool {
        match self.last {
            // Before the first check: only a real license-changed signal
            // with a license present (the first check is due shortly).
            None => woken && fp_now.is_some(),
            Some(last) => last != fp_now || (woken && fp_now.is_some() && !self.clean),
        }
    }

    /// Nothing to check: keep probing (backing off) while unlicensed.
    pub fn idle(&mut self, now: Instant) {
        if self.unlicensed() {
            self.schedule_probe(now);
        } else {
            self.probe_at = None;
        }
    }

    /// A wanted check could not run (another install held the lease, or the
    /// database was unavailable): try again at the probe cadence.
    pub fn retry_later(&mut self, now: Instant) {
        self.schedule_probe(now);
    }
}

/// Doubling delay between `min` and `max` (the scheduled check's retry when
/// another install holds the lease).
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    cur: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self { min, max: max.max(min), cur: min }
    }
    /// The next delay; the one after doubles, up to `max`.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        d
    }
    pub fn reset(&mut self) {
        self.cur = self.min;
    }
}

/// Sleep until `at`, or forever when there is nothing scheduled.
pub async fn sleep_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending::<()>().await,
    }
}

/// How long the listener waits on a silent connection before it reconnects
/// (a half-open TCP drop would otherwise hang it until the OS gives up).
pub const LISTENER_KEEPALIVE_SECS: u64 = 300;

/// Aborts the task when dropped: the listener lives exactly as long as the
/// consumer loop that owns it. The leader loop is aborted on step-down, so the
/// listener and its PostgreSQL connection go with it.
pub struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Listen for [`credential::LICENSE_CHANGED_CHANNEL`] and wake `wake` on each
/// notification. Every reconnect (a dropped connection, a keepalive timeout,
/// a failed first connect) may have missed a notification, so it wakes too:
/// the consumer then re-reads the license locally and checks only if it
/// changed or the last enterprise check was not clean. Returns at shutdown or
/// when the returned guard is dropped.
pub fn spawn_license_listener(
    pool: sqlx::PgPool,
    wake: Arc<Notify>,
    shutdown: ShutdownToken,
    keepalive: Duration,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        // The first successful connect needs no wake: the first scheduled
        // check covers anything before it.
        let mut may_have_missed = false;
        loop {
            match listen(&pool).await {
                Ok(mut listener) => {
                    backoff = Duration::from_secs(1);
                    if may_have_missed {
                        wake.notify_one();
                    }
                    may_have_missed = true;
                    loop {
                        tokio::select! {
                            _ = shutdown.cancelled() => return,
                            r = tokio::time::timeout(keepalive, listener.try_recv()) => match r {
                                Ok(Ok(Some(_))) => wake.notify_one(),
                                // sqlx reconnected on its own: notifications
                                // sent while it was down are lost.
                                Ok(Ok(None)) => {
                                    tracing::info!("content channels: license change listener reconnected");
                                    wake.notify_one();
                                }
                                Ok(Err(error)) => {
                                    tracing::warn!(%error, "content channels: license change listener lost; reconnecting");
                                    break;
                                }
                                Err(_) => {
                                    tracing::debug!("content channels: license change listener keepalive; reconnecting");
                                    break;
                                }
                            },
                        }
                    }
                }
                Err(error) => {
                    may_have_missed = true;
                    tracing::warn!(%error, retry_in = ?backoff, "content channels: license change listener unavailable");
                }
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }))
}

async fn listen(pool: &sqlx::PgPool) -> Result<sqlx::postgres::PgListener, sqlx::Error> {
    let mut listener = crate::db::listener::dedicated_listener(pool).await?;
    listener.listen(credential::LICENSE_CHANGED_CHANNEL).await?;
    Ok(listener)
}

#[cfg(test)]
#[path = "license_watch_tests.rs"]
mod tests;
