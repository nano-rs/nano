// SPDX-License-Identifier: AGPL-3.0-or-later

//! Purge ledger and the status push to the platform (NAN-3000).
//!
//! When a placement change removes a tenant from this cell, the platform opens
//! a *drain* row and waits for the cell to prove the tenant's local state is
//! gone before it lets the tenant be placed elsewhere (the pooled drain
//! gate). The supervisor drains the tenant's processes, purges its tree
//! (`tenant_dirs::purge_tenant_tree`), verifies the purge and records it
//! here; the [`Reporter`] pushes it:
//!
//! ```text
//! POST {control_url}/v1/lake/cells/{cell_id}/status
//! Authorization: Bearer <projected SA token, aud nano-lake-cell>   (cell_identity_file)
//! {"cell_id": "...", "placement_revision": 42,
//!  "tenants": [{"tenant_id": "<uuid>", "state": "running" | "idle" | "draining"}],
//!  "purged":  [{"tenant_id": "<uuid>", "reason": "drain" | "move" | "deprovision",
//!               "verified": true, "at": "<RFC 3339>",
//!               "cache_bytes_removed": 123, "tmp_bytes_removed": 45}]}
//! ```
//!
//! The platform's schema is strict (unknown fields refused), holds at most
//! 64 tenants and 64 purges, and refuses a push WHOLE (403) when it names a
//! tenant the cell has no business with, including a purge for a tenant
//! with no open drain on this cell. Each push replaces the previous one; a
//! verified purge in an accepted push closes the drain. So:
//!
//! - an accepted (2xx) push acknowledges every purge it carried: they are
//!   dropped from the ledger (re-sending one whose drain is closed would get
//!   the whole push refused);
//! - on a 403 the reporter falls back to the placed tenants alone, then
//!   offers each purge on its own: one accepted is acknowledged, one refused
//!   alone has no open drain here (already closed, or never opened, e.g. a
//!   dedicated cell) and is dropped;
//! - 404 is the platform flag `LAKE_CELL_REPORTS_ENABLED` being off: logged
//!   at INFO once, everything kept for the next push;
//! - transport errors, 429 and 5xx are retried with bounded backoff, then
//!   left to the next cadence tick.
//!
//! Purged entries not acknowledged within [`PURGED_TTL`] are aged out. The
//! ledger is persisted in the supervisor-private `state_dir`, so a restart
//! neither forgets a verified purge nor a removal it has not purged yet.

use crate::contract::TenantId;
use crate::tenant_dirs::PurgeBytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// Platform limits (the platform `lakeCellStatusPushSchema`).
pub const MAX_TENANTS: usize = 64;
pub const MAX_PURGED: usize = 64;
pub const MAX_PLACEMENT_REVISION: u64 = 2_147_483_647;
/// A verified purge the platform never acknowledged is dropped after this.
pub const PURGED_TTL: Duration = Duration::from_secs(24 * 3600);
/// Status cadence (plus up to [`PUSH_JITTER`]).
pub const PUSH_INTERVAL: Duration = Duration::from_secs(60);
pub const PUSH_JITTER: Duration = Duration::from_secs(10);
/// Individual purge probes per push after a whole-push 403.
const MAX_PROBES: usize = 16;

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Why the tenant left the cell. The cell only sees its placement shrink, so
/// it reports `drain`; the platform's gate does not distinguish the reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurgeReason {
    Drain,
    Move,
    Deprovision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantState {
    Running,
    Idle,
    Draining,
}

/// A removal seen but not yet purged and verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPurge {
    pub reason: PurgeReason,
    pub since_ms: u64,
    #[serde(default)]
    pub attempts: u32,
}

/// A verified purge, kept until the platform acknowledges it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeRecord {
    pub reason: PurgeReason,
    pub verified: bool,
    /// RFC 3339, UTC.
    pub at: String,
    pub bytes: PurgeBytes,
    pub recorded_ms: u64,
}

/// What the cell still owes the platform about removed tenants.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
// No deny_unknown_fields: an older image rolled back onto a newer ledger
// must keep its pending purges, not discard the file as corrupt.
pub struct Ledger {
    /// The tenants placed by the last placement applied (across restarts);
    /// `None` until the first one. A tenant in here that the next placement
    /// omits was removed.
    #[serde(default)]
    pub last_placed: Option<BTreeSet<TenantId>>,
    #[serde(default)]
    pub pending: BTreeMap<TenantId, PendingPurge>,
    #[serde(default)]
    pub purged: BTreeMap<TenantId, PurgeRecord>,
}

impl Ledger {
    /// Apply a newly loaded placement: removed tenants become pending
    /// purges; placed tenants are never pending or purged.
    pub fn on_placement(&mut self, placed: &BTreeSet<TenantId>, now_ms: u64) -> Vec<TenantId> {
        let mut removed = Vec::new();
        if let Some(prev) = &self.last_placed {
            for t in prev.difference(placed) {
                if !self.pending.contains_key(t) {
                    self.pending.insert(t.clone(), PendingPurge { reason: PurgeReason::Drain, since_ms: now_ms, attempts: 0 });
                    removed.push(t.clone());
                }
                // A tenant placed back and removed again: purge it again.
                self.purged.remove(t);
            }
        }
        for t in placed {
            self.pending.remove(t);
            self.purged.remove(t);
        }
        self.last_placed = Some(placed.clone());
        removed
    }

    /// A tenant tree found on disk for an unplaced tenant (a crash mid-purge,
    /// or a removal while the supervisor was down): purge it too.
    pub fn adopt_orphan(&mut self, t: &TenantId, now_ms: u64) -> bool {
        if self.pending.contains_key(t) || self.last_placed.as_ref().is_some_and(|p| p.contains(t)) {
            return false;
        }
        self.purged.remove(t);
        self.pending.insert(t.clone(), PendingPurge { reason: PurgeReason::Drain, since_ms: now_ms, attempts: 0 });
        true
    }

    /// A purge was verified. Ignored for a tenant placed again meanwhile.
    pub fn record(&mut self, t: &TenantId, bytes: PurgeBytes, at: chrono::DateTime<chrono::Utc>, now_ms: u64) -> bool {
        let Some(p) = self.pending.remove(t) else { return false };
        if self.last_placed.as_ref().is_some_and(|placed| placed.contains(t)) {
            return false;
        }
        self.purged.insert(t.clone(), PurgeRecord {
            reason: p.reason,
            verified: true,
            at: at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            bytes,
            recorded_ms: now_ms,
        });
        true
    }

    /// Accepted by the platform (drain closed) or refused alone (no open
    /// drain here): nothing more to report.
    pub fn forget_purged(&mut self, tenants: &[TenantId]) -> usize {
        tenants.iter().filter(|t| self.purged.remove(*t).is_some()).count()
    }

    /// Drop purged entries older than `ttl`; returns them.
    pub fn expire(&mut self, now_ms: u64, ttl: Duration) -> Vec<TenantId> {
        let cutoff = now_ms.saturating_sub(ttl.as_millis() as u64);
        let old: Vec<TenantId> = self.purged.iter().filter(|(_, r)| r.recorded_ms < cutoff).map(|(t, _)| t.clone()).collect();
        for t in &old {
            self.purged.remove(t);
        }
        old
    }
}

/// The ledger and its file (`<state_dir>/purge-ledger.json`, 0600).
pub struct LedgerStore {
    path: Option<PathBuf>,
    inner: Mutex<Ledger>,
}

impl LedgerStore {
    /// In memory only (tests).
    pub fn memory() -> Self {
        Self { path: None, inner: Mutex::new(Ledger::default()) }
    }

    /// Load `path` (absent = empty). An unreadable ledger is kept aside as
    /// `.corrupt` and replaced by an empty one: failing to boot the cell
    /// would strand every tenant on it.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let ledger = match std::fs::read(path) {
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(path = %path.display(), error = %e, "purge ledger unreadable; starting empty");
                    let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
                    Ledger::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ledger::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { path: Some(path.to_path_buf()), inner: Mutex::new(ledger) })
    }

    /// Run `f` on the ledger; persist if it reports a change.
    pub fn update<T>(&self, f: impl FnOnce(&mut Ledger) -> (T, bool)) -> T {
        let mut l = self.inner.lock().unwrap();
        let (out, changed) = f(&mut l);
        if changed {
            if let Err(e) = self.persist(&l) {
                tracing::error!(error = %e, "purge ledger not persisted; a restart would lose it");
            }
        }
        out
    }

    pub fn snapshot(&self) -> Ledger {
        self.inner.lock().unwrap().clone()
    }

    fn persist(&self, l: &Ledger) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec(l).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    }
}

// ------------------------------------------------------------------ push body

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantEntry {
    pub tenant_id: String,
    pub state: TenantState,
    /// NAN-3522 (`lean_ingest_counters_v1`): the tenant's live ingest
    /// process counter. Only with NANO_LAKE_CELL_INGEST_COUNTERS, and only
    /// for placed tenants; absent otherwise, so the body is byte-identical.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ingest: Option<IngestCounters>,
    /// NAN-4137 (`lean_tenzir_landing_v1`): the tenant's live landing[T]
    /// counters. Only on a `tenzir_landing` cell, only while landing[T]
    /// runs; absent otherwise, so every other body is byte-identical.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub landing: Option<LandingCounters>,
}

/// One landing[T] process life's counters (`epoch_ms` = its spawn time):
/// the platform diffs successive samples like [`IngestCounters`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandingCounters {
    pub epoch_ms: u64,
    pub status: crate::contract::LandingStatus,
}

/// One ingest process life's committed rows (`epoch_ms` = its spawn time).
/// the platform turns successive samples into daily ingest per tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestCounters {
    pub epoch_ms: u64,
    pub rows_committed_total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgedEntry {
    pub tenant_id: String,
    pub reason: PurgeReason,
    pub verified: bool,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cache_bytes_removed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tmp_bytes_removed: Option<u64>,
}

/// Exactly the platform's strict body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusPush {
    pub cell_id: String,
    pub placement_revision: u64,
    pub tenants: Vec<TenantEntry>,
    pub purged: Vec<PurgedEntry>,
}

/// What the cell knows right now, for one push.
#[derive(Debug, Clone, Default)]
pub struct StatusSnapshot {
    pub cell_id: String,
    pub placement_revision: u64,
    /// Placed tenants (running or idle).
    pub placed: Vec<(TenantId, TenantState)>,
    /// Removed but not yet purged (processes draining, or purge pending).
    pub draining: Vec<TenantId>,
    pub purged: Vec<(TenantId, PurgeRecord)>,
    /// NAN-3522: placed tenants' ingest counters (empty unless enabled).
    pub ingest: BTreeMap<TenantId, IngestCounters>,
    /// NAN-4137: placed tenants' landing counters (empty unless enabled).
    pub landing: BTreeMap<TenantId, LandingCounters>,
}

/// The platform's tenant ids are lowercase UUIDs; anything else (dev or
/// test tenants) would get every push refused as a bad request.
pub fn platform_tenant_id(t: &TenantId) -> bool {
    let s = t.as_str();
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) })
}

impl StatusSnapshot {
    pub fn tenants(&self, with_draining: bool) -> Vec<TenantEntry> {
        let placed = self.placed.iter().map(|(t, s)| (t, *s, self.ingest.get(t).copied(), self.landing.get(t).cloned()));
        let draining = self.draining.iter().filter(|_| with_draining).map(|t| (t, TenantState::Draining, None, None));
        let all: Vec<TenantEntry> = placed
            .chain(draining)
            .filter(|(t, _, _, _)| platform_tenant_id(t))
            .map(|(t, state, ingest, landing)| TenantEntry { tenant_id: t.as_str().to_owned(), state, ingest, landing })
            .collect();
        if all.len() > MAX_TENANTS {
            tracing::warn!(tenants = all.len(), "more tenants than one status push holds; reporting the first {MAX_TENANTS}");
        }
        all.into_iter().take(MAX_TENANTS).collect()
    }

    /// Purges to offer, oldest first, at most [`MAX_PURGED`].
    pub fn purges(&self) -> Vec<(TenantId, PurgedEntry)> {
        let mut v: Vec<&(TenantId, PurgeRecord)> = self.purged.iter().filter(|(t, _)| platform_tenant_id(t)).collect();
        v.sort_by_key(|(_, r)| r.recorded_ms);
        v.into_iter()
            .take(MAX_PURGED)
            .map(|(t, r)| {
                (t.clone(), PurgedEntry {
                    tenant_id: t.as_str().to_owned(),
                    reason: r.reason,
                    verified: r.verified,
                    at: r.at.clone(),
                    cache_bytes_removed: Some(r.bytes.cache_bytes),
                    tmp_bytes_removed: Some(r.bytes.tmp_bytes),
                })
            })
            .collect()
    }

    /// Everything: placed + draining tenants and every purge to offer.
    pub fn full_body(&self) -> StatusPush {
        self.body(self.tenants(true), self.purges().into_iter().map(|(_, p)| p).collect())
    }

    pub fn body(&self, tenants: Vec<TenantEntry>, purged: Vec<PurgedEntry>) -> StatusPush {
        StatusPush {
            cell_id: self.cell_id.clone(),
            placement_revision: self.placement_revision.min(MAX_PLACEMENT_REVISION),
            tenants,
            purged,
        }
    }
}

/// Where a push gets its facts and what it tells back.
pub trait StatusSource: Send + Sync + 'static {
    fn snapshot(&self) -> StatusSnapshot;
    /// These purges need no further report (accepted, or refused alone).
    fn purges_settled(&self, tenants: &[TenantId]);
    /// The outcome of one push (metrics).
    fn push_outcome(&self, _outcome: PushOutcome) {}
}

/// Ledger + a fixed tenant list: a [`StatusSource`] without a supervisor
/// (tests, and the shape the supervisor's own implementation follows).
pub struct LedgerSource {
    pub cell_id: String,
    pub revision: Mutex<u64>,
    pub placed: Mutex<Vec<(TenantId, TenantState)>>,
    pub ledger: Arc<LedgerStore>,
}

impl StatusSource for LedgerSource {
    fn snapshot(&self) -> StatusSnapshot {
        let l = self.ledger.snapshot();
        StatusSnapshot {
            cell_id: self.cell_id.clone(),
            placement_revision: *self.revision.lock().unwrap(),
            placed: self.placed.lock().unwrap().clone(),
            draining: l.pending.keys().cloned().collect(),
            purged: l.purged.into_iter().collect(),
            ingest: BTreeMap::new(),
            landing: BTreeMap::new(),
        }
    }
    fn purges_settled(&self, tenants: &[TenantId]) {
        self.ledger.update(|l| {
            let n = l.forget_purged(tenants);
            (n, n > 0)
        });
    }
}

// ------------------------------------------------------------------ reporter

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// 2xx.
    Accepted,
    /// 404: the platform route is off (`LAKE_CELL_REPORTS_ENABLED`).
    Disabled,
    /// 403: refused whole (a tenant this cell has no business with).
    Forbidden,
    /// 401: identity refused (TokenReview, audience, pod binding).
    Unauthenticated,
    /// Another 4xx (400 = the body does not match the platform schema).
    Rejected(u16),
    /// Transport error, 429 or 5xx after the retries.
    Failed,
    /// No identity token readable.
    NoIdentity,
}

impl PushOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            PushOutcome::Accepted => "accepted",
            PushOutcome::Disabled => "disabled",
            PushOutcome::Forbidden => "forbidden",
            PushOutcome::Unauthenticated => "unauthenticated",
            PushOutcome::Rejected(_) => "rejected",
            PushOutcome::Failed => "failed",
            PushOutcome::NoIdentity => "no_identity",
        }
    }
}

/// The result of one [`Reporter::push_once`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSummary {
    pub outcome: PushOutcome,
    /// Purges the platform accepted in this pass.
    pub acknowledged: Vec<TenantId>,
    /// Purges refused on their own (no open drain here): dropped.
    pub dropped: Vec<TenantId>,
}

pub struct Reporter {
    client: reqwest::Client,
    url: String,
    identity_file: PathBuf,
    attempts: u32,
    backoff: Duration,
    last_logged: Mutex<Option<PushOutcome>>,
}

impl Reporter {
    /// `control_url` is the platform API base the bootstrap route uses
    /// (`https://<platform api>/api`); `identity_file` the projected
    /// ServiceAccount token (audience `nano-lake-cell`), re-read per push so
    /// kubelet rotation needs no restart.
    pub fn new(control_url: &str, cell_id: &str, identity_file: PathBuf) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cell_id.is_empty() && cell_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "cell_id {cell_id:?} is not a platform cell id"
        );
        let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
        let url = format!("{}/v1/lake/cells/{cell_id}/status", control_url.trim_end_matches('/'));
        Ok(Self { client, url, identity_file, attempts: 3, backoff: Duration::from_secs(1), last_logged: Mutex::new(None) })
    }

    /// Retry policy for transport errors, 429 and 5xx (tests shorten it).
    pub fn with_retry(mut self, attempts: u32, backoff: Duration) -> Self {
        self.attempts = attempts.max(1);
        self.backoff = backoff;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn post(&self, body: &StatusPush) -> PushOutcome {
        let token = match tokio::fs::read_to_string(&self.identity_file).await {
            Ok(t) if !t.trim().is_empty() => Zeroizing::new(t),
            Ok(_) | Err(_) => {
                tracing::warn!(file = %self.identity_file.display(), "cell identity token unreadable; status not pushed");
                return PushOutcome::NoIdentity;
            }
        };
        let mut wait = self.backoff;
        for attempt in 1..=self.attempts {
            let res = self.client.post(&self.url).bearer_auth(token.trim()).json(body).send().await;
            let retry = match res {
                Ok(r) => match r.status().as_u16() {
                    200..=299 => return PushOutcome::Accepted,
                    401 => return PushOutcome::Unauthenticated,
                    403 => return PushOutcome::Forbidden,
                    404 => return PushOutcome::Disabled,
                    429 | 500..=599 => format!("HTTP {}", r.status().as_u16()),
                    code => return PushOutcome::Rejected(code),
                },
                Err(e) => format!("transport: {}", e.without_url()),
            };
            if attempt < self.attempts {
                tracing::debug!(attempt, error = %retry, "status push failed; retrying");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(30));
            } else {
                tracing::warn!(attempts = self.attempts, error = %retry, "status push failed; next attempt on the status cadence");
            }
        }
        PushOutcome::Failed
    }

    fn log_transition(&self, outcome: PushOutcome) {
        let mut last = self.last_logged.lock().unwrap();
        if *last == Some(outcome) {
            return;
        }
        *last = Some(outcome);
        match outcome {
            PushOutcome::Accepted => tracing::info!(url = %self.url, "cell status pushed to the platform"),
            PushOutcome::Disabled => tracing::info!(url = %self.url,
                "platform status route answered 404 (LAKE_CELL_REPORTS_ENABLED is off); keeping purges and retrying on the cadence"),
            PushOutcome::Unauthenticated => tracing::warn!(url = %self.url, "platform refused the cell identity (401) for the status push"),
            PushOutcome::Rejected(code) => tracing::error!(url = %self.url, code, "platform rejected the status push body"),
            PushOutcome::Forbidden => tracing::warn!(url = %self.url, "platform refused even the placed-tenant status (403); placement out of step?"),
            PushOutcome::Failed | PushOutcome::NoIdentity => {}
        }
    }

    /// One status push (with the 403 fallback described in the module docs).
    pub async fn push_once(&self, src: &dyn StatusSource) -> PushSummary {
        let snap = src.snapshot();
        let purges = snap.purges();
        let full = snap.body(snap.tenants(true), purges.iter().map(|(_, p)| p.clone()).collect());
        let outcome = self.post(&full).await;
        let mut summary = PushSummary { outcome, acknowledged: vec![], dropped: vec![] };
        if outcome == PushOutcome::Accepted {
            summary.acknowledged = purges.iter().map(|(t, _)| t.clone()).collect();
        } else if outcome == PushOutcome::Forbidden {
            let base_tenants = snap.tenants(false);
            let base = snap.body(base_tenants.clone(), vec![]);
            summary.outcome = self.post(&base).await;
            if summary.outcome == PushOutcome::Accepted {
                for (t, p) in purges.iter().take(MAX_PROBES) {
                    match self.post(&snap.body(base_tenants.clone(), vec![p.clone()])).await {
                        PushOutcome::Accepted => summary.acknowledged.push(t.clone()),
                        PushOutcome::Forbidden => {
                            tracing::info!(tenant = %t, "platform has no open drain for this purge on this cell; dropping it");
                            summary.dropped.push(t.clone());
                        }
                        _ => break,
                    }
                }
            }
        }
        if !summary.acknowledged.is_empty() {
            tracing::info!(tenants = ?summary.acknowledged, "platform acknowledged verified purges");
        }
        let settled: Vec<TenantId> = summary.acknowledged.iter().chain(&summary.dropped).cloned().collect();
        if !settled.is_empty() {
            src.purges_settled(&settled);
        }
        self.log_transition(summary.outcome);
        src.push_outcome(summary.outcome);
        summary
    }

    /// Push on every `notify` (placement change, new purge; debounced) and
    /// every [`PUSH_INTERVAL`] plus jitter, until `stop` returns true.
    pub async fn run(self, src: Arc<dyn StatusSource>, notify: Arc<tokio::sync::Notify>, stop: impl Fn() -> bool + Send + 'static) {
        loop {
            if stop() {
                return;
            }
            self.push_once(src.as_ref()).await;
            let wait = PUSH_INTERVAL + jitter(PUSH_JITTER);
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = notify.notified() => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }
}

/// A random duration in `[0, max)` (spreads cells' pushes apart).
pub fn jitter(max: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(now_ms());
    let ms = max.as_millis().max(1) as u64;
    Duration::from_millis(h.finish() % ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> TenantId {
        TenantId::new(s).unwrap()
    }
    const A: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    const B: &str = "7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11";
    const C: &str = "8b3e3a4c-7d0a-4f6e-9c5a-2a4d9e1f3b22";

    fn set(v: &[&str]) -> BTreeSet<TenantId> {
        v.iter().map(|s| t(s)).collect()
    }

    #[test]
    fn ledger_tracks_removals_across_placements() {
        let mut l = Ledger::default();
        // First placement after boot (no history): nothing removed.
        assert!(l.on_placement(&set(&[A, B]), 1).is_empty());
        assert_eq!(l.on_placement(&set(&[A]), 2), vec![t(B)]);
        assert_eq!(l.pending[&t(B)].reason, PurgeReason::Drain);
        let at = chrono::Utc::now();
        assert!(l.record(&t(B), PurgeBytes { cache_bytes: 7, tmp_bytes: 3, entries: 4 }, at, 3));
        assert!(l.pending.is_empty());
        let r = &l.purged[&t(B)];
        assert!(r.verified && r.at.ends_with('Z') && r.bytes.cache_bytes == 7);
        // Re-placed: nothing owed any more; removed again: owed again.
        l.on_placement(&set(&[A, B]), 4);
        assert!(l.purged.is_empty() && l.pending.is_empty());
        l.on_placement(&set(&[A]), 5);
        assert!(l.pending.contains_key(&t(B)));
        // A purge recorded after the tenant was placed back is ignored.
        l.on_placement(&set(&[A, B]), 6);
        assert!(!l.record(&t(B), PurgeBytes::default(), at, 7));
        assert!(l.purged.is_empty());
        // Orphans: only unplaced tenants, once.
        assert!(l.adopt_orphan(&t(C), 8));
        assert!(!l.adopt_orphan(&t(C), 9));
        assert!(!l.adopt_orphan(&t(A), 9));
        // Settled and aged-out purges leave.
        assert!(l.record(&t(C), PurgeBytes::default(), at, 10));
        assert_eq!(l.forget_purged(&[t(C), t(A)]), 1);
        l.on_placement(&set(&[]), 11);
        l.record(&t(A), PurgeBytes::default(), at, 12);
        assert!(l.expire(12 + 1000, Duration::from_millis(5000)).is_empty());
        assert_eq!(l.expire(12 + 6000, Duration::from_millis(5000)), vec![t(A)]);
    }

    #[test]
    fn ledger_persists_across_restarts() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("purge-ledger.json");
        let s = LedgerStore::open(&p).unwrap();
        s.update(|l| (l.on_placement(&set(&[A, B]), 1), true));
        s.update(|l| (l.on_placement(&set(&[A]), 2), true));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let again = LedgerStore::open(&p).unwrap().snapshot();
        assert_eq!(again, s.snapshot());
        assert!(again.pending.contains_key(&t(B)));
        // A corrupt ledger does not stop the cell.
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(LedgerStore::open(&p).unwrap().snapshot(), Ledger::default());
        assert!(p.with_extension("json.corrupt").exists());
    }

    #[test]
    fn body_matches_the_platform_schema() {
        let mut l = Ledger::default();
        l.on_placement(&set(&[A, B]), 1);
        l.on_placement(&set(&[A]), 2);
        l.record(&t(B), PurgeBytes { cache_bytes: 10, tmp_bytes: 2, entries: 3 }, chrono::Utc::now(), 3);
        let snap = StatusSnapshot {
            cell_id: "cell-us-p-1".into(),
            placement_revision: u64::MAX,
            placed: vec![(t(A), TenantState::Running), (t("dev-tenant"), TenantState::Idle)],
            draining: vec![t(C)],
            purged: l.purged.clone().into_iter().collect(),
            ingest: BTreeMap::new(),
            landing: BTreeMap::new(),
        };
        let body = snap.body(snap.tenants(true), snap.purges().into_iter().map(|(_, p)| p).collect());
        let v = serde_json::to_value(&body).unwrap();
        let keys = |v: &serde_json::Value| { let mut k = v.as_object().unwrap().keys().cloned().collect::<Vec<_>>(); k.sort(); k };
        assert_eq!(keys(&v), ["cell_id", "placement_revision", "purged", "tenants"]);
        assert_eq!(v["placement_revision"], 2_147_483_647u64);
        // Non-UUID tenants are never sent (the platform would refuse the push).
        assert_eq!(v["tenants"], serde_json::json!([
            {"tenant_id": A, "state": "running"}, {"tenant_id": C, "state": "draining"}]));
        let p = &v["purged"][0];
        assert_eq!(keys(p), ["at", "cache_bytes_removed", "reason", "tenant_id", "tmp_bytes_removed", "verified"]);
        assert_eq!((p["tenant_id"].as_str(), p["reason"].as_str(), p["verified"].as_bool()), (Some(B), Some("drain"), Some(true)));
        assert!(chrono::DateTime::parse_from_rfc3339(p["at"].as_str().unwrap()).is_ok());
        // Round-trips through the strict (deny_unknown_fields) shape.
        assert_eq!(serde_json::from_value::<StatusPush>(v).unwrap(), body);
        assert!(!platform_tenant_id(&t("6f1c1e2a_5b8e_4d4c_9a3e_0e2b7c9d1f00")) && !platform_tenant_id(&t("dev-tenant")));
    }

    #[test]
    fn caps_at_platform_limits() {
        let placed: Vec<(TenantId, TenantState)> =
            (0..70).map(|i| (t(&format!("{i:08x}-0000-4000-8000-000000000000")), TenantState::Idle)).collect();
        let purged: Vec<(TenantId, PurgeRecord)> = (0..70)
            .map(|i| (t(&format!("{i:08x}-1111-4000-8000-000000000000")), PurgeRecord {
                reason: PurgeReason::Drain, verified: true, at: "2026-09-28T00:00:00.000Z".into(),
                bytes: PurgeBytes::default(), recorded_ms: 1000 - i as u64 }))
            .collect();
        let snap = StatusSnapshot { cell_id: "c".into(), placement_revision: 1, placed, draining: vec![], purged, ingest: BTreeMap::new(), landing: BTreeMap::new() };
        assert_eq!(snap.tenants(true).len(), MAX_TENANTS);
        let p = snap.purges();
        assert_eq!(p.len(), MAX_PURGED);
        // Oldest first.
        assert_eq!(p[0].0.as_str(), "00000045-1111-4000-8000-000000000000");
    }
}
