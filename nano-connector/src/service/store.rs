//! Durable feed state: claims (leases), checkpoints, run outcomes.
//! [`super::pg::PgFeedStore`] in production; [`MemoryFeedStore`] for tests
//! and local runs.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::Value;
use uuid::Uuid;

use super::feed::{ClaimedFeed, FeedDefinition, RunRecord, RunStatus, TenantSlot};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The claim's lease generation is no longer current.
    #[error("the feed lease was lost (another runner holds it now)")]
    LeaseLost,
    #[error("feed store: {0}")]
    Backend(String),
    #[error("feed {feed_id}: {message}")]
    Feed { feed_id: Uuid, message: String },
}

#[async_trait::async_trait]
pub trait FeedStore: Send + Sync {
    /// Tenants this runner may work for, with the actor to act as.
    async fn tenants(&self) -> Result<Vec<TenantSlot>, StoreError>;

    /// Lease up to `limit` due feeds of one tenant. Each claim bumps the
    /// feed's lease generation and opens a `running` run record. The lease
    /// lasts `lease_secs(feed)`.
    async fn claim_due(
        &self,
        slot: &TenantSlot,
        node: &str,
        limit: usize,
        lease_secs: &(dyn Fn(Option<u64>) -> u64 + Send + Sync),
    ) -> Result<Vec<ClaimedFeed>, StoreError>;

    /// Saved checkpoint per stream id.
    async fn load_checkpoints(&self, claim: &ClaimedFeed) -> Result<HashMap<String, Value>, StoreError>;

    /// Write one stream's checkpoint, only while `claim` still holds the
    /// lease ([`StoreError::LeaseLost`] otherwise).
    async fn save_checkpoint(&self, claim: &ClaimedFeed, stream: &str, state: &Value) -> Result<(), StoreError>;

    /// Record the run and schedule the next one. The feed row is updated
    /// only while `claim` holds the lease; the run record always is.
    async fn finish(&self, claim: &ClaimedFeed, record: &RunRecord) -> Result<(), StoreError>;

    /// Advance per-feed ingest credential issuance for one tenant's feeds
    /// that have no token yet (request, then reveal once issued); see
    /// [`super::credential`]. A feed without a token is never claimed.
    /// Default: nothing to do (a store whose feeds always carry a token).
    async fn provision_credentials(&self, _slot: &TenantSlot, _limit: usize) -> Result<CredentialPass, StoreError> {
        Ok(CredentialPass::default())
    }

    /// Lease up to `limit` of one tenant's uninstalled feeds (pending
    /// delete) whose backoff has passed, for `lease_secs`.
    async fn claim_deletes(&self, _slot: &TenantSlot, _node: &str, _limit: usize, _lease_secs: u64) -> Result<Vec<PendingDelete>, StoreError> {
        Ok(Vec::new())
    }

    /// `Ok`: the feed's external state is gone, hard-delete the row (only
    /// while `claim` holds the lease). `Err(message)`: record it and back
    /// off ([`delete_backoff`]); the claim loop retries.
    async fn finish_delete(&self, _claim: &PendingDelete, _outcome: Result<(), String>) -> Result<(), StoreError> {
        Ok(())
    }
}

/// An uninstalled feed this runner holds the delete lease on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDelete {
    pub slot: TenantSlot,
    pub feed_id: Uuid,
    /// `sink = 'identity'`: its directory sub-feeds must be removed at the
    /// tenant coordinator before the row goes.
    pub identity: bool,
    pub lease_generation: i64,
    pub node: String,
    /// Failed attempts so far.
    pub attempts: u32,
}

/// Wait before retrying a failed delete: 30 s doubling per attempt, at
/// most one hour.
pub fn delete_backoff(attempts: u32) -> ChronoDuration {
    ChronoDuration::seconds((30i64 << attempts.min(7)).min(3600))
}

/// What one [`FeedStore::provision_credentials`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialPass {
    /// New issuance requests inserted.
    pub requested: usize,
    /// Requests still pending at the platform.
    pub waiting: usize,
    /// Tokens revealed, opened and sealed onto their feed.
    pub issued: usize,
    /// Attempts that failed (recorded on the feed, retried later).
    pub failed: usize,
}

/// In-memory store. Feeds are added with [`MemoryFeedStore::add`]; every
/// checkpoint write is logged with a global sequence number from
/// [`MemoryFeedStore::with_sequencer`] so tests can order it against
/// ingress receipts.
pub struct MemoryFeedStore {
    inner: Mutex<MemInner>,
    seq: Box<dyn Fn() -> u64 + Send + Sync>,
}

#[derive(Default)]
struct MemInner {
    feeds: Vec<MemFeed>,
    checkpoints: HashMap<(Uuid, String), Value>,
    commits: Vec<CommitLog>,
    runs: Vec<(Uuid, RunRecord)>,
}

struct MemFeed {
    def: FeedDefinition,
    actor: Uuid,
    enabled: bool,
    next_run_at: DateTime<Utc>,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    lease_generation: i64,
    /// Uninstalled: `(identity, attempts, next attempt, last error)`.
    pending_delete: Option<MemDelete>,
}

#[derive(Debug, Clone)]
struct MemDelete {
    identity: bool,
    attempts: u32,
    next_attempt_at: DateTime<Utc>,
    last_error: Option<String>,
}

/// One checkpoint write.
#[derive(Debug, Clone)]
pub struct CommitLog {
    pub seq: u64,
    pub feed_id: Uuid,
    pub stream: String,
    pub state: Value,
    pub lease_generation: i64,
}

impl Default for MemoryFeedStore {
    fn default() -> Self {
        let n = std::sync::atomic::AtomicU64::new(0);
        Self::with_sequencer(Box::new(move || n.fetch_add(1, std::sync::atomic::Ordering::SeqCst)))
    }
}

impl MemoryFeedStore {
    pub fn with_sequencer(seq: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self { inner: Mutex::new(MemInner::default()), seq }
    }

    pub fn add(&self, def: FeedDefinition, actor: Uuid) {
        self.inner.lock().expect("store").feeds.push(MemFeed {
            def,
            actor,
            enabled: true,
            next_run_at: DateTime::<Utc>::MIN_UTC,
            lease_owner: None,
            lease_expires_at: None,
            lease_generation: 0,
            pending_delete: None,
        });
    }

    /// Uninstall: disable the feed and queue its delete (what the API's
    /// uninstall does to `connector_feeds`).
    pub fn mark_pending_delete(&self, feed_id: Uuid, identity: bool) {
        let mut g = self.inner.lock().expect("store");
        if let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id) {
            f.enabled = false;
            f.pending_delete = Some(MemDelete { identity, attempts: 0, next_attempt_at: DateTime::<Utc>::MIN_UTC, last_error: None });
        }
    }

    /// Whether the feed row still exists.
    pub fn has_feed(&self, feed_id: Uuid) -> bool {
        self.inner.lock().expect("store").feeds.iter().any(|f| f.def.feed_id == feed_id)
    }

    /// A pending delete's `(attempts, last_error)`.
    pub fn delete_state(&self, feed_id: Uuid) -> Option<(u32, Option<String>)> {
        let g = self.inner.lock().expect("store");
        g.feeds.iter().find(|f| f.def.feed_id == feed_id).and_then(|f| f.pending_delete.as_ref()).map(|d| (d.attempts, d.last_error.clone()))
    }

    /// Make a pending delete due now (tests: the backoff passed).
    pub fn make_delete_due(&self, feed_id: Uuid) {
        let mut g = self.inner.lock().expect("store");
        if let Some(d) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id).and_then(|f| f.pending_delete.as_mut()) {
            d.next_attempt_at = DateTime::<Utc>::MIN_UTC;
        }
    }

    /// Make a feed due now (tests: "the next run").
    pub fn make_due(&self, feed_id: Uuid) {
        let mut g = self.inner.lock().expect("store");
        if let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id) {
            f.next_run_at = DateTime::<Utc>::MIN_UTC;
        }
    }

    /// Expire a feed's lease (tests: the runner holding it crashed).
    pub fn expire_lease(&self, feed_id: Uuid) {
        let mut g = self.inner.lock().expect("store");
        if let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id) {
            f.lease_expires_at = Some(DateTime::<Utc>::MIN_UTC);
        }
    }

    pub fn commits(&self) -> Vec<CommitLog> {
        self.inner.lock().expect("store").commits.clone()
    }

    pub fn checkpoint(&self, feed_id: Uuid, stream: &str) -> Option<Value> {
        self.inner.lock().expect("store").checkpoints.get(&(feed_id, stream.to_string())).cloned()
    }

    pub fn runs(&self) -> Vec<(Uuid, RunRecord)> {
        self.inner.lock().expect("store").runs.clone()
    }

    pub fn next_run_at(&self, feed_id: Uuid) -> Option<DateTime<Utc>> {
        self.inner.lock().expect("store").feeds.iter().find(|f| f.def.feed_id == feed_id).map(|f| f.next_run_at)
    }

    /// NAN-3660 (tests): what the rotate operation plus the credential pass
    /// do to a feed: a new ingest token, the lease fenced (generation + 1),
    /// failures reset and the feed due now. Checkpoints are kept.
    pub fn rotate_ingest_token(&self, feed_id: Uuid, token: super::feed::Secret) {
        let mut g = self.inner.lock().expect("store");
        if let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id) {
            f.def.ingest_token = token;
            f.def.consecutive_failures = 0;
            f.lease_generation += 1;
            f.lease_owner = None;
            f.lease_expires_at = None;
            f.next_run_at = DateTime::<Utc>::MIN_UTC;
        }
    }

    pub fn set_enabled(&self, feed_id: Uuid, enabled: bool) {
        let mut g = self.inner.lock().expect("store");
        if let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id) {
            f.enabled = enabled;
        }
    }

    fn holds(f: &MemFeed, claim: &ClaimedFeed) -> bool {
        f.lease_generation == claim.lease_generation && f.lease_owner.as_deref() == Some(claim.node.as_str())
    }
}

#[async_trait::async_trait]
impl FeedStore for MemoryFeedStore {
    async fn tenants(&self) -> Result<Vec<TenantSlot>, StoreError> {
        let g = self.inner.lock().expect("store");
        let mut out: Vec<TenantSlot> = Vec::new();
        for f in &g.feeds {
            let slot = TenantSlot { tenant_id: f.def.tenant_id, actor_id: f.actor };
            if !out.contains(&slot) {
                out.push(slot);
            }
        }
        Ok(out)
    }

    async fn claim_due(
        &self,
        slot: &TenantSlot,
        node: &str,
        limit: usize,
        lease_secs: &(dyn Fn(Option<u64>) -> u64 + Send + Sync),
    ) -> Result<Vec<ClaimedFeed>, StoreError> {
        let now = Utc::now();
        let mut g = self.inner.lock().expect("store");
        let mut out = Vec::new();
        for f in g.feeds.iter_mut() {
            if out.len() >= limit {
                break;
            }
            let free = f.lease_expires_at.is_none_or(|t| t < now);
            if f.def.tenant_id != slot.tenant_id || !f.enabled || f.next_run_at > now || !free {
                continue;
            }
            f.lease_generation += 1;
            f.lease_owner = Some(node.to_string());
            f.lease_expires_at = Some(now + ChronoDuration::seconds(lease_secs(f.def.max_run_secs) as i64));
            out.push(ClaimedFeed {
                slot: *slot,
                feed: f.def.clone(),
                lease_generation: f.lease_generation,
                node: node.to_string(),
                run_id: Uuid::now_v7(),
                claimed_at: now,
            });
        }
        Ok(out)
    }

    async fn load_checkpoints(&self, claim: &ClaimedFeed) -> Result<HashMap<String, Value>, StoreError> {
        let g = self.inner.lock().expect("store");
        Ok(g
            .checkpoints
            .iter()
            .filter(|((f, _), _)| *f == claim.feed.feed_id)
            .map(|((_, s), v)| (s.clone(), v.clone()))
            .collect())
    }

    async fn save_checkpoint(&self, claim: &ClaimedFeed, stream: &str, state: &Value) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store");
        let holds = g.feeds.iter().find(|f| f.def.feed_id == claim.feed.feed_id).is_some_and(|f| Self::holds(f, claim));
        if !holds {
            return Err(StoreError::LeaseLost);
        }
        g.checkpoints.insert((claim.feed.feed_id, stream.to_string()), state.clone());
        let seq = (self.seq)();
        g.commits.push(CommitLog {
            seq,
            feed_id: claim.feed.feed_id,
            stream: stream.to_string(),
            state: state.clone(),
            lease_generation: claim.lease_generation,
        });
        Ok(())
    }

    async fn finish(&self, claim: &ClaimedFeed, record: &RunRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store");
        g.runs.push((claim.feed.feed_id, record.clone()));
        let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == claim.feed.feed_id) else {
            return Ok(());
        };
        if !Self::holds(f, claim) {
            return if record.status == RunStatus::LeaseLost { Ok(()) } else { Err(StoreError::LeaseLost) };
        }
        f.lease_owner = None;
        f.lease_expires_at = None;
        f.next_run_at = record.next_run_at;
        f.def.consecutive_failures = if record.ok() {
            0
        } else if record.counts_as_failure() {
            f.def.consecutive_failures + 1
        } else {
            f.def.consecutive_failures
        };
        Ok(())
    }

    async fn claim_deletes(&self, slot: &TenantSlot, node: &str, limit: usize, lease_secs: u64) -> Result<Vec<PendingDelete>, StoreError> {
        let now = Utc::now();
        let mut g = self.inner.lock().expect("store");
        let mut out = Vec::new();
        for f in g.feeds.iter_mut() {
            if out.len() >= limit {
                break;
            }
            let Some(d) = &f.pending_delete else { continue };
            let free = f.lease_expires_at.is_none_or(|t| t < now);
            if f.def.tenant_id != slot.tenant_id || d.next_attempt_at > now || !free {
                continue;
            }
            f.lease_generation += 1;
            f.lease_owner = Some(node.to_string());
            f.lease_expires_at = Some(now + ChronoDuration::seconds(lease_secs as i64));
            out.push(PendingDelete {
                slot: *slot,
                feed_id: f.def.feed_id,
                identity: d.identity,
                lease_generation: f.lease_generation,
                node: node.to_string(),
                attempts: d.attempts,
            });
        }
        Ok(out)
    }

    async fn finish_delete(&self, claim: &PendingDelete, outcome: Result<(), String>) -> Result<(), StoreError> {
        let mut g = self.inner.lock().expect("store");
        let Some(index) = g.feeds.iter().position(|f| f.def.feed_id == claim.feed_id) else {
            return Ok(());
        };
        let f = &mut g.feeds[index];
        if f.lease_generation != claim.lease_generation || f.lease_owner.as_deref() != Some(claim.node.as_str()) {
            return Err(StoreError::LeaseLost);
        }
        match outcome {
            Ok(()) => {
                g.feeds.remove(index);
                g.checkpoints.retain(|(feed, _), _| *feed != claim.feed_id);
            }
            Err(message) => {
                f.lease_owner = None;
                f.lease_expires_at = None;
                if let Some(d) = f.pending_delete.as_mut() {
                    d.attempts += 1;
                    d.next_attempt_at = Utc::now() + delete_backoff(d.attempts);
                    d.last_error = Some(message);
                }
            }
        }
        Ok(())
    }
}
