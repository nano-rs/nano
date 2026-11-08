// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable feed state: claims (leases), checkpoints, run outcomes.
//! [`super::pg::PgFeedStore`] in production; [`MemoryFeedStore`] for tests
//! and local runs.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::Value;
use uuid::Uuid;

use super::feed::{ClaimedFeed, FeedDefinition, RunRecord, RunStatus};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The claim's lease generation is no longer current.
    #[error("the feed lease was lost (another runner holds it now, or the feed was changed)")]
    LeaseLost,
    #[error("feed store: {0}")]
    Backend(String),
    #[error("feed {feed_id}: {message}")]
    Feed { feed_id: Uuid, message: String },
}

#[async_trait::async_trait]
pub trait FeedStore: Send + Sync {
    /// Lease up to `limit` due, enabled feeds. Each claim bumps the feed's
    /// lease generation and opens a `running` run record. The lease lasts
    /// `lease_secs(feed max_run_secs)`.
    async fn claim_due(
        &self,
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

    /// NAN-4931: run `op` (a directory write of an identity run) only while
    /// `claim` holds the lease, holding the feed so a pause, reset or delete
    /// cannot change it until `op` is done. `Err` (lease lost) without
    /// running `op` otherwise.
    async fn fenced<'a>(&self, claim: &ClaimedFeed, op: crate::identity::FencedWrite<'a>) -> Result<(), String>;
}

/// The message a fenced write fails with when the run lost its lease.
pub const LEASE_LOST_WRITE: &str =
    "the feed lease was lost (the feed was paused, reset, deleted or re-pinned): this run's directory writes were refused";

/// A run's [`crate::identity::WriteFence`]: its store and claim.
pub struct ClaimFence {
    pub store: std::sync::Arc<dyn FeedStore>,
    pub claim: ClaimedFeed,
}

#[async_trait::async_trait]
impl crate::identity::WriteFence for ClaimFence {
    async fn run<'a>(&'a self, op: crate::identity::FencedWrite<'a>) -> Result<(), String> {
        self.store.fenced(&self.claim, op).await
    }
}

/// In-memory store. Feeds are added with [`MemoryFeedStore::add`]; every
/// checkpoint write is logged with a global sequence number from
/// [`MemoryFeedStore::with_sequencer`] so tests can order it against
/// ingest acknowledgements.
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
    enabled: bool,
    next_run_at: DateTime<Utc>,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    lease_generation: i64,
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

    pub fn add(&self, def: FeedDefinition) {
        self.inner.lock().expect("store").feeds.push(MemFeed {
            def,
            enabled: true,
            next_run_at: DateTime::<Utc>::MIN_UTC,
            lease_owner: None,
            lease_expires_at: None,
            lease_generation: 0,
        });
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

    pub fn set_enabled(&self, feed_id: Uuid, enabled: bool) {
        let mut g = self.inner.lock().expect("store");
        if let Some(f) = g.feeds.iter_mut().find(|f| f.def.feed_id == feed_id) {
            f.enabled = enabled;
            // Pause / resume fences a run in flight (the PG store does the same).
            f.lease_generation += 1;
            f.lease_owner = None;
            f.lease_expires_at = None;
        }
    }

    fn holds(f: &MemFeed, claim: &ClaimedFeed) -> bool {
        f.lease_generation == claim.lease_generation && f.lease_owner.as_deref() == Some(claim.node.as_str())
    }
}

#[async_trait::async_trait]
impl FeedStore for MemoryFeedStore {
    async fn claim_due(
        &self,
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
            if !f.enabled || f.next_run_at > now || !free {
                continue;
            }
            f.lease_generation += 1;
            f.lease_owner = Some(node.to_string());
            f.lease_expires_at = Some(now + ChronoDuration::seconds(lease_secs(f.def.max_run_secs) as i64));
            out.push(ClaimedFeed {
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

    async fn fenced<'a>(&self, claim: &ClaimedFeed, op: crate::identity::FencedWrite<'a>) -> Result<(), String> {
        let holds = {
            let g = self.inner.lock().expect("store");
            g.feeds.iter().any(|f| f.def.feed_id == claim.feed.feed_id && Self::holds(f, claim))
        };
        if !holds {
            return Err(LEASE_LOST_WRITE.into());
        }
        op.await
    }
}
