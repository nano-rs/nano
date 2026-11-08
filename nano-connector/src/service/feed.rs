// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed records, claims, run outcomes and the schedule/backoff arithmetic.
//!
//! Single-tenant (the ClickHouse product): a feed belongs to the deployment,
//! there is no tenant slot, and a feed's vendor secret is a credential in the
//! credentials store (`cloud_credentials`), opened by the store at claim time.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

/// A secret string whose `Debug`/`Display` never print the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Everything a run needs, with secrets opened.
#[derive(Debug, Clone)]
pub struct FeedDefinition {
    pub feed_id: Uuid,
    pub name: String,
    /// Bundled spec slug of the connector (e.g. `okta_system_log`).
    pub connector: String,
    /// The spec YAML pinned on the feed, and its sha256 (hex). A spec update
    /// in a new release never changes a running feed: the feed keeps its own
    /// copy.
    pub spec_yaml: String,
    pub spec_sha256: String,
    /// The parser lane label of the feed (the spec's stream `source_type`,
    /// or its template for a fan-out spec). Display and audit only; every
    /// event batch carries the stream's own rendered source type.
    pub source_type: String,
    /// Cron override; `None` = the spec's `schedule`, else the default.
    pub schedule: Option<String>,
    pub config: Map<String, Value>,
    /// The bound credential (`cloud_credentials.id`), if any.
    pub credential_id: Option<Uuid>,
    /// The credential's fields, opened at claim time.
    pub vendor_credentials: HashMap<String, Secret>,
    pub max_run_secs: Option<u64>,
    pub consecutive_failures: u32,
}

/// A feed this runner holds the lease on.
#[derive(Debug, Clone)]
pub struct ClaimedFeed {
    pub feed: FeedDefinition,
    /// Fencing token: every checkpoint and the outcome must match it.
    pub lease_generation: i64,
    pub node: String,
    pub run_id: Uuid,
    pub claimed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Success,
    Failed,
    /// The run hit its wall clock. The cursor is wherever the last
    /// acknowledged page left it.
    Timeout,
    /// Another runner took the lease; this run's outcome is discarded.
    LeaseLost,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::LeaseLost => "lease_lost",
        }
    }
}

/// One run's outcome: the audit record and the metrics source.
#[derive(Debug, Clone)]
pub struct RunRecord {
    pub status: RunStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    /// Events that got an ingest acknowledgement.
    pub events: u64,
    /// Request bytes that got an ingest acknowledgement.
    pub bytes: u64,
    /// Ingest POSTs that got an acknowledgement.
    pub batches: u64,
    pub pages: u32,
    pub requests: u32,
    /// Ingest attempts that were retried (429 / 5xx / network).
    pub ingest_retries: u64,
    /// Events the ingest refused individually.
    pub rejected_events: u64,
    pub dropped_duplicates: u64,
    pub checkpoints_committed: u64,
    /// 0 or 1 today (a run stops at its first error).
    pub errors: u32,
    pub error: Option<String>,
    /// Last ingest receipt (HEC `ackId`).
    pub last_receipt: Option<String>,
    /// When the feed is next due.
    pub next_run_at: DateTime<Utc>,
    /// The run could not start for lack of local capacity (no VRL worker
    /// slot free): recorded as `timeout`, retried soon, and not counted as
    /// a failure of the feed.
    pub deferred: bool,
}

impl RunRecord {
    /// A blank `failed` record starting at `at`.
    pub fn started(at: DateTime<Utc>) -> Self {
        Self {
            status: RunStatus::Failed,
            started_at: at,
            finished_at: at,
            events: 0,
            bytes: 0,
            batches: 0,
            pages: 0,
            requests: 0,
            ingest_retries: 0,
            rejected_events: 0,
            dropped_duplicates: 0,
            checkpoints_committed: 0,
            errors: 0,
            error: None,
            last_receipt: None,
            next_run_at: at,
            deferred: false,
        }
    }

    pub fn ok(&self) -> bool {
        self.status == RunStatus::Success
    }

    /// Counts toward `consecutive_failures` and backoff.
    pub fn counts_as_failure(&self) -> bool {
        !self.ok() && !self.deferred
    }
}

/// Default when neither the feed nor the spec names a schedule: every 5 min
/// (NAN-3783). A spec that names a slower cadence (a vendor floor, e.g. an
/// hourly aggregate API) keeps it; a feed override beats both.
pub const DEFAULT_SCHEDULE: &str = "*/5 * * * *";

/// The cron a feed runs on: the feed's override, else the pinned spec's
/// `schedule`, else [`DEFAULT_SCHEDULE`]. Blank values count as unset.
pub fn effective_schedule<'a>(feed_override: Option<&'a str>, spec_schedule: Option<&'a str>) -> &'a str {
    [feed_override, spec_schedule]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SCHEDULE)
}

/// Next fire of `schedule` strictly after `after` (5- or 6-field cron).
pub fn next_scheduled(schedule: &str, after: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let normalized = nanosiem_core::scheduler::normalize_cron(schedule);
    let parsed = cron::Schedule::from_str(&normalized).map_err(|e| format!("invalid schedule `{schedule}`: {e}"))?;
    parsed.after(&after).next().ok_or_else(|| format!("schedule `{schedule}` never fires again"))
}

/// The shortest gap between two fires of `schedule` over the next few
/// fires. Used to refuse a feed override faster than the spec's vendor floor.
pub fn min_interval(schedule: &str, from: DateTime<Utc>) -> Result<chrono::Duration, String> {
    let mut t = next_scheduled(schedule, from)?;
    let mut min = chrono::Duration::MAX;
    for _ in 0..8 {
        let next = next_scheduled(schedule, t)?;
        min = min.min(next - t);
        t = next;
    }
    Ok(min)
}

/// Failure backoff: `base * 2^(failures-1)`, capped, with ±20 % jitter.
pub fn failure_delay(failures: u32, base: Duration, cap: Duration, jitter: f64) -> Duration {
    let exp = failures.saturating_sub(1).min(20);
    let raw = base.saturating_mul(1u32 << exp).min(cap);
    let j = jitter.clamp(-1.0, 1.0) * 0.2;
    Duration::from_secs_f64((raw.as_secs_f64() * (1.0 + j)).max(1.0))
}

/// sha256 hex of a spec, for pinning.
pub fn spec_sha256(yaml: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, yaml.as_bytes());
    hex::encode(d.as_ref())
}
