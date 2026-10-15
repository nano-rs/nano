//! Feed records, claims, run outcomes and the schedule/backoff arithmetic.

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

/// One tenant the runner may work for, and the service member its signed
/// transactions act as (nil on dedicated / open core, where there is no
/// signed context).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantSlot {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
}

/// Everything a run needs, with secrets opened.
#[derive(Debug, Clone)]
pub struct FeedDefinition {
    pub tenant_id: Uuid,
    pub feed_id: Uuid,
    pub name: String,
    /// Catalog slug of the connector (e.g. `okta_system_log`).
    pub connector: String,
    /// The spec YAML pinned on the feed, and its sha256 (hex). A catalog
    /// update never changes a running feed: the feed keeps its own copy.
    pub spec_yaml: String,
    pub spec_sha256: String,
    /// The feed's source slug (the lane its credential is bound to).
    pub source_slug: String,
    /// Cron override; `None` = the spec's `schedule`, else the default.
    pub schedule: Option<String>,
    pub config: Map<String, Value>,
    pub vendor_credentials: HashMap<String, Secret>,
    /// Tenant ingress base URL (or the full HEC event endpoint).
    pub ingest_url: String,
    /// The platform-held per-feed ingest credential.
    pub ingest_token: Secret,
    pub max_run_secs: Option<u64>,
    pub consecutive_failures: u32,
}

/// A feed this runner holds the lease on.
#[derive(Debug, Clone)]
pub struct ClaimedFeed {
    pub slot: TenantSlot,
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
    /// Events that got an ingress receipt.
    pub events: u64,
    /// Request bytes that got an ingress receipt.
    pub bytes: u64,
    /// Ingress POSTs that got a receipt.
    pub batches: u64,
    pub pages: u32,
    pub requests: u32,
    /// Ingress attempts that were retried (429 / 5xx / network).
    pub ingest_retries: u64,
    /// Events the ingress refused individually (e.g. over the 4 MiB cap).
    pub rejected_events: u64,
    pub dropped_duplicates: u64,
    pub checkpoints_committed: u64,
    /// 0 or 1 today (a run stops at its first error); a count so a later
    /// per-stream continue-on-error mode keeps the same record.
    pub errors: u32,
    pub error: Option<String>,
    /// Last ingress receipt (`x-nano-delivery-receipt` or HEC `ackId`).
    pub last_receipt: Option<String>,
    /// When the feed is next due.
    pub next_run_at: DateTime<Utc>,
    /// The run could not start for lack of local capacity (no VRL worker
    /// slot free): recorded as `timeout`, retried soon, and not counted as
    /// a failure of the feed.
    pub deferred: bool,
}

impl RunRecord {
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
/// hourly aggregate API or a directory sync) keeps it; a feed override beats
/// both.
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

/// Failure backoff: `base * 2^(failures-1)`, capped, with ±20 % jitter, and
/// never sooner than the regular schedule would run again.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_caps_and_jitters() {
        let b = Duration::from_secs(30);
        let cap = Duration::from_secs(3600);
        assert_eq!(failure_delay(1, b, cap, 0.0), Duration::from_secs(30));
        assert_eq!(failure_delay(3, b, cap, 0.0), Duration::from_secs(120));
        assert_eq!(failure_delay(30, b, cap, 0.0), cap);
        assert_eq!(failure_delay(1, b, cap, 1.0), Duration::from_secs(36));
    }

    #[test]
    fn schedule_parses_five_field_cron() {
        let t = DateTime::parse_from_rfc3339("2026-10-10T12:00:30Z").unwrap().with_timezone(&Utc);
        assert_eq!(next_scheduled("*/2 * * * *", t).unwrap().to_rfc3339(), "2026-10-10T12:02:00+00:00");
        assert!(next_scheduled("nope", t).is_err());
    }

    #[test]
    fn default_schedule_runs_every_five_minutes() {
        // NAN-3783: no feed override and no spec schedule -> every 5 min.
        assert_eq!(effective_schedule(None, None), "*/5 * * * *");
        assert_eq!(effective_schedule(Some("  "), Some("")), DEFAULT_SCHEDULE);
        let mut t = DateTime::parse_from_rfc3339("2026-10-10T12:00:30Z").unwrap().with_timezone(&Utc);
        let first = next_scheduled(DEFAULT_SCHEDULE, t).unwrap();
        assert_eq!(first.to_rfc3339(), "2026-10-10T12:05:00+00:00");
        t = first;
        for _ in 0..12 {
            let next = next_scheduled(DEFAULT_SCHEDULE, t).unwrap();
            assert_eq!((next - t).num_seconds(), 300);
            t = next;
        }
    }

    #[test]
    fn vendor_floor_in_the_spec_beats_the_default_and_a_feed_override_beats_both() {
        // A spec that pins a slower vendor cadence (Slack access logs: hourly
        // aggregates; directory syncs: hourly / 6-hourly) keeps it.
        let hourly = effective_schedule(None, Some("0 * * * *"));
        assert_eq!(hourly, "0 * * * *");
        let t = DateTime::parse_from_rfc3339("2026-10-10T12:00:30Z").unwrap().with_timezone(&Utc);
        assert_eq!(next_scheduled(hourly, t).unwrap().to_rfc3339(), "2026-10-10T13:00:00+00:00");
        // A faster vendor cadence (Okta System Log every 2 min) is kept too.
        assert_eq!(effective_schedule(None, Some("*/2 * * * *")), "*/2 * * * *");
        // The operator's per-feed override wins over the spec.
        assert_eq!(effective_schedule(Some("*/15 * * * *"), Some("0 * * * *")), "*/15 * * * *");
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret::new("hunter2")), "Secret(<redacted>)");
    }
}
