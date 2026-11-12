// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ingest-stall detection (NAN-5296), shared by the ingest watchdog and
//! SIEM Health.
//!
//! An async-insert flush that never finishes holds an `async_insert_threads`
//! slot. Once those slots are gone, every new insert waits without a timeout,
//! `max_concurrent_insert_queries` fills, and every INSERT on the server fails
//! with code 202. Writes to the watchdog's own journal fail too, so detection
//! reads only `system.*` tables and the alert goes to the log, the watchdog
//! status and SIEM Health, never through an INSERT.

use std::time::Duration;

use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};

/// An `AsyncInsertFlush` running longer than this is stuck. A healthy flush of
/// a 100 MB async-insert buffer through the full view chain takes seconds.
pub const STUCK_FLUSH_ALERT_SECS: u64 = 300;

/// How long the `ingest` workload's CPU slots may stay full with a queue of
/// waiters before it is an alert. Saturation under load is normal for a few
/// seconds; a full semaphore with waiters for a minute is the 189 deadlock.
pub const SLOT_SATURATION_ALERT: Duration = Duration::from_secs(60);

/// Point-in-time stall signals read from one ClickHouse server.
///
/// `system.processes` and `system.scheduler` are server-local. On a cluster,
/// every replica that ingest can target must be probed.
pub fn stall_probe_sql() -> String {
    format!(
        "SELECT \
         coalesce((SELECT toUInt64(max(elapsed)) FROM system.processes \
                   WHERE query_kind = 'AsyncInsertFlush'), toUInt64(0)) AS longest_async_flush_seconds, \
         coalesce((SELECT count() FROM system.processes \
                   WHERE query_kind = 'AsyncInsertFlush' AND elapsed > {STUCK_FLUSH_ALERT_SECS}), toUInt64(0)) \
             AS stuck_async_flushes, \
         CAST(coalesce((SELECT \
                   countIf(type = 'inflight_limit' AND max_requests > 0 AND inflight_requests >= max_requests) > 0 \
                   AND countIf(type = 'request_queue' AND queue_length > 0) > 0 \
               FROM system.scheduler \
               WHERE path LIKE '%/ingest/semaphore' OR path LIKE '%/ingest/semaphore/queue'), 0) AS Bool) \
             AS ingest_slots_full_with_queue"
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Row)]
pub struct IngestStallProbe {
    /// Elapsed seconds of the longest-running `AsyncInsertFlush`.
    pub longest_async_flush_seconds: u64,
    /// `AsyncInsertFlush` queries running longer than [`STUCK_FLUSH_ALERT_SECS`].
    pub stuck_async_flushes: u64,
    /// The `ingest` workload's CPU semaphore is at its limit and has waiters.
    /// Always false when the workload has no `max_concurrent_threads` cap.
    pub ingest_slots_full_with_queue: bool,
}

impl IngestStallProbe {
    /// Worst-case merge across replicas: a stall on any replica is a stall.
    pub fn merge(self, other: Self) -> Self {
        Self {
            longest_async_flush_seconds: self
                .longest_async_flush_seconds
                .max(other.longest_async_flush_seconds),
            stuck_async_flushes: self
                .stuck_async_flushes
                .saturating_add(other.stuck_async_flushes),
            ingest_slots_full_with_queue: self.ingest_slots_full_with_queue
                || other.ingest_slots_full_with_queue,
        }
    }
}

/// Read the stall signals from one server.
pub async fn probe(client: &Client) -> Result<IngestStallProbe, clickhouse::error::Error> {
    client
        .query(&stall_probe_sql())
        .fetch_one::<IngestStallProbe>()
        .await
}

/// Turns successive probes into alert reasons. Slot saturation must persist
/// for [`SLOT_SATURATION_ALERT`] before it alerts; a stuck flush alerts at once
/// because its age is already the persistence.
#[derive(Debug, Clone, Default)]
pub struct StallTracker {
    saturated_since: Option<DateTime<Utc>>,
    alerting: bool,
}

/// What changed on this observation, so the caller logs once per transition
/// and keeps repeating the alert while it lasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StallAlert {
    Calm,
    Firing(Vec<String>),
    Cleared,
}

impl StallTracker {
    pub fn observe(&mut self, probe: &IngestStallProbe, now: DateTime<Utc>) -> StallAlert {
        let mut reasons = Vec::new();
        if probe.longest_async_flush_seconds > STUCK_FLUSH_ALERT_SECS {
            reasons.push(format!(
                "AsyncInsertFlush running for {}s (limit {}s)",
                probe.longest_async_flush_seconds, STUCK_FLUSH_ALERT_SECS
            ));
        }
        if probe.ingest_slots_full_with_queue {
            let since = *self.saturated_since.get_or_insert(now);
            let held = now.signed_duration_since(since).num_seconds().max(0) as u64;
            if held >= SLOT_SATURATION_ALERT.as_secs() {
                reasons.push(format!(
                    "ingest workload CPU slots full with waiters for {held}s (limit {}s)",
                    SLOT_SATURATION_ALERT.as_secs()
                ));
            }
        } else {
            self.saturated_since = None;
        }

        if reasons.is_empty() {
            if std::mem::replace(&mut self.alerting, false) {
                StallAlert::Cleared
            } else {
                StallAlert::Calm
            }
        } else {
            self.alerting = true;
            StallAlert::Firing(reasons)
        }
    }
}

#[cfg(test)]
#[path = "ingest_stall_tests.rs"]
mod tests;
