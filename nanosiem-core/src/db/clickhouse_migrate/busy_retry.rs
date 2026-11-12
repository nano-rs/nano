// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5296: retry ClickHouse code 202 (TOO_MANY_SIMULTANEOUS_QUERIES) with
//! a bounded backoff, and say why the server is full before giving up.
//!
//! 202 is transient by definition: the server is at `max_concurrent_queries`
//! or `max_concurrent_insert_queries`. A short burst clears in seconds. A
//! wedge does not: in NAN-5296 two deadlocked async-insert flushes held every
//! async-insert thread, every new insert queued behind them without a timeout,
//! and once the insert cap filled every INSERT failed with 202 until a manual
//! kill. The migrator's `_migrations` record was one of them. Retrying alone
//! does not fix that, so on giving up the error names the stuck inserts.

use std::time::Duration;

use clickhouse::Row;
use serde::Deserialize;

use super::ClickHouseMigrator;

/// Total time spent waiting between attempts before a 202 is fatal.
pub(super) const BUSY_RETRY_BUDGET: Duration = Duration::from_secs(150);
const FIRST_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(15);
/// An insert older than this is reported as stuck when the retry gives up.
const STUCK_INSERT_SECS: u64 = 300;

pub(super) fn is_too_many_simultaneous_queries(error: &str) -> bool {
    error.contains("Code: 202.") || error.contains("TOO_MANY_SIMULTANEOUS_QUERIES")
}

/// Backoff schedule: 1, 2, 4, 8, 15, 15, ... seconds, truncated so the sum
/// never exceeds [`BUSY_RETRY_BUDGET`].
pub(super) fn busy_retry_delays() -> Vec<Duration> {
    let mut delays = Vec::new();
    let mut total = Duration::ZERO;
    let mut delay = FIRST_DELAY;
    while total + delay <= BUSY_RETRY_BUDGET {
        delays.push(delay);
        total += delay;
        delay = (delay * 2).min(MAX_DELAY);
    }
    delays
}

#[derive(Debug, Row, Deserialize)]
struct StuckInserts {
    stuck: u64,
    oldest_seconds: u64,
    kinds: Vec<String>,
}

pub(super) fn describe_stuck_inserts(stuck: u64, oldest_seconds: u64, kinds: &[String]) -> String {
    format!(
        "insert slots exhausted by {stuck} stuck insert{} (oldest {oldest_seconds}s, kind {}); \
         check system.processes and the ingest watchdog before re-running",
        if stuck == 1 { "" } else { "s" },
        kinds.join("/"),
    )
}

impl ClickHouseMigrator {
    /// Execute one statement, retrying 202 with backoff for up to
    /// [`BUSY_RETRY_BUDGET`]. Any other error returns at once. The error text
    /// is ClickHouse's own, so callers' classifiers (unknown table, soft
    /// fail) still match; a final 202 also carries the stuck-insert report.
    pub(super) async fn execute_with_busy_retry(&self, sql: &str) -> Result<(), String> {
        let mut delays = busy_retry_delays().into_iter();
        loop {
            let error = match self.client.query(sql).execute().await {
                Ok(()) => return Ok(()),
                Err(error) => error.to_string(),
            };
            if !is_too_many_simultaneous_queries(&error) {
                return Err(error);
            }
            let Some(delay) = delays.next() else {
                return Err(match self.stuck_insert_report().await {
                    Some(report) => format!("{error} ({report})"),
                    None => error,
                });
            };
            tracing::warn!(
                retry_in_secs = delay.as_secs(),
                budget_secs = BUSY_RETRY_BUDGET.as_secs(),
                "ClickHouse is at its concurrent-query limit (202); retrying migration statement"
            );
            tokio::time::sleep(delay).await;
        }
    }

    /// Inserts on the connected server older than [`STUCK_INSERT_SECS`].
    /// Read-only, so it still answers when every INSERT gets 202.
    async fn stuck_insert_report(&self) -> Option<String> {
        let sql = format!(
            "SELECT count() AS stuck, toUInt64(max(elapsed)) AS oldest_seconds, \
                    arraySort(groupUniqArray(toString(query_kind))) AS kinds \
             FROM system.processes \
             WHERE query_kind IN ('Insert', 'AsyncInsertFlush') AND elapsed > {STUCK_INSERT_SECS}"
        );
        match self.client.query(&sql).fetch_one::<StuckInserts>().await {
            Ok(row) if row.stuck > 0 => {
                let report = describe_stuck_inserts(row.stuck, row.oldest_seconds, &row.kinds);
                tracing::error!("{report}");
                Some(report)
            }
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "Could not read system.processes for stuck inserts");
                None
            }
        }
    }
}
