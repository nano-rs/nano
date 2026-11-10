// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse row store for durable search job results
//! (`search_job_results`, clickhouse/181).

use chrono::{DateTime, Utc};

use crate::db::TableNames;
use crate::search::types::SearchError;

/// Rows per native INSERT block. Rows are JSON strings of a few hundred bytes
/// to a few KiB, so this keeps each block in the low MiB.
const INSERT_BATCH_ROWS: usize = 5_000;

/// Hard ceiling on one page read, whatever the caller asks for.
pub const MAX_PAGE_ROWS: u64 = 10_000;

/// Default byte budget for one page read (Codex P1-3). Enforced WHILE the rows
/// stream in, so a page of very wide rows stops early instead of buffering
/// 10 000 multi-KiB rows and their decoded JSON in the search pod.
pub const DEFAULT_PAGE_BYTE_BUDGET: usize = 16 * 1024 * 1024;

/// Slack on the `created_at` partition bounds around the job's lifetime. Rows
/// are stamped `now()` (second precision) by the ClickHouse server while the
/// job runs; the slack absorbs clock skew between ClickHouse and PostgreSQL.
const CREATED_AT_SLACK_SECS: i64 = 300;

#[derive(clickhouse::Row, serde::Serialize)]
struct ResultRow {
    job_id: String,
    attempt: u32,
    seq: u64,
    row: String,
}

/// One page as read from ClickHouse.
#[derive(Debug)]
pub struct StoredPage {
    pub rows: Vec<serde_json::Value>,
    /// The page stopped early because it reached the byte budget. A short page
    /// with this unset is a consistency problem, not a deliberate cut.
    pub byte_limited: bool,
}

/// Codex P1-4: a page holding more rows than PostgreSQL says exist, or fewer
/// without having stopped at the byte budget, came from a replica that does
/// not hold every row (yet).
pub(crate) fn page_inconsistent(page: &StoredPage, expected: u64) -> bool {
    let got = page.rows.len() as u64;
    got > expected || (got < expected && !page.byte_limited)
}

/// The authorized job's lifetime, used as the `created_at` partition bound.
#[derive(Debug, Clone, Copy)]
pub struct JobWindow {
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl JobWindow {
    /// `[created_at - slack, (finished_at or now) + slack)` as unix seconds.
    pub fn bounds(&self) -> (i64, i64) {
        let lower = self.created_at.timestamp() - CREATED_AT_SLACK_SECS;
        let upper = self.finished_at.unwrap_or_else(Utc::now).timestamp() + CREATED_AT_SLACK_SECS;
        (lower, upper)
    }
}

/// Reads and writes job result rows. All reads are already authorized by the
/// caller (owner/admin + scope re-check); this type never decides access.
#[derive(Clone)]
pub struct SearchJobResultStore {
    client: clickhouse::Client,
    table_names: TableNames,
    page_byte_budget: usize,
}

impl std::fmt::Debug for SearchJobResultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchJobResultStore").finish_non_exhaustive()
    }
}

fn ch(e: clickhouse::error::Error) -> SearchError {
    crate::search::types::parse_clickhouse_error(&e.to_string())
}

/// NAN-5215: ClickHouse `TOO_FEW_LIVE_REPLICAS` (285). `insert_quorum =
/// 'auto'` is a majority, i.e. 2 of 2 on a two-replica shard, so it raises this
/// whenever one replica of the shard is down. The check runs before any part
/// is written, so the same rows can be retried without a quorum.
pub(crate) fn is_too_few_live_replicas(message: &str) -> bool {
    message.contains("TOO_FEW_LIVE_REPLICAS") || message.contains("Code: 285")
}

/// ClickHouse errors meaning "this replica cannot serve a consistent read
/// right now" rather than a problem with the query or the caller: the
/// sequential-consistency check failing on a replica (quorum-less parts, a
/// replica behind the last quorum write) or no live/fresh replica answering.
const REPLICA_CONSISTENCY_ERRORS: &[(&str, u32)] = &[
    ("REPLICA_IS_NOT_IN_QUORUM", 289),
    ("ALL_REPLICAS_ARE_STALE", 232),
    ("NO_REPLICA_HAS_PART", 234),
    ("ALL_CONNECTION_TRIES_FAILED", 279),
    ("TOO_FEW_LIVE_REPLICAS", 285),
    ("UNSATISFIED_QUORUM_FOR_PREVIOUS_WRITE", 286),
];

/// NAN-5215: whether a page-read error is the replica/consistency class
/// (worth one eventual re-read). Auth, syntax, memory and timeouts are not.
pub(crate) fn is_replica_consistency_error(message: &str) -> bool {
    REPLICA_CONSISTENCY_ERRORS.iter().any(|(name, code)| {
        message.contains(name) || message.contains(&format!("Code: {code}."))
    })
}

/// The message a replica/consistency read error surfaces as: the same
/// retryable state the row-count check reports.
pub(crate) const STILL_REPLICATING: &str = "Search results are still replicating; retry shortly";

/// Map a page-read error. The replica/consistency class becomes the
/// retryable [`SearchError::JobResultsUnavailable`] (the caller's cue to try
/// an eventual read); everything else keeps its usual mapping.
fn read_error(e: clickhouse::error::Error) -> SearchError {
    let message = e.to_string();
    if is_replica_consistency_error(&message) {
        tracing::debug!(error = %message, "Background search page read hit a replica consistency error");
        return SearchError::JobResultsUnavailable(STILL_REPLICATING.to_string());
    }
    ch(e)
}

/// How a page read treats replication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadConsistency {
    /// `select_sequential_consistency = 1`: read-your-quorum-writes. Parts a
    /// degraded (quorum-less) write left are excluded or rejected here.
    Sequential,
    /// Plain read of whatever the serving replica holds. The caller must still
    /// check the row count against PostgreSQL; a lagging replica returns a
    /// short page, never a wrong one.
    Eventual,
}

impl ReadConsistency {
    pub(crate) fn select_sequential_consistency(self) -> &'static str {
        match self {
            Self::Sequential => "1",
            Self::Eventual => "0",
        }
    }
}

/// The page-read SQL. ONE `WHERE`, no `PREWHERE` (NAN-1412): the job/attempt/
/// seq range hits the primary key, and the `created_at` bound prunes the
/// `toYYYYMMDD(created_at)` partitions (Codex P2-8) so a page never probes
/// every retained (or TTL-lagged) day.
pub(crate) fn page_sql(table: &str) -> String {
    format!(
        "SELECT row FROM {table} \
         WHERE created_at >= toDateTime(?) AND created_at < toDateTime(?) \
           AND job_id = ? AND attempt = ? AND seq >= ? AND seq < ? \
         ORDER BY seq"
    )
}

impl SearchJobResultStore {
    pub fn new(client: clickhouse::Client, table_names: TableNames) -> Self {
        Self {
            client,
            table_names,
            page_byte_budget: DEFAULT_PAGE_BYTE_BUDGET,
        }
    }

    /// Override the per-page byte budget (tests, operators).
    pub fn with_page_byte_budget(mut self, bytes: usize) -> Self {
        self.page_byte_budget = bytes.max(1);
        self
    }

    /// Write one attempt's rows, `seq` = position in the result.
    ///
    /// Synchronous insert (async_insert off, wait_end_of_query) AND, on
    /// replicated deployments, `insert_quorum = 'auto'` (Codex P1-4): the
    /// insert returns only once a majority of the shard's replicas hold the
    /// part, so the fenced completion that follows never advertises rows a
    /// Distributed read routed to another replica cannot see yet. On a
    /// non-replicated single node the quorum settings are no-ops. Writes the
    /// LOCAL table (a Distributed wrapper cannot be a native-insert target);
    /// reads route through the wrapper on clusters.
    pub async fn insert_rows(
        &self,
        job_id: &str,
        attempt: u32,
        rows: &[serde_json::Value],
    ) -> Result<(), SearchError> {
        if rows.is_empty() {
            return Ok(());
        }
        let base = self
            .client
            .clone()
            .with_validation(false)
            .with_option("async_insert", "0")
            .with_option("wait_end_of_query", "1");
        let quorum_writer = base
            .clone()
            .with_option("insert_quorum", "auto")
            .with_option("insert_quorum_parallel", "0");
        // NAN-5215: with one replica of a two-replica shard down the majority
        // quorum cannot be met. Fall back to a quorum-less insert (the live
        // replica takes the part; the returning one fetches it) instead of
        // failing the job. Readers then see the rows via an eventual read
        // checked against the PostgreSQL row count (see `ReadConsistency`).
        let degraded_writer = base.with_option("insert_quorum", "0");
        let mut degraded = false;
        let mut seq: u64 = 0;
        for chunk in rows.chunks(INSERT_BATCH_ROWS) {
            if !degraded {
                match self
                    .insert_chunk(&quorum_writer, job_id, attempt, seq, chunk)
                    .await
                {
                    Ok(()) => {
                        seq += chunk.len() as u64;
                        continue;
                    }
                    Err(e) if is_too_few_live_replicas(&e.to_string()) => {
                        tracing::warn!(
                            job_id,
                            attempt,
                            error = %e,
                            "Background search results: insert quorum unavailable (a replica is \
                             down); retrying without quorum"
                        );
                        degraded = true;
                    }
                    Err(e) => return Err(ch(e)),
                }
            }
            self.insert_chunk(&degraded_writer, job_id, attempt, seq, chunk)
                .await
                .map_err(ch)?;
            seq += chunk.len() as u64;
        }
        Ok(())
    }

    /// One native INSERT block of rows starting at `first_seq`.
    async fn insert_chunk(
        &self,
        writer: &clickhouse::Client,
        job_id: &str,
        attempt: u32,
        first_seq: u64,
        chunk: &[serde_json::Value],
    ) -> Result<(), clickhouse::error::Error> {
        let mut insert = writer
            .insert::<ResultRow>(&self.table_names.local("search_job_results"))
            .await?;
        for (offset, row) in chunk.iter().enumerate() {
            // Encoding cannot fail for an in-memory `Value`; keep the error
            // path anyway rather than panic.
            let encoded = serde_json::to_string(row)
                .map_err(|e| clickhouse::error::Error::Custom(format!("encode result row: {e}")))?;
            insert
                .write(&ResultRow {
                    job_id: job_id.to_string(),
                    attempt,
                    seq: first_seq + offset as u64,
                    row: encoded,
                })
                .await?;
        }
        insert.end().await
    }

    /// Rows `[offset, offset + limit)` of one attempt, in result order,
    /// stopping early at the byte budget.
    ///
    /// `seq` is dense from 0, so the page is a primary-key range read on
    /// `(job_id, attempt, seq)` — no OFFSET scan however deep the page. Rows
    /// are decoded as they stream in and the cursor is dropped (cancelling the
    /// read) as soon as the budget is reached; at least one row is always
    /// returned so paging can make progress past a single huge row.
    pub async fn read_page(
        &self,
        job_id: &str,
        attempt: u32,
        window: JobWindow,
        offset: u64,
        limit: u64,
        consistency: ReadConsistency,
    ) -> Result<StoredPage, SearchError> {
        let limit = limit.min(MAX_PAGE_ROWS);
        if limit == 0 {
            return Ok(StoredPage {
                rows: Vec::new(),
                byte_limited: false,
            });
        }
        let (lower, upper) = window.bounds();
        let sql = page_sql(&self.table_names.read("search_job_results"));
        let mut cursor = self
            .client
            .query(&sql)
            .bind(lower)
            .bind(upper)
            .bind(job_id)
            .bind(attempt)
            .bind(offset)
            .bind(offset.saturating_add(limit))
            // Read-your-quorum-writes on replicated tables (no-op otherwise);
            // `Eventual` only after a sequential read came back inconsistent.
            .with_option(
                "select_sequential_consistency",
                consistency.select_sequential_consistency(),
            )
            .fetch::<String>()
            .map_err(read_error)?;
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut byte_limited = false;
        while let Some(encoded) = cursor.next().await.map_err(read_error)? {
            if !rows.is_empty() && bytes + encoded.len() > self.page_byte_budget {
                byte_limited = true;
                break;
            }
            bytes += encoded.len();
            rows.push(serde_json::from_str(&encoded).map_err(|e| {
                SearchError::SqlValidationError(format!("corrupt stored result row: {e}"))
            })?);
        }
        Ok(StoredPage { rows, byte_limited })
    }
}

#[cfg(test)]
#[path = "results_tests.rs"]
mod tests;
