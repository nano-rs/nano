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
        let writer = self
            .client
            .clone()
            .with_validation(false)
            .with_option("async_insert", "0")
            .with_option("wait_end_of_query", "1")
            .with_option("insert_quorum", "auto")
            .with_option("insert_quorum_parallel", "0");
        let mut seq: u64 = 0;
        for chunk in rows.chunks(INSERT_BATCH_ROWS) {
            let mut insert = writer
                .insert::<ResultRow>(&self.table_names.local("search_job_results"))
                .await
                .map_err(ch)?;
            for row in chunk {
                let encoded = serde_json::to_string(row).map_err(|e| {
                    SearchError::SqlValidationError(format!("encode result row: {e}"))
                })?;
                insert
                    .write(&ResultRow {
                        job_id: job_id.to_string(),
                        attempt,
                        seq,
                        row: encoded,
                    })
                    .await
                    .map_err(ch)?;
                seq += 1;
            }
            insert.end().await.map_err(ch)?;
        }
        Ok(())
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
            // Read-your-quorum-writes on replicated tables (no-op otherwise).
            .with_option("select_sequential_consistency", "1")
            .fetch::<String>()
            .map_err(ch)?;
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut byte_limited = false;
        while let Some(encoded) = cursor.next().await.map_err(ch)? {
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
