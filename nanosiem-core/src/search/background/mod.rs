// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable search background jobs (NAN-4915).
//!
//! A background job is a search that runs outside the interactive request:
//! either explicitly submitted (`async_mode`, `POST /api/search/jobs`) or an
//! interactive search that outran its budget and was handed off
//! ([`JobOrigin::Escalated`]).
//!
//! * **Control plane — PostgreSQL** (`search_jobs`, migration 291): state
//!   machine, fenced leases, progress, result metadata, typed errors. Any search
//!   replica can serve status, cancel, and pages for any job.
//! * **Rows — ClickHouse** (`search_job_results`, clickhouse/181, 24 h TTL),
//!   keyed by `(job_id, attempt, seq)`.
//! * **Execution — a worker pool inside nanosiem-search**
//!   ([`BackgroundSearchJobs::start`]). It claims with `FOR UPDATE SKIP LOCKED`,
//!   runs the search under a stable per-attempt ClickHouse `query_id`
//!   (`<uuid>-a<attempt>`, cancelled with `KILL QUERY`), renews its lease, and
//!   writes the rows. A worker that dies stops renewing; once the lease lapses
//!   another worker (or the restarted process) re-runs the job as the next
//!   attempt, and the fenced writes keep the dead attempt from clobbering it.
//! * **Isolation from interactive search (S6)**: workers draw from their own
//!   semaphore, never from the interactive [`AdmissionController`]
//!   (`crate::search::AdmissionController`), and run with Analytics-tier
//!   ClickHouse settings (lower scheduler priority) plus a dedicated
//!   `max_execution_time`. A pile of background jobs therefore cannot consume
//!   an interactive admission slot.

mod identity;
mod repository;
mod results;
mod service;
mod types;

#[cfg(test)]
mod tests;

pub use identity::{freeze_time_window, identity_hash, normalize_job_request};
pub use repository::SearchJobRepository;
pub use results::SearchJobResultStore;
pub use service::{BackgroundJobConfig, BackgroundSearchJobs};
pub use types::{
    DurableJobInfo, DurableSearchJob, JobErrorKind, JobOrigin, JobResultsPage, NewSearchJob,
    SubmitOutcome, classify_search_error, decode_job_id, encode_job_id, is_durable_job_id,
};

/// The result-page SQL (for EXPLAIN-based partition-pruning tests).
#[doc(hidden)]
pub fn page_sql_for_tests(table: &str) -> String {
    results::page_sql(table)
}

/// TypeId prefix for durable search job ids (`sjob_<base32>`).
pub const SEARCH_JOB_ID_PREFIX: &str = "sjob";

/// Retention of a finished job's metadata and rows. Fixed (not configurable)
/// because the ClickHouse results table's TTL is DDL (clickhouse/181): a
/// longer PostgreSQL retention would advertise pages whose rows are gone.
pub const RESULT_RETENTION: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
