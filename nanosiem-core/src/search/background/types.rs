// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable search job records, typed errors, and API-facing page types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::auth::ScopeSet;
use crate::search::jobs::{SearchJobProgress, SearchJobStatus};
use crate::search::types::{SearchError, SearchRequest, SearchResponse};

use super::SEARCH_JOB_ID_PREFIX;

/// Public id (`sjob_<base32>`) for a durable job's UUID.
pub fn encode_job_id(id: &Uuid) -> String {
    crate::typeid::encode(SEARCH_JOB_ID_PREFIX, id)
}

/// Parse a public durable job id. Only the `sjob_` typeid form is accepted —
/// legacy in-memory job ids are bare UUID strings and must keep routing to the
/// legacy store, so the bare-UUID fallback of [`crate::typeid::decode`] is
/// deliberately NOT honored here.
pub fn decode_job_id(public_id: &str) -> Option<Uuid> {
    if !is_durable_job_id(public_id) {
        return None;
    }
    crate::typeid::decode(SEARCH_JOB_ID_PREFIX, public_id).ok()
}

/// Whether `public_id` names a durable job (vs a legacy in-memory job).
pub fn is_durable_job_id(public_id: &str) -> bool {
    public_id
        .strip_prefix(SEARCH_JOB_ID_PREFIX)
        .is_some_and(|rest| rest.starts_with('_'))
}

/// Why a background job was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobOrigin {
    /// Explicitly submitted as a background job.
    Submitted,
    /// An interactive search that outran its budget and was handed off.
    Escalated,
}

impl JobOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Escalated => "escalated",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "escalated" => Self::Escalated,
            _ => Self::Submitted,
        }
    }
}

/// Typed, NON-retryable failure classes (S6). The UI renders each one with a
/// specific remedy instead of a generic "search failed"; none of them is fixed
/// by simply re-running the same job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobErrorKind {
    /// Cancelled by the owner or an admin.
    Cancelled,
    /// Hit the background job time limit (`max_execution_time`).
    Timeout,
    /// Exceeded a ClickHouse memory / row / byte limit. Narrow the time range
    /// or add filters.
    QueryTooLarge,
    /// The query itself is invalid (parse / field / validation error).
    InvalidQuery,
    /// Every attempt lost its worker (process restarts) before finishing.
    WorkerLost,
    /// Anything else.
    Internal,
}

impl JobErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::QueryTooLarge => "query_too_large",
            Self::InvalidQuery => "invalid_query",
            Self::WorkerLost => "worker_lost",
            Self::Internal => "internal",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "cancelled" => Self::Cancelled,
            "timeout" => Self::Timeout,
            "query_too_large" => Self::QueryTooLarge,
            "invalid_query" => Self::InvalidQuery,
            "worker_lost" => Self::WorkerLost,
            "internal" => Self::Internal,
            _ => return None,
        })
    }
}

/// Map a search failure to its typed kind and the message safe to show the
/// job's owner. Internal failures are masked (the detail is logged by the
/// worker), mirroring the HTTP layer's mapping of the same errors.
pub fn classify_search_error(error: &SearchError) -> (JobErrorKind, String) {
    let text = error.to_string();
    // Raw ClickHouse codes, plus the friendly rewrites `parse_clickhouse_error`
    // produces for them (it maps memory / row limits to SqlValidationError).
    let too_large = |t: &str| {
        t.contains("MEMORY_LIMIT_EXCEEDED")
            || t.contains("TOO_MANY_ROWS")
            || t.contains("TOO_MANY_BYTES")
            || t.contains("exceeded memory limit")
            || t.contains("returned too many rows")
    };
    match error {
        _ if too_large(&text) => (
            JobErrorKind::QueryTooLarge,
            "Search exceeded a ClickHouse resource limit; narrow the time range or add filters"
                .to_string(),
        ),
        SearchError::Cancelled => (JobErrorKind::Cancelled, "Search was cancelled".to_string()),
        SearchError::Timeout(_) => (
            JobErrorKind::Timeout,
            "Search exceeded the background job time limit; narrow the time range or add filters"
                .to_string(),
        ),
        SearchError::ResponseTooLarge(..) => (
            JobErrorKind::QueryTooLarge,
            "Search result is too large; narrow the time range or add filters".to_string(),
        ),
        SearchError::ParseError(_)
        | SearchError::StructuredParseError { .. }
        | SearchError::FieldNotFound { .. }
        | SearchError::InvalidTimeRange
        | SearchError::SqlValidationError(_) => (JobErrorKind::InvalidQuery, text),
        SearchError::SqlGenError(msg) => {
            // Same rule as the HTTP mapping (NAN-1339): guardrail messages are
            // written for the user; other generation failures stay masked.
            if msg.starts_with("Invalid query:") || msg.starts_with("Unsupported operation:") {
                (JobErrorKind::InvalidQuery, msg.clone())
            } else {
                (JobErrorKind::InvalidQuery, "Query processing failed".to_string())
            }
        }
        _ if text.contains("TIMEOUT_EXCEEDED") || text.contains("Timeout exceeded") => (
            JobErrorKind::Timeout,
            "Search exceeded the background job time limit; narrow the time range or add filters"
                .to_string(),
        ),
        _ => (
            JobErrorKind::Internal,
            "Search failed with an internal error".to_string(),
        ),
    }
}

/// Input to [`super::SearchJobRepository::insert_or_attach`].
#[derive(Debug, Clone)]
pub struct NewSearchJob {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub identity_hash: String,
    pub request: SearchRequest,
    pub scope_deny: BTreeSet<String>,
    pub scope_artifact_deny: BTreeSet<String>,
    pub origin: JobOrigin,
    pub max_attempts: i32,
    /// The client's requested page size (sizes the inline first page only).
    pub page_limit: Option<i32>,
}

/// A durable search job row.
#[derive(Debug, Clone)]
pub struct DurableSearchJob {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub identity_hash: String,
    pub query: String,
    pub request: SearchRequest,
    /// The submitting client's requested page size, if any.
    pub page_limit: Option<i32>,
    pub scope_deny: BTreeSet<String>,
    pub scope_artifact_deny: BTreeSet<String>,
    pub origin: JobOrigin,
    pub state: SearchJobStatus,
    pub attempt: i32,
    pub max_attempts: i32,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub ch_query_id: Option<String>,
    pub progress: Option<SearchJobProgress>,
    pub result_attempt: Option<i32>,
    pub row_count: Option<i64>,
    pub result_truncated: bool,
    /// The SearchResponse with `results` emptied (total_count, fields, ...).
    pub result_meta: Option<SearchResponse>,
    pub error_kind: Option<JobErrorKind>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub heartbeat_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

impl DurableSearchJob {
    /// The public `sjob_…` id.
    pub fn public_id(&self) -> String {
        encode_job_id(&self.id)
    }

    /// The source scope the job executes under, rebuilt from its stamp.
    ///
    /// `scope_deny` is the full live-row deny-set; `scope_artifact_deny` is the
    /// per-source RBAC half. The difference is the row-filter-only part (the
    /// audit gate), exactly as [`crate::auth::compose_viewer_scope`] built it.
    pub fn scope(&self) -> ScopeSet {
        let row_filter_only: BTreeSet<String> = self
            .scope_deny
            .difference(&self.scope_artifact_deny)
            .cloned()
            .collect();
        ScopeSet::with_row_filter_only(self.scope_artifact_deny.clone(), row_filter_only)
    }

    /// NAN-2096 semantics: the caller may read the job's status/rows only if
    /// every source they are CURRENTLY denied was also denied when the job was
    /// stamped. A source restricted after submission makes the result
    /// unreadable (including to an admin whose own scope is narrower).
    pub fn result_visible_under(&self, current_deny: &BTreeSet<String>) -> bool {
        current_deny.is_subset(&self.scope_deny)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            SearchJobStatus::Completed | SearchJobStatus::Failed | SearchJobStatus::Cancelled
        )
    }

    /// Elapsed wall time: running jobs against now, finished jobs against
    /// their finish time.
    pub fn elapsed_ms(&self) -> u64 {
        let start = self.started_at.unwrap_or(self.created_at);
        let end = self.finished_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(start).num_milliseconds().max(0) as u64
    }

    pub(crate) fn origin_from_db(s: &str) -> JobOrigin {
        JobOrigin::parse(s)
    }
}

/// Result of a submission: the job, and whether it was an existing identical
/// running job the caller attached to rather than a new scan.
#[derive(Debug, Clone)]
pub struct SubmitOutcome {
    pub job: DurableSearchJob,
    pub attached: bool,
}

/// One page of a completed job's rows.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct JobResultsPage {
    /// Job id (`sjob_…`).
    pub job_id: String,
    /// Job state.
    pub status: SearchJobStatus,
    /// Rows in this page, in result order.
    pub rows: Vec<serde_json::Value>,
    /// Offset of the first row in this page.
    pub offset: u64,
    /// Page size requested (after clamping).
    pub limit: u64,
    /// Rows stored for the job.
    pub row_count: u64,
    /// Offset of the next page, absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u64>,
    /// True when the job stopped at the background result cap: more rows
    /// matched than were stored. `total_count` (when present) is the true count.
    pub truncated: bool,
}

/// Durable-job detail carried on the job status / list responses.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DurableJobInfo {
    /// `submitted` or `escalated`.
    pub origin: JobOrigin,
    /// Current (or final) attempt number, 1-based. >1 means the job was
    /// reclaimed after a worker was lost (e.g. a search-service restart).
    pub attempt: i32,
    /// Attempts allowed before the job fails `worker_lost`.
    pub max_attempts: i32,
    /// Rows stored for the job (completed jobs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    /// More rows matched than the background result cap stored.
    pub result_truncated: bool,
    /// Typed failure class (failed / cancelled jobs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<JobErrorKind>,
    /// Wall time since the job started (or until it finished).
    pub elapsed_ms: u64,
    /// When the job was created (ms since epoch).
    pub created_at_ms: u64,
    /// When the job's metadata and rows expire (ms since epoch).
    pub expires_at_ms: u64,
}

impl DurableSearchJob {
    pub fn info(&self) -> DurableJobInfo {
        DurableJobInfo {
            origin: self.origin,
            attempt: self.attempt,
            max_attempts: self.max_attempts,
            row_count: self.row_count.map(|c| c.max(0) as u64),
            result_truncated: self.result_truncated,
            error_kind: self.error_kind,
            elapsed_ms: self.elapsed_ms(),
            created_at_ms: self.created_at.timestamp_millis().max(0) as u64,
            expires_at_ms: self.expires_at.timestamp_millis().max(0) as u64,
        }
    }

    /// Status response. `result` is the inline first page for completed jobs.
    pub fn status_response(
        &self,
        result: Option<SearchResponse>,
    ) -> crate::search::jobs::SearchJobStatusResponse {
        crate::search::jobs::SearchJobStatusResponse {
            job_id: self.public_id(),
            status: self.state.clone(),
            progress: if self.state == SearchJobStatus::Running {
                self.progress.clone().map(|mut p| {
                    p.elapsed_ms = self.elapsed_ms();
                    p
                })
            } else {
                None
            },
            result,
            error: self.error_message.clone(),
            queue_position: None,
            estimated_wait_seconds: None,
            durable: Some(self.info()),
        }
    }

    pub fn summary(&self) -> crate::search::jobs::SearchJobSummary {
        crate::search::jobs::SearchJobSummary {
            job_id: self.public_id(),
            status: self.state.clone(),
            query: crate::search::jobs::truncate_query_preview(&self.query),
            created_at_ms: self.created_at.timestamp_millis().max(0) as u64,
            elapsed_ms: self.elapsed_ms(),
            queue_position: None,
            priority: crate::search::admission::QueryPriority::Analytics,
            durable: Some(self.info()),
        }
    }

    pub fn admin_summary(&self) -> crate::search::jobs::AdminSearchJobSummary {
        crate::search::jobs::AdminSearchJobSummary {
            job_id: self.public_id(),
            status: self.state.clone(),
            user_id: Some(self.owner_user_id.to_string()),
            query: crate::search::jobs::truncate_query_preview(&self.query),
            created_at_ms: self.created_at.timestamp_millis().max(0) as u64,
            elapsed_ms: self.elapsed_ms(),
            queue_position: None,
            priority: crate::search::admission::QueryPriority::Analytics,
            durable: Some(self.info()),
        }
    }
}
