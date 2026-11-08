// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL control plane for durable search jobs (`search_jobs`, 291).
//!
//! Every write a worker makes after claiming is FENCED on
//! `(id, lease_owner, attempt, state = 'running')`. Losing the fence (lease
//! reclaimed by another worker, job cancelled) returns `false`; the caller must
//! stop and must not write anything else for that attempt.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

use crate::search::jobs::{SearchJobProgress, SearchJobStatus};
use crate::search::types::{SearchError, SearchRequest, SearchResponse};

use super::types::{DurableSearchJob, JobErrorKind, NewSearchJob};

/// Column list shared by every `RETURNING` / `SELECT` so [`JobRow`] always
/// maps (runtime `query_as` drift is compiler-invisible — keep ONE list).
const JOB_COLUMNS: &str = "id, owner_user_id, identity_hash, query, request, page_limit, scope_deny, \
    scope_artifact_deny, origin, state, attempt, max_attempts, lease_owner, lease_expires_at, \
    ch_query_id, progress, result_attempt, row_count, result_truncated, result_meta, error_kind, \
    error_message, created_at, started_at, heartbeat_at, finished_at, expires_at";

#[derive(sqlx::FromRow)]
struct JobRow {
    id: Uuid,
    owner_user_id: Uuid,
    identity_hash: String,
    query: String,
    request: serde_json::Value,
    page_limit: Option<i32>,
    scope_deny: serde_json::Value,
    scope_artifact_deny: serde_json::Value,
    origin: String,
    state: String,
    attempt: i32,
    max_attempts: i32,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    ch_query_id: Option<String>,
    progress: Option<serde_json::Value>,
    result_attempt: Option<i32>,
    row_count: Option<i64>,
    result_truncated: bool,
    result_meta: Option<serde_json::Value>,
    error_kind: Option<String>,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    heartbeat_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

impl JobRow {
    fn into_job(self) -> Result<DurableSearchJob, SearchError> {
        let request: SearchRequest = serde_json::from_value(self.request).map_err(|e| {
            SearchError::SqlValidationError(format!("corrupt search_jobs.request: {e}"))
        })?;
        // A corrupt scope stamp must NEVER decay to "empty" — the worker would
        // then execute the job UNRESTRICTED. Refuse the row instead.
        let set = |v: serde_json::Value, column: &str| -> Result<BTreeSet<String>, SearchError> {
            serde_json::from_value(v).map_err(|e| {
                SearchError::SqlValidationError(format!("corrupt search_jobs.{column}: {e}"))
            })
        };
        let scope_deny = set(self.scope_deny, "scope_deny")?;
        let scope_artifact_deny = set(self.scope_artifact_deny, "scope_artifact_deny")?;
        Ok(DurableSearchJob {
            id: self.id,
            owner_user_id: self.owner_user_id,
            identity_hash: self.identity_hash,
            query: self.query,
            request,
            page_limit: self.page_limit,
            scope_deny,
            scope_artifact_deny,
            origin: DurableSearchJob::origin_from_db(&self.origin),
            state: self
                .state
                .parse::<SearchJobStatus>()
                .unwrap_or(SearchJobStatus::Failed),
            attempt: self.attempt,
            max_attempts: self.max_attempts,
            lease_owner: self.lease_owner,
            lease_expires_at: self.lease_expires_at,
            ch_query_id: self.ch_query_id,
            progress: self
                .progress
                .and_then(|p| serde_json::from_value::<SearchJobProgress>(p).ok()),
            result_attempt: self.result_attempt,
            row_count: self.row_count,
            result_truncated: self.result_truncated,
            result_meta: self
                .result_meta
                .and_then(|m| serde_json::from_value::<SearchResponse>(m).ok()),
            error_kind: self.error_kind.as_deref().and_then(JobErrorKind::parse),
            error_message: self.error_message,
            created_at: self.created_at,
            started_at: self.started_at,
            heartbeat_at: self.heartbeat_at,
            finished_at: self.finished_at,
            expires_at: self.expires_at,
        })
    }
}

fn db(e: sqlx::Error) -> SearchError {
    SearchError::DatabaseError(e)
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// Repository over `public.search_jobs`.
#[derive(Clone, Debug)]
pub struct SearchJobRepository {
    pool: PgPool,
}

impl SearchJobRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Attach to the owner's identical live job, or insert a new queued job
    /// if the owner is under `max_live` live jobs.
    ///
    /// Serialized per owner (Codex P2-5): one transaction takes a
    /// transaction-scoped advisory lock keyed on the owner, then reads the
    /// identical live job, counts live jobs, and inserts — so concurrent
    /// distinct submissions cannot all observe the same count and overshoot
    /// the cap. Attaching never counts against the cap. Different owners never
    /// contend (the lock key is the owner). The partial unique index remains
    /// the backstop for identity uniqueness.
    pub async fn insert_or_attach_capped(
        &self,
        new: &NewSearchJob,
        max_live: i64,
    ) -> Result<(DurableSearchJob, bool), SearchError> {
        let request_json = serde_json::to_value(&new.request)
            .map_err(|e| SearchError::SqlValidationError(format!("serialize request: {e}")))?;
        let deny = serde_json::to_value(&new.scope_deny).unwrap_or_default();
        let artifact = serde_json::to_value(&new.scope_artifact_deny).unwrap_or_default();

        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('search_jobs:' || $1::text, 0))")
            .bind(new.owner_user_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;

        let existing = sqlx::query_as::<_, JobRow>(&format!(
            "SELECT {JOB_COLUMNS} FROM search_jobs \
             WHERE owner_user_id = $1 AND identity_hash = $2 \
               AND state IN ('queued', 'running') \
             LIMIT 1"
        ))
        .bind(new.owner_user_id)
        .bind(&new.identity_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(row) = existing {
            tx.commit().await.map_err(db)?;
            return Ok((row.into_job()?, true));
        }

        let (live,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM search_jobs \
             WHERE owner_user_id = $1 AND state IN ('queued', 'running')",
        )
        .bind(new.owner_user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if live >= max_live {
            tx.rollback().await.map_err(db)?;
            return Err(SearchError::AdmissionDenied(format!(
                "You already have {live} background searches queued or running \
                 (limit {max_live}); wait for one to finish or cancel one"
            )));
        }

        let row = sqlx::query_as::<_, JobRow>(&format!(
            "INSERT INTO search_jobs (id, owner_user_id, identity_hash, query, request, \
                 time_start, time_end, scope_deny, scope_artifact_deny, origin, max_attempts, \
                 page_limit) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             RETURNING {JOB_COLUMNS}"
        ))
        .bind(new.id)
        .bind(new.owner_user_id)
        .bind(&new.identity_hash)
        .bind(&new.request.query)
        .bind(&request_json)
        .bind(new.request.time_range.start)
        .bind(new.request.time_range.end)
        .bind(&deny)
        .bind(&artifact)
        .bind(new.origin.as_str())
        .bind(new.max_attempts)
        .bind(new.page_limit)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok((row.into_job()?, false))
    }

    /// NAN-3809: the caller's newest COMPLETED, non-empty, unexpired job with
    /// exactly this attach identity that finished at or after `settled_after`
    /// (so it read the window after it settled).
    pub async fn find_settled_completed(
        &self,
        owner: Uuid,
        identity_hash: &str,
        settled_after: DateTime<Utc>,
    ) -> Result<Option<DurableSearchJob>, SearchError> {
        sqlx::query_as::<_, JobRow>(&format!(
            "SELECT {JOB_COLUMNS} FROM search_jobs \
             WHERE owner_user_id = $1 AND identity_hash = $2 AND state = 'completed' \
               AND row_count > 0 AND finished_at >= $3 AND expires_at > NOW() \
             ORDER BY finished_at DESC LIMIT 1"
        ))
        .bind(owner)
        .bind(identity_hash)
        .bind(settled_after)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .map(JobRow::into_job)
        .transpose()
    }

    pub async fn get(&self, id: Uuid) -> Result<Option<DurableSearchJob>, SearchError> {
        sqlx::query_as::<_, JobRow>(&format!(
            "SELECT {JOB_COLUMNS} FROM search_jobs WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .map(JobRow::into_job)
        .transpose()
    }

    /// Number of the owner's queued + running jobs.
    pub async fn live_count_for_owner(&self, owner: Uuid) -> Result<i64, SearchError> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM search_jobs \
             WHERE owner_user_id = $1 AND state IN ('queued', 'running')",
        )
        .bind(owner)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(n)
    }

    /// Fail running jobs whose lease lapsed with no attempts left. Runs before
    /// every claim so an exhausted job is never re-claimed and never left
    /// `running` forever.
    pub async fn reap_exhausted(&self) -> Result<u64, SearchError> {
        let done = sqlx::query(
            "UPDATE search_jobs SET state = 'failed', error_kind = 'worker_lost', \
                 error_message = 'The search worker was lost on every attempt (service restarts); run the search again', \
                 lease_owner = NULL, lease_expires_at = NULL, finished_at = NOW(), \
                 expires_at = NOW() + INTERVAL '24 hours' \
             WHERE state = 'running' AND lease_expires_at < NOW() AND attempt >= max_attempts",
        )
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected())
    }

    /// Claim the oldest runnable job: a queued job, or a running job whose
    /// lease lapsed (its worker died) and that has attempts left. The claim
    /// bumps `attempt`, stamps the lease, and assigns the attempt's stable
    /// ClickHouse query id. Returns the claimed job and the previous attempt's
    /// query id (to KILL any orphan of it).
    pub async fn claim_next(
        &self,
        worker_id: &str,
        lease_ttl: Duration,
    ) -> Result<Option<(DurableSearchJob, Option<String>)>, SearchError> {
        let row = sqlx::query_as::<_, JobRow>(&format!(
            "WITH next AS ( \
                 SELECT id FROM search_jobs \
                 WHERE state = 'queued' \
                    OR (state = 'running' AND lease_expires_at < NOW() AND attempt < max_attempts) \
                 ORDER BY created_at \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT 1 \
             ) \
             UPDATE search_jobs j SET \
                 state = 'running', \
                 attempt = j.attempt + 1, \
                 lease_owner = $1, \
                 lease_expires_at = NOW() + make_interval(secs => $2), \
                 heartbeat_at = NOW(), \
                 started_at = COALESCE(j.started_at, NOW()), \
                 ch_query_id = replace(j.id::text, '-', '') || '-a' || (j.attempt + 1)::text, \
                 progress = NULL \
             FROM next WHERE j.id = next.id \
             RETURNING {cols}",
            cols = JOB_COLUMNS
                .split(", ")
                .map(|c| format!("j.{}", c.trim()))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .bind(worker_id)
        .bind(secs(lease_ttl))
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        // Attempt N-1's query id is deterministic (see `attempt_query_id`).
        Ok(match row {
            Some(row) => {
                let job = row.into_job()?;
                let prev = (job.attempt > 1).then(|| attempt_query_id(job.id, job.attempt - 1));
                Some((job, prev))
            }
            None => None,
        })
    }

    /// Renew the lease and publish progress. `false` = fence lost (cancelled,
    /// reclaimed, or finished elsewhere): stop the attempt.
    pub async fn renew_lease(
        &self,
        id: Uuid,
        worker_id: &str,
        attempt: i32,
        lease_ttl: Duration,
        progress: Option<&SearchJobProgress>,
    ) -> Result<bool, SearchError> {
        let progress = progress.and_then(|p| serde_json::to_value(p).ok());
        let done = sqlx::query(
            "UPDATE search_jobs SET lease_expires_at = NOW() + make_interval(secs => $4), \
                 heartbeat_at = NOW(), progress = COALESCE($5, progress) \
             WHERE id = $1 AND lease_owner = $2 AND attempt = $3 AND state = 'running'",
        )
        .bind(id)
        .bind(worker_id)
        .bind(attempt)
        .bind(secs(lease_ttl))
        .bind(progress)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// Fenced completion. `meta` is the response with `results` emptied.
    pub async fn complete(
        &self,
        id: Uuid,
        worker_id: &str,
        attempt: i32,
        row_count: i64,
        truncated: bool,
        meta: &SearchResponse,
    ) -> Result<bool, SearchError> {
        let meta = serde_json::to_value(meta)
            .map_err(|e| SearchError::SqlValidationError(format!("serialize result meta: {e}")))?;
        let done = sqlx::query(
            "UPDATE search_jobs SET state = 'completed', result_attempt = $3, row_count = $4, \
                 result_truncated = $5, result_meta = $6, lease_owner = NULL, \
                 lease_expires_at = NULL, finished_at = NOW(), \
                 expires_at = NOW() + INTERVAL '24 hours' \
             WHERE id = $1 AND lease_owner = $2 AND attempt = $3 AND state = 'running'",
        )
        .bind(id)
        .bind(worker_id)
        .bind(attempt)
        .bind(row_count)
        .bind(truncated)
        .bind(meta)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// Fenced failure with a typed kind.
    pub async fn fail(
        &self,
        id: Uuid,
        worker_id: &str,
        attempt: i32,
        kind: JobErrorKind,
        message: &str,
    ) -> Result<bool, SearchError> {
        let done = sqlx::query(
            "UPDATE search_jobs SET state = 'failed', error_kind = $4, error_message = $5, \
                 lease_owner = NULL, lease_expires_at = NULL, finished_at = NOW(), \
                 expires_at = NOW() + INTERVAL '24 hours' \
             WHERE id = $1 AND lease_owner = $2 AND attempt = $3 AND state = 'running'",
        )
        .bind(id)
        .bind(worker_id)
        .bind(attempt)
        .bind(kind.as_str())
        .bind(message)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(done.rows_affected() == 1)
    }

    /// Cancel a queued or running job. Returns `Some(ch_query_id)` when the job
    /// was live and is now cancelled (the caller KILLs the query), `None` when
    /// it was already finished or does not exist. Cancelling a queued job is
    /// remembered durably: no worker will ever claim it.
    pub async fn cancel(&self, id: Uuid) -> Result<Option<Option<String>>, SearchError> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "UPDATE search_jobs SET state = 'cancelled', error_kind = 'cancelled', \
                 error_message = 'Search was cancelled', lease_owner = NULL, \
                 lease_expires_at = NULL, finished_at = NOW(), \
                 expires_at = NOW() + INTERVAL '24 hours' \
             WHERE id = $1 AND state IN ('queued', 'running') \
             RETURNING ch_query_id",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(row.map(|(q,)| q))
    }

    /// The owner's jobs, newest first.
    pub async fn list_for_owner(
        &self,
        owner: Uuid,
        limit: i64,
    ) -> Result<Vec<DurableSearchJob>, SearchError> {
        sqlx::query_as::<_, JobRow>(&format!(
            "SELECT {JOB_COLUMNS} FROM search_jobs WHERE owner_user_id = $1 \
             ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(owner)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .into_iter()
        .map(JobRow::into_job)
        .collect()
    }

    /// Every job, newest first (admin view; the caller filters by scope).
    pub async fn list_recent(&self, limit: i64) -> Result<Vec<DurableSearchJob>, SearchError> {
        sqlx::query_as::<_, JobRow>(&format!(
            "SELECT {JOB_COLUMNS} FROM search_jobs ORDER BY created_at DESC LIMIT $1"
        ))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .into_iter()
        .map(JobRow::into_job)
        .collect()
    }

    /// Live job counts (queued, running) for metrics / admin stats.
    pub async fn live_counts(&self) -> Result<(i64, i64), SearchError> {
        let row: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE state = 'queued'), \
                    COUNT(*) FILTER (WHERE state = 'running') \
             FROM search_jobs WHERE state IN ('queued', 'running')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(row)
    }

    /// Delete finished jobs past retention; fail live jobs that sat past their
    /// expiry (nothing claimed them for 24 h — no worker is running).
    pub async fn sweep_expired(&self) -> Result<u64, SearchError> {
        let failed = sqlx::query(
            "UPDATE search_jobs SET state = 'failed', error_kind = 'worker_lost', \
                 error_message = 'No search worker picked up this job before it expired', \
                 lease_owner = NULL, lease_expires_at = NULL, finished_at = NOW() \
             WHERE state = 'queued' AND expires_at < NOW()",
        )
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        let deleted = sqlx::query(
            "DELETE FROM search_jobs \
             WHERE state IN ('completed', 'failed', 'cancelled') AND expires_at < NOW()",
        )
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        Ok(failed + deleted)
    }
}

/// The stable ClickHouse query id of one attempt. MUST match the SQL in
/// [`SearchJobRepository::claim_next`] (`replace(id::text,'-','') || '-a' || n`).
pub(crate) fn attempt_query_id(id: Uuid, attempt: i32) -> String {
    format!("{}-a{}", id.simple(), attempt)
}
