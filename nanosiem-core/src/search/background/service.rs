// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background job facade (submit / attach / status / pages / cancel) and the
//! leased worker pool that executes jobs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore};
use uuid::Uuid;

use crate::auth::ScopeSet;
use crate::search::admission::{ClickHouseQuerySettings, QueryPriority};
use crate::search::jobs::SearchJobStatus;
use crate::search::service::{SearchService, all_query_ids};
use crate::search::types::{SearchError, SearchRequest, SearchResponse};

use super::identity::{freeze_time_window, identity_hash, normalize_job_request};
use super::repository::{SearchJobRepository, attempt_query_id};
use super::results::{
    JobWindow, MAX_PAGE_ROWS, ReadConsistency, SearchJobResultStore, StoredPage, page_inconsistent,
};
use super::types::{
    DurableSearchJob, JobErrorKind, JobOrigin, JobResultsPage, NewSearchJob, SubmitOutcome,
    classify_search_error,
};

/// Tunables for the background job pool. Defaults suit a single enterprise
/// ClickHouse deployment; every value can be overridden by env (see
/// [`BackgroundJobConfig::from_env`]).
#[derive(Debug, Clone)]
pub struct BackgroundJobConfig {
    /// Concurrent background jobs per search replica. This is the background
    /// permit pool — separate from, and never drawing on, the interactive
    /// admission controller.
    pub concurrency: usize,
    /// Lease length. A worker that stops renewing (process died) loses the job
    /// to another worker this long after its last renewal.
    pub lease_ttl: Duration,
    /// How often a worker renews its lease and publishes progress.
    pub heartbeat_interval: Duration,
    /// Idle poll interval when no job is runnable (a local submit wakes the
    /// pool immediately; the poll covers submits on other replicas and lapsed
    /// leases).
    pub poll_interval: Duration,
    /// Maximum rows a job stores. More matches → `result_truncated`.
    pub result_cap: usize,
    /// ClickHouse `max_execution_time` for a background attempt.
    pub max_execution_secs: u32,
    /// Attempts before a job whose worker keeps dying fails `worker_lost`.
    pub max_attempts: i32,
    /// How long an interactive search may run before it is handed off to a
    /// background job (for clients that accept a job answer).
    pub interactive_handoff: Duration,
    /// Live (queued + running) jobs one owner may hold. Attaching to an
    /// identical live job never counts against it.
    pub max_live_jobs_per_owner: i64,
    /// Byte ceiling on one background attempt's result (Codex P1-3), enforced
    /// by ClickHouse (`max_result_bytes`, overflow = throw) and by the
    /// client-side guard while the response streams in. Exceeding it fails the
    /// job `query_too_large` instead of growing the search pod's heap.
    pub result_max_bytes: u64,
}

impl Default for BackgroundJobConfig {
    fn default() -> Self {
        Self {
            concurrency: 2,
            lease_ttl: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(10),
            poll_interval: Duration::from_secs(2),
            result_cap: 100_000,
            max_execution_secs: 1_800,
            max_attempts: 3,
            interactive_handoff: Duration::from_secs(45),
            max_live_jobs_per_owner: 10,
            result_max_bytes: 256 * 1024 * 1024,
        }
    }
}

impl BackgroundJobConfig {
    /// Defaults overridden by:
    /// `SEARCH_JOB_CONCURRENCY`, `SEARCH_JOB_LEASE_SECS`,
    /// `SEARCH_JOB_HEARTBEAT_SECS`, `SEARCH_JOB_POLL_MS`,
    /// `SEARCH_JOB_RESULT_CAP`, `SEARCH_JOB_MAX_EXECUTION_SECS`,
    /// `SEARCH_JOB_MAX_ATTEMPTS`, `SEARCH_INTERACTIVE_HANDOFF_SECS`,
    /// `SEARCH_JOB_MAX_LIVE_PER_OWNER`, `SEARCH_JOB_RESULT_MAX_BYTES`.
    pub fn from_env() -> Self {
        fn env<T: std::str::FromStr>(name: &str) -> Option<T> {
            std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
        }
        let d = Self::default();
        let lease_ttl = env::<u64>("SEARCH_JOB_LEASE_SECS")
            .filter(|s| *s >= 2)
            .map(Duration::from_secs)
            .unwrap_or(d.lease_ttl);
        // Renew at most every third of the lease so one missed renewal never
        // costs the lease.
        let heartbeat_interval = env::<u64>("SEARCH_JOB_HEARTBEAT_SECS")
            .filter(|s| *s >= 1)
            .map(Duration::from_secs)
            .unwrap_or(d.heartbeat_interval)
            .min(lease_ttl / 3)
            .max(Duration::from_millis(500));
        Self {
            concurrency: env::<usize>("SEARCH_JOB_CONCURRENCY")
                .filter(|c| *c >= 1)
                .unwrap_or(d.concurrency),
            lease_ttl,
            heartbeat_interval,
            poll_interval: env::<u64>("SEARCH_JOB_POLL_MS")
                .filter(|m| *m >= 100)
                .map(Duration::from_millis)
                .unwrap_or(d.poll_interval),
            result_cap: env::<usize>("SEARCH_JOB_RESULT_CAP")
                .filter(|c| *c >= 1)
                .unwrap_or(d.result_cap),
            max_execution_secs: env::<u32>("SEARCH_JOB_MAX_EXECUTION_SECS")
                .filter(|s| *s >= 1)
                .unwrap_or(d.max_execution_secs),
            max_attempts: env::<i32>("SEARCH_JOB_MAX_ATTEMPTS")
                .filter(|a| *a >= 1)
                .unwrap_or(d.max_attempts),
            interactive_handoff: env::<u64>("SEARCH_INTERACTIVE_HANDOFF_SECS")
                .filter(|s| *s >= 1)
                .map(Duration::from_secs)
                .unwrap_or(d.interactive_handoff),
            max_live_jobs_per_owner: env::<i64>("SEARCH_JOB_MAX_LIVE_PER_OWNER")
                .filter(|n| *n >= 1)
                .unwrap_or(d.max_live_jobs_per_owner),
            result_max_bytes: env::<u64>("SEARCH_JOB_RESULT_MAX_BYTES")
                .filter(|b| *b >= 1024)
                .unwrap_or(d.result_max_bytes),
        }
    }

    /// ClickHouse settings for a background attempt: the Analytics tier
    /// (scheduler priority below Interactive) with the job time limit, and
    /// threads capped so one job cannot monopolize the server's cores.
    /// The execution limits installed on every background attempt. The row
    /// ceiling leaves headroom above the result cap for in-band metadata rows;
    /// the request's own LIMIT is what bounds the stored rows.
    pub(crate) fn execution_limits(&self) -> crate::search::SearchExecutionLimits {
        crate::search::SearchExecutionLimits {
            max_result_rows: self.result_cap as u64 + 16,
            max_result_bytes: self.result_max_bytes,
        }
    }

    pub fn ch_settings(&self) -> ClickHouseQuerySettings {
        let mut settings = QueryPriority::Analytics.to_ch_settings();
        settings.max_execution_time = self.max_execution_secs;
        settings.max_threads = settings.max_threads.min(16);
        settings
    }
}

struct Inner {
    repo: SearchJobRepository,
    results: SearchJobResultStore,
    search: Arc<SearchService>,
    config: BackgroundJobConfig,
    worker_id: String,
    wake: Notify,
    slots: Arc<Semaphore>,
}

/// Durable background search jobs. Cheap to clone.
#[derive(Clone)]
pub struct BackgroundSearchJobs {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for BackgroundSearchJobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundSearchJobs")
            .field("worker_id", &self.inner.worker_id)
            .field("config", &self.inner.config)
            .finish()
    }
}

impl BackgroundSearchJobs {
    pub fn new(
        repo: SearchJobRepository,
        results: SearchJobResultStore,
        search: Arc<SearchService>,
        config: BackgroundJobConfig,
    ) -> Self {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "search".to_string());
        let worker_id = format!("{}:{}", host, Uuid::now_v7().simple());
        Self::with_worker_id(repo, results, search, config, worker_id)
    }

    /// Construct with an explicit worker identity (tests simulate several
    /// replicas / a restarted process in one binary).
    pub fn with_worker_id(
        repo: SearchJobRepository,
        results: SearchJobResultStore,
        search: Arc<SearchService>,
        config: BackgroundJobConfig,
        worker_id: String,
    ) -> Self {
        let slots = Arc::new(Semaphore::new(config.concurrency));
        Self {
            inner: Arc::new(Inner {
                repo,
                results,
                search,
                config,
                worker_id,
                wake: Notify::new(),
                slots,
            }),
        }
    }

    pub fn config(&self) -> &BackgroundJobConfig {
        &self.inner.config
    }

    pub fn worker_id(&self) -> &str {
        &self.inner.worker_id
    }

    pub fn repository(&self) -> &SearchJobRepository {
        &self.inner.repo
    }

    /// Submit a background job, or attach to the caller's identical live job.
    ///
    /// The query is parsed first so a typo is an immediate 400, not a queued
    /// job that fails later. `scope` is the caller's EFFECTIVE scope — it is
    /// stamped on the job and is what the job executes under.
    pub async fn submit(
        &self,
        request: &SearchRequest,
        owner: Uuid,
        scope: &ScopeSet,
        origin: JobOrigin,
    ) -> Result<SubmitOutcome, SearchError> {
        request.time_range.validate()?;
        // Freeze relative `earliest=`/`latest=` against ONE captured instant so
        // every attempt (and the identity) uses the same absolute window. A
        // hand-off passes a request the handler already froze at arrival, which
        // this leaves unchanged.
        let request = &freeze_time_window(request, chrono::Utc::now())?;
        if let Err(e) = crate::query::parse_query(request.query.trim()) {
            return Err(SearchError::ParseError(e.to_string()));
        }
        let normalized = normalize_job_request(request, self.inner.config.result_cap);
        let identity = identity_hash(&normalized, owner, scope);
        let new = NewSearchJob {
            id: Uuid::now_v7(),
            owner_user_id: owner,
            identity_hash: identity,
            request: normalized,
            scope_deny: scope.deny_set().clone(),
            scope_artifact_deny: scope.artifact_deny_set().clone(),
            origin,
            max_attempts: self.inner.config.max_attempts,
            page_limit: request
                .limit
                .map(|l| l.min(super::results::MAX_PAGE_ROWS as usize) as i32),
        };
        // Attach-or-insert under the per-owner cap, serialized per owner in one
        // transaction (Codex P2-5): attaching is always allowed; only a NEW job
        // counts against the cap, and concurrent distinct submits cannot all
        // observe the same count.
        let (job, attached) = self
            .inner
            .repo
            .insert_or_attach_capped(&new, self.inner.config.max_live_jobs_per_owner)
            .await?;
        if !attached {
            self.inner.wake.notify_one();
        }
        tracing::info!(
            job_id = %job.public_id(),
            attached,
            origin = origin.as_str(),
            "Background search job submitted"
        );
        Ok(SubmitOutcome { job, attached })
    }

    pub async fn get(&self, id: Uuid) -> Result<Option<DurableSearchJob>, SearchError> {
        self.inner.repo.get(id).await
    }

    /// NAN-3809: a finished durable job of this caller that answers exactly
    /// `request` over a settled absolute window, to re-serve through its
    /// result pages instead of re-running the search. `None` when the window
    /// is relative or still settling, the query reads state outside its
    /// events, or no such job exists. The match is the attach identity, which
    /// binds the owner and BOTH halves of the caller's effective scope: a
    /// different user, or the same user under a narrower or wider scope,
    /// never matches.
    pub async fn settled_reuse(
        &self,
        request: &SearchRequest,
        owner: Uuid,
        scope: &ScopeSet,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<DurableSearchJob>, SearchError> {
        use crate::search::settled_reuse::{is_settled_end, query_allows_settled_reuse, settled_after};
        if request.time_range.validate().is_err()
            || !is_settled_end(request.time_range.end, now)
            || !query_allows_settled_reuse(&request.query)
        {
            return Ok(None);
        }
        let normalized = normalize_job_request(request, self.inner.config.result_cap);
        let identity = identity_hash(&normalized, owner, scope);
        let job = self
            .inner
            .repo
            .find_settled_completed(owner, &identity, settled_after(request.time_range.end))
            .await?;
        Ok(job.filter(|job| {
            job.owner_user_id == owner && job.result_visible_under(scope.deny_set())
        }))
    }

    /// A page of a COMPLETED job's rows. The caller has already authorized the
    /// read; a non-completed job returns an empty page with no `next_offset`.
    pub async fn results_page(
        &self,
        job: &DurableSearchJob,
        offset: u64,
        limit: u64,
    ) -> Result<JobResultsPage, SearchError> {
        let limit = limit.clamp(1, MAX_PAGE_ROWS);
        let row_count = job.row_count.unwrap_or(0).max(0) as u64;
        let (SearchJobStatus::Completed, Some(attempt)) = (job.state.clone(), job.result_attempt)
        else {
            return Err(SearchError::JobResultsUnavailable(
                "Search job has not completed".to_string(),
            ));
        };
        // Codex P2-7: a page past the stored rows is a contract error, never
        // an empty 200 a client could read as "no more matches". Offset 0 of a
        // job that stored nothing is the one legitimate empty page.
        if offset > 0 && offset >= row_count {
            return Err(SearchError::SqlValidationError(format!(
                "offset {offset} is beyond the {row_count} rows this job stored"
            )));
        }
        // Codex P1-4: PostgreSQL says exactly how many rows exist. A page that
        // comes back shorter than that — without having stopped at the byte
        // budget — means the replica serving the read does not hold every row
        // yet. Refuse (retryable) rather than return a short 200.
        let expected = limit.min(row_count.saturating_sub(offset));
        let page = if row_count == 0 {
            StoredPage {
                rows: Vec::new(),
                byte_limited: false,
            }
        } else {
            let window = JobWindow {
                created_at: job.created_at,
                finished_at: job.finished_at,
            };
            let key = results_key(job.id);
            let read = |consistency| {
                self.inner.results.read_page(
                    &key,
                    attempt as u32,
                    window,
                    offset,
                    limit,
                    consistency,
                )
            };
            // NAN-5215: a write taken while a replica was down skips the
            // insert quorum, and a sequential-consistency read then hides (or
            // rejects) those parts. Retry once as a plain read, but only for
            // an inconsistent page or a replica/consistency error (read_page
            // maps that class to JobResultsUnavailable); auth, syntax and
            // timeouts surface as before. The row-count check below still
            // refuses a lagging replica's short page.
            match read(ReadConsistency::Sequential).await {
                Ok(page) if !page_inconsistent(&page, expected) => page,
                Ok(_) | Err(SearchError::JobResultsUnavailable(_)) => {
                    read(ReadConsistency::Eventual).await?
                }
                Err(error) => return Err(error),
            }
        };
        let got = page.rows.len() as u64;
        if page_inconsistent(&page, expected) {
            tracing::warn!(
                job_id = %job.public_id(),
                offset,
                expected,
                got,
                "Background search page inconsistent with stored row count (replica lag?)"
            );
            return Err(SearchError::JobResultsUnavailable(
                "Search results are still replicating; retry shortly".to_string(),
            ));
        }
        let end = offset.saturating_add(got);
        Ok(JobResultsPage {
            job_id: job.public_id(),
            status: job.state.clone(),
            rows: page.rows,
            offset,
            limit,
            row_count,
            next_offset: (end < row_count).then_some(end),
            truncated: job.result_truncated,
        })
    }

    /// The legacy-compatible inline result of a completed job: the stored
    /// response metadata with its first `limit` rows. Old pollers that read
    /// `result.results` keep working; new clients page via
    /// [`Self::results_page`].
    pub async fn inline_result(
        &self,
        job: &DurableSearchJob,
        limit: u64,
    ) -> Result<Option<SearchResponse>, SearchError> {
        if job.state != SearchJobStatus::Completed {
            return Ok(None);
        }
        let Some(mut meta) = job.result_meta.clone() else {
            return Ok(None);
        };
        meta.results = self.results_page(job, 0, limit).await?.rows;
        Ok(Some(meta))
    }

    /// Cancel a queued or running job. KILLs the current attempt's ClickHouse
    /// queries (data + companions) from this replica — the kill is
    /// cluster-aware, so it does not matter which replica runs the worker.
    /// Returns whether the job was live and is now cancelled.
    pub async fn cancel(&self, id: Uuid) -> Result<bool, SearchError> {
        match self.inner.repo.cancel(id).await? {
            Some(query_id) => {
                if let Some(query_id) = query_id {
                    if let Err(e) = self
                        .inner
                        .search
                        .cancel_exact_queries(&all_query_ids(&query_id))
                        .await
                    {
                        tracing::warn!(error = %e, %query_id, "KILL of cancelled background job failed; the worker will stop at its next lease renewal");
                    }
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub async fn list_for_owner(
        &self,
        owner: Uuid,
        limit: i64,
    ) -> Result<Vec<DurableSearchJob>, SearchError> {
        self.inner.repo.list_for_owner(owner, limit).await
    }

    pub async fn list_recent(&self, limit: i64) -> Result<Vec<DurableSearchJob>, SearchError> {
        self.inner.repo.list_recent(limit).await
    }

    /// Start the worker pool and the expiry sweeper. Returns their handles.
    pub fn start(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let dispatcher = {
            let this = self.clone();
            tokio::spawn(async move { this.dispatch_loop().await })
        };
        let sweeper = {
            let this = self.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(300));
                loop {
                    tick.tick().await;
                    match this.inner.repo.sweep_expired().await {
                        Ok(n) if n > 0 => tracing::info!(rows = n, "Swept expired search jobs"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "Search job expiry sweep failed"),
                    }
                }
            })
        };
        tracing::info!(
            worker_id = %self.inner.worker_id,
            concurrency = self.inner.config.concurrency,
            lease_secs = self.inner.config.lease_ttl.as_secs(),
            result_cap = self.inner.config.result_cap,
            "Background search job workers started"
        );
        vec![dispatcher, sweeper]
    }

    /// Claim and run ONE job if one is runnable, waiting for it to finish.
    /// Test hook: drives exactly one attempt deterministically.
    pub async fn run_one(&self) -> Result<bool, SearchError> {
        let permit = self
            .inner
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let _ = self.inner.repo.reap_exhausted().await?;
        match self
            .inner
            .repo
            .claim_next(&self.inner.worker_id, self.inner.config.lease_ttl)
            .await?
        {
            Some((job, prev)) => {
                self.run_attempt(job, prev).await;
                drop(permit);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn dispatch_loop(&self) {
        loop {
            let permit = self
                .inner
                .slots
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            if let Err(e) = self.inner.repo.reap_exhausted().await {
                tracing::warn!(error = %e, "Search job reap failed");
            }
            match self
                .inner
                .repo
                .claim_next(&self.inner.worker_id, self.inner.config.lease_ttl)
                .await
            {
                Ok(Some((job, prev))) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        this.run_attempt(job, prev).await;
                        drop(permit);
                    });
                    // Try for another runnable job straight away.
                    continue;
                }
                Ok(None) => drop(permit),
                Err(e) => {
                    drop(permit);
                    tracing::warn!(error = %e, "Search job claim failed");
                }
            }
            tokio::select! {
                _ = self.inner.wake.notified() => {}
                _ = tokio::time::sleep(self.inner.config.poll_interval) => {}
            }
        }
    }

    /// Execute one claimed attempt end to end. Never panics on job failure:
    /// every outcome is a fenced PG write or a deliberate abandonment.
    async fn run_attempt(&self, job: DurableSearchJob, previous_query_id: Option<String>) {
        let inner = &self.inner;
        let job_id = job.id;
        let public_id = job.public_id();
        let attempt = job.attempt;
        let query_id = job
            .ch_query_id
            .clone()
            .unwrap_or_else(|| attempt_query_id(job_id, attempt));

        // A reclaimed job: the previous attempt's worker is presumed dead, but
        // its ClickHouse query may still be running (the server only notices a
        // vanished HTTP client at its next write). Kill it before re-scanning.
        if let Some(previous) = previous_query_id {
            tracing::warn!(job_id = %public_id, attempt, "Reclaimed background search job after lease expiry");
            let _ = inner
                .search
                .cancel_exact_queries(&all_query_ids(&previous))
                .await;
        }

        let lost = Arc::new(Notify::new());
        let heartbeat = {
            let this = self.clone();
            let lost = lost.clone();
            let query_id = query_id.clone();
            tokio::spawn(async move { this.heartbeat(job_id, attempt, query_id, lost).await })
        };

        let mut request = job.request.clone();
        request.request_id = Some(query_id.clone());
        let scope = job.scope();
        let settings = inner.config.ch_settings();
        // Backstop above ClickHouse's own max_execution_time.
        let backstop = Duration::from_secs(u64::from(inner.config.max_execution_secs) + 60);
        tracing::info!(job_id = %public_id, attempt, %query_id, "Background search attempt starting");

        let outcome = tokio::select! {
            result = tokio::time::timeout(
                backstop,
                inner.search.search_background_attempt(
                    request,
                    &scope,
                    settings,
                    inner.config.execution_limits(),
                ),
            ) => Some(result.unwrap_or(Err(SearchError::Timeout(backstop.as_millis() as u64)))),
            _ = lost.notified() => None,
        };

        let Some(result) = outcome else {
            // Cancelled or reclaimed: stop scanning, write nothing.
            heartbeat.abort();
            let _ = inner
                .search
                .cancel_exact_queries(&all_query_ids(&query_id))
                .await;
            tracing::info!(job_id = %public_id, attempt, "Background search attempt abandoned (cancelled or lease lost)");
            return;
        };

        match result {
            Ok(mut response) => {
                let rows = std::mem::take(&mut response.results);
                let row_count = rows.len();
                let truncated = row_count >= inner.config.result_cap;
                // The heartbeat keeps the lease alive across the insert.
                let stored = inner
                    .results
                    .insert_rows(&results_key(job_id), attempt as u32, &rows)
                    .await;
                drop(rows);
                let written = match stored {
                    Ok(()) => {
                        inner
                            .repo
                            .complete(
                                job_id,
                                &inner.worker_id,
                                attempt,
                                row_count as i64,
                                truncated,
                                &response,
                            )
                            .await
                    }
                    Err(e) => {
                        tracing::error!(job_id = %public_id, attempt, error = %e, "Writing background search results failed");
                        inner
                            .repo
                            .fail(
                                job_id,
                                &inner.worker_id,
                                attempt,
                                JobErrorKind::Internal,
                                "Storing the search results failed",
                            )
                            .await
                    }
                };
                match written {
                    Ok(true) => tracing::info!(job_id = %public_id, attempt, rows = row_count, truncated, "Background search job completed"),
                    Ok(false) => tracing::info!(job_id = %public_id, attempt, "Background search result discarded: fence lost (cancelled or reclaimed)"),
                    Err(e) => tracing::error!(job_id = %public_id, attempt, error = %e, "Recording background search completion failed; the lease will lapse and the job will be retried"),
                }
            }
            Err(e) => {
                let (kind, message) = classify_search_error(&e);
                if kind == JobErrorKind::Internal {
                    tracing::error!(job_id = %public_id, attempt, error = %e, "Background search attempt failed");
                } else {
                    tracing::info!(job_id = %public_id, attempt, kind = kind.as_str(), error = %e, "Background search attempt failed");
                }
                if let Err(write_err) = inner
                    .repo
                    .fail(job_id, &inner.worker_id, attempt, kind, &message)
                    .await
                {
                    tracing::error!(job_id = %public_id, error = %write_err, "Recording background search failure failed");
                }
            }
        }
        heartbeat.abort();
    }

    /// Renew the lease every `heartbeat_interval`, publishing ClickHouse
    /// progress. Signals `lost` when the fence is gone (cancel / reclaim) or
    /// when PostgreSQL has been unreachable for a whole lease (the lease has
    /// certainly lapsed, so another worker may already own the job).
    async fn heartbeat(&self, job_id: Uuid, attempt: i32, query_id: String, lost: Arc<Notify>) {
        let inner = &self.inner;
        let mut last_renewed = Instant::now();
        loop {
            tokio::time::sleep(inner.config.heartbeat_interval).await;
            let progress = inner.search.get_query_progress(&query_id).await;
            match inner
                .repo
                .renew_lease(
                    job_id,
                    &inner.worker_id,
                    attempt,
                    inner.config.lease_ttl,
                    progress.as_ref(),
                )
                .await
            {
                Ok(true) => last_renewed = Instant::now(),
                Ok(false) => {
                    lost.notify_one();
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Background search lease renewal failed");
                    if last_renewed.elapsed() >= inner.config.lease_ttl {
                        lost.notify_one();
                        return;
                    }
                }
            }
        }
    }
}

/// Key of a job's rows in `search_job_results`.
fn results_key(id: Uuid) -> String {
    id.simple().to_string()
}
