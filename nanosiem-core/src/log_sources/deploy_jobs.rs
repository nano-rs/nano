// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log-source deploys as background jobs (NAN-5132).
//!
//! A deploy used to run inside the HTTP request. It takes seconds to minutes
//! (render, promote, Vector reload, correlated ack), and when an edge or
//! client timed out, hyper dropped the handler future and the deploy could
//! stop between promotion and reload. Every deploy, undeploy, publish and
//! deploy-all now runs in a detached task owned by [`DeployJobRunner`]:
//!
//! * the task runs to success or rollback whether or not anyone is still
//!   waiting for it;
//! * its progress (phase) and outcome live in `log_source_deploy_jobs`, so any
//!   app host can answer a poll;
//! * a heartbeat marks the owning process alive; a job whose heartbeat stopped
//!   is reported `interrupted` instead of `running` forever.
//!
//! The job adds no locking of its own. The work it runs is the service's
//! deploy, which holds the NAN-2297 deploy lock for its whole critical
//! section, so jobs serialize exactly as requests did.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::types::DeploymentResult;
use crate::typeid;

/// How often a running job refreshes its heartbeat.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// A non-terminal job whose heartbeat is older than this is `interrupted`.
pub const STALE_AFTER: Duration = Duration::from_secs(60);
/// Finished jobs older than this are pruned by [`DeployJobRunner::recover`].
pub const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

/// What a job does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = LogSourceDeployJobKind)]
pub enum DeployJobKind {
    Deploy,
    Undeploy,
    Publish,
    DeployAll,
}

impl DeployJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Undeploy => "undeploy",
            Self::Publish => "publish",
            Self::DeployAll => "deploy_all",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "deploy" => Self::Deploy,
            "undeploy" => Self::Undeploy,
            "publish" => Self::Publish,
            "deploy_all" => Self::DeployAll,
            _ => return None,
        })
    }
}

/// Where a job stands. `queued` lasts until the deploy holds the deploy lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = LogSourceDeployJobState)]
pub enum DeployJobState {
    Queued,
    Running,
    /// The deploy went live (role split: possibly still `delivery.state =
    /// "pending"` on some ingest hosts, see the result).
    Succeeded,
    /// The deploy did not go live. Nothing was promoted, or the promoted
    /// config could not be rolled back (the message says which).
    Failed,
    /// Vector refused the new config and the previous one was restored.
    RolledBack,
    /// The API process stopped while the job ran. The boot render rewrites
    /// the Vector config from the database; re-run the deploy.
    Interrupted,
}

impl DeployJobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
            Self::Interrupted => "interrupted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "rolled_back" => Self::RolledBack,
            "interrupted" => Self::Interrupted,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Running)
    }
}

/// The step a job is on. Reported by the service as it goes; never moves
/// backwards except to `rolling_back`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = LogSourceDeployJobPhase)]
pub enum DeployPhase {
    Queued,
    /// Another deploy holds the deploy lock.
    WaitingForLock,
    /// Compiling the source's VRL.
    Validating,
    /// Rendering and staging the Vector config.
    Rendering,
    /// `vector validate` on the staged tree (when enabled).
    ValidatingConfig,
    /// Backing up the active config and promoting the staged one.
    Promoting,
    /// Reloading Vector (or publishing a generation to the ingest hosts) and
    /// waiting for the correlated acknowledgement and health.
    Reloading,
    /// NAN-5132 (two-phase activation): every ingest host acknowledged the
    /// staged (parked) generation; routing traffic to the source (or, for an
    /// undeploy, dropping its parked chain) and waiting for the acknowledgement.
    Activating,
    /// Vector refused the config; restoring the previous one.
    RollingBack,
    Done,
}

impl DeployPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::WaitingForLock => "waiting_for_lock",
            Self::Validating => "validating",
            Self::Rendering => "rendering",
            Self::ValidatingConfig => "validating_config",
            Self::Promoting => "promoting",
            Self::Reloading => "reloading",
            Self::Activating => "activating",
            Self::RollingBack => "rolling_back",
            Self::Done => "done",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => Self::Queued,
            "waiting_for_lock" => Self::WaitingForLock,
            "validating" => Self::Validating,
            "rendering" => Self::Rendering,
            "validating_config" => Self::ValidatingConfig,
            "promoting" => Self::Promoting,
            "reloading" => Self::Reloading,
            "activating" => Self::Activating,
            "rolling_back" => Self::RollingBack,
            "done" => Self::Done,
            _ => return None,
        })
    }

    /// The deploy holds the deploy lock from this phase on.
    fn holds_lock(self) -> bool {
        !matches!(self, Self::Queued | Self::WaitingForLock)
    }
}

/// Progress reports from inside a deploy. Synchronous and infallible: a
/// progress write that fails must never fail the deploy it describes.
pub trait DeployProgress: Send + Sync {
    fn phase(&self, phase: DeployPhase);
}

/// Progress sink for callers that do not track a job (boot, sync paths).
pub struct NoProgress;

impl DeployProgress for NoProgress {
    fn phase(&self, _phase: DeployPhase) {}
}

/// A log-source deploy job, as polled by clients.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[schema(as = LogSourceDeployJob)]
pub struct DeployJob {
    #[serde(with = "typeid::deploy_job")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub kind: DeployJobKind,
    /// The log source, or null for deploy-all.
    #[serde(with = "typeid::log_source::opt")]
    #[schema(value_type = Option<String>)]
    pub log_source_id: Option<Uuid>,
    pub state: DeployJobState,
    pub phase: DeployPhase,
    /// Final (or latest) human-readable message.
    pub message: Option<String>,
    /// The deploy's result once finished (deploy, undeploy, publish). Carries
    /// NAN-5279 `delivery` on a role-split install.
    pub result: Option<DeploymentResult>,
    /// HTTP status the synchronous call would have returned for an error.
    pub error_status: Option<u16>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub heartbeat_at: DateTime<Utc>,
    /// True when this request joined a job that was already queued for the
    /// same target instead of starting a new one. Only set on submission.
    #[serde(default)]
    pub coalesced: bool,
    /// Where to poll this job.
    pub status_path: String,
}

/// Path a client polls for a job.
pub fn job_status_path(id: Uuid) -> String {
    format!(
        "/api/log-sources/deploy-jobs/{}",
        typeid::encode(typeid::deploy_job::PREFIX, &id)
    )
}

/// A job to create.
#[derive(Debug, Clone)]
pub struct NewDeployJob {
    pub kind: DeployJobKind,
    pub log_source_id: Option<Uuid>,
    pub requested_by: Option<Uuid>,
    /// May join an identical queued job. Publish never coalesces (it carries
    /// the caller's reviewed revision), and neither does a synchronous call
    /// (it waits for its own outcome).
    pub coalescible: bool,
}

impl NewDeployJob {
    fn coalesce_key(&self) -> String {
        format!(
            "{}:{}",
            self.kind.as_str(),
            self.log_source_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "*".to_string())
        )
    }
}

/// How the work ended, as the job records it.
#[derive(Debug, Clone)]
pub enum JobOutcome {
    /// The service returned a deploy result (success or not).
    Result(DeploymentResult),
    /// Finished without a per-source result (deploy-all).
    Done(String),
    /// The service returned an error; `status` is the HTTP status the
    /// synchronous call maps it to.
    Error { status: u16, message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum DeployJobError {
    #[error("deploy job store error: {0}")]
    Store(String),
}

impl From<sqlx::Error> for DeployJobError {
    fn from(e: sqlx::Error) -> Self {
        Self::Store(e.to_string())
    }
}

/// What a job finished as.
#[derive(Debug, Clone)]
pub struct JobFinish {
    pub state: DeployJobState,
    pub message: Option<String>,
    pub result: Option<DeploymentResult>,
    pub error_status: Option<u16>,
}

/// Persistence for jobs. PostgreSQL in production ([`PgDeployJobStore`]);
/// [`MemoryDeployJobStore`] for tests.
#[async_trait::async_trait]
pub trait DeployJobStore: Send + Sync {
    /// Insert a job, or return the queued coalescible job for the same target
    /// (`true` = joined an existing job).
    async fn create_or_join(
        &self,
        new: &NewDeployJob,
        owner: &str,
    ) -> Result<(DeployJob, bool), DeployJobError>;
    /// Record a phase; moves `queued` to `running` once the lock is held.
    async fn set_phase(&self, id: Uuid, phase: DeployPhase) -> Result<(), DeployJobError>;
    async fn heartbeat(&self, id: Uuid) -> Result<(), DeployJobError>;
    async fn finish(&self, id: Uuid, finish: &JobFinish) -> Result<(), DeployJobError>;
    async fn get(&self, id: Uuid) -> Result<Option<DeployJob>, DeployJobError>;
    async fn list_for_source(
        &self,
        log_source_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DeployJob>, DeployJobError>;
    /// Mark non-terminal jobs whose heartbeat is older than `stale_after` as
    /// interrupted (all of them, or just `only`). Returns how many.
    async fn interrupt_stale(
        &self,
        stale_after: Duration,
        only: Option<Uuid>,
    ) -> Result<u64, DeployJobError>;
    /// Delete finished jobs older than `older_than`.
    async fn prune(&self, older_than: Duration) -> Result<u64, DeployJobError>;
}

const INTERRUPTED_MESSAGE: &str = "The API stopped while this deploy was running. On restart the \
    API rewrites the Vector config from the database, so no half-applied config is left behind; \
    run the deploy again to confirm it.";

/// Runs deploy work as detached jobs and records their progress.
pub struct DeployJobRunner {
    store: Arc<dyn DeployJobStore>,
    instance: String,
}

/// The submitted job.
pub struct Submitted {
    pub job: DeployJob,
    /// `work` was not run: the request joined `job`, which was already queued.
    pub coalesced: bool,
}

impl DeployJobRunner {
    pub fn new(store: Arc<dyn DeployJobStore>) -> Self {
        Self {
            store,
            instance: format!("api-{}", Uuid::new_v4().simple()),
        }
    }

    pub fn with_pool(pool: PgPool) -> Self {
        Self::new(Arc::new(PgDeployJobStore::new(pool)))
    }

    /// Create a job and run `work` for it in a detached task, or join the
    /// queued identical job (then `work` is dropped without running).
    ///
    /// `work` receives the progress sink to hand to the service. It runs in
    /// its own task: dropping the caller (a client disconnect) never cancels
    /// it, and a panic in it is recorded as a failed job.
    pub async fn submit<F>(&self, new: NewDeployJob, work: F) -> Result<Submitted, DeployJobError>
    where
        F: FnOnce(Arc<dyn DeployProgress>) -> BoxFuture<'static, JobOutcome> + Send + 'static,
    {
        let (mut job, coalesced) = self.store.create_or_join(&new, &self.instance).await?;
        if coalesced {
            job.coalesced = true;
            tracing::info!(job_id = %job.id, kind = new.kind.as_str(), "deploy request joined a queued job");
            return Ok(Submitted { job, coalesced });
        }
        let id = job.id;
        let store = Arc::clone(&self.store);
        tokio::spawn(run_job(store, id, work));
        Ok(Submitted { job, coalesced })
    }

    /// The job, with a stale non-terminal job reported as interrupted.
    pub async fn get(&self, id: Uuid) -> Result<Option<DeployJob>, DeployJobError> {
        let Some(job) = self.store.get(id).await? else {
            return Ok(None);
        };
        if !job.state.is_terminal() && is_stale(&job, Utc::now()) {
            self.store.interrupt_stale(STALE_AFTER, Some(id)).await?;
            return self.store.get(id).await;
        }
        Ok(Some(job))
    }

    pub async fn list_for_source(
        &self,
        log_source_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DeployJob>, DeployJobError> {
        let jobs = self.store.list_for_source(log_source_id, limit.clamp(1, 100)).await?;
        let now = Utc::now();
        if jobs.iter().any(|j| !j.state.is_terminal() && is_stale(j, now)) {
            self.store.interrupt_stale(STALE_AFTER, None).await?;
            return self.store.list_for_source(log_source_id, limit.clamp(1, 100)).await;
        }
        Ok(jobs)
    }

    /// Boot-time recovery: interrupt jobs whose process died, prune old ones.
    pub async fn recover(&self) -> Result<(u64, u64), DeployJobError> {
        let interrupted = self.store.interrupt_stale(STALE_AFTER, None).await?;
        let pruned = self.store.prune(RETENTION).await?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "deploy jobs left running by a stopped API process were marked interrupted");
        }
        Ok((interrupted, pruned))
    }

    /// Wait until `id` is terminal (polling the store). For a request that
    /// joined a job another task or host runs.
    pub async fn wait(&self, id: Uuid, poll: Duration) -> Result<Option<DeployJob>, DeployJobError> {
        loop {
            match self.get(id).await? {
                Some(job) if job.state.is_terminal() => return Ok(Some(job)),
                None => return Ok(None),
                Some(_) => tokio::time::sleep(poll).await,
            }
        }
    }
}

fn is_stale(job: &DeployJob, now: DateTime<Utc>) -> bool {
    let stale = chrono::Duration::from_std(STALE_AFTER).unwrap_or_else(|_| chrono::Duration::seconds(60));
    now - job.heartbeat_at > stale
}

/// Ordered updates for one job, applied by a single writer task.
enum Update {
    Phase(DeployPhase),
    Heartbeat,
    Finish(JobFinish),
}

struct ChannelProgress {
    tx: tokio::sync::mpsc::UnboundedSender<Update>,
    last: Mutex<DeployPhase>,
    rolled_back: AtomicBool,
}

impl DeployProgress for ChannelProgress {
    fn phase(&self, phase: DeployPhase) {
        if phase == DeployPhase::RollingBack {
            self.rolled_back.store(true, Ordering::SeqCst);
        }
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        // Never backwards, except into rolling_back.
        if phase <= *last && phase != DeployPhase::RollingBack {
            return;
        }
        *last = phase;
        let _ = self.tx.send(Update::Phase(phase));
    }
}

/// Map the work's outcome to the job's final state.
pub(crate) fn finish_for(outcome: JobOutcome, rolled_back: bool) -> JobFinish {
    match outcome {
        JobOutcome::Result(result) => {
            let state = if result.success {
                DeployJobState::Succeeded
            } else if rolled_back {
                DeployJobState::RolledBack
            } else {
                DeployJobState::Failed
            };
            JobFinish {
                state,
                message: Some(result.message.clone()),
                result: Some(result),
                error_status: None,
            }
        }
        JobOutcome::Done(message) => JobFinish {
            state: DeployJobState::Succeeded,
            message: Some(message),
            result: None,
            error_status: None,
        },
        JobOutcome::Error { status, message } => JobFinish {
            state: DeployJobState::Failed,
            message: Some(message),
            result: None,
            error_status: Some(status),
        },
    }
}

async fn run_job<F>(store: Arc<dyn DeployJobStore>, id: Uuid, work: F)
where
    F: FnOnce(Arc<dyn DeployProgress>) -> BoxFuture<'static, JobOutcome> + Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Update>();
    let progress = Arc::new(ChannelProgress {
        tx: tx.clone(),
        last: Mutex::new(DeployPhase::Queued),
        rolled_back: AtomicBool::new(false),
    });

    let writer_store = Arc::clone(&store);
    let writer = tokio::spawn(async move {
        while let Some(update) = rx.recv().await {
            let result = match &update {
                Update::Phase(phase) => writer_store.set_phase(id, *phase).await,
                Update::Heartbeat => writer_store.heartbeat(id).await,
                Update::Finish(finish) => writer_store.finish(id, finish).await,
            };
            if let Err(error) = result {
                // The deploy itself is unaffected; only its progress record is.
                tracing::warn!(job_id = %id, %error, "could not record deploy job progress");
            }
        }
    });

    progress.phase(DeployPhase::WaitingForLock);
    let mut handle = tokio::spawn(work(progress.clone() as Arc<dyn DeployProgress>));
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.tick().await;
    let joined = loop {
        tokio::select! {
            joined = &mut handle => break joined,
            _ = heartbeat.tick() => { let _ = tx.send(Update::Heartbeat); }
        }
    };

    let rolled_back = progress.rolled_back.load(Ordering::SeqCst);
    let finish = match joined {
        Ok(outcome) => finish_for(outcome, rolled_back),
        Err(join_error) => {
            tracing::error!(job_id = %id, error = %join_error, "deploy job task failed");
            JobFinish {
                state: DeployJobState::Failed,
                message: Some(format!(
                    "The deploy stopped unexpectedly ({}). Check the API log; the deploy lock was \
                     released and the next deploy re-renders the config.",
                    if join_error.is_panic() { "panic" } else { "cancelled" }
                )),
                result: None,
                error_status: Some(500),
            }
        }
    };
    tracing::info!(job_id = %id, state = finish.state.as_str(), "deploy job finished");
    let _ = tx.send(Update::Finish(finish));
    drop(tx);
    drop(progress);
    let _ = writer.await;
}

// ============================================================================
// PostgreSQL store
// ============================================================================

pub struct PgDeployJobStore {
    pool: PgPool,
}

impl PgDeployJobStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct JobRow {
    id: Uuid,
    kind: String,
    log_source_id: Option<Uuid>,
    state: String,
    phase: String,
    message: Option<String>,
    result: Option<serde_json::Value>,
    error_status: Option<i16>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    heartbeat_at: DateTime<Utc>,
}

impl JobRow {
    fn into_job(self) -> DeployJob {
        DeployJob {
            id: self.id,
            kind: DeployJobKind::parse(&self.kind).unwrap_or(DeployJobKind::Deploy),
            log_source_id: self.log_source_id,
            state: DeployJobState::parse(&self.state).unwrap_or(DeployJobState::Failed),
            phase: DeployPhase::parse(&self.phase).unwrap_or(DeployPhase::Queued),
            message: self.message,
            result: self
                .result
                .and_then(|value| serde_json::from_value(value).ok()),
            error_status: self.error_status.and_then(|s| u16::try_from(s).ok()),
            created_at: self.created_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            heartbeat_at: self.heartbeat_at,
            coalesced: false,
            status_path: job_status_path(self.id),
        }
    }
}

const JOB_COLUMNS: &str = "id, kind, log_source_id, state, phase, message, result, error_status, \
     created_at, started_at, finished_at, heartbeat_at";

#[async_trait::async_trait]
impl DeployJobStore for PgDeployJobStore {
    async fn create_or_join(
        &self,
        new: &NewDeployJob,
        owner: &str,
    ) -> Result<(DeployJob, bool), DeployJobError> {
        let key = new.coalesce_key();
        // A queued job can finish between the conflicting insert and the
        // read; retry the pair a few times.
        for _ in 0..5 {
            let inserted: Option<JobRow> = sqlx::query_as(&format!(
                "INSERT INTO log_source_deploy_jobs \
                     (id, kind, log_source_id, coalesce_key, coalescible, requested_by, owner_instance) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (coalesce_key) WHERE state = 'queued' AND coalescible DO NOTHING \
                 RETURNING {JOB_COLUMNS}"
            ))
            .bind(Uuid::now_v7())
            .bind(new.kind.as_str())
            .bind(new.log_source_id)
            .bind(&key)
            .bind(new.coalescible)
            .bind(new.requested_by)
            .bind(owner)
            .fetch_optional(&self.pool)
            .await?;
            if let Some(row) = inserted {
                return Ok((row.into_job(), false));
            }
            let existing: Option<JobRow> = sqlx::query_as(&format!(
                "SELECT {JOB_COLUMNS} FROM log_source_deploy_jobs \
                 WHERE coalesce_key = $1 AND state = 'queued' AND coalescible"
            ))
            .bind(&key)
            .fetch_optional(&self.pool)
            .await?;
            if let Some(row) = existing {
                return Ok((row.into_job(), true));
            }
        }
        Err(DeployJobError::Store(
            "could not create or join a deploy job after 5 attempts".to_string(),
        ))
    }

    async fn set_phase(&self, id: Uuid, phase: DeployPhase) -> Result<(), DeployJobError> {
        sqlx::query(
            "UPDATE log_source_deploy_jobs SET \
                 phase = $2, \
                 state = CASE WHEN $3 AND state = 'queued' THEN 'running' ELSE state END, \
                 started_at = CASE WHEN $3 THEN COALESCE(started_at, now()) ELSE started_at END, \
                 heartbeat_at = now() \
             WHERE id = $1 AND state IN ('queued', 'running')",
        )
        .bind(id)
        .bind(phase.as_str())
        .bind(phase.holds_lock())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn heartbeat(&self, id: Uuid) -> Result<(), DeployJobError> {
        sqlx::query(
            "UPDATE log_source_deploy_jobs SET heartbeat_at = now() \
             WHERE id = $1 AND state IN ('queued', 'running')",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn finish(&self, id: Uuid, finish: &JobFinish) -> Result<(), DeployJobError> {
        let result = finish
            .result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| DeployJobError::Store(e.to_string()))?;
        // `interrupted` is overwritable: a job whose heartbeat writes failed
        // (PostgreSQL unreachable for a minute) but which then finished
        // records what really happened.
        sqlx::query(
            "UPDATE log_source_deploy_jobs SET \
                 state = $2, phase = 'done', message = $3, result = $4, error_status = $5, \
                 started_at = COALESCE(started_at, now()), finished_at = now(), heartbeat_at = now() \
             WHERE id = $1 AND state IN ('queued', 'running', 'interrupted')",
        )
        .bind(id)
        .bind(finish.state.as_str())
        .bind(&finish.message)
        .bind(result)
        .bind(finish.error_status.map(|s| s as i16))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<DeployJob>, DeployJobError> {
        let row: Option<JobRow> = sqlx::query_as(&format!(
            "SELECT {JOB_COLUMNS} FROM log_source_deploy_jobs WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(JobRow::into_job))
    }

    async fn list_for_source(
        &self,
        log_source_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DeployJob>, DeployJobError> {
        // Deploy-all jobs cover every source, so they are listed too.
        let rows: Vec<JobRow> = sqlx::query_as(&format!(
            "SELECT {JOB_COLUMNS} FROM log_source_deploy_jobs \
             WHERE log_source_id = $1 OR kind = 'deploy_all' \
             ORDER BY created_at DESC LIMIT $2"
        ))
        .bind(log_source_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(JobRow::into_job).collect())
    }

    async fn interrupt_stale(
        &self,
        stale_after: Duration,
        only: Option<Uuid>,
    ) -> Result<u64, DeployJobError> {
        let result = sqlx::query(
            "UPDATE log_source_deploy_jobs SET \
                 state = 'interrupted', phase = 'done', message = $1, error_status = 500, \
                 finished_at = now() \
             WHERE state IN ('queued', 'running') \
               AND heartbeat_at < now() - make_interval(secs => $2) \
               AND ($3::uuid IS NULL OR id = $3)",
        )
        .bind(INTERRUPTED_MESSAGE)
        .bind(stale_after.as_secs_f64())
        .bind(only)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn prune(&self, older_than: Duration) -> Result<u64, DeployJobError> {
        let result = sqlx::query(
            "DELETE FROM log_source_deploy_jobs \
             WHERE finished_at IS NOT NULL AND finished_at < now() - make_interval(secs => $1)",
        )
        .bind(older_than.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

// ============================================================================
// In-memory store (tests)
// ============================================================================

/// A [`DeployJobStore`] in process memory, with the same semantics as the
/// PostgreSQL store. For tests.
#[derive(Default)]
pub struct MemoryDeployJobStore {
    jobs: Mutex<Vec<(DeployJob, String, bool)>>,
}

impl MemoryDeployJobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test hook: age a job's heartbeat, as if its process had stopped.
    pub fn age_heartbeat(&self, id: Uuid, by: Duration) {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((job, _, _)) = jobs.iter_mut().find(|(j, _, _)| j.id == id) {
            job.heartbeat_at -= chrono::Duration::from_std(by).unwrap_or_default();
        }
    }

    /// Phases recorded so far are not kept; this returns the current row.
    pub fn snapshot(&self) -> Vec<DeployJob> {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        jobs.iter().map(|(j, _, _)| j.clone()).collect()
    }
}

#[async_trait::async_trait]
impl DeployJobStore for MemoryDeployJobStore {
    async fn create_or_join(
        &self,
        new: &NewDeployJob,
        _owner: &str,
    ) -> Result<(DeployJob, bool), DeployJobError> {
        let key = new.coalesce_key();
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if new.coalescible {
            if let Some((job, _, _)) = jobs
                .iter()
                .find(|(j, k, c)| *c && *k == key && j.state == DeployJobState::Queued)
            {
                return Ok((job.clone(), true));
            }
        }
        let id = Uuid::now_v7();
        let now = Utc::now();
        let job = DeployJob {
            id,
            kind: new.kind,
            log_source_id: new.log_source_id,
            state: DeployJobState::Queued,
            phase: DeployPhase::Queued,
            message: None,
            result: None,
            error_status: None,
            created_at: now,
            started_at: None,
            finished_at: None,
            heartbeat_at: now,
            coalesced: false,
            status_path: job_status_path(id),
        };
        jobs.push((job.clone(), key, new.coalescible));
        Ok((job, false))
    }

    async fn set_phase(&self, id: Uuid, phase: DeployPhase) -> Result<(), DeployJobError> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((job, _, _)) = jobs.iter_mut().find(|(j, _, _)| j.id == id) {
            if job.state.is_terminal() {
                return Ok(());
            }
            job.phase = phase;
            if phase.holds_lock() {
                job.state = DeployJobState::Running;
                job.started_at.get_or_insert_with(Utc::now);
            }
            job.heartbeat_at = Utc::now();
        }
        Ok(())
    }

    async fn heartbeat(&self, id: Uuid) -> Result<(), DeployJobError> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((job, _, _)) = jobs.iter_mut().find(|(j, _, _)| j.id == id) {
            if !job.state.is_terminal() {
                job.heartbeat_at = Utc::now();
            }
        }
        Ok(())
    }

    async fn finish(&self, id: Uuid, finish: &JobFinish) -> Result<(), DeployJobError> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((job, _, _)) = jobs.iter_mut().find(|(j, _, _)| j.id == id) {
            if job.state.is_terminal() && job.state != DeployJobState::Interrupted {
                return Ok(());
            }
            let now = Utc::now();
            job.state = finish.state;
            job.phase = DeployPhase::Done;
            job.message = finish.message.clone();
            job.result = finish.result.clone();
            job.error_status = finish.error_status;
            job.started_at.get_or_insert(now);
            job.finished_at = Some(now);
            job.heartbeat_at = now;
        }
        Ok(())
    }

    async fn get(&self, id: Uuid) -> Result<Option<DeployJob>, DeployJobError> {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        Ok(jobs.iter().find(|(j, _, _)| j.id == id).map(|(j, _, _)| j.clone()))
    }

    async fn list_for_source(
        &self,
        log_source_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DeployJob>, DeployJobError> {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<DeployJob> = jobs
            .iter()
            .map(|(j, _, _)| j)
            .filter(|j| j.log_source_id == Some(log_source_id) || j.kind == DeployJobKind::DeployAll)
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        out.truncate(limit.max(0) as usize);
        Ok(out)
    }

    async fn interrupt_stale(
        &self,
        stale_after: Duration,
        only: Option<Uuid>,
    ) -> Result<u64, DeployJobError> {
        let cutoff = Utc::now() - chrono::Duration::from_std(stale_after).unwrap_or_default();
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let mut n = 0;
        for (job, _, _) in jobs.iter_mut() {
            if job.state.is_terminal() || job.heartbeat_at >= cutoff {
                continue;
            }
            if only.is_some_and(|id| id != job.id) {
                continue;
            }
            job.state = DeployJobState::Interrupted;
            job.phase = DeployPhase::Done;
            job.message = Some(INTERRUPTED_MESSAGE.to_string());
            job.error_status = Some(500);
            job.finished_at = Some(Utc::now());
            n += 1;
        }
        Ok(n)
    }

    async fn prune(&self, older_than: Duration) -> Result<u64, DeployJobError> {
        let cutoff = Utc::now() - chrono::Duration::from_std(older_than).unwrap_or_default();
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let before = jobs.len();
        jobs.retain(|(j, _, _)| j.finished_at.is_none_or(|f| f >= cutoff));
        Ok((before - jobs.len()) as u64)
    }
}

#[cfg(test)]
#[path = "deploy_jobs_tests.rs"]
mod tests;
