// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log-source deploy jobs (NAN-5132).
//!
//! `POST /api/log-sources/{id}/deploy|undeploy|publish` and
//! `POST /api/log-sources/deploy-all` run their work as a background job
//! ([`DeployJobRunner`]). With `?wait=false` they answer 202 with the job at
//! once; the default (`wait=true`) waits for the job and answers exactly as
//! before. Either way the deploy runs in a detached task, so a client or edge
//! disconnect cannot stop it halfway.
//!
//! Implements:
//! - GET /api/log-sources/deploy-jobs/{job_id} - Poll one job
//! - GET /api/log-sources/{id}/deploy-jobs - Recent jobs for a source

use std::future::Future;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use futures::FutureExt;
use nanosiem_core::log_sources::deploy_jobs::{
    DeployJob, DeployJobKind, DeployJobState, DeployPhase, DeployProgress, JobOutcome,
    NewDeployJob,
};
use nanosiem_core::log_sources::DeploymentResult;
use nanosiem_core::typeid::{self, TypeIdParam};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};

const LOG_SOURCES_VIEW: &str = "log_sources:view";

/// `?wait=` on the deploy routes.
#[derive(Debug, Deserialize, IntoParams)]
pub struct DeployWaitQuery {
    /// `false`: answer 202 with the deploy job at once and run the deploy in
    /// the background (poll `status_path`). `true` (default): wait for the
    /// job and answer with its result, as before. The deploy runs to
    /// completion or rollback either way, even if the client disconnects.
    #[serde(default = "default_wait")]
    pub wait: bool,
}

fn default_wait() -> bool {
    true
}

/// NAN-5298 follow-up (review): the longest a `wait=true` request holds its
/// connection. The edge's `proxy_read_timeout` is 300 s and the web gives up at
/// 310 s; a deploy still running past this answers 202 with the job (and its
/// `status_path`) instead of a 504 without one, which invited duplicate
/// deploys. The deploy itself keeps running either way.
pub(crate) const SYNC_DEPLOY_WAIT: std::time::Duration = std::time::Duration::from_secs(270);

/// How long a `wait=true` request still waits for its job after spending
/// `elapsed` before it (NAN-5406: the OCSF gate runs before the job is
/// enqueued and can take a minute or more per stage on a slow host). The whole
/// request stays inside [`SYNC_DEPLOY_WAIT`], so it still answers before the
/// edge gives up; a job left running answers 202 with its `status_path`.
pub(crate) fn remaining_sync_wait(elapsed: std::time::Duration) -> std::time::Duration {
    SYNC_DEPLOY_WAIT.saturating_sub(elapsed)
}

/// A running job in the reload phase carries what the reload wait is doing
/// (NAN-5298 follow-up: a large config can take minutes to compile, and an
/// unexplained "Reloading Vector" for that long reads as a hang).
pub(crate) fn with_reload_status(mut job: DeployJob) -> DeployJob {
    if job.state == DeployJobState::Running
        && matches!(job.phase, DeployPhase::Reloading | DeployPhase::Activating)
    {
        if let Some(status) = nanosiem_core::parsers::current_reload_wait() {
            job.message = Some(status.describe());
        }
    }
    job
}

/// What a deploy job's work produced.
pub(crate) enum DeployOk {
    /// A per-source deploy result (deploy, undeploy, publish).
    Result(DeploymentResult),
    /// Deploy-all: the legacy synchronous body and the job message.
    Done(serde_json::Value, String),
}

/// Who asked, for the audit event the job emits.
pub(crate) struct DeployAudit {
    pub action: &'static str,
    pub auth: AuthContext,
    pub client: ClientContext,
    /// Extra detail fields merged into every event this job emits (NAN-5079:
    /// how the OCSF gate passed).
    pub extra: Option<serde_json::Value>,
}

impl DeployAudit {
    fn emit(&self, state: &AppState, log_source_id: Option<Uuid>, details: Option<serde_json::Value>) {
        let mut event = AuditEvent::builder(AuditSource::LogSource, self.action)
            .actor(Some(self.auth.user_id()), None)
            .api_key(self.auth.api_key_id, self.auth.api_key_name.clone())
            .client_context(&self.client);
        if let Some(id) = log_source_id {
            event = event.resource("log_source", Some(id), None::<String>);
        }
        let details = match (details, self.extra.clone()) {
            (Some(serde_json::Value::Object(mut base)), Some(serde_json::Value::Object(extra))) => {
                base.extend(extra);
                Some(serde_json::Value::Object(base))
            }
            (Some(details), _) => Some(details),
            (None, extra) => extra,
        };
        if let Some(details) = details {
            event = event.details(details);
        }
        state.emit_audit(event.build());
    }
}

/// Run `work` as a deploy job; see the module docs for `wait`.
///
/// `request_started` is when the handler began: work it did before the job
/// (the OCSF gate) counts against the synchronous wait.
///
/// `work` receives a clone of the state and the job's progress sink. The
/// audit event is emitted when the work finishes successfully, as the
/// synchronous handlers always did; a request that joined a queued job is
/// audited at once with the job it joined.
pub(crate) async fn run_deploy_job<W, Fut>(
    state: &AppState,
    audit: DeployAudit,
    kind: DeployJobKind,
    log_source_id: Option<Uuid>,
    wait: bool,
    request_started: std::time::Instant,
    work: W,
) -> Result<Response, ApiError>
where
    W: FnOnce(AppState, Arc<dyn DeployProgress>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<DeployOk, ApiError>> + Send + 'static,
{
    let requested_by = audit.auth.user_id();
    let audit = Arc::new(audit);
    let job_audit = Arc::clone(&audit);
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<DeployOk, ApiError>>();
    let job_state = state.clone();
    let submitted = state
        .log_source_deploy_jobs
        .submit(
            NewDeployJob {
                kind,
                log_source_id,
                requested_by: Some(requested_by),
                // A waiting caller needs its own outcome; a publish carries
                // the caller's reviewed revision. Neither joins another job.
                coalescible: !wait && kind != DeployJobKind::Publish,
            },
            move |progress| {
                async move {
                    let outcome = work(job_state.clone(), progress).await;
                    match &outcome {
                        Ok(DeployOk::Result(result)) => job_audit.emit(
                            &job_state,
                            log_source_id,
                            Some(serde_json::json!({ "success": result.success })),
                        ),
                        Ok(DeployOk::Done(..)) => job_audit.emit(&job_state, log_source_id, None),
                        Err(_) => {}
                    }
                    let recorded = match &outcome {
                        Ok(DeployOk::Result(result)) => JobOutcome::Result(result.clone()),
                        Ok(DeployOk::Done(_, message)) => JobOutcome::Done(message.clone()),
                        Err(error) => JobOutcome::Error {
                            status: error.status_code().as_u16(),
                            message: error.to_string(),
                        },
                    };
                    // The waiting request may be gone (client disconnect);
                    // the job record above is what counts.
                    let _ = tx.send(outcome);
                    recorded
                }
                .boxed()
            },
        )
        .await
        .map_err(|e| ApiError::InternalError(format!("Could not start the deploy job: {e}")))?;

    if submitted.coalesced {
        audit.emit(
            state,
            log_source_id,
            Some(serde_json::json!({
                "coalesced_into": typeid::encode(typeid::deploy_job::PREFIX, &submitted.job.id),
            })),
        );
    }
    if !wait {
        return Ok((StatusCode::ACCEPTED, Json(submitted.job)).into_response());
    }
    let Ok(received) = tokio::time::timeout(remaining_sync_wait(request_started.elapsed()), rx).await else {
        // Still running: hand back the job to poll rather than letting the
        // edge cut the connection with no job id.
        let job = state
            .log_source_deploy_jobs
            .get(submitted.job.id)
            .await
            .ok()
            .flatten()
            .map(with_reload_status)
            .unwrap_or(submitted.job);
        return Ok((StatusCode::ACCEPTED, Json(job)).into_response());
    };
    match received {
        Ok(Ok(DeployOk::Result(result))) => Ok(Json(result).into_response()),
        Ok(Ok(DeployOk::Done(body, _))) => Ok(Json(body).into_response()),
        Ok(Err(error)) => Err(error),
        // The work panicked; the job recorded it as failed.
        Err(_) => Err(ApiError::InternalError(format!(
            "The deploy stopped unexpectedly; see deploy job {}",
            typeid::encode(typeid::deploy_job::PREFIX, &submitted.job.id)
        ))),
    }
}

/// Poll one deploy job.
#[utoipa::path(
    get,
    path = "/api/log-sources/deploy-jobs/{job_id}",
    tag = "log_sources",
    params(
        ("job_id" = String, Path, description = "Deploy job ID (djob_…)")
    ),
    responses(
        (status = 200, description = "The deploy job: state, phase, and the result once finished", body = DeployJob),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_deploy_job(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(job_id): Path<String>,
) -> Result<Json<DeployJob>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;
    let id = typeid::decode(typeid::deploy_job::PREFIX, &job_id)
        .map_err(|e| ApiError::BadRequest(format!("Invalid deploy job id: {e}")))?;
    let job = state
        .log_source_deploy_jobs
        .get(id)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("Deploy job not found: {job_id}")))?;
    Ok(Json(with_reload_status(job)))
}

/// Query for [`list_log_source_deploy_jobs`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct DeployJobListQuery {
    /// Most recent first; 1–100, default 10.
    pub limit: Option<i64>,
}

/// Recent deploy jobs for a log source (newest first), including deploy-all
/// jobs, so a reloaded page can find a deploy that is still running.
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/deploy-jobs",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID"),
        DeployJobListQuery,
    ),
    responses(
        (status = 200, description = "Recent deploy jobs", body = Vec<DeployJob>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_log_source_deploy_jobs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<DeployJobListQuery>,
) -> Result<Json<Vec<DeployJob>>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;
    let jobs = state
        .log_source_deploy_jobs
        .list_for_source(*id, query.limit.unwrap_or(10))
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    Ok(Json(jobs.into_iter().map(with_reload_status).collect()))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_deploy_job, list_log_source_deploy_jobs),
    components(schemas(DeployJob, DeployJobKind, DeployJobState, DeployPhase))
)]
pub struct LogSourceDeployJobsApiDoc;

#[cfg(test)]
#[path = "log_source_deploy_jobs_budget_tests.rs"]
mod budget_tests;
