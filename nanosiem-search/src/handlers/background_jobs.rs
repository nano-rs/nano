// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable background search jobs (NAN-4915): submit / attach, result pages,
//! and the shared authorization + response helpers the batch, stream, and job
//! routes use.
//!
//! Contract (S5, "never a silent empty 200"): a search only ever becomes a job
//! answer for a caller that asked for one — `async_mode: true`, `POST
//! /api/search/jobs`, or the `x-nano-accept-async: 1` header that permits an
//! interactive search to be handed off at the budget. A job answer carries a
//! `job_id` and NO `results` key; pages of a job that is not completed are a
//! 409 `JOB_NOT_READY`, never an empty page.

use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use nanosiem_core::{
    SearchRequest,
    auth::{ScopeSet, permissions},
    search::{
        AsyncSearchResponse, SearchJobStatus,
        background::{
            DurableSearchJob, JobOrigin, JobResultsPage, SubmitOutcome, decode_job_id,
        },
    },
};
use serde::Deserialize;

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError};

/// Request header by which a client accepts a job answer from `POST
/// /api/search` / `POST /api/search/stream` when the search outruns the
/// interactive budget. Clients that do not send it never receive one.
pub const HEADER_ACCEPT_ASYNC: &str = "x-nano-accept-async";

/// Response header naming the job a search was handed off to.
pub const HEADER_SEARCH_JOB: &str = "x-nano-search-job";

/// Extractor for [`HEADER_ACCEPT_ASYNC`] (`1` / `true`).
#[derive(Clone, Copy, Debug)]
pub struct AcceptAsync(pub bool);

impl<S: Sync> axum::extract::FromRequestParts<S> for AcceptAsync {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let accept = parts
            .headers
            .get(HEADER_ACCEPT_ASYNC)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
        Ok(AcceptAsync(accept))
    }
}

/// Whether an interactive search may be handed off to a background job
/// (NAN-4915) when it outlives the interactive budget.
///
/// NAN-5277: never for a `| ai` search. Its time goes to the LLM call, not to
/// ClickHouse, so a hand-off re-ran the whole search and paid for the model
/// call twice, and the re-run held one of the few background workers per
/// replica (default 2) for minutes. Every other user's escalated search queued
/// behind it. The `| ai` call is bounded in the search service instead
/// (`ai_pipe_guard`), so the interactive request finishes on its own. A query
/// that does not parse keeps the hand-off (the search fails fast either way).
pub(crate) fn handoff_eligible(query: &str) -> bool {
    match nanosiem_core::query::parse_query(query) {
        Ok(parsed) => nanosiem_core::search::query_processing::extract_ai_command(&parsed).is_none(),
        Err(_) => true,
    }
}

/// The job answer for a submission / attach / hand-off.
pub(crate) fn async_response(outcome: &SubmitOutcome) -> AsyncSearchResponse {
    AsyncSearchResponse {
        job_id: outcome.job.public_id(),
        status: outcome.job.state.to_string(),
        attached: Some(outcome.attached),
        origin: Some(outcome.job.origin),
    }
}

/// Header map stamping `x-nano-search-job` for a job answer.
pub(crate) fn job_headers(mut headers: HeaderMap, outcome: &SubmitOutcome) -> HeaderMap {
    if let Ok(value) = HeaderValue::from_str(&outcome.job.public_id()) {
        headers.insert(HEADER_SEARCH_JOB, value);
    }
    headers
}

/// Submit (or attach) a durable job for `request` under the caller's scope.
pub(crate) async fn submit_job(
    state: &SearchState,
    auth: &crate::AuthContext,
    request: &SearchRequest,
    scope: &ScopeSet,
    origin: JobOrigin,
) -> Result<SubmitOutcome, SearchError> {
    state
        .background_jobs
        .submit(request, auth.claims.sub, scope, origin)
        .await
        .map_err(SearchError::from)
}

/// Load a durable job the caller may READ: `search:execute` (checked by the
/// caller first), ownership unless `settings:system`, and the NAN-2096
/// source-scope re-check against the job's stamp. Every refusal is the same
/// 404 a missing job returns, so this is not an existence oracle.
pub(crate) async fn load_readable_job(
    state: &SearchState,
    auth: &crate::AuthContext,
    public_id: &str,
) -> Result<DurableSearchJob, SearchError> {
    let job = load_owned_job(state, auth, public_id).await?;
    if !job.result_visible_under(super::search::effective_scope(auth).deny_set()) {
        tracing::warn!(
            job_id = %public_id,
            user_id = %auth.claims.sub,
            "Background search job hidden: caller's source scope narrowed since submission"
        );
        return Err(not_found(public_id));
    }
    Ok(job)
}

/// Load a durable job the caller owns (or any job for `settings:system`),
/// WITHOUT the scope re-check — used by cancel, which destroys rather than
/// reads (see `cancel_search_job`).
pub(crate) async fn load_owned_job(
    state: &SearchState,
    auth: &crate::AuthContext,
    public_id: &str,
) -> Result<DurableSearchJob, SearchError> {
    let id = decode_job_id(public_id).ok_or_else(|| not_found(public_id))?;
    let job = state
        .background_jobs
        .get(id)
        .await
        .map_err(SearchError::from)?
        .ok_or_else(|| not_found(public_id))?;
    let is_admin = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    if !is_admin && job.owner_user_id != auth.claims.sub {
        return Err(not_found(public_id));
    }
    Ok(job)
}

fn not_found(public_id: &str) -> SearchError {
    SearchError::NotFound(format!("Job not found: {public_id}"))
}

/// Submit a background search job
///
/// Runs the search as a durable background job and returns its id
/// immediately. If the caller already has an identical job queued or running
/// (same query, absolute time range, dataset/view flags and source scope), the
/// response attaches to it (`attached: true`) instead of starting a second
/// scan. Poll `GET /api/search/jobs/{job_id}` and page completed results with
/// `GET /api/search/jobs/{job_id}/results`. Jobs and their rows are kept for
/// 24 hours and survive search-service restarts.
#[utoipa::path(
    post,
    path = "/api/search/jobs",
    tag = "search",
    request_body = SearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 202, description = "Job created or attached", body = AsyncSearchResponse),
        (status = 400, description = "Invalid query or time range", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn submit_search_job(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Json(request): Json<SearchRequest>,
) -> Result<(StatusCode, HeaderMap, Json<AsyncSearchResponse>), SearchError> {
    super::require_search_execute(&auth)?;
    let scope = super::search::effective_scope(&auth);
    let outcome = submit_job(&state, &auth, &request, &scope, JobOrigin::Submitted).await?;
    Ok((
        StatusCode::ACCEPTED,
        job_headers(HeaderMap::new(), &outcome),
        Json(async_response(&outcome)),
    ))
}

/// Paging parameters for a completed job's rows.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct JobResultsQuery {
    /// Offset of the first row (default 0).
    pub offset: Option<u64>,
    /// Page size (default 500, max 10000).
    pub limit: Option<u64>,
}

/// Page through a completed background job's results
///
/// Continuation: reads stored rows, never re-runs the search. Returns 409
/// `JOB_NOT_READY` while the job is queued or running, if it failed or was
/// cancelled, or if the replica serving the read does not yet hold every
/// stored row; 400 for an offset past the stored rows — never an empty or
/// short page that could be mistaken for "no more matches".
#[utoipa::path(
    get,
    path = "/api/search/jobs/{job_id}/results",
    tag = "search",
    params(
        ("job_id" = String, Path, description = "Background search job ID (sjob_…)"),
        JobResultsQuery,
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "One page of the job's rows (may stop early at the page byte budget; follow next_offset)", body = JobResultsPage),
        (status = 400, description = "offset is beyond the rows this job stored", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
        (status = 404, description = "Job not found", body = ErrorResponse),
        (status = 409, description = "Job not completed (running, failed or cancelled), or its rows are still replicating (retry)", body = ErrorResponse),
    )
)]
pub async fn get_search_job_results(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Path(job_id): Path<String>,
    Query(page): Query<JobResultsQuery>,
) -> Result<Json<JobResultsPage>, SearchError> {
    super::require_search_execute(&auth)?;
    let job = load_readable_job(&state, &auth, &job_id).await?;
    match job.state {
        SearchJobStatus::Completed => {}
        SearchJobStatus::Queued | SearchJobStatus::Running => {
            return Err(SearchError::JobNotReady(
                "Search job is still running; poll its status until it completes".to_string(),
            ));
        }
        SearchJobStatus::Failed => {
            return Err(SearchError::JobNotReady(format!(
                "Search job failed: {}",
                job.error_message.as_deref().unwrap_or("unknown error")
            )));
        }
        SearchJobStatus::Cancelled => {
            return Err(SearchError::JobNotReady(
                "Search job was cancelled".to_string(),
            ));
        }
    }
    let page = state
        .background_jobs
        .results_page(&job, page.offset.unwrap_or(0), page.limit.unwrap_or(500))
        .await
        .map_err(SearchError::from)?;
    Ok(Json(page))
}

#[cfg(test)]
#[path = "background_jobs_tests.rs"]
mod tests;
