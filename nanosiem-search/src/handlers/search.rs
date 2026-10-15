// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search endpoints: execute, cancel, explain, fetch log, prevalence, field stats.

use axum::{
    extract::{Path, State},
    Json,
};
use nanosiem_core::{
    auth::permissions, search::FieldValueInfo, PrevalenceScatterData, RawSqlRequest, SearchRequest,
    SearchResponse, TimeRangeInput,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::{
    reject_shared_raw_sql, require_current_shared_authority, require_search_execute,
    require_shared_npl_base_search_contract, require_shared_npl_contract,
    require_shared_npl_contract_for_view,
    require_shared_prevalence_component, SearchResultResponse,
};
use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

fn deferred_tree_marker(request: &SearchRequest) -> Result<Option<SearchResponse>, SearchError> {
    if request.offset.unwrap_or(0) != 0 || request.limit == Some(0) { return Ok(None); }
    let parsed = nanosiem_core::query::parse_query(&request.query).map_err(|_| SearchError::BadRequest("Invalid query".into()))?;
    if !super::tree_page::supports_paged_tree(&parsed) { return Ok(None); }
    let Some(tree) = nanosiem_core::search::query_processing::extract_tree_command(&parsed) else { return Ok(None); };
    let mut response = SearchResponse::empty();
    response.results = vec![serde_json::json!({"_display_type": "tree", "_tree_pending": true,
        "_tree_query": request.query, "_tree_time_range": request.time_range, "_tree_run_id": uuid::Uuid::now_v7(),
        "_tree_config": {"parent_field": tree.parent_field, "child_field": tree.child_field, "label_field": tree.label_field,
            "detail_field": tree.detail_field, "prevalence_field": tree.prevalence_field, "root_filter": tree.root_filter},
        "_tree_nodes": []})];
    response.total_count_exact = false;
    response.display_type = Some(nanosiem_core::search::DisplayType::Tree);
    Ok(Some(response))
}

/// Reserve `request_id` for the CREDENTIAL that is starting the query.
///
/// NAN-2100: the reserved identity is
/// [`AuthContext::credential_principal_id`](crate::AuthContext::credential_principal_id)
/// — the api-key id for api-key auth, the user id for an interactive session.
/// `cancel_search` compares the same accessor, so one credential can never
/// cancel another's search merely because they share a human owner. Read it
/// through the accessor rather than `claims.sub`: this service's `claims.sub`
/// happens to already be the key id (NAN-2043), but `nanosiem-api-lib`'s
/// `AuthContext` sets it to the key's OWNER, and this boundary must not depend
/// on which convention a given context uses.
pub(crate) async fn reserve_query_owner(
    state: &SearchState,
    request_id: String,
    auth: &crate::AuthContext,
) -> Result<String, SearchError> {
    let in_use = || SearchError::BadRequest("request_id is already in use".to_string());
    let tenant = auth.tenant_scope;
    let principal_id = auth.credential_principal_id();
    let execution_id = tenant.execution_request_id(&request_id);
    let search = state.search_for_auth(auth)?;
    match state
        .reserve_query_owner_for(tenant, &request_id, principal_id)
        .await
    {
        // NAN-2100: the LOCAL reservation is authoritative on its own in a
        // single-instance deployment (no shared registry) and whenever the
        // shared one is degraded, so its conflict verdict must be honored in
        // both arms — not just Redis's. Reserving over another credential's
        // in-flight id would let that credential cancel this query.
        Ok(true) => {
            if search
                .query_tracker()
                .reserve_request(execution_id.clone(), principal_id)
            {
                Ok(execution_id)
            } else {
                Err(in_use())
            }
        }
        Ok(false) => Err(in_use()),
        Err(error) => {
            tracing::warn!(%error, %request_id, "Shared query ownership unavailable; using local ownership");
            if search
                .query_tracker()
                .reserve_request(execution_id.clone(), principal_id)
            {
                Ok(execution_id)
            } else {
                Err(in_use())
            }
        }
    }
}

/// Compose the caller's EFFECTIVE source-scope deny-set (NAN-1799).
///
/// The per-user `denied_sources` resolved by the middleware (fail-closed —
/// a resolver outage 503s the request before it reaches any handler) is
/// unioned with the `audit` source unless the caller holds `audit:view`.
/// An empty result is the unrestricted scope, which generates byte-identical
/// SQL to the pre-scoping behavior for audit-view admins.
///
/// This REPLACES the old handler-level `enforce_non_audit_query` rewrite of
/// the nPL text: the `SearchService` now injects the exclusion from the
/// `ScopeSet` itself on every nPL path, so handlers pass the composed scope
/// instead of pre-mangling `request.query`. The same composed scope MUST be
/// folded into every cache key (see `cache.rs`) — the scope changes the
/// executed SQL, so it is part of result identity.
///
/// NAN-2219: delegates to `nanosiem_core::auth::compose_viewer_scope`, the ONE
/// definition, shared with `nanosiem-api`'s
/// `AuthContext::effective_viewer_scope` so the two request surfaces cannot
/// drift. The returned scope carries BOTH halves: `deny_set()` (live rows,
/// audit gate included — byte-identical to the previous inline composition) and
/// `artifact_deny_set()` (per-source RBAC only), which is what the prevalence
/// provenance gates behind `| prevalence` read.
pub(crate) fn effective_scope(auth: &crate::AuthContext) -> nanosiem_core::auth::ScopeSet {
    nanosiem_core::auth::compose_viewer_scope(
        &auth.denied_sources,
        auth.claims.has_permission(permissions::AUDIT_VIEW),
    )
}

/// Execute a piped query
///
/// POST /api/search
///
/// If async_mode=true, returns a job_id immediately for polling.
/// Otherwise, executes synchronously and returns results.
/// NAN-3071: the interactive lane ran out of budget on a query the durable
/// lane still refuses. Since NAN-3078 prevalence, lookup, inputlookup and
/// identity stages run as durable post-processed jobs; what remains refused is
/// `| ai`, a source-replacing inputlookup, and a candidate page over the
/// 50,000-row post-processing envelope. Keep the real failure and say how to
/// make the query fit.
fn unescalatable_exhaustion(kind: &str) -> SearchError {
    let cause = SearchError::ResourceExhausted(kind.to_string()).public_message();
    SearchError::ResourceExhausted(format!(
        "{cause}. The query has a Nano-side stage that cannot move to a background job (`| ai`, a source-replacing inputlookup, or more than 50,000 rows to post-process). Aggregate before that stage (for example `| stats ... by <field>` before `| ai`), narrow the time range, or lower the result limit."
    ))
}

/// NAN-3883: the id of a queued or running durable job of this caller that is
/// computing exactly `request` and that the caller may still read, after the
/// caller's current authority is re-checked. `None` when there is none.
async fn attachable_in_flight_job(
    state: &SearchState,
    auth: &crate::AuthContext,
    search_service: &nanosiem_core::SearchService,
    request: &SearchRequest,
    user_id: uuid::Uuid,
    scope: &nanosiem_core::auth::ScopeSet,
    durable_authority: Option<&nanosiem_core::search::DurableSearchJobAuthority>,
) -> Result<Option<String>, SearchError> {
    let Some(job) = search_service.in_flight_durable_job_for_attach(request, user_id, scope, durable_authority).await else {
        return Ok(None);
    };
    let visible = job.result_visible_under(scope.deny_set())
        && super::search_jobs::require_job_retention_visible(auth, &job).is_ok()
        && super::search_jobs::require_job_task_read_authority(auth, &job).is_ok();
    if !visible {
        return Ok(None);
    }
    require_current_shared_authority(state, auth).await?;
    Ok(Some(job.id))
}

/// Request header by which a client states whether it follows an
/// asynchronous answer (an `AsyncSearchResponse` whose job it polls).
///
/// NAN-3474: the interactive wall cap applies to every caller unless it sends
/// `0`. A caller without the header already had to accept a job id: a query
/// that exhausts the lake's scan/memory budget is escalated for everyone. A
/// cold 7d search ran ~57 s into the cell's 55 s statement deadline before
/// that escalation, so atomic callers (k6, scripts, the API) got the edge's
/// 502 at 60 s instead of the job id. `0` keeps the strictly synchronous
/// contract (run to completion, however long) for in-cluster callers that
/// have no proxy in front of them, and for the web's atomic `search()` whose
/// callers render rows only. Deliberately separate from
/// `x-nano-progressive-views`, which also changes the response shape of
/// Lateral and tree queries.
const ASYNC_CAPABLE_HEADER: &str = "x-nano-accept-async";

/// NAN-3229: how long an interactive `/api/search` may hold its HTTP request
/// before it is moved to a durable job (NAN-3474: measured from the start of
/// the request, for every caller that did not opt out with
/// `x-nano-accept-async: 0`).
///
/// A lean-cell query may take up to 130 s (`DEFAULT_LAKE_CELL_TIMEOUT_SECS`),
/// but every proxy in front of search has a shorter idle limit: Cloudflare
/// answers 524 at 100 s, nginx's default is 60 s, and forward proxies are
/// commonly 60 s. A query that ran 60-130 s therefore reached the browser as
/// a 502/504 while search was still working on it (NAN-3229: nginx 504 and a
/// forward proxy's 502, both at 60 s; the web client itself aborts at 60 s).
/// 45 s keeps a 15 s margin under all of them, so a slow query comes back as
/// a job id the UI already polls. The admission
/// estimate still escalates resource-bound queries immediately; this is the
/// wall-clock backstop for a query the estimate admitted that is simply slow.
const INTERACTIVE_ESCALATION_DEADLINE_SECS: u64 = 45;

/// Operator override for [`INTERACTIVE_ESCALATION_DEADLINE_SECS`]; `0`
/// disables deadline escalation.
const INTERACTIVE_ESCALATION_DEADLINE_ENV: &str = "NANO_SEARCH_INTERACTIVE_ESCALATE_AFTER_SECS";

fn parse_escalation_deadline(raw: Option<&str>) -> Option<std::time::Duration> {
    let secs = match raw.map(str::trim) {
        None | Some("") => INTERACTIVE_ESCALATION_DEADLINE_SECS,
        Some(value) => match value.parse::<u64>() {
            Ok(secs) => secs,
            Err(_) => {
                tracing::warn!(value, "{INTERACTIVE_ESCALATION_DEADLINE_ENV} is not an integer; using the default");
                INTERACTIVE_ESCALATION_DEADLINE_SECS
            }
        },
    };
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

fn configured_escalation_deadline() -> Option<std::time::Duration> {
    static DEADLINE: std::sync::OnceLock<Option<std::time::Duration>> = std::sync::OnceLock::new();
    *DEADLINE.get_or_init(|| {
        parse_escalation_deadline(std::env::var(INTERACTIVE_ESCALATION_DEADLINE_ENV).ok().as_deref())
    })
}

/// The deadline for this request, or `None` when it must run to completion
/// in the request: a client that opted out (`x-nano-accept-async: 0`) cannot
/// follow a job id, and a debug run's evidence must describe the execution.
fn interactive_escalation_deadline(
    headers: &axum::http::HeaderMap,
    debug: bool,
) -> Option<std::time::Duration> {
    if debug || opted_out_of_async(headers) {
        return None;
    }
    configured_escalation_deadline()
}

/// NAN-3474: only an explicit `0` opts out; absent or any other value means
/// the caller takes a job id rather than an edge 502.
fn opted_out_of_async(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(ASYNC_CAPABLE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "0")
}

/// NAN-3474: the part of `deadline` left after `elapsed` of request setup
/// (auth, scope, cache lookup), so the cap is measured from when the proxy
/// started waiting, never restarted at execution.
fn remaining_deadline(deadline: std::time::Duration, elapsed: std::time::Duration) -> std::time::Duration {
    deadline.saturating_sub(elapsed)
}

/// NAN-3229: the user-actionable refusal for a timeline past the deadline.
fn histogram_deadline_error(deadline: std::time::Duration) -> SearchError {
    SearchError::QueryError(format!(
        "The timeline did not finish within {} s; narrow the time range to see it",
        deadline.as_secs()
    ))
}

enum DeadlineOutcome<T> {
    Finished(T),
    Escalated(String),
}

/// Run `execution`; if it has not finished by `deadline`, ask `escalate` to
/// queue the same search as a durable job. `Ok(Some(job_id))` abandons the
/// interactive execution (dropping it cancels its lake read, exactly as a
/// client disconnect does); `Ok(None)` means the durable lane cannot take this
/// query, so the interactive execution (paused, not restarted) is awaited to
/// its own end.
async fn finish_or_escalate<T, Exec, Escalate, EscalateFut>(
    execution: Exec,
    deadline: std::time::Duration,
    escalate: Escalate,
) -> Result<DeadlineOutcome<T>, SearchError>
where
    Exec: std::future::Future<Output = T>,
    Escalate: FnOnce() -> EscalateFut,
    EscalateFut: std::future::Future<Output = Result<Option<String>, SearchError>>,
{
    tokio::pin!(execution);
    match tokio::time::timeout(deadline, &mut execution).await {
        Ok(result) => Ok(DeadlineOutcome::Finished(result)),
        Err(_) => match escalate().await? {
            Some(job_id) => Ok(DeadlineOutcome::Escalated(job_id)),
            None => Ok(DeadlineOutcome::Finished(execution.await)),
        },
    }
}

#[utoipa::path(
    post,
    path = "/api/search",
    tag = "search",
    request_body = SearchRequest,
    params(
        ("x-nano-progressive-views" = Option<String>, Header, description = "1 returns a lean Lateral or native-tree dispatcher; use /api/search/stream for Lateral and /api/search/tree-page for tree roots/children"),
        ("x-nano-accept-async" = Option<String>, Header, description = "A search still running 45 s after the request arrived (NANO_SEARCH_INTERACTIVE_ESCALATE_AFTER_SECS) is moved to a durable job (body {job_id, status}, header x-nano-query-escalated: deadline), so it never outlives the 60 s edge. 0 opts out: the request runs to completion (a resource-bound query can still answer with a job id). Unless 0, a `use_cache: true` search of a settled absolute window (ending at least 5 min ago) that the caller already ran as a durable job, with the same deny set, authority and unchanged data, answers {job_id, status: completed} with x-nano-cache: hit and x-nano-cache-age; its rows are read through the job result pages."), // NAN-3809
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Search results (sync or async job id)", body = SearchResultResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 422, description = "Too large to run interactively (COLD_SCAN_TOO_LARGE): one pass would stage more uncached data than the tenant reader's cold-read ceiling (derived from its cache size). Body carries needed_bytes and ceiling_bytes, plus background_ceiling_bytes when an async search could run it. A cold read under the ceiling is never refused: it queues for the reader's heavy cold-read slot and the stream reports progress events with phase cold_scan.", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Admission denied; ADMISSION_BACKEND_UNAVAILABLE includes Retry-After: 2 and a retryable dependency marker", body = ErrorResponse),
        (status = 409, description = "Query was cancelled (request_id was killed via DELETE /api/search/{request_id} or an admin cancel)", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 503, description = "Search authority temporarily unavailable; retry after two seconds", body = ErrorResponse),
    )
)]
pub async fn search(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    request_headers: axum::http::HeaderMap,
    Json(mut request): Json<SearchRequest>,
) -> Result<(axum::http::HeaderMap, Json<SearchResultResponse>), SearchError> {
    use crate::cache::cache_status_headers;
    use nanosiem_core::search::QueryPriority;
    // NAN-3008: total server wall time, reported as `server_wall_ms`.
    let handler_started = Instant::now();
    // NAN-3077: opt-in per-phase evidence. A debug run is always a real run
    // (never a result-cache read), so its evidence describes the execution.
    let debug = wants_search_debug(&request_headers, &auth);
    let progressive_views = request_headers.get("x-nano-progressive-views").is_some_and(|value| value == "1")
        && nanosiem_core::query::parse_query(&request.query).ok().is_some_and(|query|
            nanosiem_core::search::query_processing::extract_lateral_command(&query).is_some()
            && nanosiem_core::search::query_processing::extract_post_lateral_commands(&query).is_empty()
            || matches!(query, nanosiem_core::query::Query::Piped { command: nanosiem_core::query::Command::Tree { .. }, .. }));
    let bypass = bypass || debug || progressive_views;

    // NAN-2028: gate on search:execute (matching every sibling handler) before
    // any work — an under-scoped API key must not run piped searches.
    require_search_execute(&auth)?;

    // NAN-1799: compose the effective deny-set (per-user source scope ∪ audit
    // gate) ONCE, before the cache lookup — the scope is folded into the cache
    // key, and the service injects the exclusion into the executed SQL. This
    // replaces the old H1 `enforce_non_audit_query` rewrite of request.query.
    let scope = effective_scope(&auth);
    // Resolving the tenant view touches no data. The shared nPL contract is
    // checked against it so `| ai` is admitted only on a tenant-billed view.
    let search_service = state.search_with_ai_for_auth(&auth)?;
    // NAN-3018: a shared `dataset=risk` request binds its tenant's own decay /
    // clear state onto a request-local view (lean-lake cell tenants only).
    let search_service = state
        .bind_shared_risk_dataset(&auth, request.dataset.as_deref(), search_service)
        .await?;
    // A shared risk result depends on the tenant's live clear state, so a
    // cached copy would hide an analyst's clear. Such results are never read
    // from or written to the result cache.
    let risk_uncached = search_service.tenant_risk_dataset_bound();
    let bypass = bypass || risk_uncached;
    require_shared_npl_contract_for_view(
        &auth,
        &request.query,
        request.dataset.as_deref(),
        &search_service,
    )?;

    // NAN-3883: `DELETE /api/search/{request_id}` stops this request at any
    // point, including one that arrived before it (a superseded UI run): that
    // request is refused before it reserves its id.
    let mut cancel_signal = match request.request_id.as_deref() {
        Some(request_id) => Some(
            search_service
                .query_tracker()
                .cancel_signal(&auth.tenant_scope.execution_request_id(request_id), auth.credential_principal_id())
                .ok_or(SearchError::Cancelled)?,
        ),
        None => None,
    };
    if let Some(request_id) = request.request_id.clone() {
        // NAN-2100: reserve under the CREDENTIAL (see `reserve_query_owner`).
        request.request_id = Some(reserve_query_owner(&state, request_id, &auth).await?);
    }

    let user_id = auth.claims.sub;
    let durable_authority = auth.durable_search_authority();
    let priority = match request.priority.as_deref() {
        Some("analytics") => QueryPriority::Analytics,
        _ => QueryPriority::Interactive,
    };

    // Check for async mode — returns a job_id immediately for polling.
    if request.async_mode {
        require_current_shared_authority(&state, &auth).await?;
        let job_id = search_service
            .search_async_with_admission(
                request,
                user_id,
                priority,
                &scope,
                durable_authority.as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to start async search");
                SearchError::from(e)
            })?;

        if let Err(error) = require_current_shared_authority(&state, &auth).await {
            // The runner revalidates this immutable stamp independently.
            // An outage after submission is not evidence of revocation.
            if !matches!(error, SearchError::SearchAuthorityUnavailable) {
                if let Err(cancel_error) = search_service.cancel_job(&job_id).await {
                    tracing::warn!(
                        job_id = %job_id,
                        error = %cancel_error,
                        "failed to cancel async search after authority revocation"
                    );
                }
            }
            return Err(error);
        }

        return Ok((
            cache_status_headers(false, None),
            Json(SearchResultResponse::Async(
                nanosiem_core::search::AsyncSearchResponse {
                    job_id,
                    status: "queued".to_string(),
                },
            )),
        ));
    }

    // The native tree preview and exact job pages own the expensive work.
    // Atomic clients and deployments without a hosted job lane retain the existing tree path.
    if progressive_views && search_service.has_durable_view_lane() && request.dataset.as_deref().unwrap_or("logs") == "logs" {
        if let Some(mut response) = deferred_tree_marker(&request)? {
            require_current_shared_authority(&state, &auth).await?;
            response.server_wall_ms = Some(handler_started.elapsed().as_millis() as u64);
            return Ok((cache_status_headers(false, None), Json(SearchResultResponse::Sync(super::SearchPageResponse::new(response, &request)))));
        }
    }

    // Check search result cache (Dragonfly/Redis). NAN-1595: skip on refresh
    // bypass; stamp x-nano-cache hit/age so the UI can show the cached notice.
    // NAN-1799: the effective deny-set is folded into the cache key (computed
    // above, BEFORE this lookup) so differently-scoped users never share an
    // entry.
    // NAN-2361 wave 6: a shared tenant's cache identity carries the serving
    // generation (erasure / retention swaps invalidate at once); dedicated
    // deployments have none. Resolved once per request, before the lookup.
    let serving_generation = if crate::is_shared_scope(auth.tenant_scope) && state.result_cache.is_some() {
        search_service.serving_generation_key().await
    } else {
        None
    };
    if !bypass {
        if let Some(ref cache) = state.result_cache {
            if let Some(mut cached) = cache
                .get_for(auth.tenant_scope, &request, &scope, serving_generation.as_ref())
                .await
            {
                let age = cache
                    .age_secs(&crate::cache::SearchResultCache::cache_key_for(
                        auth.tenant_scope,
                        &request,
                        &scope,
                        serving_generation.as_ref(),
                    ))
                    .await;
                require_current_shared_authority(&state, &auth).await?;
                record_search_query("piped_cached", 0.0, true);
                cached.server_wall_ms = Some(handler_started.elapsed().as_millis() as u64);
                return Ok((
                    cache_status_headers(true, age),
                    Json(SearchResultResponse::Sync(super::SearchPageResponse::new(cached, &request))),
                ));
            }
        }
    }

    // NAN-3809: an identical settled search this caller already ran as a
    // durable job is re-served through that job's result pages (the client
    // follows the job id exactly as after a deadline escalation). Only a
    // cache-reading load (a pasted or shared URL; a user run and the refresh
    // badge send `use_cache: false`) of a caller that accepts a job id.
    if !bypass && request.use_cache && !opted_out_of_async(&request_headers) {
        if let Some(job) = search_service
            .settled_durable_job_for_reuse(&request, user_id, &scope, durable_authority.as_ref())
            .await
        {
            let visible = job.result_visible_under(scope.deny_set())
                && super::search_jobs::require_job_retention_visible(&auth, &job).is_ok()
                && super::search_jobs::require_job_task_read_authority(&auth, &job).is_ok();
            if visible {
                // Every hit re-checks the caller's CURRENT authority.
                require_current_shared_authority(&state, &auth).await?;
                record_search_query("piped_settled_job", 0.0, true);
                let age = job
                    .completed_at
                    .map(|at| (chrono::Utc::now() - at).num_seconds().max(0) as u64);
                return Ok((
                    cache_status_headers(true, age),
                    Json(SearchResultResponse::Async(
                        nanosiem_core::search::AsyncSearchResponse {
                            job_id: job.id,
                            status: "completed".to_string(),
                        },
                    )),
                ));
            }
        }
    }

    // NAN-3883: the same search is already running as this caller's durable
    // job (a reload, a reopened tab or history entry, or a re-click of an
    // absolute range while it escalated): follow that job instead of starting
    // the same long scan a second time.
    if !bypass && !opted_out_of_async(&request_headers) {
        if let Some(job_id) = attachable_in_flight_job(&state, &auth, &search_service, &request, user_id, &scope, durable_authority.as_ref()).await? {
            record_search_query("piped_attached_job", 0.0, true);
            return Ok((
                cache_status_headers(false, None),
                Json(SearchResultResponse::Async(nanosiem_core::search::AsyncSearchResponse {
                    job_id,
                    status: "running".to_string(),
                })),
            ));
        }
    }

    // Synchronous execution (cache miss). NAN-701: sync path now also goes
    // through the admission controller — previously it bypassed the
    // per-user limit / queue / timeout entirely, so dashboard panel
    // refreshes overshot `max_concurrent_queries_for_user`.
    let start = Instant::now();
    let execution = nanosiem_core::search::streaming::DEFER_LATERAL_VIEW.scope(progressive_views,
        search_service.search_with_admission(request.clone(), user_id, priority, &scope));
    // NAN-3883: a cancel drops the execution (and with it the lake read).
    let execution = async {
        match cancel_signal.as_mut() {
            Some(signal) => tokio::select! {
                result = execution => result,
                () = signal.cancelled() => Err(nanosiem_core::SearchError::Cancelled),
            },
            None => execution.await,
        }
    };
    let (result, debug_evidence) = if debug {
        let (result, evidence) = nanosiem_core::search::lake_debug::collect(execution).await;
        (result, Some(evidence))
    } else if let Some(cap) = interactive_escalation_deadline(&request_headers, debug) {
        let deadline = remaining_deadline(cap, handler_started.elapsed());
        // NAN-3229: never hold a browser's request past the proxies in front
        // of search; a slow query becomes the job the UI already polls.
        let escalate = || async {
            match require_current_shared_authority(&state, &auth).await {
                Ok(()) => {}
                // A dependency blip must not end a query that is still running.
                Err(SearchError::SearchAuthorityUnavailable) => return Ok(None),
                Err(error) => return Err(error),
            }
            // NAN-3883: an identical request (a double-fired run) that
            // escalated first already owns the durable job; share it.
            if let Some(job_id) = attachable_in_flight_job(&state, &auth, &search_service, &request, user_id, &scope, durable_authority.as_ref()).await? {
                return Ok(Some(job_id));
            }
            let job_id = match search_service
                .search_async_with_task(
                    request.clone(),
                    user_id,
                    priority,
                    &scope,
                    durable_authority.as_ref(),
                    nanosiem_core::search::DurableLakeTask::SearchNplV1,
                )
                .await
            {
                Ok(job_id) => job_id,
                Err(error) => {
                    tracing::info!(error = %error, deadline_secs = cap.as_secs(),
                        "slow interactive query cannot move to a durable job; keeping the interactive request");
                    return Ok(None);
                }
            };
            if let Err(error) = require_current_shared_authority(&state, &auth).await {
                // The runner revalidates this immutable stamp independently.
                // An outage after submission is not evidence of revocation.
                if !matches!(error, SearchError::SearchAuthorityUnavailable) {
                    if let Err(cancel_error) = search_service.cancel_job(&job_id).await {
                        tracing::warn!(job_id = %job_id, error = %cancel_error,
                            "failed to cancel deadline-escalated search after authority revocation");
                    }
                }
                return Err(error);
            }
            Ok(Some(job_id))
        };
        match finish_or_escalate(execution, deadline, escalate).await? {
            DeadlineOutcome::Finished(result) => (result, None),
            DeadlineOutcome::Escalated(job_id) => {
                let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
                tracing::info!(job_id = %job_id, duration_ms, deadline_secs = cap.as_secs(),
                    "escalated slow interactive query to a durable job at the request deadline");
                record_search_query("piped_escalated", duration_ms, true);
                let mut headers = cache_status_headers(false, None);
                headers.insert(
                    "x-nano-query-escalated",
                    axum::http::HeaderValue::from_static("deadline"),
                );
                return Ok((
                    headers,
                    Json(SearchResultResponse::Async(
                        nanosiem_core::search::AsyncSearchResponse {
                            job_id,
                            status: "queued".to_string(),
                        },
                    )),
                ));
            }
        }
    } else {
        (execution.await, None)
    };
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    if let Err(nanosiem_core::SearchError::ResourceExhausted(kind)) = &result {
        // Revalidate before stamping durable work after a long interactive
        // attempt. A dependency outage must not create then cancel a job.
        require_current_shared_authority(&state, &auth).await?;
        let job_id = search_service
            .search_async_with_task(
                request.clone(),
                user_id,
                priority,
                &scope,
                durable_authority.as_ref(),
                nanosiem_core::search::DurableLakeTask::shed_from_resource_error(kind),
            )
            .await;
        let job_id = match job_id {
            Ok(job_id) => job_id,
            // No durable lane for this tenant (e.g. a lean tenant without its
            // job runner yet): answer with the budget refusal itself, not an
            // opaque dependency outage.
            Err(nanosiem_core::SearchError::ServiceUnavailable(detail)) => {
                tracing::warn!(error = %detail, exhausted_budget = %kind,
                    "resource-bound query has no durable lane; returning the budget refusal");
                return Err(SearchError::ResourceExhausted(kind.clone()));
            }
            // NAN-3071: the durable lane still refuses `| ai`, a
            // source-replacing inputlookup and oversized post-processing pages
            // (NAN-3078 runs every other Nano-side stage durably). Answer with
            // the interactive lane's real failure and how to fix the query,
            // not the refusal text.
            Err(error) if nanosiem_core::search::service::is_durable_lane_post_processing_refusal(&error) => {
                tracing::info!(exhausted_budget = %kind,
                    "resource-bound query has Nano-side stages the durable lane cannot run; returning the budget refusal");
                return Err(unescalatable_exhaustion(kind));
            }
            Err(error) => {
                tracing::error!(error = %error, "failed to escalate resource-bound query");
                return Err(SearchError::from(error));
            }
        };
        if let Err(error) = require_current_shared_authority(&state, &auth).await {
            // The runner revalidates this immutable stamp independently.
            // An outage after submission is not evidence of revocation.
            if !matches!(error, SearchError::SearchAuthorityUnavailable) {
                if let Err(cancel_error) = search_service.cancel_job(&job_id).await {
                    tracing::warn!(
                        job_id = %job_id,
                        error = %cancel_error,
                        "failed to cancel escalated search after authority revocation"
                    );
                }
            }
            return Err(error);
        }
        tracing::info!(
            job_id = %job_id,
            exhausted_budget = %kind,
            duration_ms,
            "automatically escalated interactive query to durable lake job"
        );
        record_search_query("piped_escalated", duration_ms, true);
        let mut headers = cache_status_headers(false, None);
        headers.insert(
            "x-nano-query-escalated",
            axum::http::HeaderValue::from_static("durable-job"),
        );
        return Ok((
            headers,
            Json(SearchResultResponse::Async(
                nanosiem_core::search::AsyncSearchResponse {
                    job_id,
                    status: "queued".to_string(),
                },
            )),
        ));
    }

    record_search_query("piped", duration_ms, result.is_ok());

    if result.is_ok() {
        require_current_shared_authority(&state, &auth).await?;
    }

    // Cache successful results in the background, keyed under the scope the
    // query executed with. NAN-3406: never a run under per-request perf
    // overrides (the key is computed inside the spawned write, outside this
    // request's override scope, so it would land under the ordinary key).
    let perf_overrides = nanosiem_core::search::lake_debug::perf_overrides().is_some();
    if let (Ok(response), false) = (&result, risk_uncached || progressive_views || perf_overrides) {
        if let Some(ref cache) = state.result_cache {
            let cache = cache.clone();
            let req = request.clone();
            let scope_for_cache = scope.clone();
            let resp = response.clone();
            let tenant = auth.tenant_scope;
            let generation = serving_generation.clone();
            tokio::spawn(async move {
                cache
                    .set_for(tenant, &req, &resp, &scope_for_cache, generation.as_ref())
                    .await;
            });
        }
    }

    let mut response = result?;
    response.server_wall_ms = Some(handler_started.elapsed().as_millis() as u64);
    let headers = cache_status_headers(nanosiem_core::request_timing::lake_result_cache_hit(), None);
    if let Some(mut evidence) = debug_evidence {
        evidence["service_ms"] = serde_json::json!(duration_ms);
        evidence["handler_ms"] = serde_json::json!(handler_started.elapsed().as_secs_f64() * 1000.0);
        return Ok((
            headers,
            Json(SearchResultResponse::SyncWithDebug(super::SearchResponseWithDebug {
                response: super::SearchPageResponse::new(response, &request),
                debug: evidence,
            })),
        ));
    }
    Ok((headers, Json(SearchResultResponse::Sync(super::SearchPageResponse::new(response, &request)))))
}

/// Header that asks `/api/search` for per-phase lake evidence (NAN-3077).
pub(crate) const SEARCH_DEBUG_HEADER: &str = "x-nano-search-debug";

/// Response header carrying the route-wide evidence (every search route).
pub(crate) const SEARCH_DEBUG_EVIDENCE_HEADER: &str = "x-nano-search-debug-evidence";

/// NAN-3077: route-wide opt-in evidence. For a caller allowed debug evidence
/// (see [`wants_search_debug`]) every lake call a request makes (asset
/// dossier/events/artifacts, event detail, identity, field values, ...) is
/// recorded and returned, compact, in [`SEARCH_DEBUG_EVIDENCE_HEADER`]
/// (`/api/search` also keeps its body `debug` document). Runs after auth.
///
/// NAN-3406: the same request may carry
/// [`nanosiem_core::search::lake_debug::PERF_OVERRIDES_HEADER`] (per-request
/// A/B values of query[T]'s speed switches). It is honoured only here, for a
/// caller [`wants_search_debug`] already admits; anyone else's is ignored
/// silently (it is never read, and lake calls are built from scratch, so it
/// is never forwarded). An honoured override also bypasses this service's
/// result caches, so a cached answer of one mode never stands in for the
/// other.
pub(crate) async fn lake_debug_middleware(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let wants = request
        .extensions()
        .get::<crate::AuthContext>()
        .is_some_and(|auth| wants_search_debug(request.headers(), auth));
    if !wants {
        return next.run(request).await;
    }
    let perf_overrides = authorized_perf_overrides(request.headers());
    if perf_overrides.is_some() {
        request.headers_mut().insert(
            axum::http::HeaderName::from_static(crate::cache::HEADER_CACHE_BYPASS),
            axum::http::HeaderValue::from_static("1"),
        );
    }
    let started = Instant::now();
    let (mut response, mut evidence) =
        nanosiem_core::search::lake_debug::collect_with_perf_overrides(perf_overrides, next.run(request)).await;
    evidence["handler_ms"] = serde_json::json!(started.elapsed().as_secs_f64() * 1000.0);
    let text = nanosiem_core::search::lake_debug::header_value(evidence, 16 * 1024);
    if let Ok(value) = axum::http::HeaderValue::from_str(&text) {
        response
            .headers_mut()
            .insert(axum::http::HeaderName::from_static(SEARCH_DEBUG_EVIDENCE_HEADER), value);
    }
    response
}

/// NAN-3406: the canonical per-request switch overrides of a request whose
/// caller [`wants_search_debug`] already admitted (call it only then).
fn authorized_perf_overrides(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(nanosiem_core::search::lake_debug::PERF_OVERRIDES_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(nanosiem_core::search::lake_debug::canonical_perf_overrides)
}

/// Debug evidence is returned only when asked for AND the caller may already
/// see generated SQL (`search:sql`): the evidence is counts and timings, but
/// it describes the tenant's storage layout, so it stays with the privileged
/// role. Anyone else gets the ordinary response, never an error.
pub(crate) fn wants_search_debug(headers: &axum::http::HeaderMap, auth: &crate::AuthContext) -> bool {
    headers
        .get(SEARCH_DEBUG_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "1")
        && auth.claims.has_permission(permissions::SEARCH_SQL)
}

/// Response for cancel_search endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CancelSearchResponse {
    /// Whether a query was actually cancelled
    pub cancelled: bool,
}

/// Cancel a running search query
///
/// Cancels a running query by its client-provided request_id.
/// Returns cancelled=true if a query was found and killed, cancelled=false if no matching query was running.
#[utoipa::path(
    delete,
    path = "/api/search/{request_id}",
    tag = "search",
    params(
        ("request_id" = String, Path, description = "Client-provided request ID of the running query")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Cancellation result", body = CancelSearchResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn cancel_search(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Path(request_id): Path<String>,
) -> Result<Json<CancelSearchResponse>, SearchError> {
    // NAN-2100: cancellation is a destructive search-plane operation — it issues
    // ClickHouse `KILL QUERY` against the data/count/histogram/field-stats ids
    // and fans out across replicas. It must take the SAME capability gate as
    // every other search route, BEFORE any registry lookup or engine call, so
    // revoking `search:execute` also revokes the ability to terminate searches.
    require_search_execute(&auth)?;

    tracing::info!("Received cancel request for request_id: {}", request_id);
    let search_service = state.search_for_auth(&auth)?;

    let can_admin_cancel = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    if !can_admin_cancel {
        // NAN-2100: compare the CREDENTIAL that started the query, resolved
        // through the named accessor rather than raw `claims.sub` (see
        // `AuthContext::credential_principal_id`). One human's separate api keys
        // are separate principals: a zero-permission key must not be able to
        // kill work started by a more privileged key of the same owner.
        // Interactive sessions of one human deliberately remain a SINGLE
        // principal — the authorization subject is the user, and per-session
        // isolation is not part of this boundary.
        let principal = auth.credential_principal_id();
        let execution_id = auth.tenant_scope.execution_request_id(&request_id);
        let local_owner = search_service
            .query_tracker()
            .get(&execution_id)
            .and_then(|info| info.owner_principal_id);
        let owner = if local_owner.is_some() {
            local_owner
        } else {
            match state
                .shared_query_owner_for(auth.tenant_scope, &request_id)
                .await
            {
                Ok(owner) => owner,
                // Fail closed: an unavailable ownership registry is not
                // permission to cancel. `None` never matches a principal.
                Err(error) => {
                    tracing::warn!(%error, %request_id, "Shared query ownership unavailable during cancellation");
                    None
                }
            }
        };
        if owner.is_none() {
            // NAN-3883: nobody runs this id yet. The UI cancels a superseded
            // run as it starts the next one, often before that run's POST is
            // admitted; remember the cancel (for this principal only) so the
            // request is refused when it arrives instead of running beside
            // the current search.
            search_service
                .query_tracker()
                .request_cancel(&auth.tenant_scope.execution_request_id(&request_id), principal);
            return Ok(Json(CancelSearchResponse { cancelled: false }));
        }
        if owner != Some(principal) {
            return Ok(Json(CancelSearchResponse { cancelled: false }));
        }
    }

    let execution_id = auth.tenant_scope.execution_request_id(&request_id);
    // Membership and feature authority may have been revoked while the owner
    // lookup above awaited the shared registry. Revalidate at the destructive
    // boundary so a stale request cannot kill work after that revocation.
    require_current_shared_authority(&state, &auth).await?;
    let cancelled = search_service
        .cancel_query(&execution_id)
        .await
        .map_err(|e| {
            // Keep the request-scoped log line: the helper logs the error without
            // the request_id an operator needs to correlate the failed kill.
            tracing::error!(error = %e, request_id = %request_id, "Failed to cancel query");
            // This error is a FAILED cancel (the lake worker was unreachable, so the
            // kill never landed), not "the query was cancelled" — `cancel_query`
            // never yields `Cancelled`, so the deliberate 409/QUERY_CANCELLED
            // contract is untouched. What it does yield is `ServiceUnavailable` from
            // the lake worker transport, and answering 400 there tells the caller
            // their DELETE was malformed instead of "retry".
            crate::error::mask_query_failure(e, "Failed to cancel query")
        })?;

    // NAN-3883: a request still in admission, planning or the cache lookup
    // has no engine query to kill yet; its handler stops on this signal.
    let signalled = search_service
        .query_tracker()
        .request_cancel(&execution_id, auth.credential_principal_id());
    let cancelled = cancelled || signalled;

    if cancelled {
        tracing::info!("Successfully cancelled query: {}", request_id);
    } else {
        tracing::debug!("No running query found for request_id: {}", request_id);
    }

    Ok(Json(CancelSearchResponse { cancelled }))
}

/// Execute a raw SQL query (SELECT only)
#[utoipa::path(
    post,
    path = "/api/search/sql",
    tag = "search",
    request_body = RawSqlRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "SQL search results", body = SearchResponse),
        (status = 400, description = "Invalid SQL or query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Endpoint unavailable for hosted tenants (route_not_available)"),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn search_sql(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<RawSqlRequest>,
) -> Result<Json<SearchResponse>, SearchError> {
    // NAN-173: Gate raw SQL behind dedicated permission
    if !auth.claims.has_permission(permissions::SEARCH_SQL) {
        return Err(SearchError::Forbidden(
            "Raw SQL queries require the search:sql permission".to_string(),
        ));
    }
    reject_shared_raw_sql(&auth)?;

    // NAN-2001: the audit-view gate now lives in ClickHouse. Derive the raw-SQL
    // identity EXPLICITLY from audit:view (fail-closed default `Hidden` →
    // `nanosiem_rawsql_noaudit` + its RESTRICTIVE `source_type!='audit'` row
    // policy). The retired `inject_audit_filter` (and the pre-validation that
    // only guarded it) are gone — no in-app SQL rewriting. Never infer audit
    // visibility from scope (§3.3).
    let audit_access = if auth.claims.has_permission(permissions::AUDIT_VIEW) {
        nanosiem_core::search::RawSqlAuditAccess::Visible
    } else {
        nanosiem_core::search::RawSqlAuditAccess::Hidden
    };

    // NAN-1799 FAIL-CLOSED (unchanged): raw SQL cannot be AST-injected with a
    // per-source exclusion, so the service refuses outright (SqlValidationError)
    // when the caller has ANY restricted source. Pass the SOURCE deny-set only —
    // audit is handled by the RawSqlAuditAccess identity, NOT folded into scope.
    let start = Instant::now();
    let search_service = state.search_for_auth(&auth)?;
    let result = search_service
        .search_sql(request, &auth.denied_sources, audit_access)
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("sql", duration_ms, result.is_ok());

    Ok(Json(result?))
}

/// Request for explaining a query
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ExplainRequest {
    /// The piped query string to explain
    pub query: String,
    /// Time range for the query
    pub time_range: TimeRangeInput,
    /// Show SQL with table_view field pruning (matches actual search behavior)
    #[serde(default)]
    pub table_view: bool,
    /// Per-query dataset (`logs`/`spans`/`metrics`/`risk`) so the explained SQL
    /// matches the executed source — without it, Inspect SQL shows `FROM logs`
    /// for a spans/metrics/risk query.
    #[serde(default)]
    pub dataset: Option<String>,
}

/// Response for explain endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ExplainResponse {
    /// The generated SQL query
    pub sql: String,
    /// Whether table_view field pruning was applied
    pub table_view: bool,
}

/// Explain a piped query (show generated SQL without executing)
#[utoipa::path(
    post,
    path = "/api/search/explain",
    tag = "search",
    request_body = ExplainRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Generated SQL for the query", body = ExplainResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn explain(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>, SearchError> {
    // NAN-2028: explain() returns the generated ClickHouse SQL, so it takes the
    // same search:execute gate as search().
    require_search_execute(&auth)?;
    require_shared_npl_contract(&auth, &request.query, request.dataset.as_deref())?;
    // NAN-1799: pass the composed scope so "Inspect SQL" renders the exact
    // gated SQL the executed path runs for this caller.
    let scope = effective_scope(&auth);
    let search_service = state.search_for_auth(&auth)?;
    let start = Instant::now();
    let result = search_service
        .explain(
            &request.query,
            &request.time_range,
            request.table_view,
            request.dataset.as_deref(),
            &scope,
        )
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("explain", duration_ms, result.is_ok());

    let sql = result.map_err(|e| {
        tracing::error!(error = %e, "Query explain failed");
        // Surface user-actionable generation guardrails (see the SqlGenError
        // mapping in error.rs); mask internal failures.
        // FieldNotFound is the input-side field-validation rejection (NAN-1354)
        // — /api/search surfaces it verbatim via the From impl in error.rs, so
        // explain must match instead of masking it as "Query processing failed"
        // (NAN-1396). Only the user's own field names are echoed.
        if matches!(e, nanosiem_core::SearchError::FieldNotFound { .. }) {
            return e.into();
        }
        // NAN-2241: a syntax error is the author's own query coming back at
        // them — /api/search surfaces it (structured, with position and
        // suggestions) via the From impl in error.rs, and explain masked it as
        // "Query processing failed", stranding anyone iterating on a `rex`
        // pattern in Inspect SQL with no idea what was wrong. Echoes only the
        // caller's own input.
        if matches!(
            e,
            nanosiem_core::SearchError::ParseError(_)
                | nanosiem_core::SearchError::StructuredParseError { .. }
        ) {
            return e.into();
        }
        if let nanosiem_core::SearchError::SqlGenError(ref msg) = e {
            if msg.starts_with("Invalid query:") || msg.starts_with("Unsupported operation:") {
                return SearchError::QueryError(msg.clone());
            }
        }
        // explain resolves the lake worker client and round-trips it for lake
        // datasets, so ServiceUnavailable is reachable here — masking it as 400
        // would tell someone iterating in Inspect SQL that their query is
        // broken while the backend is simply down.
        crate::error::mask_query_failure(e, "Query processing failed")
    })?;
    require_current_shared_authority(&state, &auth).await?;
    Ok(Json(ExplainResponse {
        sql,
        table_view: request.table_view,
    }))
}

/// Request for fetching a log event by ID
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FetchLogRequest {
    /// The log event ID
    pub id: String,
    /// Time range hint (for partition pruning)
    pub time_range: Option<TimeRangeInput>,
    /// Source type hint. When provided, the query can use the
    /// `(source_type, timestamp, ...)` PK index for a tight range read instead
    /// of scanning every source_type's marks within the time window. Without
    /// this hint, S3-backed historical lookups take 12–60s vs <1s with it.
    pub source_type: Option<String>,
}

/// Response for fetch_log endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FetchLogResponse {
    /// The full log event as JSON
    pub event: Option<serde_json::Value>,
}

/// Fetch a single log event by ID (for row expansion)
///
/// Used when user expands a row in table_view mode to fetch full event data.
/// Much faster than SELECT * for all results since it only fetches one row.
#[utoipa::path(
    post,
    path = "/api/search/log",
    tag = "search",
    request_body = FetchLogRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Full log event data", body = FetchLogResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn fetch_log(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<FetchLogRequest>,
) -> Result<Json<FetchLogResponse>, SearchError> {
    // NAN-2028: fetch-by-id is a search-surface read (returns a full log event),
    // so it takes the same search:execute gate — effective_scope below is a
    // deny-set that defaults OPEN and is not an authz check on its own.
    require_search_execute(&auth)?;
    // NAN-694 / NAN-1799: callers must not retrieve denied rows by direct id —
    // audit (without audit:view) or any source-scope-denied source_type. The
    // composed ScopeSet is applied at the SQL layer to match the rest of the
    // search surface.
    let scope = effective_scope(&auth);
    let search_service = state.search_for_auth(&auth)?;

    let start = Instant::now();
    let result = search_service
        .fetch_log_by_id(
            &request.id,
            request.time_range.as_ref(),
            request.source_type.as_deref(),
            &scope,
        )
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("fetch_log", duration_ms, result.is_ok());

    match result {
        Ok(event) => {
            require_current_shared_authority(&state, &auth).await?;
            Ok(Json(FetchLogResponse { event }))
        }
        Err(e) => Err(crate::error::mask_query_failure(
            e,
            "Failed to fetch log event",
        )),
    }
}

/// Get prevalence artifacts for a search query
///
/// Extracts distinct domains, hashes, and IPs from logs matching the query,
/// then returns their prevalence data for visualization. This runs asynchronously
/// after the main search to avoid slowing down initial results.
#[utoipa::path(
    post,
    path = "/api/search/prevalence-artifacts",
    tag = "search",
    request_body = SearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Prevalence scatter data for matched artifacts", body = PrevalenceScatterData),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn prevalence_artifacts(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<SearchRequest>,
) -> Result<(axum::http::HeaderMap, Json<PrevalenceScatterData>), SearchError> {
    // NAN-2028: runs a query over the log store — same search:execute gate.
    require_search_execute(&auth)?;
    require_shared_prevalence_component(&auth)?;
    require_shared_npl_contract(&auth, &request.query, request.dataset.as_deref())?;
    // NAN-1799: the service injects the composed deny-set into the nPL path
    // itself — no more pre-rewrite of request.query here.
    let scope = effective_scope(&auth);

    // NAN-1593: the prevalence-artifacts scatter fires on every search-page
    // load / shared-link follow, separately from the main search — cache it
    // through the same Dragonfly layer so reloads don't re-extract artifacts
    // and re-run their prevalence lookups. Keyed on the raw `query` plus the
    // time range and dataset, with the caller's effective deny-set folded in
    // by `companion_key` (NAN-1799 — the scope changes the executed SQL, so
    // it is part of result identity); `request_id` is excluded since it's a
    // per-request cancellation handle, not part of result identity.
    let cache_key = crate::cache::SearchResultCache::companion_key_for(
        auth.tenant_scope,
        "prevart",
        &[
            request.query.as_bytes(),
            request
                .time_range
                .start
                .timestamp_micros()
                .to_string()
                .as_bytes(),
            request
                .time_range
                .end
                .timestamp_micros()
                .to_string()
                .as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<PrevalenceScatterData>(&cache_key).await {
                let age = cache.age_secs(&cache_key).await;
                require_current_shared_authority(&state, &auth).await?;
                record_search_query("prevalence_artifacts_cached", 0.0, true);
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let search_service = state.search_for_auth(&auth)?;
    let start = Instant::now();
    let result = search_service
        .get_prevalence_artifacts(&request, &scope)
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("prevalence_artifacts", duration_ms, result.is_ok());

    match &result {
        Ok(_) => tracing::info!("Prevalence artifacts completed in {:.2}ms", duration_ms),
        Err(e) => tracing::error!("Prevalence artifacts failed: {:?}", e),
    }

    let response = result?;
    require_current_shared_authority(&state, &auth).await?;
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((
        crate::cache::cache_status_headers(false, None),
        Json(response),
    ))
}

/// Get field statistics for a search query (async, separate from main search)
///
/// Called in the background after search results load. Returns topK values
/// and cardinality (uniq) for all fields, enabling accurate field panel badges.
#[utoipa::path(
    post,
    path = "/api/search/field-stats",
    tag = "search",
    request_body = FieldStatsRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Field statistics with cardinality", body = FieldStatsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn field_stats_for_query(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(mut request): Json<FieldStatsRequest>,
) -> Result<(axum::http::HeaderMap, Json<FieldStatsResponse>), SearchError> {
    use nanosiem_core::search::QueryPriority;

    // NAN-2028: runs a query over the log store — same search:execute gate.
    require_search_execute(&auth)?;
    // NAN-3093: field stats run only the base search (pipes stripped), so
    // only the base search is held to the shared contract.
    require_shared_npl_base_search_contract(&auth, &request.query, request.dataset.as_deref())?;
    // NAN-1799: the service injects the composed deny-set into the nPL path
    // itself — no more pre-rewrite of the query here.
    let scope = effective_scope(&auth);
    let query = request.query.clone();

    let time_range = TimeRangeInput {
        start: request.start,
        end: request.end,
    };

    // NAN-1593: the field-stats panel fires on every search-page load and
    // shared-link follow, separately from the main search — cache it through
    // the same Dragonfly layer so reloads don't re-run the aggregation. Keyed
    // on the raw `query` plus the time range / column subset / dataset, with
    // the caller's effective deny-set folded in by `companion_key` (NAN-1799);
    // `request_id` is excluded since it's a per-request cancellation handle,
    // not part of result identity.
    let cache_key = crate::cache::SearchResultCache::companion_key_for(
        auth.tenant_scope,
        // NAN-3216: the lake used to cache an EMPTY answer for every `columns`
        // request without the (now retired) `sample_columns` opt-in. A new
        // prefix keeps those stale empties from being served after the roll.
        "fstats-v2",
        &[
            query.as_bytes(),
            request.start.timestamp_micros().to_string().as_bytes(),
            request.end.timestamp_micros().to_string().as_bytes(),
            // JSON-encode (not join) so a comma in a column name can't shift the
            // boundary — ["a,b"] must not collide with ["a","b"] (NAN-1593 review).
            serde_json::to_string(&request.columns)
                .unwrap_or_default()
                .as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<FieldStatsResponse>(&cache_key).await {
                let age = cache.age_secs(&cache_key).await;
                require_current_shared_authority(&state, &auth).await?;
                record_search_query("field_stats_cached", 0.0, true);
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    // NAN-1428: reserve ownership of the request_id so the cancel endpoint
    // can authorize killing the derived `{request_id}-fstats` query even
    // after the main search has completed and unregistered the id.
    if let Some(rid) = request.request_id.clone() {
        // NAN-2100: reserve under the CREDENTIAL (see `reserve_query_owner`).
        request.request_id = Some(reserve_query_owner(&state, rid, &auth).await?);
    }

    // NAN-1427: admission-gated, with the derived companion query_id and
    // per-priority CH settings. `columns` (when sent by the UI) reduces the
    // stat'd column set to what the field panel actually renders.
    let search_service = state.search_for_auth(&auth)?;
    let stats = search_service
        .get_field_stats_with_admission(
            &query,
            &time_range,
            request.columns.as_deref(),
            request.request_id.as_deref(),
            auth.claims.sub,
            QueryPriority::Interactive,
            request.dataset.as_deref(),
            &scope,
        )
        .await?;
    // NAN-2771: a lake sample reports its row count, which does not depend on
    // the requested columns; ClickHouse keeps the widest field's count.
    let fields = stats.fields;
    let total_events = stats
        .sampled_rows
        .unwrap_or_else(|| fields.iter().map(|f| f.count).max().unwrap_or(0));

    let response = FieldStatsResponse {
        fields,
        total_events,
    };
    require_current_shared_authority(&state, &auth).await?;
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((
        crate::cache::cache_status_headers(false, None),
        Json(response),
    ))
}

/// Get top values for a SINGLE field (on-demand, Kibana-style)
///
/// Called when user expands a field in the sidebar.
#[utoipa::path(
    post,
    path = "/api/search/field-values",
    tag = "search",
    request_body = FieldValuesRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "Top field values with counts", body = FieldValuesResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn field_values(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<FieldValuesRequest>,
) -> Result<(axum::http::HeaderMap, Json<FieldValuesResponse>), SearchError> {
    let start = Instant::now();

    // NAN-2028: returns log-derived field values — same search:execute gate.
    require_search_execute(&auth)?;
    // NAN-3093: field values run only the base search (pipes stripped).
    require_shared_npl_base_search_contract(&auth, &request.query, request.dataset.as_deref())?;
    validate_field_values_limit(request.limit)?;
    // NAN-1799: the service injects the composed deny-set into the nPL path
    // itself — no more pre-rewrite of the query here.
    let scope = effective_scope(&auth);
    let query = request.query.clone();

    let time_range = TimeRangeInput {
        start: request.start,
        end: request.end,
    };

    // NAN-1593: drill-in field values are re-requested whenever the user
    // re-expands a field, and re-fetched on shared-link follow — cache them
    // through the same Dragonfly layer. Keyed on the raw `query` plus the
    // field, time range, limit, and dataset, with the caller's effective
    // deny-set folded in by `companion_key` (NAN-1799).
    let cache_key = crate::cache::SearchResultCache::companion_key_for(
        auth.tenant_scope,
        // NAN-2344: response metadata now distinguishes returned top-N
        // coverage from the full population. Version the cache namespace so a
        // rolling deploy never asks the new response type to deserialize the
        // older, ambiguous shape.
        // v3 expands repeated OCSF leaves before grouping, so stale v2 entries
        // containing JSON array combinations must never repaint the field rail.
        "fvalues-v3",
        &[
            request.field.as_bytes(),
            query.as_bytes(),
            request.start.timestamp_micros().to_string().as_bytes(),
            request.end.timestamp_micros().to_string().as_bytes(),
            request.limit.to_string().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<FieldValuesResponse>(&cache_key).await {
                let age = cache.age_secs(&cache_key).await;
                require_current_shared_authority(&state, &auth).await?;
                record_search_query("field_values_cached", 0.0, true);
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let search_service = state.search_for_auth(&auth)?;
    let result = search_service
        .get_field_values_for_panel(
            &request.field,
            &query,
            &time_range,
            request.limit,
            request.dataset.as_deref(),
            &scope,
        )
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("field_values", duration_ms, result.is_ok());

    let result = result?;
    let mut response = field_values_response(request.field, result.values, request.limit);
    if let Some(window) = result.sampled_window {
        response.approximate = true;
        response.sampled_start = Some(window.start);
        response.sampled_end = Some(window.end);
    }
    require_current_shared_authority(&state, &auth).await?;
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((
        crate::cache::cache_status_headers(false, None),
        Json(response),
    ))
}

/// Request for a search's timeline alone.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SearchHistogramRequest {
    /// The piped query string, exactly as sent to `POST /api/search`.
    pub query: String,
    /// Time range of the search.
    pub time_range: TimeRangeInput,
    /// Per-query dataset selector, as on `POST /api/search`.
    #[serde(default)]
    pub dataset: Option<String>,
}

/// A search's timeline, answered on its own.
#[derive(Debug, Clone, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SearchHistogramResponse {
    /// The buckets `POST /api/search` would return in `histogram`. Empty when
    /// the search renders no timeline (aggregates, product views).
    pub histogram: Vec<nanosiem_core::search::HistogramBucket>,
    /// The search's exact total when the timeline proves it: every base
    /// event is exactly one result row. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,
    /// Per-phase lake evidence (`x-nano-search-debug: 1` with `search:sql`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub debug: Option<serde_json::Value>,
}

/// Get the timeline (histogram) of a search without its rows
///
/// The Search page sends its rows request with `skip_histogram: true` and
/// asks for the timeline here at the same time, so rows paint as soon as
/// they are ready instead of waiting for the histogram companion.
#[utoipa::path(
    post,
    path = "/api/search/histogram",
    tag = "search",
    request_body = SearchHistogramRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 503, description = "Search authority temporarily unavailable (search_authority_unavailable); Retry-After: 2", body = crate::error::ErrorResponse),
        (status = 200, description = "The search's histogram buckets and, when provable, its exact total", body = SearchHistogramResponse),
        (status = 400, description = "Query error, or the timeline did not finish within the interactive deadline", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn search_histogram(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    request_headers: axum::http::HeaderMap,
    Json(request): Json<SearchHistogramRequest>,
) -> Result<(axum::http::HeaderMap, Json<SearchHistogramResponse>), SearchError> {
    use nanosiem_core::search::QueryPriority;

    require_search_execute(&auth)?;
    let debug = wants_search_debug(&request_headers, &auth);
    let bypass = bypass || debug;
    let empty = || SearchHistogramResponse { histogram: Vec::new(), total_count: None, debug: None };
    // The risk grain has no time axis (the search itself answers an empty
    // timeline for it), so there is nothing to compute or authorize here.
    if nanosiem_core::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"))
        == nanosiem_core::query::Dataset::Risk
    {
        return Ok((crate::cache::cache_status_headers(false, None), Json(empty())));
    }
    let scope = effective_scope(&auth);
    // The same view and shared contract as `/api/search`: the histogram-only
    // view runs the search's full preparation, then only the timeline.
    let search_service = state.search_with_ai_for_auth(&auth)?;
    require_shared_npl_contract_for_view(
        &auth,
        &request.query,
        request.dataset.as_deref(),
        &search_service,
    )?;
    let time_range = request.time_range.clone();
    let cache_key = crate::cache::SearchResultCache::companion_key_for(
        auth.tenant_scope,
        "histogram-v1",
        &[
            request.query.as_bytes(),
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<SearchHistogramResponse>(&cache_key).await {
                let age = cache.age_secs(&cache_key).await;
                require_current_shared_authority(&state, &auth).await?;
                record_search_query("search_histogram_cached", 0.0, true);
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let start = Instant::now();
    let execution = search_service.search_histogram_with_admission(
        &request.query,
        &time_range,
        request.dataset.as_deref(),
        auth.claims.sub,
        QueryPriority::Interactive,
        &scope,
    );
    let (result, debug_evidence) = if debug {
        let (result, evidence) = nanosiem_core::search::lake_debug::collect(execution).await;
        (result, Some(evidence))
    } else if let Some(deadline) = configured_escalation_deadline() {
        // NAN-3229: the timeline has no durable lane. Bound it under the 60 s
        // edge so a slow timeline ends as a typed timeout (the page keeps its
        // rows and drops the chart) instead of a proxy 502 that held a slot.
        match tokio::time::timeout(deadline, execution).await {
            Ok(result) => (result, None),
            Err(_) => {
                record_search_query("search_histogram", start.elapsed().as_secs_f64() * 1000.0, false);
                return Err(histogram_deadline_error(deadline));
            }
        }
    } else {
        (execution.await, None)
    };
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("search_histogram", duration_ms, result.is_ok());
    let result = result?;
    let mut response = SearchHistogramResponse {
        histogram: result.histogram,
        total_count: result.total_count,
        debug: None,
    };
    require_current_shared_authority(&state, &auth).await?;
    if let Some(mut evidence) = debug_evidence {
        evidence["service_ms"] = serde_json::json!(duration_ms);
        response.debug = Some(evidence);
    } else if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }
    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
}

/// Request for on-demand field values
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FieldValuesRequest {
    /// Field name to get values for
    pub field: String,
    /// The piped query string to filter events
    pub query: String,
    /// Start of time range
    pub start: chrono::DateTime<chrono::Utc>,
    /// End of time range
    pub end: chrono::DateTime<chrono::Utc>,
    /// Maximum number of values to return (default 100)
    #[serde(default = "default_field_values_limit")]
    #[schema(minimum = 1, maximum = 1000)]
    pub limit: usize,
    /// Per-query dataset selector: `logs` (default), `spans`,
    /// `metrics`, or `risk`. Drill-in must resolve the field and base source
    /// against the same dataset the search targeted, else a spans/metrics/risk
    /// field reads the UDM `logs` table and returns nothing.
    #[serde(default)]
    pub dataset: Option<String>,
}

fn default_field_values_limit() -> usize {
    100
}

const MAX_FIELD_VALUES_LIMIT: usize = 1_000;

fn validate_field_values_limit(limit: usize) -> Result<(), SearchError> {
    if (1..=MAX_FIELD_VALUES_LIMIT).contains(&limit) {
        Ok(())
    } else {
        Err(SearchError::BadRequest(format!(
            "field-values limit must be between 1 and {MAX_FIELD_VALUES_LIMIT}"
        )))
    }
}

/// Response for field values
#[derive(Debug, Clone, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct FieldValuesResponse {
    /// The field name
    pub field: String,
    /// Top values with counts
    pub values: Vec<FieldValueInfo>,
    /// Number of top values returned in `values`.
    pub returned_value_count: usize,
    /// Event count covered by the returned top values. This is NOT the total
    /// event population when more distinct values exist beyond the requested
    /// top-N.
    pub covered_event_count: u64,
    /// True when the response filled the requested top-N and additional
    /// distinct values may exist. Conservative: an exact-cardinality tie at
    /// the limit also reports true because proving completeness needs another
    /// full aggregation.
    pub may_have_more_values: bool,
    /// Backwards-compatible alias of `covered_event_count`.
    ///
    /// This field historically sounded like the full matching population even
    /// though it only summed the returned top values. New clients should use
    /// the explicit fields above.
    pub total_count: u64,
    /// true when the values (and their percentages) were counted
    /// over the newest slice `[sampled_start, sampled_end]` of a wide window
    /// that the count rollups cannot answer, not over the whole window.
    #[serde(default)]
    pub approximate: bool,
    /// Start of the sampled slice (only when `approximate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampled_start: Option<chrono::DateTime<chrono::Utc>>,
    /// End of the sampled slice (only when `approximate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampled_end: Option<chrono::DateTime<chrono::Utc>>,
}

fn field_values_response(
    field: String,
    values: Vec<FieldValueInfo>,
    requested_limit: usize,
) -> FieldValuesResponse {
    let returned_value_count = values.len();
    let covered_event_count = values.iter().map(|value| value.count).sum();
    FieldValuesResponse {
        field,
        values,
        returned_value_count,
        covered_event_count,
        may_have_more_values: requested_limit > 0 && returned_value_count >= requested_limit,
        total_count: covered_event_count,
        approximate: false,
        sampled_start: None,
        sampled_end: None,
    }
}

/// Request for async field stats
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FieldStatsRequest {
    /// The piped query string
    pub query: String,
    /// Start of time range
    pub start: chrono::DateTime<chrono::Utc>,
    /// End of time range
    pub end: chrono::DateTime<chrono::Utc>,
    /// Client request id of the originating search. When set, the
    /// field-stats query runs under the derived ClickHouse query_id
    /// `{request_id}-fstats`, so `DELETE /api/search/{request_id}` cancels it
    /// together with the data query.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Optional column subset to compute stats for. The stats
    /// query's I/O scales with the number of columns aggregated, so callers
    /// should send only the columns they render. Names are intersected with
    /// the live table inventory (unknown names dropped; an empty intersection
    /// falls back to the full set). Omit for the full column inventory.
    #[serde(default)]
    pub columns: Option<Vec<String>>,
    /// Deprecated, ignored. Accepted for older clients (desktop
    /// sends it with every `columns` request). The primary lake now always
    /// computes `columns` stats from a bounded row sample (projected to the
    /// requested canonical fields when they are all known); `total_events` is
    /// then the sample's row count (at most 1,000), not the window total.
    #[serde(default)]
    #[allow(dead_code)]
    pub sample_columns: bool,
    /// Per-query dataset selector: `logs` (default), `spans`,
    /// `metrics`, or `risk`. The companion enumerates the dataset's columns and
    /// wraps the dataset's base SQL — without it a spans/metrics search's field
    /// panel runs the UDM column list against `otel_spans` and ClickHouse 47's.
    #[serde(default)]
    pub dataset: Option<String>,
}

/// Response for field stats
#[derive(Debug, Clone, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct FieldStatsResponse {
    /// Field information list
    pub fields: Vec<nanosiem_core::search::FieldInfo>,
    /// Total number of events in the time range
    pub total_events: u64,
}

// NAN-2030: the `require_search_execute` gate + its under-scoped-key regression
// test now live in `handlers/mod.rs` and `handlers/authz_guard.rs` so every
// handler shares one gate under one contract.

#[cfg(test)]
mod field_values_endpoint_tests {
    use nanosiem_core::search::FieldValueInfo;

    /// NAN-2149: the search drill-in endpoint must keep delegating field
    /// resolution to SearchService. Resolving a column in the handler would
    /// bypass the shared OCSF class-split/enum display expression and diverge
    /// from GET /api/fields/{name}/values.
    #[test]
    fn search_field_values_endpoint_delegates_to_shared_service_path() {
        let src = include_str!("search.rs");
        const MARKER: &str = "pub async fn ";
        let start = src
            .find(&format!("{MARKER}field_values("))
            .expect("field_values handler not found");
        let end = src
            .match_indices(MARKER)
            .map(|(i, _)| i)
            .find(|&i| i > start)
            .unwrap_or(src.len());
        let body = &src[start..end];

        assert!(
            body.contains(".get_field_values_for_panel("),
            "POST /api/search/field-values must delegate to SearchService"
        );
        assert!(
            body.contains("request.dataset.as_deref()"),
            "field-values must preserve the request's dataset/profile selector"
        );
        assert!(
            !body.contains("field_access_expr"),
            "the endpoint must not grow its own schema-resolution path"
        );
    }

    #[test]
    fn field_values_names_top_n_coverage_without_claiming_population_completeness() {
        let response = super::field_values_response(
            "dest_ip".to_string(),
            vec![
                FieldValueInfo {
                    value: "10.1.1.1".to_string(),
                    count: 9,
                    percentage: 52.9,
                },
                FieldValueInfo {
                    value: "10.1.1.2".to_string(),
                    count: 8,
                    percentage: 47.1,
                },
            ],
            2,
        );

        assert_eq!(response.returned_value_count, 2);
        assert_eq!(response.covered_event_count, 17);
        assert_eq!(response.total_count, response.covered_event_count);
        assert!(response.may_have_more_values);
    }

    #[test]
    fn a_short_field_values_page_is_known_complete() {
        let response = super::field_values_response(
            "dest_ip".to_string(),
            vec![FieldValueInfo {
                value: "10.1.1.1".to_string(),
                count: 9,
                percentage: 100.0,
            }],
            40,
        );

        assert!(!response.may_have_more_values);
    }

    #[test]
    fn field_values_limit_is_bounded_before_query_execution() {
        assert!(super::validate_field_values_limit(1).is_ok());
        assert!(super::validate_field_values_limit(1_000).is_ok());
        assert!(super::validate_field_values_limit(0).is_err());
        assert!(super::validate_field_values_limit(1_001).is_err());
    }
}

/// NAN-2219: `nanosiem-search` carries its OWN `AuthContext` and composes its
/// own scope, so the row-filter / derived-artifact split has to be pinned HERE
/// as well as at `nanosiem-api`'s `AuthContext::effective_viewer_scope`. Both
/// delegate to `nanosiem_core::auth::compose_viewer_scope`; these assertions are
/// what catches this crate re-inlining the composition and losing the split —
/// which would silently restore the inverted `| prevalence` numbers this issue
/// fixed, on the primary search surface.
#[cfg(test)]
mod effective_scope_split_tests {
    use nanosiem_core::auth::{types::TokenClaims, ApiKeyInfo, ArtifactScope, ScopeSet};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    // The permission IDS, not the `permissions::*` constants. `authz_guard`'s
    // `every_handler_is_authorization_accounted_for` splits this file on the
    // literal `pub async fn ` — which also occurs inside a string in
    // `field_values_endpoint_tests` — and runs the resulting phantom region to
    // EOF. Naming `SEARCH_EXECUTE` here would land inside that region and
    // silently satisfy the guard for it, muting part of a pre-existing
    // (unrelated) failure. Matches how the sibling scope tests in
    // `nanosiem-api-lib::auth_context` spell these.
    const SEARCH_EXECUTE_ID: &str = "search:execute";
    const AUDIT_VIEW_ID: &str = "audit:view";

    fn jwt_auth(permissions: &[&str]) -> crate::AuthContext {
        crate::AuthContext::from_jwt(TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: Uuid::now_v7(),
            roles: vec![],
            permissions: permissions.iter().map(|item| item.to_string()).collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(permissions: &[&str]) -> crate::AuthContext {
        crate::AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "effective-scope-split-test".to_string(),
            permissions: permissions.iter().map(|item| item.to_string()).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    /// NAN-3077: debug evidence needs the header AND `search:sql`.
    #[test]
    fn search_debug_needs_the_header_and_search_sql() {
        let mut asked = axum::http::HeaderMap::new();
        asked.insert(super::SEARCH_DEBUG_HEADER, axum::http::HeaderValue::from_static("1"));
        let sql = nanosiem_core::auth::permissions::SEARCH_SQL;
        assert!(super::wants_search_debug(&asked, &api_key_auth(&[SEARCH_EXECUTE_ID, sql])));
        assert!(super::wants_search_debug(&asked, &jwt_auth(&[SEARCH_EXECUTE_ID, sql])));
        assert!(!super::wants_search_debug(&asked, &api_key_auth(&[SEARCH_EXECUTE_ID])));
        assert!(!super::wants_search_debug(&axum::http::HeaderMap::new(), &api_key_auth(&[SEARCH_EXECUTE_ID, sql])));
        let mut other = axum::http::HeaderMap::new();
        other.insert(super::SEARCH_DEBUG_HEADER, axum::http::HeaderValue::from_static("true"));
        assert!(!super::wants_search_debug(&other, &api_key_auth(&[SEARCH_EXECUTE_ID, sql])));
    }

    /// NAN-3406: what the route-wide middleware lets a handler see for a
    /// request carrying `x-nano-perf-overrides` (the overrides its lake
    /// calls forward, and whether its caches are bypassed).
    async fn perf_overrides_seen(auth: Option<crate::AuthContext>, headers: &[(&'static str, &'static str)]) -> (Option<String>, bool) {
        use tower::ServiceExt;
        let app = axum::Router::new()
            .route("/probe", axum::routing::get(|request_headers: axum::http::HeaderMap| async move {
                let bypass = request_headers.get(crate::cache::HEADER_CACHE_BYPASS).is_some();
                let overrides = nanosiem_core::search::lake_debug::perf_overrides();
                axum::Json(serde_json::json!({"overrides": overrides, "bypass": bypass}))
            }))
            .layer(axum::middleware::from_fn(super::lake_debug_middleware));
        let mut request = axum::http::Request::builder().uri("/probe");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(axum::body::Body::empty()).unwrap();
        if let Some(auth) = auth {
            request.extensions_mut().insert(auth);
        }
        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        (body["overrides"].as_str().map(str::to_owned), body["bypass"].as_bool().unwrap())
    }

    /// NAN-3406: overrides are honoured only for a caller already admitted
    /// to debug evidence (the header AND `search:sql`); anyone else's are
    /// ignored silently and never reach a lake call.
    #[tokio::test]
    async fn perf_overrides_need_search_debug_authorization() {
        let sql = nanosiem_core::auth::permissions::SEARCH_SQL;
        let overrides = ("x-nano-perf-overrides", "flat_filter_leaves=1,lane_routing_v2=0");
        let debug = (super::SEARCH_DEBUG_HEADER, "1");
        // Authorized: forwarded (canonical) and caches bypassed.
        assert_eq!(
            perf_overrides_seen(Some(api_key_auth(&[SEARCH_EXECUTE_ID, sql])), &[overrides, debug]).await,
            (Some("flat_filter_leaves=1,lane_routing_v2=0".to_string()), true)
        );
        // No search:sql, no debug header, a bad debug value, or no auth at all: ignored.
        assert_eq!(perf_overrides_seen(Some(api_key_auth(&[SEARCH_EXECUTE_ID])), &[overrides, debug]).await, (None, false));
        assert_eq!(perf_overrides_seen(Some(jwt_auth(&[SEARCH_EXECUTE_ID, sql])), &[overrides]).await, (None, false));
        assert_eq!(perf_overrides_seen(Some(jwt_auth(&[SEARCH_EXECUTE_ID, sql])), &[overrides, (super::SEARCH_DEBUG_HEADER, "true")]).await, (None, false));
        assert_eq!(perf_overrides_seen(None, &[overrides, debug]).await, (None, false));
        // Authorized debug without overrides (or with only junk): nothing changes.
        assert_eq!(perf_overrides_seen(Some(api_key_auth(&[SEARCH_EXECUTE_ID, sql])), &[debug]).await, (None, false));
        assert_eq!(
            perf_overrides_seen(Some(api_key_auth(&[SEARCH_EXECUTE_ID, sql])), &[("x-nano-perf-overrides", "evil=1"), debug]).await,
            (None, false)
        );
    }

    /// The NAN-2219 case: an ordinary analyst on a tenant whose
    /// `restricted_source_types` registry is empty. `audit:view` is Admin-only,
    /// so its absence must NOT be read as a per-source boundary.
    #[test]
    fn unscoped_caller_without_audit_view_is_row_restricted_but_not_artifact_restricted() {
        for auth in [
            jwt_auth(&[SEARCH_EXECUTE_ID]),
            api_key_auth(&[SEARCH_EXECUTE_ID]),
        ] {
            let scope = super::effective_scope(&auth);

            // Row filter: audit event rows stay denied (NAN-1801 unchanged).
            assert_eq!(scope.deny_set(), &set(&["audit"]));
            assert!(scope.is_restricted());

            // Artifacts: no per-source boundary exists, so none is invented —
            // `| prevalence` keeps the source-less dictionary fast path instead
            // of the aggregates migration 170 never backfilled.
            assert!(scope.artifact_deny_set().is_empty());
            assert!(ArtifactScope::from_scope(&scope).is_unrestricted());
        }
    }

    /// A GENUINELY source-scoped caller keeps its real per-source denies in
    /// BOTH halves; only the `audit:view` gate is split off.
    #[test]
    fn a_source_scoped_caller_keeps_its_real_denies_in_both_halves() {
        for mut auth in [
            jwt_auth(&[SEARCH_EXECUTE_ID]),
            api_key_auth(&[SEARCH_EXECUTE_ID]),
        ] {
            auth.denied_sources = ScopeSet::from_denied(set(&["insider_threat"]));
            let scope = super::effective_scope(&auth);

            assert_eq!(scope.deny_set(), &set(&["audit", "insider_threat"]));
            assert_eq!(scope.artifact_deny_set(), &set(&["insider_threat"]));
            assert!(!ArtifactScope::from_scope(&scope).is_unrestricted());
        }
    }

    /// A tenant that registers `audit` in `restricted_source_types` has a REAL
    /// per-source boundary on it, so it is denied in BOTH halves regardless of
    /// the permission. The split must not launder a registry deny into
    /// artifact visibility.
    #[test]
    fn registry_restricted_audit_survives_in_both_halves() {
        for mut auth in [
            jwt_auth(&[SEARCH_EXECUTE_ID]),
            jwt_auth(&[SEARCH_EXECUTE_ID, AUDIT_VIEW_ID]),
            api_key_auth(&[SEARCH_EXECUTE_ID]),
            api_key_auth(&[SEARCH_EXECUTE_ID, AUDIT_VIEW_ID]),
        ] {
            auth.denied_sources = ScopeSet::from_denied(set(&["audit"]));
            let scope = super::effective_scope(&auth);

            assert_eq!(scope.deny_set(), &set(&["audit"]));
            assert_eq!(scope.artifact_deny_set(), &set(&["audit"]));
            assert!(!ArtifactScope::from_scope(&scope).is_unrestricted());
        }
    }

    /// An unrestricted `audit:view` holder still yields the fully EMPTY scope
    /// both halves — the contract that keeps downstream SQL byte-identical to
    /// the pre-scoping form.
    #[test]
    fn an_unrestricted_audit_viewer_yields_an_empty_scope() {
        for auth in [
            jwt_auth(&[SEARCH_EXECUTE_ID, AUDIT_VIEW_ID]),
            api_key_auth(&[SEARCH_EXECUTE_ID, AUDIT_VIEW_ID]),
        ] {
            assert_eq!(super::effective_scope(&auth), ScopeSet::unrestricted());
        }
    }
}

#[cfg(test)]
mod nan3229_deadline_escalation {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn headers(value: Option<&'static str>) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        if let Some(value) = value {
            headers.insert(ASYNC_CAPABLE_HEADER, axum::http::HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn the_default_deadline_sits_under_every_proxy_in_front_of_search() {
        let deadline = parse_escalation_deadline(None).expect("enabled by default");
        // nginx / forward-proxy / web-client 60 s, Cloudflare 100 s.
        assert_eq!(deadline, Duration::from_secs(45));
        assert!(deadline <= Duration::from_secs(50), "keep a margin under the 60 s edge: {deadline:?}");
        assert_eq!(parse_escalation_deadline(Some("")), Some(deadline));
        assert_eq!(parse_escalation_deadline(Some("not-a-number")), Some(deadline));
        assert_eq!(parse_escalation_deadline(Some(" 30 ")), Some(Duration::from_secs(30)));
        assert_eq!(parse_escalation_deadline(Some("0")), None, "0 disables escalation");
    }

    /// NAN-3474: an atomic caller (k6, scripts, the API) without the header
    /// ran ~57 s into the cell's statement deadline and got the edge's 502;
    /// it now gets the same wall cap. Only an explicit `0` opts out.
    #[test]
    fn every_non_debug_caller_gets_the_wall_cap_unless_it_opts_out() {
        assert!(interactive_escalation_deadline(&headers(Some("1")), false).is_some());
        assert!(interactive_escalation_deadline(&headers(None), false).is_some());
        assert!(interactive_escalation_deadline(&headers(Some("true")), false).is_some());
        assert!(interactive_escalation_deadline(&headers(Some("0")), false).is_none());
        assert!(interactive_escalation_deadline(&headers(Some(" 0 ")), false).is_none());
        // A debug run always describes the execution.
        assert!(interactive_escalation_deadline(&headers(Some("1")), true).is_none());
        assert!(interactive_escalation_deadline(&headers(None), true).is_none());
        // Progressive views alone changes nothing.
        let mut progressive = axum::http::HeaderMap::new();
        progressive.insert("x-nano-progressive-views", axum::http::HeaderValue::from_static("1"));
        assert!(interactive_escalation_deadline(&progressive, false).is_some());
    }

    #[test]
    fn the_cap_is_measured_from_the_request_not_from_execution() {
        let cap = Duration::from_secs(45);
        assert_eq!(remaining_deadline(cap, Duration::from_millis(300)), Duration::from_millis(44_700));
        assert_eq!(remaining_deadline(cap, Duration::from_secs(50)), Duration::ZERO);
    }

    /// NAN-3474 acceptance shape: a query that would run into the cell's
    /// 55 s statement deadline is answered with a job id at the cap, measured
    /// from the request's arrival.
    #[tokio::test]
    async fn a_slow_query_escalates_at_the_wall_cap_after_request_setup() {
        let arrived = Instant::now();
        tokio::time::sleep(Duration::from_millis(30)).await; // auth, scope, cache lookup
        let cap = Duration::from_millis(120);
        let execution = async {
            // Far past the cap: the cell's 55 s statement deadline.
            tokio::time::sleep(Duration::from_secs(55)).await;
            Err::<u32, SearchError>(SearchError::ResourceExhausted("scan".into()))
        };
        let outcome = finish_or_escalate(execution, remaining_deadline(cap, arrived.elapsed()), || async {
            Ok(Some("job-cap".to_string()))
        })
        .await
        .unwrap();
        let answered = arrived.elapsed();
        assert!(matches!(outcome, DeadlineOutcome::Escalated(ref id) if id == "job-cap"));
        assert!(answered >= cap, "escalated before the cap: {answered:?}");
        assert!(answered < cap + Duration::from_millis(100), "the cap restarted at execution: {answered:?}");
    }

    #[tokio::test]
    async fn a_fast_query_under_the_cap_keeps_its_interactive_answer() {
        let asked = AtomicBool::new(false);
        let execution = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok::<_, SearchError>("rows")
        };
        let outcome = finish_or_escalate(execution, Duration::from_secs(45), || async {
            asked.store(true, Ordering::SeqCst);
            Ok(Some("job".to_string()))
        })
        .await
        .unwrap();
        assert!(matches!(outcome, DeadlineOutcome::Finished(Ok("rows"))));
        assert!(!asked.load(Ordering::SeqCst), "a fast query must never submit a durable job");
    }

    #[test]
    fn a_timeline_past_the_deadline_is_a_user_actionable_refusal() {
        let error = histogram_deadline_error(Duration::from_secs(45));
        assert_eq!(error.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert!(error.public_message().contains("within 45 s"), "{}", error.public_message());
    }

    #[tokio::test]
    async fn a_query_that_finishes_in_time_never_asks_to_escalate() {
        let asked = AtomicBool::new(false);
        let outcome = finish_or_escalate(async { 7 }, Duration::from_secs(5), || async {
            asked.store(true, Ordering::SeqCst);
            Ok(Some("job".to_string()))
        })
        .await
        .unwrap();
        assert!(matches!(outcome, DeadlineOutcome::Finished(7)));
        assert!(!asked.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_slow_query_becomes_a_job_and_its_interactive_run_is_dropped() {
        struct DropFlag<'a>(&'a AtomicBool);
        impl Drop for DropFlag<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = AtomicBool::new(false);
        let flag = DropFlag(&dropped);
        let execution = async move {
            let _flag = flag;
            std::future::pending::<u32>().await
        };
        let outcome = finish_or_escalate(execution, Duration::from_millis(20), || async {
            Ok(Some("job-1".to_string()))
        })
        .await
        .unwrap();
        assert!(matches!(outcome, DeadlineOutcome::Escalated(ref id) if id == "job-1"));
        assert!(dropped.load(Ordering::SeqCst), "the interactive execution must be cancelled");
    }

    #[tokio::test]
    async fn a_query_the_durable_lane_refuses_keeps_running_to_its_own_end() {
        let execution = async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            "rows"
        };
        let outcome = finish_or_escalate(execution, Duration::from_millis(10), || async { Ok(None) })
            .await
            .unwrap();
        assert!(matches!(outcome, DeadlineOutcome::Finished("rows")));
    }

    #[tokio::test]
    async fn a_revoked_authority_at_the_deadline_is_returned() {
        let outcome = finish_or_escalate(
            std::future::pending::<u32>(),
            Duration::from_millis(10),
            || async { Err(SearchError::Forbidden("revoked".into())) },
        )
        .await;
        assert!(matches!(outcome, Err(SearchError::Forbidden(_))));
    }
}

#[cfg(test)]
mod nan3071_unescalatable_exhaustion {
    use super::*;

    #[test]
    fn a_refused_escalation_keeps_the_interactive_failure_and_says_how_to_fix_it() {
        let refusal = nanosiem_core::SearchError::SqlValidationError(
            nanosiem_core::search::service::DURABLE_LANE_POST_PROCESSING_REFUSAL.to_string(),
        );
        assert!(nanosiem_core::search::service::is_durable_lane_post_processing_refusal(&refusal));
        assert!(!nanosiem_core::search::service::is_durable_lane_post_processing_refusal(
            &nanosiem_core::SearchError::SqlValidationError("something else".into())
        ));

        let error = unescalatable_exhaustion("memory");
        assert_eq!(error.code(), "RESOURCE_EXHAUSTED");
        assert_eq!(error.status_code(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        let message = error.public_message();
        assert!(message.starts_with("Interactive query exhausted its memory budget."), "{message}");
        assert!(message.contains("before `| ai`"), "{message}");
        assert!(!message.contains("durable SQL-only lane"), "the refusal text must not reach the user: {message}");

        // A lake producer's full sentence is kept as the cause.
        let sentence = unescalatable_exhaustion("scan slice needs 812.00 MB, budget 512.00 MB");
        assert!(sentence.public_message().starts_with("scan slice needs 812.00 MB, budget 512.00 MB."));
    }
}

#[cfg(test)]
mod deferred_tree_tests {
    use super::*;
    #[test]
    fn terminal_tree_dispatcher_contains_no_event_rows_and_keeps_the_requested_window() {
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "device.hostname=\"host\" | tree parent=actor.process.uid child=process.uid label=process.name",
            "time_range": {"start": "2026-09-30T00:00:00Z", "end": "2026-09-30T01:00:00Z"}
        })).unwrap();
        let response = deferred_tree_marker(&request).unwrap().unwrap();
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0]["_tree_pending"], true);
        assert_eq!(response.results[0]["_tree_nodes"], serde_json::json!([]));
        assert_eq!(response.results[0]["_tree_time_range"], serde_json::to_value(&request.time_range).unwrap());
        assert!(!response.total_count_exact);
        let mut atomic = request; atomic.query.push_str(" | head 1");
        assert!(deferred_tree_marker(&atomic).unwrap().is_none());
        atomic.query = "device.hostname=\"host\" | lateral | tree parent=actor.process.uid child=process.uid label=process.name".into();
        assert!(deferred_tree_marker(&atomic).unwrap().is_none());
    }
}
