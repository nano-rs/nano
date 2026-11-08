// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search endpoints: execute, cancel, explain, fetch log, prevalence, field stats.

use axum::{
    Json,
    extract::{Path, State},
};
use nanosiem_core::{
    PrevalenceScatterData, RawSqlRequest, SearchRequest, SearchResponse, TimeRangeInput,
    auth::permissions,
    search::FieldValueInfo,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::{SearchResultResponse, require_search_execute};
use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

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
    principal_id: uuid::Uuid,
) -> Result<(), SearchError> {
    let in_use = || SearchError::BadRequest("request_id is already in use".to_string());
    match state.reserve_query_owner(&request_id, principal_id).await {
        // NAN-2100: the LOCAL reservation is authoritative on its own in a
        // single-instance deployment (no shared registry) and whenever the
        // shared one is degraded, so its conflict verdict must be honored in
        // both arms — not just Redis's. Reserving over another credential's
        // in-flight id would let that credential cancel this query.
        Ok(true) => {
            if state
                .search
                .query_tracker()
                .reserve_request(request_id, principal_id)
            {
                Ok(())
            } else {
                Err(in_use())
            }
        }
        Ok(false) => Err(in_use()),
        Err(error) => {
            tracing::warn!(%error, %request_id, "Shared query ownership unavailable; using local ownership");
            if state
                .search
                .query_tracker()
                .reserve_request(request_id, principal_id)
            {
                Ok(())
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
/// If async_mode=true, starts (or attaches to) a durable background job and
/// returns its job_id immediately for polling.
///
/// Otherwise executes synchronously and returns results. A client that sends
/// `x-nano-accept-async: 1` also accepts a hand-off: if the search is still
/// running at the interactive budget (`SEARCH_INTERACTIVE_HANDOFF_SECS`,
/// default 45 s) it is moved to a background job and the response is a job
/// answer (`job_id`, `origin: "escalated"`, `x-nano-search-job` header) — never
/// an empty result set. Clients that do not send the header never receive a
/// job answer from this route.
/// NAN-4664: the `/api/search` body, plus whether `use_cache` was sent at
/// all (`SearchRequest::use_cache` reads an absent field as `false`, which
/// the result cache must not treat as an explicit opt-out).
pub struct SearchBody {
    pub request: SearchRequest,
    pub explicit_use_cache: Option<bool>,
}

impl<S: Send + Sync> axum::extract::FromRequest<S> for SearchBody {
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        use axum::response::IntoResponse;
        let Json(value) = Json::<serde_json::Value>::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let explicit_use_cache = value.get("use_cache").and_then(serde_json::Value::as_bool);
        let request = serde_json::from_value::<SearchRequest>(value).map_err(|error| {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                format!("Failed to deserialize the JSON body into the target type: {error}"),
            )
                .into_response()
        })?;
        Ok(Self { request, explicit_use_cache })
    }
}

/// NAN-4664: the server-resolved authority dimension beyond the deny sets
/// that could shape a shared search's result: the admission priority (its
/// ClickHouse budgets). Folded into the in-flight identity so a follower only
/// ever receives a run computed under the same authority as its own.
pub(crate) fn inflight_authority_fingerprint(priority: nanosiem_core::search::QueryPriority) -> Vec<u8> {
    format!("pri={priority:?}").into_bytes()
}

/// NAN-3077: a terminal `| tree` asked for progressively answers this pending
/// marker at once; the client paints a bounded preview and pages the exact
/// tree from a background job through `/api/search/tree-page`.
pub(crate) fn deferred_tree_marker(request: &SearchRequest) -> Result<Option<SearchResponse>, SearchError> {
    if request.offset.unwrap_or(0) != 0 || request.limit == Some(0) {
        return Ok(None);
    }
    let parsed = nanosiem_core::query::parse_query(&request.query)
        .map_err(|_| SearchError::BadRequest("Invalid query".into()))?;
    if !super::tree_page::supports_paged_tree(&parsed) {
        return Ok(None);
    }
    let Some(tree) = nanosiem_core::search::query_processing::extract_tree_command(&parsed) else {
        return Ok(None);
    };
    let mut response = SearchResponse::empty();
    response.results = vec![serde_json::json!({"_display_type": "tree", "_tree_pending": true,
        "_tree_query": request.query, "_tree_time_range": request.time_range, "_tree_run_id": uuid::Uuid::now_v7(),
        "_tree_config": {"parent_field": tree.parent_field, "child_field": tree.child_field, "label_field": tree.label_field,
            "detail_field": tree.detail_field, "prevalence_field": tree.prevalence_field, "root_filter": tree.root_filter},
        "_tree_nodes": []})];
    response.display_type = Some(nanosiem_core::search::DisplayType::Tree);
    Ok(Some(response))
}

/// NAN-3077: whether a request asked for a progressive product view
/// (`x-nano-progressive-views: 1`) of a terminal `| lateral` or `| tree`.
pub(crate) fn wants_progressive_view(headers: &axum::http::HeaderMap, query: &str) -> bool {
    headers
        .get("x-nano-progressive-views")
        .is_some_and(|value| value == "1")
        && nanosiem_core::query::parse_query(query).ok().is_some_and(|query| {
            nanosiem_core::search::query_processing::extract_lateral_command(&query).is_some()
                && nanosiem_core::search::query_processing::extract_post_lateral_commands(&query).is_empty()
                || matches!(
                    query,
                    nanosiem_core::query::Query::Piped {
                        command: nanosiem_core::query::Command::Tree { .. },
                        ..
                    }
                )
        })
}

/// Response header naming how an `/api/search` answer was produced
/// (NAN-4664): `leader` ran the search, `follower` received an identical
/// in-flight run's result without running it.
pub const INFLIGHT_HEADER: &str = "x-nano-inflight";

#[utoipa::path(
    post,
    path = "/api/search",
    tag = "search",
    request_body = SearchRequest,
    params(
        ("x-nano-accept-async" = Option<String>, Header, description = "Set to 1 to accept a background-job answer when the search outruns the interactive budget"),
        ("x-nano-progressive-views" = Option<String>, Header, description = "1 returns a minimal Lateral or tree dispatcher for a terminal `| lateral` / `| tree`; use /api/search/stream for Lateral (view_update events after each hop) and /api/search/tree-page for tree roots/children"), // NAN-3077
        ("x-nano-admission-wait-ms" = Option<u64>, Header, description = "How long this search may wait in the fair admission queue for a slot, in ms (default 60000, or the full queue timeout for x-nano-accept-async: 0; always capped at the configured search queue timeout, 300 s by default). Agents running many hunts at once set it so they slow down instead of failing; 0 fails fast. A 429 ADMISSION_DENIED with Retry-After: 2 comes only when this budget ends or the queue is full."), // NAN-4664
        ("x-nano-query-class" = Option<String>, Header, description = "`agent` marks an automated agent's search (pivt, the desktop agent, MCP/agent API callers). Agent-class searches share at most the search slots less a reserved human share (a quarter, at least one), hold at most that share of the admission queue, and are served after every waiting human search; deadlines and result caps are unchanged. A key nano Desktop mints for its agents is always the agent class, whatever this header says. Anything else, or no header, is a human search."), // NAN-4703
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Search results (sync or async job id)", body = SearchResultResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Admission denied (the x-nano-admission-wait-ms budget ended or the admission queue is full); carries Retry-After: 2", body = ErrorResponse),
        (status = 409, description = "Query was cancelled (request_id was killed via DELETE /api/search/{request_id} or an admin cancel)", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn search(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    super::background_jobs::AcceptAsync(accept_async): super::background_jobs::AcceptAsync,
    request_headers: axum::http::HeaderMap,
    SearchBody { mut request, explicit_use_cache }: SearchBody,
) -> Result<(axum::http::HeaderMap, Json<SearchResultResponse>), SearchError> {
    use crate::cache::cache_status_headers;
    // Total analyst-visible server time, including admission and orchestration.
    let handler_started = Instant::now();
    // NAN-3077: a progressive product view never reads or writes the result
    // cache (its first answer is a dispatcher, not the result).
    let progressive_views = wants_progressive_view(&request_headers, &request.query);
    let bypass = bypass || progressive_views;
    use nanosiem_core::search::QueryPriority;
    use nanosiem_core::search::background::JobOrigin;

    // NAN-2028: gate on search:execute (matching every sibling handler) before
    // any work — an under-scoped API key must not run piped searches.
    require_search_execute(&auth)?;

    // NAN-1799: compose the effective deny-set (per-user source scope ∪ audit
    // gate) ONCE, before the cache lookup — the scope is folded into the cache
    // key, and the service injects the exclusion into the executed SQL. This
    // replaces the old H1 `enforce_non_audit_query` rewrite of request.query.
    let scope = effective_scope(&auth);

    // NAN-4915: a hand-off must be able to KILL the interactive query it
    // replaces, which needs a known query id. Assign one when the client did
    // not (only for hand-off-eligible requests — other paths are unchanged).
    // Only a FIRST page may be handed off: a job stores the whole result from
    // row 0, so a later page (`offset > 0`) of an interactive result must stay
    // interactive rather than become a job whose first page is the wrong rows.
    let accept_async = accept_async && request.offset.unwrap_or(0) == 0;
    if accept_async && !request.async_mode && request.request_id.is_none() {
        request.request_id = Some(uuid::Uuid::now_v7().to_string());
    }
    // NAN-4915 (Codex P1-2): a hand-off must continue the SAME search. Freeze
    // relative `earliest=`/`latest=` once, at arrival, and run the interactive
    // attempt on the frozen request too — otherwise the job would re-resolve
    // `-1h` against its own, later clock.
    if accept_async && !request.async_mode {
        request = nanosiem_core::search::background::freeze_time_window(&request, chrono::Utc::now())
            .map_err(SearchError::from)?;
    }

    if let Some(request_id) = request.request_id.clone() {
        // NAN-2100: reserve under the CREDENTIAL (see `reserve_query_owner`).
        reserve_query_owner(&state, request_id, auth.credential_principal_id()).await?;
    }

    // The job owner (durable jobs, settled reuse) stays the credential subject;
    // admission counts against the owning user (NAN-4928 review P1).
    let user_id = auth.claims.sub;
    let admission_user = super::admission_user(&auth)?;
    let priority = match request.priority.as_deref() {
        Some("analytics") => QueryPriority::Analytics,
        _ => QueryPriority::Interactive,
    };

    // Async mode — NAN-4915: a durable background job (PG lease + CH rows),
    // attaching to the caller's identical live job if there is one. Returns
    // the job id immediately for polling.
    if request.async_mode {
        let outcome =
            super::background_jobs::submit_job(&state, &auth, &request, &scope, JobOrigin::Submitted)
                .await?;
        return Ok((
            super::background_jobs::job_headers(cache_status_headers(false, None), &outcome),
            Json(SearchResultResponse::Async(
                super::background_jobs::async_response(&outcome),
            )),
        ));
    }

    // NAN-3077: the tree preview and the exact job pages own the expensive
    // work; the progressive answer is a pending marker.
    if progressive_views && request.dataset.as_deref().unwrap_or("logs") == "logs" {
        if let Some(mut response) = deferred_tree_marker(&request)? {
            response.server_wall_ms = Some(handler_started.elapsed().as_millis() as u64);
            response.queue_wait_ms = Some(0);
            return Ok((cache_status_headers(false, None), Json(SearchResultResponse::Sync(response))));
        }
    }

    // NAN-3809: a settled absolute window this caller already ran as a
    // durable job (same attach identity: query, window, flags, owner and both
    // halves of the effective scope) is re-served through that job's result
    // pages instead of re-running the search. Only for callers that accept a
    // job answer, and not for an explicit `use_cache: false` or a bypass.
    // NAN-4928 review P2: a probe of a hidden source must reach the audited
    // source gate, so it never takes the reuse or cache fast paths.
    let probes_hidden_source = crate::inflight::names_denied_source(&request.query, scope.deny_set());
    if accept_async && !probes_hidden_source && crate::cache::reads_result_cache(bypass, explicit_use_cache) {
        let now = chrono::Utc::now();
        if let Some(job) = state
            .background_jobs
            .settled_reuse(&request, user_id, &scope, now)
            .await
            .map_err(SearchError::from)?
        {
            record_search_query("piped_settled_reuse", 0.0, true);
            let age = job
                .finished_at
                .map(|finished| (now - finished).num_seconds().max(0) as u64);
            let outcome = nanosiem_core::search::background::SubmitOutcome { job, attached: true };
            tracing::info!(job_id = %outcome.job.public_id(), "Settled search re-served from a finished background job");
            return Ok((
                super::background_jobs::job_headers(cache_status_headers(true, age), &outcome),
                Json(SearchResultResponse::Async(
                    super::background_jobs::async_response(&outcome),
                )),
            ));
        }
    }

    // Check search result cache (Dragonfly/Redis). NAN-1595: skip on refresh
    // bypass; stamp x-nano-cache hit/age so the UI can show the cached notice.
    // NAN-1799: the effective deny-set is folded into the cache key (computed
    // above, BEFORE this lookup) so differently-scoped users never share an
    // entry. NAN-4664: `use_cache` is tri-state; an explicit `false` skips
    // this read (a fresh run that still writes and still shares).
    if !probes_hidden_source && crate::cache::reads_result_cache(bypass, explicit_use_cache) {
        if let Some(ref cache) = state.result_cache {
            if let Some(mut cached) = cache.get(&request, &scope).await {
                record_search_query("piped_cached", 0.0, true);
                let age = cache
                    .age_secs(&crate::cache::SearchResultCache::cache_key(&request, &scope))
                    .await;
                cached.server_wall_ms = Some(handler_started.elapsed().as_millis() as u64);
                cached.queue_wait_ms = Some(0);
                return Ok((
                    cache_status_headers(true, age),
                    Json(SearchResultResponse::Sync(cached)),
                ));
            }
        }
    }

    // Synchronous execution (cache miss). NAN-701: sync path now also goes
    // through the admission controller — previously it bypassed the
    // per-user limit / queue / timeout entirely, so dashboard panel
    // refreshes overshot `max_concurrent_queries_for_user`.
    let start = Instant::now();
    // NAN-4664: identical searches already running share one run (the
    // leader holds the admission slot; followers take none). Fresh, not
    // cached, so it applies to `use_cache: false` and bypass refreshes too.
    // The identity folds the caller's effective deny sets, so a caller never
    // follows a run computed under a wider (or different) scope.
    let share_key = (!progressive_views
        && crate::inflight::share_eligible(&request.query, scope.deny_set()))
    .then(|| {
        crate::cache::SearchResultCache::inflight_key_for(
            &request,
            &scope,
            &inflight_authority_fingerprint(priority),
        )
    });
    // Set when this request followed another's run (an atomic: the handler
    // future must stay Send).
    let followed = std::sync::atomic::AtomicBool::new(false);
    let run_search = || {
        nanosiem_core::search::streaming::DEFER_LATERAL_VIEW.scope(
            progressive_views,
            state
                .search
                .search_with_admission(request.clone(), admission_user, priority, &scope),
        )
    };
    let interactive = async {
        match share_key.as_deref() {
            Some(key) => {
                let (result, role) = crate::inflight::searches()
                    .run(key, run_search, crate::inflight::query_determined_failure)
                    .await;
                followed.store(
                    role == crate::inflight::Role::Follower,
                    std::sync::atomic::Ordering::Relaxed,
                );
                result
            }
            None => run_search().await,
        }
    };
    let result = if accept_async {
        // NAN-4915 hand-off: the interactive budget bounds how long this
        // request may hold an interactive admission slot. Past it, the query is
        // KILLed (its permit is released when the future drops) and the search
        // continues as a durable background job on the background permit pool.
        let handoff = state.background_jobs.config().interactive_handoff;
        match tokio::time::timeout(handoff, interactive).await {
            Ok(result) => result,
            Err(_elapsed) => {
                if let Some(request_id) = request.request_id.as_deref() {
                    if let Err(e) = state.search.cancel_query(request_id).await {
                        tracing::warn!(error = %e, %request_id, "Could not KILL the interactive query being handed off");
                    }
                }
                let outcome = super::background_jobs::submit_job(
                    &state,
                    &auth,
                    &request,
                    &scope,
                    JobOrigin::Escalated,
                )
                .await?;
                record_search_query("piped_escalated", start.elapsed().as_secs_f64() * 1000.0, true);
                tracing::info!(
                    job_id = %outcome.job.public_id(),
                    attached = outcome.attached,
                    handoff_secs = handoff.as_secs(),
                    "Interactive search handed off to a background job"
                );
                return Ok((
                    super::background_jobs::job_headers(cache_status_headers(false, None), &outcome),
                    Json(SearchResultResponse::Async(
                        super::background_jobs::async_response(&outcome),
                    )),
                ));
            }
        }
    } else {
        interactive.await
    };
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("piped", duration_ms, result.is_ok());

    // Cache successful results in the background, keyed under the scope the
    // query executed with. NAN-4664: a follower's result is the leader's,
    // which the leader writes.
    let follower = followed.load(std::sync::atomic::Ordering::Relaxed);
    if let (Ok(response), false) = (&result, follower || progressive_views) {
        if let Some(ref cache) = state.result_cache {
            let cache = cache.clone();
            let req = request.clone();
            let scope_for_cache = scope.clone();
            let resp = response.clone();
            tokio::spawn(async move {
                cache.set(&req, &resp, &scope_for_cache).await;
            });
        }
    }

    let mut headers = cache_status_headers(false, None);
    if share_key.is_some() {
        headers.insert(
            INFLIGHT_HEADER,
            axum::http::HeaderValue::from_static(if follower { "follower" } else { "leader" }),
        );
    }
    let mut response = result?;
    response.server_wall_ms = Some(handler_started.elapsed().as_millis() as u64);
    if follower {
        // A follower waits on the in-flight leader, not the admission queue.
        response.queue_wait_ms = Some(0);
    }
    Ok((headers, Json(SearchResultResponse::Sync(response))))
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
        let local_owner = state
            .search
            .query_tracker()
            .get(&request_id)
            .and_then(|info| info.owner_principal_id);
        let owner = if local_owner.is_some() {
            local_owner
        } else {
            match state.shared_query_owner(&request_id).await {
                Ok(owner) => owner,
                // Fail closed: an unavailable ownership registry is not
                // permission to cancel. `None` never matches a principal.
                Err(error) => {
                    tracing::warn!(%error, %request_id, "Shared query ownership unavailable during cancellation");
                    None
                }
            }
        };
        if owner != Some(principal) {
            return Ok(Json(CancelSearchResponse { cancelled: false }));
        }
    }

    let cancelled = state.search.cancel_query(&request_id).await.map_err(|e| {
        tracing::error!(error = %e, request_id = %request_id, "Failed to cancel query");
        SearchError::QueryError("Failed to cancel query".to_string())
    })?;

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
    let result = state
        .search
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
    /// for a spans/metrics/risk query (NAN-1569, NAN-1798).
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
    // NAN-1799: pass the composed scope so "Inspect SQL" renders the exact
    // gated SQL the executed path runs for this caller.
    let scope = effective_scope(&auth);
    let start = Instant::now();
    let result = state
        .search
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
            if msg.starts_with("Invalid query:")
                || msg.starts_with("Unsupported operation:")
            {
                return SearchError::QueryError(msg.clone());
            }
        }
        SearchError::QueryError("Query processing failed".to_string())
    })?;
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
    /// Source type hint (NAN-1032). When provided, the query can use the
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

    let start = Instant::now();
    let result = state
        .search
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
        Ok(event) => Ok(Json(FetchLogResponse { event })),
        Err(e) => {
            tracing::error!(error = %e, log_id = %request.id, "Failed to fetch log");
            Err(SearchError::QueryError(
                "Failed to fetch log event".to_string(),
            ))
        }
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
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "prevart",
        &[
            request.query.as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<PrevalenceScatterData>(&cache_key).await {
                record_search_query("prevalence_artifacts_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let start = Instant::now();
    let result = state.search.get_prevalence_artifacts(&request, &scope).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("prevalence_artifacts", duration_ms, result.is_ok());

    match &result {
        Ok(_) => tracing::info!("Prevalence artifacts completed in {:.2}ms", duration_ms),
        Err(e) => tracing::error!("Prevalence artifacts failed: {:?}", e),
    }

    let response = result?;
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
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
        (status = 200, description = "Field statistics with cardinality", body = FieldStatsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn field_stats_for_query(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<FieldStatsRequest>,
) -> Result<(axum::http::HeaderMap, Json<FieldStatsResponse>), SearchError> {
    use nanosiem_core::search::QueryPriority;

    // NAN-2028: runs a query over the log store — same search:execute gate.
    require_search_execute(&auth)?;
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
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "fstats",
        &[
            query.as_bytes(),
            request.start.timestamp_micros().to_string().as_bytes(),
            request.end.timestamp_micros().to_string().as_bytes(),
            // JSON-encode (not join) so a comma in a column name can't shift the
            // boundary — ["a,b"] must not collide with ["a","b"] (NAN-1593 review).
            serde_json::to_string(&request.columns).unwrap_or_default().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<FieldStatsResponse>(&cache_key).await {
                record_search_query("field_stats_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    // NAN-1428: reserve ownership of the request_id so the cancel endpoint
    // can authorize killing the derived `{request_id}-fstats` query even
    // after the main search has completed and unregistered the id.
    if let Some(rid) = request.request_id.clone() {
        // NAN-2100: reserve under the CREDENTIAL (see `reserve_query_owner`).
        reserve_query_owner(&state, rid, auth.credential_principal_id()).await?;
    }

    // NAN-1427: admission-gated, with the derived companion query_id and
    // per-priority CH settings. `columns` (when sent by the UI) reduces the
    // stat'd column set to what the field panel actually renders.
    let fields = state
        .search
        .get_field_stats_with_admission(
            &query,
            &time_range,
            request.columns.as_deref(),
            request.request_id.as_deref(),
            super::admission_user(&auth)?,
            QueryPriority::Interactive,
            request.dataset.as_deref(),
            &scope,
        )
        .await?;
    let total_events = fields.iter().map(|f| f.count).max().unwrap_or(0);

    let response = FieldStatsResponse {
        fields,
        total_events,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
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
    let cache_key = crate::cache::SearchResultCache::companion_key(
        // NAN-2344: response metadata now distinguishes returned top-N
        // coverage from the full population. Version the cache namespace so a
        // rolling deploy never asks the new response type to deserialize the
        // older, ambiguous shape.
        "fvalues-v2",
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
                record_search_query("field_values_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let result = state
        .search
        .get_field_values(
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

    let values = result?;
    let response = field_values_response(request.field, values, request.limit);
    if let Some(cache) = state.result_cache.as_ref() {
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
    /// Per-query dataset selector (NAN-1559): `logs` (default), `spans`,
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
    /// Client request id of the originating search (NAN-1428). When set, the
    /// field-stats query runs under the derived ClickHouse query_id
    /// `{request_id}-fstats`, so `DELETE /api/search/{request_id}` cancels it
    /// together with the data query.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Optional column subset to compute stats for (NAN-1427). The stats
    /// query's I/O scales with the number of columns aggregated, so callers
    /// should send only the columns they render. Names are intersected with
    /// the live table inventory (unknown names dropped; an empty intersection
    /// falls back to the full set). Omit for the full column inventory.
    #[serde(default)]
    pub columns: Option<Vec<String>>,
    /// Per-query dataset selector (NAN-1559): `logs` (default), `spans`,
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
            body.contains(".get_field_values("),
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

    /// The NAN-2219 case: an ordinary analyst on a tenant whose
    /// `restricted_source_types` registry is empty. `audit:view` is Admin-only,
    /// so its absence must NOT be read as a per-source boundary.
    #[test]
    fn unscoped_caller_without_audit_view_is_row_restricted_but_not_artifact_restricted() {
        for auth in [jwt_auth(&[SEARCH_EXECUTE_ID]), api_key_auth(&[SEARCH_EXECUTE_ID])] {
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
        for mut auth in [jwt_auth(&[SEARCH_EXECUTE_ID]), api_key_auth(&[SEARCH_EXECUTE_ID])] {
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
