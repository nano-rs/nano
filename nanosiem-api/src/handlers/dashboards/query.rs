// SPDX-License-Identifier: AGPL-3.0-or-later

//! Panel query execution and variable substitution helpers

use axum::{extract::State, Extension, Json};
use nanosiem_core::{
    auth::permissions,
    query::parse_query,
    search::query_processing::{
        classify_query_cost, substitute_panel_variables, validate_panel_query_commands,
        validate_panel_query_unscoped_prevalence,
    },
    SearchRequest, SearchResponse,
};
use nanosiem_search::cache::SearchResultCache;

use super::types::{PanelQueryRequest, PanelQueryResponse};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Hard row cap for panel queries (both arms). A result that hits this cap when
/// more rows matched is flagged `truncated` in the response (DSH40).
const PANEL_ROW_LIMIT: usize = 10_000;

/// Execute a panel query
///
/// Supports both piped query syntax and raw SQL mode.
/// Variables in the query (e.g., $field) are substituted with provided values.
#[utoipa::path(
    post,
    path = "/api/dashboards/panel/query",
    tag = "dashboards",
    request_body = PanelQueryRequest,
    responses(
        (status = 200, description = "Query executed successfully", body = PanelQueryResponse),
        (status = 400, description = "Invalid query"),
        (status = 403, description = "Forbidden - missing dashboards:view permission"),
    ),
    security(("api_key" = []))
)]
pub async fn panel_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<PanelQueryRequest>,
) -> Result<Json<PanelQueryResponse>, ApiError> {
    ensure_permission(&auth, permissions::DASHBOARDS_VIEW)?;

    let is_sql = request.query_mode.as_str() == "sql";

    // DSH19: substitution escapes per target language, so it must know the mode
    // (the piped nPL arm and the SQL arm have different quoting/escaping rules).
    let query = substitute_panel_variables(&request.query, &request.variables, is_sql);

    // NAN-1799: compose the effective deny-set once for the PIPED arm — the
    // service injects it into the nPL query AST (per-source RBAC + the audit-log
    // gate). Union the `audit` source into the caller's per-source deny set
    // unless they hold `audit:view`; an unrestricted caller with `audit:view`
    // yields a byte-identical query (empty deny set => unrestricted scope).
    // NAN-2001: this audit-folded scope is the PIPED arm's audit mechanism ONLY.
    // The raw-SQL arm must NOT use it (it would fail closed for every non-audit
    // caller); the SQL arm builds a source-only scope + an explicit
    // RawSqlAuditAccess below, and the ClickHouse row policy hides audit rows.
    // NAN-2219: use the canonical composer rather than re-inlining it — a
    // hand-built `ScopeSet::from_denied(..)` loses the row-filter/artifact
    // split, which silently re-restricts a `| prevalence` panel for every
    // caller without `audit:view`.
    let scope = auth.effective_viewer_scope();

    // Execute based on query mode. Each arm yields
    // `(response, cached, cache_age_secs)` so the caller can report cache
    // transparency (DSH8, CONTRACT 1).
    let (response, cached, cache_age_secs): (SearchResponse, bool, Option<u64>) = if is_sql {
        // DSH1: raw SQL is a privileged surface. `panel_query` previously
        // gated only on `dashboards:view`, letting a dashboards-viewer (incl.
        // demo users, who are granted `dashboards:view` + `search:execute` but
        // deliberately NOT `search:sql`) run arbitrary SELECTs over the full
        // logs table, 10k rows/call, with no admission control. Require the
        // dedicated permission here, mirroring `nanosiem-search`'s /api/search/sql
        // handler ("Raw SQL queries require the search:sql permission").
        ensure_permission(&auth, permissions::SEARCH_SQL)?;

        // DSH60: bind SQL panels to the dashboard time picker via opt-in
        // Grafana-style macros — `$__timeFilter(col)`, `$__timeFrom`,
        // `$__timeTo` — expanded against the dashboard window. This must run
        // BEFORE the SQL reaches the service, whose `validate_sql` parses it and
        // cannot tolerate an un-expanded macro. SQL with no macro is unchanged
        // (and still scans all time, as before); authors opt in with e.g.
        // `... WHERE $__timeFilter(timestamp) ...`. The injected literals come
        // from the dashboard window, not user input — no injection surface.
        let query = nanosiem_core::sql_hygiene::expand_sql_time_macros(
            &query,
            &request.time_range.start,
            &request.time_range.end,
        );

        // Execute raw SQL query.
        //
        // NAN-2001: the SQL arm must NOT fold `audit` into the scope — the shared
        // audit-folded `scope` above would trip search_sql's per-source
        // fail-closed guard (`scope.is_restricted()`) and REFUSE every caller
        // without `audit:view`, instead of hiding audit rows. So pass a
        // SOURCE-ONLY scope (per-source denials still fail closed via NAN-1799)
        // plus an explicit RawSqlAuditAccess: audit rows are hidden by the
        // ClickHouse `nanosiem_rawsql_noaudit` identity's RESTRICTIVE row policy.
        // The audit-folded `scope` remains the PIPED arm's mechanism (unchanged).
        let sql_scope =
            nanosiem_core::auth::ScopeSet::from_denied(auth.denied_sources.deny_set().clone());
        let audit_access = if auth.has_permission(permissions::AUDIT_VIEW) {
            nanosiem_core::search::RawSqlAuditAccess::Visible
        } else {
            nanosiem_core::search::RawSqlAuditAccess::Hidden
        };
        let sql_request = nanosiem_core::RawSqlRequest {
            sql: query,
            time_range: request.time_range,
            limit: Some(PANEL_ROW_LIMIT),
            offset: None,
        };
        // Raw SQL is neither cached nor routed through admission control here.
        (
            state
                .search_service
                .search_sql(sql_request, &sql_scope, audit_access)
                .await?,
            false,
            None,
        )
    } else {
        // DSH1: the piped arm previously ran with only `dashboards:view`.
        // Require `search:execute` (the canonical piped-search permission) in
        // addition, matching the retro/search paths.
        ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

        // NAN-1799: the piped audit + per-source gate is applied by the service,
        // which injects the composed deny-set (`&scope`) into the query AST. The
        // handler no longer runs its own `enforce_non_audit_query` rewrite — the
        // deny-set threaded through `search_with_admission` below covers it.

        // Default to piped query mode.
        //
        // NAN-701: All four hardcoded flags below were wrong.
        //   - skip_histogram=false fired an unused histogram subquery per panel.
        //   - skip_field_stats=false fired an unused field-stats subquery per panel.
        //   - use_cache=false disabled CH server-side query cache, forcing
        //     re-execution on every dashboard refresh.
        //   - async_mode=false bypassed admission control (the gate lives in
        //     the search handler's async branch). Fixed by routing through
        //     `search_with_admission`, which gates the sync path too.
        let search_request = SearchRequest {
            query,
            time_range: request.time_range,
            limit: Some(PANEL_ROW_LIMIT),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: true,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        };

        // NAN-708: parse once, then (a) reject surface-bound commands
        // that have dedicated nanosiem UIs (tree/asset/cloud/ai/lateral/funnel)
        // and produce shape-incompatible output for generic panels, and
        // (b) classify cost so cheap panels jump the admission queue
        // ahead of expensive ones (prevalence, lookup, wide time). The
        // admission heap is priority-aware, so under load the dashboard
        // fills in cheap-to-expensive instead of every panel spinning
        // together. Detection rules bypass admission entirely and are
        // unaffected.
        let parsed = parse_query(&search_request.query)
            .map_err(|e| ApiError::ParseError(format!("{}", e)))?;
        if let Err(blocked) = validate_panel_query_commands(&parsed) {
            return Err(ApiError::ValidationError(format!(
                "The `| {}` command isn't supported in dashboard panels — {}.",
                blocked.keyword(),
                blocked.redirect_hint()
            )));
        }
        // NAN-712: reject `| prevalence` panels when the resolved query
        // has zero narrowing — `*`-defaulted variables turn dashboards
        // into "scan everything for rarity," the worst-case shape that
        // pinned saturn even with NAN-701..709 in place. The frontend
        // recognizes the UNSCOPED_PREVALENCE error code and renders a
        // panel-level "Apply a filter to load this panel" empty state
        // instead of a generic error banner.
        if let Err(wildcard_fields) = validate_panel_query_unscoped_prevalence(&parsed) {
            return Err(ApiError::UnscopedPrevalence(wildcard_fields));
        }
        let priority = classify_query_cost(&parsed, &search_request.time_range);

        // NAN-702: reuse the same compressed cache the search HTTP handler
        // populates. DSH8/CONTRACT 1: we inline the get/set that
        // `SearchResultCache::execute_or_cache` does (rather than call it) so we
        // can report hit-vs-miss and the entry age to the client, and honor a
        // user-initiated `bypass_cache` (the panel Refresh affordance). Falls
        // through to a plain `search_with_admission` when REDIS_URL is unset.
        let user_id = auth.claims.sub;
        let search_service = state.search_service.clone();
        // NAN-1799: move a clone of the effective scope into the admission
        // closure so the original `scope` stays available for the scoped
        // cache-key computation below.
        let run_scope = scope.clone();
        let run = move |req: SearchRequest| async move {
            search_service
                .search_with_admission(req, user_id, priority, &run_scope)
                .await
        };

        let bypass = request.bypass_cache.unwrap_or(false);
        match state.search_result_cache.as_ref() {
            Some(cache) if !bypass => match cache.get(&search_request, &scope).await {
                Some(hit) => {
                    let age = cache
                        .age_secs(&SearchResultCache::cache_key(&search_request, &scope))
                        .await;
                    (hit, true, age)
                }
                None => {
                    let resp = run(search_request.clone()).await?;
                    spawn_cache_set(cache, &search_request, &resp, &scope);
                    (resp, false, None)
                }
            },
            Some(cache) => {
                // Bypass: recompute live and repopulate the cache for the next
                // caller (mirrors the search handler's cache-bypass refresh).
                let resp = run(search_request.clone()).await?;
                spawn_cache_set(cache, &search_request, &resp, &scope);
                (resp, false, None)
            }
            None => (run(search_request).await?, false, None),
        }
    };

    // DSH40: a result is truncated only when it hits the hard row cap AND more
    // rows matched. Aggregations that return fewer rows than the underlying
    // record count are NOT truncated.
    let shown = response.results.len();
    let truncated = shown == PANEL_ROW_LIMIT && response.total_count > shown as u64;

    Ok(Json(PanelQueryResponse {
        results: response.results,
        // DSH53: forward column_order so numeric group-by columns render as
        // labels, not values, on the client.
        column_order: response.column_order,
        total_count: response.total_count,
        execution_time_ms: response.execution_time_ms,
        truncated,
        cached,
        cache_age_secs,
    }))
}

/// Populate the result cache in the background — mirrors
/// `SearchResultCache::execute_or_cache`'s fire-and-forget SET so the caller
/// isn't blocked on the Redis write (DSH8).
fn spawn_cache_set(
    cache: &SearchResultCache,
    request: &SearchRequest,
    response: &SearchResponse,
    scope: &nanosiem_core::auth::ScopeSet,
) {
    let cache = cache.clone();
    let req = request.clone();
    let resp = response.clone();
    let scope = scope.clone();
    tokio::spawn(async move {
        cache.set(&req, &resp, &scope).await;
    });
}
