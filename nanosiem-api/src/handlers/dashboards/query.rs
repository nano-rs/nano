// SPDX-License-Identifier: AGPL-3.0-or-later

//! Panel query execution and variable substitution helpers

use axum::{extract::State, Extension, Json};
use nanosiem_core::{
    auth::permissions,
    query::parse_query,
    search::query_processing::{
        classify_query_cost, validate_panel_query_commands,
        validate_panel_query_unscoped_prevalence,
    },
    SearchRequest, SearchResponse,
};
use nanosiem_search::cache::SearchResultCache;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

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
    let query = substitute_variables(&request.query, &request.variables, is_sql);

    // NAN-704: gate audit-log access for users without `audit:view`.
    // `panel_query` is the only authenticated search surface that lacked
    // this gate (see `nanosiem-search/src/handlers/search.rs:62` for the
    // canonical pattern). The enforcement is applied INSIDE each query
    // mode arm because piped vs SQL use different rewrite functions and
    // different parsers — running the piped rewrite on raw SQL would
    // fail with a parse error.
    let has_audit_view = auth.claims.has_permission(permissions::AUDIT_VIEW);

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
        // BEFORE `inject_audit_filter` (below), which parses the SQL and cannot
        // tolerate an un-expanded macro. SQL with no macro is unchanged (and
        // still scans all time, as before); authors opt in with e.g.
        // `... WHERE $__timeFilter(timestamp) ...`. The injected literals come
        // from the dashboard window, not user input — no injection surface.
        let query = nanosiem_core::sql_hygiene::expand_sql_time_macros(
            &query,
            &request.time_range.start,
            &request.time_range.end,
        );

        // Execute raw SQL query.
        //
        // NAN-704: audit gate applied at the SQL level via
        // `inject_audit_filter`. Mirrors the /api/search/sql
        // handler's enforcement (`nanosiem-search/src/handlers/search.rs:232`).
        // Trailing `;` is stripped because the filter injection
        // parses the SQL and wouldn't tolerate it.
        let sql = if has_audit_view {
            query
        } else {
            nanosiem_core::search::inject_audit_filter(query.trim_end_matches(';'))
                .map_err(ApiError::from)?
        };
        let sql_request = nanosiem_core::RawSqlRequest {
            sql,
            time_range: request.time_range,
            limit: Some(PANEL_ROW_LIMIT),
            offset: None,
        };
        // Raw SQL is neither cached nor routed through admission control here.
        (
            state.search_service.search_sql(sql_request).await?,
            false,
            None,
        )
    } else {
        // DSH1: the piped arm previously ran with only `dashboards:view`.
        // Require `search:execute` (the canonical piped-search permission) in
        // addition, matching the retro/search paths.
        ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

        // NAN-704: piped audit gate, AST-level rewrite. Wraps any
        // `OR`-based attempt to bypass with `(<orig>) AND source_type != "audit"`.
        let query = if has_audit_view {
            query
        } else {
            nanosiem_core::search::query_processing::enforce_non_audit_query(&query)
                .map_err(ApiError::from)?
        };

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
        let run = move |req: SearchRequest| async move {
            search_service
                .search_with_admission(req, user_id, priority)
                .await
        };

        let bypass = request.bypass_cache.unwrap_or(false);
        match state.search_result_cache.as_ref() {
            Some(cache) if !bypass => match cache.get(&search_request).await {
                Some(hit) => {
                    let age = cache
                        .age_secs(&SearchResultCache::cache_key(&search_request))
                        .await;
                    (hit, true, age)
                }
                None => {
                    let resp = run(search_request.clone()).await?;
                    spawn_cache_set(cache, &search_request, &resp);
                    (resp, false, None)
                }
            },
            Some(cache) => {
                // Bypass: recompute live and repopulate the cache for the next
                // caller (mirrors the search handler's cache-bypass refresh).
                let resp = run(search_request.clone()).await?;
                spawn_cache_set(cache, &search_request, &resp);
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
fn spawn_cache_set(cache: &SearchResultCache, request: &SearchRequest, response: &SearchResponse) {
    let cache = cache.clone();
    let req = request.clone();
    let resp = response.clone();
    tokio::spawn(async move {
        cache.set(&req, &resp).await;
    });
}

/// Substitute `$name` variables in a query string.
///
/// DSH18: a single left-to-right regex pass (`$([A-Za-z_][A-Za-z0-9_]*)`) with
/// a map lookup — NOT the previous per-entry `str::replace` over
/// nondeterministic HashMap order, which (a) shadowed prefixed identifiers
/// (`$host` clobbering `$host_group`) and (b) re-scanned the accumulated
/// string, so a value that happened to contain `$othervar` was substituted
/// again. Only **defined** names are substituted; an unknown `$token` is left
/// intact (matching prior server behavior and avoiding silent corruption).
///
/// DSH19: values are escaped per target language.
/// - SQL arm: SQL-escape (`''` doubling + backslash) exactly as before; the SQL
///   author supplies the surrounding quotes (`col = '$var'`).
/// - Piped (nPL) arm: nPL has NO backslash escaping (NAN-1157) and no `''`
///   convention. A bare `field=$var` is wrapped in double quotes so multi-word
///   / special-char values stay a single term; a `$var` already sitting inside
///   a quoted literal (preceded by `"` or `'`) is inserted un-wrapped. In both
///   cases the active quote char is STRIPPED from the value (not backslashed),
///   since nPL can't represent an escaped quote.
fn substitute_variables(
    query: &str,
    variables: &Option<HashMap<String, String>>,
    is_sql: bool,
) -> String {
    let vars = match variables {
        Some(v) => v,
        None => return query.to_string(),
    };

    static VAR_RE: OnceLock<Regex> = OnceLock::new();
    let re = VAR_RE.get_or_init(|| Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").unwrap());

    let mut out = String::with_capacity(query.len());
    let mut last = 0;
    for caps in re.captures_iter(query) {
        let whole = caps.get(0).unwrap();
        let name = &caps[1];
        let value = match vars.get(name) {
            Some(v) => v,
            // Leave undefined `$token` intact (do not advance `last`, so the
            // literal text is preserved by the next append / the tail append).
            None => continue,
        };

        out.push_str(&query[last..whole.start()]);
        if is_sql {
            out.push_str(&escape_sql_value(value));
        } else {
            out.push_str(&format_piped_value(value, query[..whole.start()].chars().next_back()));
        }
        last = whole.end();
    }
    out.push_str(&query[last..]);
    out
}

/// Format a substituted value for the piped (nPL) arm (DSH19). `preceding` is
/// the char immediately before the `$token`; when it's a quote the token is
/// inside a string literal, so the value is inserted without adding new quotes.
/// nPL has no backslash escaping, so the active quote char is stripped.
fn format_piped_value(value: &str, preceding: Option<char>) -> String {
    match preceding {
        Some(q @ ('"' | '\'')) => value.replace(q, ""),
        _ => format!("\"{}\"", value.replace('"', "")),
    }
}

/// Escape a value for safe SQL interpolation.
/// Escapes single quotes by doubling them, and escapes backslashes.
fn escape_sql_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_variables_piped_quotes_and_isolates() {
        let query = "source_type = $source AND severity = $level";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "apache".to_string());
        vars.insert("level".to_string(), "error".to_string());

        // Piped arm quote-wraps bare values so multi-word / special-char values
        // stay a single term (DSH4/DSH19).
        let result = substitute_variables(query, &Some(vars), false);
        assert_eq!(result, "source_type = \"apache\" AND severity = \"error\"");
    }

    #[test]
    fn test_substitute_variables_sql_escapes_only() {
        let query = "source_type = '$source'";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "O'Brien".to_string());

        // SQL arm doubles single quotes; the author supplies the quotes.
        let result = substitute_variables(query, &Some(vars), true);
        assert_eq!(result, "source_type = 'O''Brien'");
    }

    #[test]
    fn test_substitute_variables_no_vars() {
        let query = "source_type = apache";
        let result = substitute_variables(query, &None, false);
        assert_eq!(result, "source_type = apache");
    }

    #[test]
    fn test_substitute_variables_missing_var_left_intact() {
        let query = "source_type = $source AND severity = $level";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "apache".to_string());
        // $level is not provided, should remain as-is.

        let result = substitute_variables(query, &Some(vars), false);
        assert_eq!(result, "source_type = \"apache\" AND severity = $level");
    }

    #[test]
    fn test_substitute_variables_prefix_shadowing() {
        // DSH18: `$host` must not clobber `$host_group`, regardless of map order.
        let query = "src_host=$host AND group=$host_group";
        let mut vars = HashMap::new();
        vars.insert("host".to_string(), "web1".to_string());
        vars.insert("host_group".to_string(), "prod".to_string());

        let result = substitute_variables(query, &Some(vars), false);
        assert_eq!(result, "src_host=\"web1\" AND group=\"prod\"");
    }

    #[test]
    fn test_substitute_variables_piped_no_backslash_escape() {
        // DSH19: nPL keeps backslashes literal; the value is quote-wrapped, and
        // embedded double quotes are stripped (not backslash-escaped).
        let query = "file_path=$path";
        let mut vars = HashMap::new();
        vars.insert("path".to_string(), r#"C:\Windows\a"b"#.to_string());

        let result = substitute_variables(query, &Some(vars), false);
        assert_eq!(result, r#"file_path="C:\Windows\ab""#);
    }

    #[test]
    fn test_substitute_variables_piped_inside_quotes() {
        // A `$var` already inside a quoted literal is inserted un-wrapped, with
        // the active quote char stripped.
        let query = "user=\"$user\"";
        let mut vars = HashMap::new();
        vars.insert("user".to_string(), "John \"JD\" Smith".to_string());

        let result = substitute_variables(query, &Some(vars), false);
        assert_eq!(result, "user=\"John JD Smith\"");
    }
}
