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
    SearchRequest,
};
use std::collections::HashMap;

use super::types::{PanelQueryRequest, PanelQueryResponse};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

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

    // Substitute variables in the query
    let query = substitute_variables(&request.query, &request.variables);

    // NAN-704: gate audit-log access for users without `audit:view`.
    // `panel_query` is the only authenticated search surface that lacked
    // this gate (see `nanosiem-search/src/handlers/search.rs:62` for the
    // canonical pattern). The enforcement is applied INSIDE each query
    // mode arm because piped vs SQL use different rewrite functions and
    // different parsers — running the piped rewrite on raw SQL would
    // fail with a parse error.
    let has_audit_view = auth.claims.has_permission(permissions::AUDIT_VIEW);

    // Execute based on query mode
    let response = match request.query_mode.as_str() {
        "sql" => {
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
                limit: Some(10000), // Panel queries can return more results
                offset: None,
            };
            state.search_service.search_sql(sql_request).await?
        }
        _ => {
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
                limit: Some(10000),
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

            // NAN-702: route through SearchResultCache::execute_or_cache so
            // dashboard refreshes hit the same compressed responses the
            // search HTTP handler caches. Falls through to a plain
            // search_with_admission when REDIS_URL is unset.
            let user_id = auth.claims.sub;
            let search_service = state.search_service.clone();
            let run = move |req: SearchRequest| async move {
                search_service
                    .search_with_admission(req, user_id, priority)
                    .await
            };
            match state.search_result_cache.as_ref() {
                Some(cache) => cache.execute_or_cache(&search_request, run).await?,
                None => run(search_request).await?,
            }
        }
    };

    Ok(Json(PanelQueryResponse {
        results: response.results,
        total_count: response.total_count,
        execution_time_ms: response.execution_time_ms,
    }))
}

/// Substitute variables in a query string
///
/// Variables are in the format $variable_name and are replaced with
/// the corresponding value from the variables map.
fn substitute_variables(query: &str, variables: &Option<HashMap<String, String>>) -> String {
    let vars = match variables {
        Some(v) => v,
        None => return query.to_string(),
    };

    let mut result = query.to_string();
    for (key, value) in vars {
        // Replace $key with the value, escaping single quotes to prevent SQL injection
        let pattern = format!("${}", key);
        let escaped_value = escape_sql_value(value);
        result = result.replace(&pattern, &escaped_value);
    }

    result
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
    fn test_substitute_variables() {
        let query = "source_type = $source AND severity = $level";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "apache".to_string());
        vars.insert("level".to_string(), "error".to_string());

        let result = substitute_variables(query, &Some(vars));
        assert_eq!(result, "source_type = apache AND severity = error");
    }

    #[test]
    fn test_substitute_variables_no_vars() {
        let query = "source_type = apache";
        let result = substitute_variables(query, &None);
        assert_eq!(result, "source_type = apache");
    }

    #[test]
    fn test_substitute_variables_missing_var() {
        let query = "source_type = $source AND severity = $level";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "apache".to_string());
        // $level is not provided, should remain as-is

        let result = substitute_variables(query, &Some(vars));
        assert_eq!(result, "source_type = apache AND severity = $level");
    }
}
