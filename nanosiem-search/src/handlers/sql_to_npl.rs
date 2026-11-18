// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL → nPL (NAN-5575). Converts agent-written Agent Lane SQL into nPL a
//! person can open in Search. Static and read-only: nothing is executed, no
//! data is read. The AI fallback is a separate, explicit enterprise call
//! (`POST /api/melod/sql-to-npl`).

use axum::{extract::State, Json};
use nanosiem_core::query::sql_to_npl::{
    convert_request, ConvertContext, Difference, DifferenceKind, SqlSpan, SqlToNplBatchRequest,
    SqlToNplBatchResponse, SqlToNplRequest, SqlToNplResponse, MAX_BATCH,
};
use utoipa::OpenApi;

use super::require_search_execute;
use crate::error::{ErrorResponse, SearchError};
use crate::SearchState;

fn context(state: &SearchState) -> ConvertContext {
    ConvertContext::new(state.search.active_profile().clone())
}

/// Convert one Agent Lane SQL query to nPL.
///
/// Returns the nPL, the Search time range (the SQL's `timestamp` bounds, with
/// the run-window placeholders bound to `window_start` / `window_end`), and
/// whether the compiled nPL provably matches the SQL (`exact`). SQL outside
/// the convertible subset comes back with `unsupported_reason` and no nPL.
#[utoipa::path(
    post,
    path = "/api/search/sql-to-npl",
    tag = "search",
    request_body = SqlToNplRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Conversion result (also for SQL that cannot be converted)", body = SqlToNplResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute", body = ErrorResponse),
    )
)]
pub async fn sql_to_npl(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<SqlToNplRequest>,
) -> Result<Json<SqlToNplResponse>, SearchError> {
    // Converting reads no data, but its output is a query to run in Search:
    // the same gate as Search itself.
    require_search_execute(&auth)?;
    Ok(Json(convert_request(&request, &context(&state))))
}

/// Convert up to 50 Agent Lane SQL queries in one call (one view's SQL steps).
#[utoipa::path(
    post,
    path = "/api/search/sql-to-npl/batch",
    tag = "search",
    request_body = SqlToNplBatchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Results in request order", body = SqlToNplBatchResponse),
        (status = 400, description = "More than 50 items", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute", body = ErrorResponse),
    )
)]
pub async fn sql_to_npl_batch(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<SqlToNplBatchRequest>,
) -> Result<Json<SqlToNplBatchResponse>, SearchError> {
    require_search_execute(&auth)?;
    if request.items.len() > MAX_BATCH {
        return Err(SearchError::BadRequest(format!("at most {MAX_BATCH} queries per batch")));
    }
    let ctx = context(&state);
    let results = request.items.iter().map(|r| convert_request(r, &ctx)).collect();
    Ok(Json(SqlToNplBatchResponse { results }))
}

#[derive(OpenApi)]
#[openapi(
    paths(sql_to_npl, sql_to_npl_batch),
    components(schemas(
        SqlToNplRequest,
        SqlToNplBatchRequest,
        SqlToNplResponse,
        SqlToNplBatchResponse,
        Difference,
        DifferenceKind,
        SqlSpan
    ))
)]
pub struct SqlToNplApiDoc;
