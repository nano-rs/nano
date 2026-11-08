// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded provisional roots and exact, authorized job root/child pages
//! (NAN-3077). A `| tree` search sent with `x-nano-progressive-views: 1`
//! answers a pending marker at once; the client then paints a bounded
//! 200-row preview from here and pages the exact tree out of a durable
//! background job (NAN-4915) by `job_id`.
use crate::{
    error::{ErrorResponse, SearchError},
    SearchState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    Json,
};
use nanosiem_core::{
    query::{Command, PrettyPrint},
    search::{SearchRequest, SearchResponse},
    TimeRangeInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn page_size() -> usize {
    25
}
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TreePageRequest {
    /// Exact pages use an owned Search Job; preview uses query and time_range.
    pub job_id: Option<String>,
    pub query: Option<String>,
    pub time_range: Option<TimeRangeInput>,
    /// Child-index path within the deterministically ordered materialized forest.
    #[serde(default)]
    pub parent_path: Vec<usize>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "page_size")]
    pub limit: usize,
}
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TreePageResponse {
    pub status: String,
    pub error: Option<String>,
    pub preview: bool,
    pub nodes: Vec<Value>,
    pub config: Value,
    pub next_offset: Option<usize>,
    pub total_roots: usize,
    /// Counts describe the original materialized view, never unseen ancestry.
    pub total_nodes: usize,
    /// Input or reachable branches were capped/truncated; unseen ancestry is unknown.
    pub source_truncated: bool,
    pub total_count: u64,
    pub total_count_exact: bool,
    /// why the tree is empty, edgeless or partial (e.g. "No events
    /// in range carry http_request.referrer."), when the builder knows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub(crate) fn supports_paged_tree(query: &nanosiem_core::query::Query) -> bool {
    fn prefix(query: &nanosiem_core::query::Query) -> bool {
        match query {
            nanosiem_core::query::Query::Search(_) => true,
            nanosiem_core::query::Query::Piped { source, command } => {
                !matches!(
                    command,
                    Command::Tree { .. }
                        | Command::Asset { .. }
                        | Command::Cloud { .. }
                        | Command::Lateral { .. }
                        | Command::Ai { .. }
                        | Command::Output { .. }
                        | Command::Services
                        | Command::Service { .. }
                        | Command::Trace { .. }
                        | Command::Metric { .. }
                        | Command::Retro { .. }
                        | Command::Baseline { .. }
                        | Command::Funnel { .. }
                        // Mutable enrichments cannot guarantee stable child-index paths.
                        | Command::InputLookup { .. }
                        | Command::Lookup { .. }
                        | Command::Prevalence { .. }
                        | Command::ResolveIdentity { .. }
                        | Command::Risk { .. }
                ) && prefix(source)
            }
        }
    }
    matches!(query, nanosiem_core::query::Query::Piped { source, command: Command::Tree { .. } } if prefix(source))
}

/// Native SQL prefixes retain their semantics; the preview alone adds a bound.
pub fn preview_query(query: &str) -> Result<String, SearchError> {
    let parsed = nanosiem_core::query::parse_query(query)
        .map_err(|_| SearchError::BadRequest("Invalid tree query".into()))?;
    if !supports_paged_tree(&parsed) {
        return Err(SearchError::BadRequest(
            "This tree prefix retains the atomic path".into(),
        ));
    }
    let nanosiem_core::query::Query::Piped {
        source,
        command: command @ Command::Tree { .. },
    } = parsed
    else {
        return Err(SearchError::BadRequest(
            "Tree paging requires a terminal tree command".into(),
        ));
    };
    Ok(nanosiem_core::query::Query::Piped {
        source: Box::new(nanosiem_core::query::Query::Piped {
            source,
            command: Command::Head { count: 200 },
        }),
        command,
    }
    .pretty_print())
}

fn shallow_node(node: &Value, path: Vec<usize>) -> Value {
    let mut fields = node
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter(|(key, _)| key.as_str() != "children")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>()
        })
        .unwrap_or_default();
    let children = node["children"].as_array().map(Vec::len).unwrap_or(0);
    fields.insert("children".into(), json!([]));
    fields.insert("_children_count".into(), json!(children));
    fields.insert("_page_path".into(), json!(path));
    Value::Object(fields)
}

pub fn page_tree(
    response: &SearchResponse,
    request: &TreePageRequest,
    preview: bool,
) -> Result<TreePageResponse, SearchError> {
    if request.limit == 0
        || request.limit > 100
        || request.parent_path.len() > 16
        || request.offset > 20_000
    {
        return Err(SearchError::BadRequest(
            "Tree pages require limit 1..100, offset <=20000 and a path of at most 16 levels"
                .into(),
        ));
    }
    let marker = response
        .results
        .iter()
        .find(|row| row["_display_type"] == "tree")
        .ok_or_else(|| SearchError::BadRequest("Job does not contain a tree view".into()))?;
    let roots = marker["_tree_nodes"]
        .as_array()
        .ok_or_else(|| SearchError::BadRequest("Invalid tree result".into()))?;
    let mut siblings = roots;
    for index in &request.parent_path {
        siblings = siblings
            .get(*index)
            .and_then(|node| node["children"].as_array())
            .ok_or_else(|| SearchError::NotFound("Tree path not found".into()))?;
    }
    let nodes = siblings
        .iter()
        .enumerate()
        .skip(request.offset)
        .take(request.limit)
        .map(|(index, node)| {
            let mut path = request.parent_path.clone();
            path.push(index);
            shallow_node(node, path)
        })
        .collect::<Vec<_>>();
    let next = request.offset.saturating_add(nodes.len());
    let mut stack = roots.iter().collect::<Vec<_>>();
    let mut total_nodes = 0;
    let mut source_truncated = marker["_tree_truncated"] == true;
    while let Some(node) = stack.pop() {
        total_nodes += 1;
        source_truncated |= node["_truncated"] == true;
        if let Some(children) = node["children"].as_array() {
            stack.extend(children);
        }
    }
    Ok(TreePageResponse {
        status: "completed".into(),
        error: None,
        preview,
        nodes,
        config: marker["_tree_config"].clone(),
        next_offset: (next < siblings.len()).then_some(next),
        total_roots: roots.len(),
        total_nodes,
        source_truncated,
        total_count: response.total_count,
        // A stored job's tree is the complete materialized view; a preview
        // never claims exact counts.
        total_count_exact: !preview,
        note: marker["_tree_note"].as_str().map(str::to_string),
    })
}

#[utoipa::path(post, path = "/api/search/tree-page", tag = "search", request_body = TreePageRequest,
    responses((status = 200, description = "Bounded roots or children, or job progress", body = TreePageResponse),
        (status = 400, body = ErrorResponse), (status = 401, description = "Unauthorized"), (status = 403, description = "Missing search permission"),
        (status = 404, description = "Job or path unavailable")), security(("bearer_auth" = []), ("api_key" = [])))]
pub async fn get_tree_page(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Json(request): Json<TreePageRequest>,
) -> Result<Json<TreePageResponse>, SearchError> {
    super::require_search_execute(&auth)?;
    // Validate before starting work or reading any stored output.
    if request.limit == 0
        || request.limit > 100
        || request.parent_path.len() > 16
        || request.offset > 20_000
    {
        return Err(SearchError::BadRequest("Invalid tree page bounds".into()));
    }
    if let Some(job_id) = &request.job_id {
        if request.query.is_some() || request.time_range.is_some() {
            return Err(SearchError::BadRequest(
                "Supply job_id or preview query/time_range, not both".into(),
            ));
        }
        // Reuse the full search capability, ownership, tenant, source scope,
        // retention, signed-manifest and current-authority delivery fences.
        // The job's first stored row is the tree marker.
        let Json(status) = super::search_jobs::get_search_job(
            State(state),
            Extension(auth),
            Path(job_id.clone()),
            Query(super::search_jobs::JobStatusQuery { limit: Some(1) }),
        )
        .await?;
        if let Some(response) = &status.result {
            return Ok(Json(page_tree(response, &request, false)?));
        }
        return Ok(Json(TreePageResponse {
            status: serde_json::to_value(status.status)
                .unwrap_or_default()
                .as_str()
                .unwrap_or("failed")
                .into(),
            error: status.error,
            preview: false,
            nodes: vec![],
            config: Value::Null,
            next_offset: None,
            total_roots: 0,
            total_nodes: 0,
            source_truncated: false,
            total_count: 0,
            total_count_exact: false,
            note: None,
        }));
    }
    if !request.parent_path.is_empty() || request.offset != 0 {
        return Err(SearchError::BadRequest(
            "Preview supports only the first roots page".into(),
        ));
    }
    let query = preview_query(
        request
            .query
            .as_deref()
            .ok_or_else(|| SearchError::BadRequest("Missing preview query".into()))?,
    )?;
    let range = request
        .time_range
        .clone()
        .ok_or_else(|| SearchError::BadRequest("Missing preview time_range".into()))?;
    let response = state
        .search
        .search_with_admission(
            SearchRequest {
                query,
                time_range: range,
                limit: Some(1),
                offset: Some(0),
                include_sql: Some(false),
                skip_histogram: true,
                skip_field_stats: true,
                use_cache: false,
                table_view: false,
                request_id: None,
                async_mode: false,
                priority: None,
                dataset: Some("logs".into()),
            },
            super::admission_user(&auth)?,
            nanosiem_core::search::QueryPriority::Interactive,
            &super::search::effective_scope(&auth),
        )
        .await?;
    Ok(Json(page_tree(&response, &request, true)?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_tree_page),
    components(schemas(TreePageRequest, TreePageResponse))
)]
pub struct TreePageApiDoc;

#[cfg(test)]
#[path = "tree_page_tests.rs"]
mod tests;
