// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded provisional roots and exact, authorized job root/child pages.
use crate::{
    error::{ErrorResponse, SearchError},
    SearchState,
};
use axum::{
    extract::{Extension, Path, State},
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

pub(super) fn supports_paged_tree(query: &nanosiem_core::query::Query) -> bool {
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
    let mut source_truncated = marker["_tree_truncated"] == true || !response.total_count_exact;
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
        total_count_exact: !preview && response.total_count_exact,
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
        let Json(status) =
            super::search_jobs::get_search_job(State(state), Extension(auth), Path(job_id.clone()))
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
            error: status.error.map(|error| nanosiem_core::branding::without_internal_code_name(&error).into_owned()),
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
    let search = state.search_with_ai_for_auth(&auth)?;
    super::require_shared_npl_contract_for_view(&auth, &query, Some("logs"), &search)?;
    let response = search
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
            auth.claims.sub,
            nanosiem_core::search::QueryPriority::Interactive,
            &super::search::effective_scope(&auth),
        )
        .await?;
    super::require_current_shared_authority(&state, &auth).await?;
    Ok(Json(page_tree(&response, &request, true)?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_tree_page),
    components(schemas(TreePageRequest, TreePageResponse))
)]
pub struct TreePageApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    fn request(path: Vec<usize>, offset: usize, limit: usize) -> TreePageRequest {
        TreePageRequest {
            job_id: Some("owned-job".into()),
            query: None,
            time_range: None,
            parent_path: path,
            offset,
            limit,
        }
    }
    fn forest() -> SearchResponse {
        let mut response = SearchResponse::empty();
        response.total_count = 1;
        response.total_count_exact = true;
        response.results = vec![
            json!({"_display_type": "tree", "_tree_config": {"child_field": "process.uid"}, "_tree_nodes": [
            {"id": "root", "label": "root", "_synthesized": true, "occurrences": 0, "children": [
                {"id": "a", "label": "a", "_ancestors": [{"id": "ancestor"}], "occurrences": 4, "children": []},
                {"id": "b", "label": "b", "_truncated": true, "children": []}]},
            {"id": "second-root", "label": "second", "children": []}]}),
        ];
        response
    }
    #[test]
    fn roots_and_children_are_server_pages_without_losing_tree_metadata() {
        let response = forest();
        let first = page_tree(&response, &request(vec![], 0, 1), false).unwrap();
        assert_eq!(first.nodes.len(), 1);
        assert_eq!(first.nodes[0]["children"], json!([]));
        assert_eq!(first.nodes[0]["_children_count"], 2);
        assert_eq!(first.nodes[0]["_page_path"], json!([0]));
        assert_eq!(first.nodes[0]["_synthesized"], true);
        assert_eq!(first.next_offset, Some(1));
        assert!(first.source_truncated);
        assert_eq!(first.total_roots, 2);
        assert_eq!(first.total_nodes, 4);
        let children = page_tree(&response, &request(vec![0], 0, 1), false).unwrap();
        assert_eq!(children.nodes[0]["id"], "a");
        assert_eq!(children.nodes[0]["occurrences"], 4);
        assert_eq!(children.nodes[0]["_ancestors"], json!([{"id": "ancestor"}]));
        assert_eq!(children.nodes[0]["_page_path"], json!([0, 0]));
        assert_eq!(children.next_offset, Some(1));
        let tail = page_tree(&response, &request(vec![0], 1, 1), false).unwrap();
        assert_eq!(tail.nodes[0]["_truncated"], true);
        assert_eq!(tail.next_offset, None);
        let root_tail = page_tree(&response, &request(vec![], 1, 1), false).unwrap();
        assert_eq!(root_tail.nodes[0]["id"], "second-root");
        assert_eq!(root_tail.next_offset, None);
        assert_eq!(first.total_count, response.total_count);
    }
    #[test]
    fn preview_is_bounded_and_cannot_claim_complete_ancestry_or_counts() {
        let query = preview_query("device.hostname=\"host\" | tree parent=actor.process.uid child=process.uid label=process.name").unwrap();
        let parsed = nanosiem_core::query::parse_query(&query).unwrap();
        let nanosiem_core::query::Query::Piped {
            source,
            command: Command::Tree { .. },
        } = parsed
        else {
            panic!("missing tree");
        };
        assert!(matches!(
            *source,
            nanosiem_core::query::Query::Piped {
                command: Command::Head { count: 200 },
                ..
            }
        ));
        let mutable = "* | lookup assets host OUTPUT owner | tree parent=parent child=child label=label";
        let parsed = nanosiem_core::query::parse_query(mutable).unwrap();
        assert!(!supports_paged_tree(&parsed));
        assert!(preview_query(mutable).is_err());
        let page = page_tree(&forest(), &request(vec![], 0, 25), true).unwrap();
        assert!(page.preview);
        assert!(!page.total_count_exact);
        assert!(preview_query("* | tree parent=parent child=child label=label | head 1").is_err());
        assert!(preview_query(
            "device.hostname=\"host\" | lateral | tree parent=parent child=child label=label"
        )
        .is_err());
    }
    #[test]
    fn empty_tree_note_reaches_the_page() {
        let mut response = SearchResponse::empty();
        response.results = vec![json!({"_display_type": "tree", "_tree_config": {}, "_tree_nodes": [],
            "_tree_note": "No events in range carry http_request.referrer."})];
        let page = page_tree(&response, &request(vec![], 0, 25), false).unwrap();
        assert!(page.nodes.is_empty());
        assert_eq!(page.note.as_deref(), Some("No events in range carry http_request.referrer."));
        assert_eq!(page_tree(&forest(), &request(vec![], 0, 25), false).unwrap().note, None);
    }
    #[test]
    fn page_bounds_and_missing_paths_fail_closed() {
        assert!(page_tree(&forest(), &request(vec![10], 0, 25), false).is_err());
        assert!(page_tree(&forest(), &request(vec![], 0, 0), false).is_err());
        assert!(page_tree(&forest(), &request(vec![], 0, 101), false).is_err());
        assert!(page_tree(&forest(), &request(vec![0; 17], 0, 25), false).is_err());
        assert!(page_tree(&SearchResponse::empty(), &request(vec![], 0, 25), false).is_err());
    }
}
