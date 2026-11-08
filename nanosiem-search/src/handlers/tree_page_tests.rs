// SPDX-License-Identifier: AGPL-3.0-or-later
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
