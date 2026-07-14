use super::*;

#[test]
fn the_tool_this_app_cannot_call_says_so() {
    // Verified against a live run: `search_sql` comes back "Forbidden: Raw SQL
    // queries require the search:sql permission". The MCP server advertises it as
    // its PRIMARY search tool, so an analyst reading the tools screen has to be
    // able to see that this app's read-only key cannot use it.
    assert_eq!(
        required_permission("search_sql").as_deref(),
        Some("search:sql")
    );
    assert_eq!(
        required_permission("search").as_deref(),
        Some("search:execute")
    );
}

#[test]
fn an_unknown_tool_admits_it_rather_than_guessing() {
    // An earlier version inferred the permission from the name's prefix, which is
    // exactly how a screen ends up stating a requirement the server never had.
    // nano exposes no per-tool permission metadata, so "unknown" is the honest
    // answer for anything not verified.
    assert_eq!(required_permission("list_detections"), None);
    assert_eq!(required_permission("get_case"), None);
    assert_eq!(required_permission("isolate_host"), None);
    assert_eq!(required_permission(""), None);
}
