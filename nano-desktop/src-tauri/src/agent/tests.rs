use super::*;
use serde_json::json;

#[test]
fn row_rendering_drops_internal_and_empty_fields() {
    // `*_unified` are query accelerators, not schema at the surface — showing
    // them would have the assistant reasoning about columns the analyst can't
    // even see in the table.
    let row = json!({
        "timestamp": "2026-07-12T10:00:00Z",
        "user_unified": "svc-deploy",
        "_inserted_at": "2026-07-12T10:00:01Z",
        "actor.user.name": "svc-deploy",
        "dst_endpoint.port": 0,
        "status": "",
        "message": "ConsoleLogin",
    });

    let rendered = compact_row(&row);

    assert!(rendered.contains("actor.user.name=svc-deploy"));
    assert!(rendered.contains("message=ConsoleLogin"));
    assert!(!rendered.contains("_unified"));
    assert!(!rendered.contains("_inserted_at"));
    // Zero-valued and empty fields are ClickHouse defaults, not evidence.
    assert!(!rendered.contains("dst_endpoint.port"));
    assert!(!rendered.contains("status="));
}

#[test]
fn long_values_are_clipped() {
    let row = json!({ "message": "x".repeat(MAX_VALUE_CHARS + 200) });
    let rendered = compact_row(&row);

    assert!(rendered.contains("[truncated]"));
    assert!(rendered.chars().count() < MAX_VALUE_CHARS + 100);
}

#[test]
fn screen_states_how_many_rows_the_assistant_actually_got() {
    // The failure this guards against: handing over 15 of 400 rows and letting
    // the model answer as though it reviewed the whole result set.
    let rows: Vec<Value> = (0..40)
        .map(|i| json!({ "user": format!("user{i}") }))
        .collect();
    let screen = json!({
        "screen": "Search",
        "query": "*",
        "total_count": 125_031,
        "rows": rows,
    });

    let rendered = render_screen(&screen);

    assert!(rendered.contains("Total matching events: 125031"));
    assert!(rendered.contains("40 loaded"));
    assert!(rendered.contains(&format!("{MAX_ROWS} below")));
    assert!(rendered.contains(&format!("(+{} further loaded rows", 40 - MAX_ROWS)));
    // Only the capped set is actually present.
    assert!(rendered.contains("user0"));
    assert!(!rendered.contains("user39"));
}

#[test]
fn empty_query_is_stated_rather_than_left_blank() {
    let screen = json!({ "screen": "Search", "query": "" });
    assert!(render_screen(&screen).contains("no search run yet"));
}

#[test]
fn notebook_title_reads_like_an_investigation() {
    // A list of pivt sessions should read like a list of questions, not
    // "pivt session 4".
    assert_eq!(
        notebook_title("why did ConsoleLogin spike?"),
        "pivt · why did ConsoleLogin spike?"
    );

    let long = "a".repeat(120);
    let title = notebook_title(&long);
    assert!(title.ends_with('…'), "long prompts are truncated: {title}");
    assert!(title.chars().count() < 75);
}
