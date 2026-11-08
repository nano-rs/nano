// NAN-4971: the notification_body helper (ported from main, NAN-4478).
use super::*;
use serde_json::json;

#[test]
fn notification_helper_is_closed_typed_and_does_not_reinterpret_event_text() {
    let scope = Scope {
        input: json!({"event":{"event_type":"case.created", "created_at":"2024-03-09T16:00:00Z", "rule_name":"{{credentials.KEY}}"}}),
        ..Default::default()
    };
    let body = evaluate(r#"notification_body "generic" input.event """#, &scope).unwrap();
    assert!(body.as_str().unwrap().contains("{{credentials.KEY}}"));
    for text in [
        r#"notification_body "unknown" input.event """#,
        r#"notification_body "slack" input.event """#,
        r#"notification_body "generic" input.missing """#,
        r#"notification_body "generic" credentials.KEY """#,
        r#"notification_body "generic" input.event"#,
    ] {
        assert!(evaluate(text, &scope).is_err(), "{text}");
    }
}
