// SPDX-License-Identifier: AGPL-3.0-or-later

use serde_json::json;

use super::*;

#[test]
fn nul_in_string_is_replaced_not_stripped() {
    assert_eq!(pg_safe_str("evil\0x"), "evil\u{FFFD}x");
    // Stripping would collide with the clean value; replacement must not.
    assert_ne!(pg_safe_str("admin\0"), pg_safe_str("admin"));
}

#[test]
fn clean_string_is_borrowed() {
    assert!(matches!(pg_safe_str("clean"), Cow::Borrowed("clean")));
    assert_eq!(pg_safe_string("clean".to_string()), "clean");
}

#[test]
fn invalid_utf8_bytes_and_nul_are_replaced() {
    let bytes = b"a\xff\0b";
    assert_eq!(pg_safe_bytes(bytes), "a\u{FFFD}\u{FFFD}b");
}

#[test]
fn nested_values_and_keys_are_sanitized() {
    let mut value = json!({
        "user": "evil\u{0000}x",
        "k\u{0000}ey": {"deep": ["ok", "a\u{0000}b", 1, null, true]},
        "n": 5
    });
    assert!(!json_is_pg_safe(&value));
    assert!(sanitize_json_for_pg(&mut value));
    assert!(json_is_pg_safe(&value));
    assert_eq!(value["user"], "evil\u{FFFD}x");
    assert_eq!(value["k\u{FFFD}ey"]["deep"][1], "a\u{FFFD}b");
    assert_eq!(value["n"], 5);
    // The serialized form no longer carries the escape PostgreSQL rejects.
    assert!(!serde_json::to_string(&value).unwrap().contains("\\u0000"));
}

#[test]
fn sanitized_key_collision_keeps_both_fields() {
    let mut value = json!({"a\u{FFFD}": 1, "a\u{0000}": 2});
    sanitize_json_for_pg(&mut value);
    let map = value.as_object().unwrap();
    assert_eq!(map.len(), 2, "no field may be overwritten: {map:?}");
}

#[test]
fn clean_json_is_untouched_and_borrowed() {
    let value = json!({"a": ["b", {"c": "d"}]});
    assert!(matches!(pg_safe_json(&value), Cow::Borrowed(_)));
    let mut copy = value.clone();
    assert!(!sanitize_json_for_pg(&mut copy));
    assert_eq!(copy, value);
}

#[test]
fn batch_counts_changed_events() {
    let mut events = vec![json!({"u": "a\u{0000}"}), json!({"u": "b"})];
    assert_eq!(sanitize_events_for_pg(&mut events), 1);
}

#[test]
fn error_text_is_one_inert_line() {
    let raw = "Code: 6. Cannot parse 'a\0b\nINJECTED\r\x1b[31m' (CANNOT_PARSE)";
    let safe = pg_safe_error_text(raw);
    assert!(is_pg_safe_str(&safe));
    assert!(!safe.contains('\n') && !safe.contains('\r') && !safe.contains('\x1b'));
    assert_eq!(safe, "Code: 6. Cannot parse 'a\u{FFFD}b INJECTED \u{FFFD}[31m' (CANNOT_PARSE)");
}
