// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5324: update audit events record what changed.

use serde_json::json;

use super::changes::{changes_between, field_changes, new_values};

#[test]
fn only_changed_fields_are_recorded_with_old_and_new() {
    let before = json!({"per_user_limit": 5, "global_limit": 20, "queue": true});
    let after = json!({"per_user_limit": 8, "global_limit": 20, "queue": true});
    assert_eq!(
        field_changes(&before, &after),
        json!({"changes": {"per_user_limit": {"old": 5, "new": 8}}})
    );
}

#[test]
fn added_and_removed_keys_show_null_on_the_missing_side() {
    let before = json!({"a": 1});
    let after = json!({"b": 2});
    assert_eq!(
        field_changes(&before, &after),
        json!({"changes": {"a": {"old": 1, "new": null}, "b": {"old": null, "new": 2}}})
    );
}

#[test]
fn no_change_yields_empty_changes() {
    let v = json!({"a": [1, 2]});
    assert_eq!(field_changes(&v, &v), json!({"changes": {}}));
}

#[test]
fn array_values_such_as_permissions_compare_whole() {
    #[derive(serde::Serialize)]
    struct Key {
        permissions: Vec<&'static str>,
    }
    let d = changes_between(
        &Key { permissions: vec!["search:execute"] },
        &Key { permissions: vec!["search:execute", "rules:view"] },
    );
    assert_eq!(
        d,
        json!({"changes": {"permissions": {
            "old": ["search:execute"],
            "new": ["search:execute", "rules:view"]
        }}})
    );
}

#[test]
fn new_values_records_after_state_with_null_old() {
    assert_eq!(
        new_values(&json!({"x": 1})),
        json!({"changes": {"x": {"old": null, "new": 1}}})
    );
}
