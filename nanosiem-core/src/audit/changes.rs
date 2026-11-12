// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit `details` helpers for "what changed" (NAN-5324).
//!
//! Update events used to carry `details: null`, so the audit trail said a
//! setting or API key changed but never what changed. These helpers turn a
//! before/after pair of serializable values into a compact, deterministic
//! `{"changes": {field: {"old": …, "new": …}}}` object.

use serde::Serialize;
use serde_json::{Map, Value};

/// Top-level field diff between two JSON objects.
///
/// Returns `{"changes": {field: {"old": old, "new": new}}}` for every key whose
/// value differs (a key missing on one side is `null` there). Non-object
/// inputs are compared as a whole under the `"value"` key. Keys are emitted in
/// sorted order so the record is stable.
pub fn field_changes(before: &Value, after: &Value) -> Value {
    let mut changes = Map::new();
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let old = b.get(key).cloned().unwrap_or(Value::Null);
                let new = a.get(key).cloned().unwrap_or(Value::Null);
                if old != new {
                    changes.insert(key.clone(), serde_json::json!({ "old": old, "new": new }));
                }
            }
        }
        _ if before != after => {
            changes.insert(
                "value".to_string(),
                serde_json::json!({ "old": before, "new": after }),
            );
        }
        _ => {}
    }
    serde_json::json!({ "changes": Value::Object(changes) })
}

/// [`field_changes`] for any two serializable values. A value that fails to
/// serialize is recorded as `null` rather than dropping the audit detail.
pub fn changes_between<T: Serialize + ?Sized>(before: &T, after: &T) -> Value {
    let b = serde_json::to_value(before).unwrap_or(Value::Null);
    let a = serde_json::to_value(after).unwrap_or(Value::Null);
    field_changes(&b, &a)
}

/// The after-state only, for when the before-state could not be read. Keeps
/// the same `changes` shape with `old: null` so readers don't special-case it.
pub fn new_values<T: Serialize + ?Sized>(after: &T) -> Value {
    field_changes(&Value::Object(Map::new()), &serde_json::to_value(after).unwrap_or(Value::Null))
}
