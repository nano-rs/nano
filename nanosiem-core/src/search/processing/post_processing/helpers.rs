// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared helper functions for post-processing
//!
//! Provides utility functions used across multiple post-processing submodules:
//! - Nested field access with dot-notation support
//! - JSON value to raw string conversion

/// Get a value from a JSON object using dot-notation for nested fields.
/// Supports both flat fields (e.g., "host_count") and nested fields (e.g., "_prevalence.hash.artifact").
///
/// # Arguments
/// * `row` - The JSON value to search in
/// * `field` - The field path (can use dot notation for nested access)
///
/// # Returns
/// * `Some(&serde_json::Value)` - The value at the field path
/// * `None` - If the field doesn't exist or path is invalid
pub(crate) fn get_nested_value<'a>(
    row: &'a serde_json::Value,
    field: &str,
) -> Option<&'a serde_json::Value> {
    // First try direct access (most common case)
    if let Some(val) = row.get(field) {
        return Some(val);
    }

    // If field contains dots, try nested access
    if field.contains('.') {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = row;

        for part in parts {
            current = current.get(part)?;
        }

        return Some(current);
    }

    None
}

/// Return every value reached by a dotted path, traversing arrays along the
/// way. OCSF represents fields such as `file.hashes` as arrays of objects, so
/// an enrichment keyed by `file.hashes.value` may legitimately yield several
/// candidates for one event.
pub(crate) fn get_nested_values<'a>(
    row: &'a serde_json::Value,
    field: &str,
) -> Vec<&'a serde_json::Value> {
    if let Some(value) = row.get(field) {
        return match value {
            serde_json::Value::Array(values) => values.iter().collect(),
            _ => vec![value],
        };
    }

    fn descend<'a>(
        value: &'a serde_json::Value,
        segments: &[&str],
        values: &mut Vec<&'a serde_json::Value>,
    ) {
        if segments.is_empty() {
            match value {
                serde_json::Value::Array(items) => {
                    for item in items {
                        descend(item, segments, values);
                    }
                }
                _ => values.push(value),
            }
            return;
        }

        match value {
            serde_json::Value::Object(object) => {
                if let Some(next) = object.get(segments[0]) {
                    descend(next, &segments[1..], values);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    descend(item, segments, values);
                }
            }
            _ => {}
        }
    }

    let segments = field.split('.').collect::<Vec<_>>();
    let mut values = Vec::new();
    descend(row, &segments, &mut values);
    values
}

/// Project a dotted field into one JSON value. Scalar paths remain scalar;
/// paths crossing an OCSF repeated object preserve all reached leaves as an
/// array instead of silently dropping the field or inventing a scalar alias.
pub(crate) fn project_nested_value(
    row: &serde_json::Value,
    field: &str,
) -> Option<serde_json::Value> {
    if let Some(value) = row.get(field) {
        return Some(value.clone());
    }
    let values = get_nested_values(row, field);
    match values.as_slice() {
        [] => None,
        [value] => Some((*value).clone()),
        _ => Some(serde_json::Value::Array(
            values.into_iter().cloned().collect(),
        )),
    }
}

/// Map-oriented variant used by evaluators that already hold an object.
pub(crate) fn get_nested_map_value<'a>(
    row: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(value) = row.get(field) {
        return Some(value);
    }
    let mut segments = field.split('.');
    let mut current = row.get(segments.next()?)?;
    for segment in segments {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Get the raw string representation of a JSON value without JSON quotes
/// For strings, returns the string content directly
/// For other types, returns the JSON representation
pub(crate) fn json_value_to_raw_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        _ => v.to_string(), // Arrays and objects use JSON repr
    }
}

#[cfg(test)]
mod tests {
    use super::{get_nested_values, project_nested_value};

    #[test]
    fn nested_values_traverse_ocsf_object_arrays() {
        let event = serde_json::json!({
            "file": {
                "hashes": [
                    {"algorithm": "SHA-256", "value": "abc"},
                    {"algorithm": "MD5", "value": "def"}
                ]
            }
        });

        let values = get_nested_values(&event, "file.hashes.value")
            .into_iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();

        assert_eq!(values, vec!["abc", "def"]);
        assert_eq!(
            project_nested_value(&event, "file.hashes.value"),
            Some(serde_json::json!(["abc", "def"]))
        );
    }
}
