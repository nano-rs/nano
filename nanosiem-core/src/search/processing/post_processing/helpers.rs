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
