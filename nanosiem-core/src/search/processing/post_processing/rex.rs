// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rex (regex extraction) post-processing
//!
//! This module provides regex-based field extraction and substitution:
//! - Extract mode: Extract named capture groups into new fields
//! - Sed mode: Apply regex replacement on field values

use regex::Regex;

use crate::query::RexMode;
use crate::search::SearchError;

use super::helpers::get_nested_value;

/// Extract named capture group names from a regex pattern
/// Returns a list of group names in order of appearance
/// Example: "(?<user>\w+)@(?<domain>\w+)" -> ["user", "domain"]
fn extract_named_groups(pattern: &str) -> Vec<String> {
    let re = Regex::new(r"\(\?<([^>]+)>").unwrap();
    re.captures_iter(pattern)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Apply rex command as post-processing
///
/// # Arguments
/// * `results` - The results to process
/// * `field` - Source field to extract from (defaults to "message")
/// * `pattern` - Regex pattern with named capture groups
/// * `mode` - Extract (default) or Sed mode
///
/// # Returns
/// * `Ok(Vec<serde_json::Value>)` - The processed results with extracted fields
/// * `Err(SearchError)` - If regex compilation fails
pub(super) fn apply_rex_post_processing(
    results: Vec<serde_json::Value>,
    field: Option<&str>,
    pattern: &str,
    mode: &RexMode,
) -> Result<Vec<serde_json::Value>, SearchError> {
    let source_field = field.unwrap_or("message");

    match mode {
        RexMode::Extract => {
            // Extract named capture groups
            let group_names = extract_named_groups(pattern);

            if group_names.is_empty() {
                tracing::warn!("Rex pattern has no named capture groups: {}", pattern);
                return Ok(results);
            }

            // Compile the regex
            let re = Regex::new(pattern).map_err(|e| {
                SearchError::SqlGenError(format!("Invalid rex pattern '{}': {}", pattern, e))
            })?;

            Ok(results
                .into_iter()
                .map(|mut row| {
                    // Get the source field value first (before mutable borrow)
                    let source_value = get_nested_value(&row, source_field)
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    if let (Some(source_value), serde_json::Value::Object(ref mut obj)) =
                        (source_value, &mut row)
                    {
                        // Apply regex and extract named groups
                        if let Some(captures) = re.captures(&source_value) {
                            for name in &group_names {
                                if let Some(matched) = captures.name(name.as_str()) {
                                    obj.insert(
                                        name.clone(),
                                        serde_json::Value::String(matched.as_str().to_string()),
                                    );
                                }
                            }
                        }
                    }
                    row
                })
                .collect())
        }
        RexMode::Sed { replacement, .. } => {
            // Compile the regex
            let re = Regex::new(pattern).map_err(|e| {
                SearchError::SqlGenError(format!("Invalid rex pattern '{}': {}", pattern, e))
            })?;

            Ok(results
                .into_iter()
                .map(|mut row| {
                    if let serde_json::Value::Object(ref mut obj) = row {
                        // Get the source field value
                        if let Some(source_value) = obj.get(source_field).and_then(|v| v.as_str()) {
                            // Apply regex replacement
                            let replaced = re.replace_all(source_value, replacement.as_str());
                            obj.insert(
                                source_field.to_string(),
                                serde_json::Value::String(replaced.into_owned()),
                            );
                        }
                    }
                    row
                })
                .collect())
        }
    }
}
