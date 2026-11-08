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
            // Compile the regex
            let re = Regex::new(pattern).map_err(|e| {
                SearchError::SqlGenError(format!("Invalid rex pattern '{}': {}", pattern, e))
            })?;
            // NAN-4933: the regex engine's own group names, so both
            // `(?<name>…)` and Python's `(?P<name>…)` extract (the hand-rolled
            // scan knew only the first and silently left the rows unchanged).
            let group_names: Vec<String> = re.capture_names().flatten().map(str::to_string).collect();

            if group_names.is_empty() {
                // No named groups: the SQL path's `rex_matches` column
                // (`extractAll`: the first capturing group, else the match).
                return Ok(results
                    .into_iter()
                    .map(|mut row| {
                        let source_value = get_nested_value(&row, source_field)
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let serde_json::Value::Object(ref mut obj) = row {
                            let matches: Vec<serde_json::Value> = source_value
                                .map(|text| {
                                    re.captures_iter(&text)
                                        .filter_map(|c| c.get(1).or_else(|| c.get(0)))
                                        .map(|m| serde_json::Value::String(m.as_str().to_string()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            obj.insert("rex_matches".into(), serde_json::Value::Array(matches));
                        }
                        row
                    })
                    .collect());
            }

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
                        // As the SQL `extractGroups(...)[i]`: '' when the
                        // pattern or the group does not match.
                        let captures = re.captures(&source_value);
                        for name in &group_names {
                            let text = captures
                                .as_ref()
                                .and_then(|c| c.name(name.as_str()))
                                .map_or("", |m| m.as_str());
                            obj.insert(name.clone(), serde_json::Value::String(text.to_string()));
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
