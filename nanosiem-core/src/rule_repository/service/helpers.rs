// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for rule repository operations.
//!
//! Contains utilities for string conversion, MITRE mapping,
//! query customization, file collection, and lookback parsing.

use super::super::github_client::TreeEntry;

/// Parse lookback duration string (e.g., "15m", "1h", "30m") to minutes
pub(crate) fn parse_lookback_to_minutes(lookback: &str) -> Option<i32> {
    let lookback = lookback.trim().to_lowercase();

    // Try to parse formats like "15m", "1h", "30m", "2h", "1d"
    if let Some(stripped) = lookback.strip_suffix('m') {
        stripped.parse().ok()
    } else if let Some(stripped) = lookback.strip_suffix('h') {
        stripped.parse::<i32>().ok().map(|h| h * 60)
    } else if let Some(stripped) = lookback.strip_suffix('d') {
        stripped.parse::<i32>().ok().map(|d| d * 24 * 60)
    } else {
        // Try parsing as just a number (assume minutes)
        lookback.parse().ok()
    }
}

/// Convert a string to snake_case, preserving acronyms
/// "AppX Package" -> "appx_package"
/// "AppInstaller.EXE" -> "appinstaller_exe"
pub(crate) fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_was_underscore = true;
    let mut prev_was_lower = false;

    for c in s.chars() {
        if c.is_alphanumeric() {
            // Only add underscore before uppercase if previous was lowercase
            // This keeps acronyms together: "EXE" stays "exe", "AppX" stays "appx"
            if c.is_uppercase() && prev_was_lower && !result.is_empty() {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
            prev_was_underscore = false;
            prev_was_lower = c.is_lowercase();
        } else if c == ' ' || c == '-' || c == '.' || c == '_' {
            if !prev_was_underscore && !result.is_empty() {
                result.push('_');
                prev_was_underscore = true;
                prev_was_lower = false;
            }
        }
        // Skip other characters (like quotes, parentheses, etc.)
    }

    // Remove trailing underscore
    while result.ends_with('_') {
        result.pop();
    }

    result
}

/// Convert MITRE ATT&CK tactic name to ID
pub(crate) fn convert_mitre_tactic_to_id(tactic: &str) -> String {
    let normalized = tactic.to_lowercase().replace([' ', '-'], "_");

    match normalized.as_str() {
        "reconnaissance" => "TA0043".to_string(),
        "resource_development" => "TA0042".to_string(),
        "initial_access" => "TA0001".to_string(),
        "execution" => "TA0002".to_string(),
        "persistence" => "TA0003".to_string(),
        "privilege_escalation" => "TA0004".to_string(),
        "defense_evasion" => "TA0005".to_string(),
        "credential_access" => "TA0006".to_string(),
        "discovery" => "TA0007".to_string(),
        "lateral_movement" => "TA0008".to_string(),
        "collection" => "TA0009".to_string(),
        "command_and_control" | "c2" => "TA0011".to_string(),
        "exfiltration" => "TA0010".to_string(),
        "impact" => "TA0040".to_string(),
        // If it's already an ID (starts with TA), return as-is
        _ if tactic.starts_with("TA") => tactic.to_string(),
        // Return original if unknown
        _ => tactic.to_string(),
    }
}

/// Apply stored customizations (source_type mappings) to an upstream query.
/// This ensures that when computing diffs, the user's source_type overrides are
/// reapplied to the upstream query so only real upstream changes appear in the diff.
pub(crate) fn apply_customizations_to_query(
    query: String,
    customizations: &Option<serde_json::Value>,
) -> String {
    let cust = match customizations {
        Some(v) => v,
        None => return query,
    };

    let obj = match cust.as_object() {
        Some(o) => o,
        None => return query,
    };

    // If merge_to_single_source_type is set, replace all source_type= expressions
    if let Some(merged) = obj
        .get("merge_to_single_source_type")
        .and_then(|v| v.as_str())
    {
        if !merged.is_empty() {
            return apply_merged_source_type(&query, merged);
        }
    }

    // Otherwise, apply individual source_type mappings
    if let Some(mappings) = obj.get("source_type_mappings").and_then(|v| v.as_object()) {
        let mut result = query;
        for (original, replacement) in mappings {
            if let Some(replacement_str) = replacement.as_str() {
                if replacement_str.is_empty() {
                    continue;
                }
                result = apply_single_source_type_mapping(&result, original, replacement_str);
            }
        }
        return result;
    }

    query
}

/// Replace all source_type=X (including OR chains) with a single source type
fn apply_merged_source_type(query: &str, merged_type: &str) -> String {
    // Match OR chains: source_type=X OR source_type=Y OR source_type=Z
    // Optionally wrapped in parentheses
    let chain_pattern = regex::Regex::new(
        r#"(?i)\(?source_type\s*=\s*["']?[a-zA-Z0-9_-]+["']?(?:\s+OR\s+source_type\s*=\s*["']?[a-zA-Z0-9_-]+["']?)+\)?"#
    ).unwrap();

    let result = chain_pattern.replace_all(query, format!("source_type={}", merged_type).as_str());

    // If no chain was found, try replacing individual source_type= occurrences
    if result == query {
        let single_pattern =
            regex::Regex::new(r#"(?i)source_type\s*=\s*["']?[a-zA-Z0-9_-]+["']?"#).unwrap();
        return single_pattern
            .replace_all(query, format!("source_type={}", merged_type).as_str())
            .to_string();
    }

    result.to_string()
}

/// Replace a single source_type value with its mapped replacement
fn apply_single_source_type_mapping(query: &str, original: &str, replacement: &str) -> String {
    let escaped = regex::escape(original);
    // Match source_type=original with optional quotes, case-insensitive
    let patterns = [
        format!(r#"(?i)source_type\s*=\s*"{}""#, escaped),
        format!(r#"(?i)source_type\s*=\s*'{}'"#, escaped),
        format!(r#"(?i)source_type\s*=\s*{}(?![a-zA-Z0-9_-])"#, escaped),
    ];

    let mut result = query.to_string();
    for pat in &patterns {
        if let Ok(re) = regex::Regex::new(pat) {
            result = re
                .replace_all(&result, format!("source_type={}", replacement).as_str())
                .to_string();
        }
    }
    result
}

/// Recursively collect rule files from a directory
pub(crate) fn collect_rule_files(
    dir: &std::path::Path,
    base_dir: &std::path::Path,
    extensions: &[String],
    files: &mut Vec<TreeEntry>,
) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rule_files(&path, base_dir, extensions, files);
            } else if path.is_file() {
                let path_str = path.to_string_lossy();
                if extensions.iter().any(|ext| path_str.ends_with(ext)) {
                    // Get relative path from base_dir
                    if let Ok(rel_path) = path.strip_prefix(base_dir) {
                        files.push(TreeEntry {
                            path: rel_path.to_string_lossy().to_string(),
                            entry_type: "blob".to_string(),
                            sha: String::new(), // We'll compute this differently for local files
                            size: path.metadata().ok().map(|m| m.len() as i64),
                            url: None,
                        });
                    }
                }
            }
        }
    }
}
