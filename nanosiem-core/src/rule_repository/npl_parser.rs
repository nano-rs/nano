// SPDX-License-Identifier: AGPL-3.0-or-later

//! nPL (nano Pipe Language) rule parser
//!
//! Parses nPL detection rules with YAML frontmatter and extracts metadata,
//! source types, and required fields for coverage analysis.

use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

/// Errors from nPL parsing
#[derive(Debug, Error)]
pub enum NplParseError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Missing frontmatter delimiter")]
    MissingFrontmatter,

    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// A parsed nPL detection rule
#[derive(Debug, Clone)]
pub struct NplRule {
    pub title: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub severity: Option<String>,
    pub mode: Option<String>,
    pub detection_mode: Option<String>,
    pub schedule: Option<String>,
    pub lookback: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub tags: Vec<String>,
    pub ai_triage_hints: Option<AiTriageHints>,
    /// Target folder for the rule (Network, Identity, Endpoint, Cloud, Uncategorized)
    pub folder: Option<String>,
    /// The nPL query (everything after the frontmatter)
    pub query: String,
    /// Source types extracted from the query
    pub source_types: Vec<String>,
    /// UDM fields referenced in the query
    pub required_fields: Vec<String>,
}

/// AI triage hints for alert analysis
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AiTriageHints {
    #[serde(default)]
    pub ignore_when: Vec<String>,
    #[serde(default)]
    pub suspicious_when: Vec<String>,
    #[serde(default)]
    pub context: Option<String>,
}

/// Raw YAML frontmatter structure
#[derive(Debug, Deserialize)]
struct RawNplFrontmatter {
    title: String,
    description: Option<String>,
    author: Option<String>,
    severity: Option<String>,
    mode: Option<String>,
    detection_mode: Option<String>,
    schedule: Option<String>,
    lookback: Option<String>,
    #[serde(default)]
    mitre_tactics: Vec<String>,
    #[serde(default)]
    mitre_techniques: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    ai_triage_hints: Option<AiTriageHints>,
    /// Target folder for the rule (Network, Identity, Endpoint, Cloud, Uncategorized)
    folder: Option<String>,
}

/// Parse an nPL rule from YAML frontmatter + query content
pub fn parse_npl(content: &str) -> Result<NplRule, NplParseError> {
    // Split frontmatter from query
    // Format: ---\n<yaml>\n---\n<query>
    let content = content.trim();

    if !content.starts_with("---") {
        return Err(NplParseError::MissingFrontmatter);
    }

    // Find the closing ---
    let rest = &content[3..].trim_start_matches('\n');
    let end_idx = rest
        .find("\n---")
        .ok_or(NplParseError::MissingFrontmatter)?;

    let yaml_content = &rest[..end_idx];
    let query = rest[end_idx + 4..].trim().to_string();

    // Parse the YAML frontmatter
    let frontmatter: RawNplFrontmatter = serde_yaml::from_str(yaml_content)?;

    // Extract source types from the query
    let source_types = extract_source_types(&query);

    // Extract required fields from the query
    let required_fields = extract_required_fields(&query);

    Ok(NplRule {
        title: frontmatter.title,
        description: frontmatter.description,
        author: frontmatter.author,
        severity: frontmatter.severity,
        mode: frontmatter.mode,
        detection_mode: frontmatter.detection_mode,
        schedule: frontmatter.schedule,
        lookback: frontmatter.lookback,
        mitre_tactics: frontmatter.mitre_tactics,
        mitre_techniques: frontmatter.mitre_techniques,
        tags: frontmatter.tags,
        ai_triage_hints: frontmatter.ai_triage_hints,
        folder: frontmatter.folder,
        query,
        source_types,
        required_fields,
    })
}

/// Extract source_type values from an nPL query
/// Matches patterns like:
///   source_type=windows_sysmon
///   source_type="windows_sysmon"
///   source_type=windows_sysmon OR source_type=endpoint_edr
pub fn extract_source_types(query: &str) -> Vec<String> {
    let mut source_types = Vec::new();

    // Match source_type=value or source_type="value" patterns.
    // Also handles the no-underscore `sourcetype=` alias.
    let re = Regex::new(r#"(?i)source_?type\s*=\s*"?([a-zA-Z0-9_-]+)"?"#).unwrap();

    for cap in re.captures_iter(query) {
        if let Some(st) = cap.get(1) {
            let value = st.as_str().to_lowercase();
            if !source_types.contains(&value) {
                source_types.push(value);
            }
        }
    }

    source_types
}

/// Extract UDM field names referenced in the query
pub fn extract_required_fields(query: &str) -> Vec<String> {
    let mut fields = Vec::new();

    // Common UDM fields to look for
    let udm_fields = [
        // Core identifiers
        "event_type",
        "action", // legacy synonym for event_type
        "status",
        "result",
        // Network
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
        "src_host",
        "dest_host",
        "protocol",
        "bytes_in",
        "bytes_out",
        "packets_in",
        "packets_out",
        "url",
        "url_domain",
        "url_path",
        "url_query",
        // Process
        "process_name",
        "process_path",
        "process_hash",
        "process_id",
        "process_guid",
        "command_line",
        "parent_command_line",
        "parent_process_path",
        "parent_process_id",
        // File
        "file_path",
        "file_name",
        "file_hash",
        "file_size",
        "file_action",
        // User/Auth
        "user",
        "user_id",
        "user_domain",
        "user_type",
        "target_user",
        "target_user_id",
        "target_user_domain",
        "auth_type",
        "auth_result",
        "logon_type",
        // DNS
        "query",
        "query_type",
        "answer",
        "answer_type",
        // Registry (Windows)
        "registry_key",
        "registry_value",
        "registry_data",
        // Enrichment fields
        "enriched_src_country",
        "enriched_dest_country",
        "enriched_src_asn",
        "enriched_dest_asn",
        "enriched_src_city",
        "enriched_dest_city",
        // Prevalence fields
        "prevalence_file_hash",
        "prevalence_process_hash",
        "prevalence_dest_domain",
        "prevalence_dest_ip",
        "prevalence_min",
        // Email
        "subject",
        "sender",
        "recipient",
        "attachment_name",
        "attachment_hash",
        // Cloud
        "cloud_provider",
        "cloud_region",
        "cloud_account_id",
        "resource_type",
        "resource_id",
        "resource_name",
        // Generic
        "user_agent",
        "http_method",
        "http_status",
        "session_id",
        "transaction_id",
    ];

    let query_lower = query.to_lowercase();

    for field in udm_fields {
        // Check if field appears in query (as field reference, not just substring)
        // Look for: field=, field!=, field CONTAINS, field IN, etc.
        let patterns = [
            format!(r"\b{}\s*[=!<>]", regex::escape(field)),
            format!(r"\b{}\s+(?:CONTAINS|IN|NOT|LIKE)", regex::escape(field)),
            format!(r"(?:by|BY)\s+.*\b{}\b", regex::escape(field)),
            format!(r"fields\s*\(.*\b{}\b", regex::escape(field)),
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
                if re.is_match(&query_lower) {
                    if !fields.contains(&field.to_string()) {
                        fields.push(field.to_string());
                    }
                    break;
                }
            }
        }
    }

    fields
}

/// Validate source types against available source types in the environment
#[derive(Debug, Clone)]
pub struct SourceTypeValidation {
    /// Source types required by the rule
    pub required: Vec<String>,
    /// Source types available in the environment
    pub available: Vec<String>,
    /// Source types that are missing
    pub missing: Vec<String>,
    /// Whether all required source types are available
    pub is_valid: bool,
    /// Suggestions for alternative source types
    pub suggestions: Vec<SourceTypeSuggestion>,
}

#[derive(Debug, Clone)]
pub struct SourceTypeSuggestion {
    pub missing_type: String,
    pub suggested_type: String,
    pub reason: String,
}

/// Validate that required source types are available
pub fn validate_source_types(required: &[String], available: &[String]) -> SourceTypeValidation {
    let available_lower: Vec<String> = available.iter().map(|s| s.to_lowercase()).collect();

    let mut missing = Vec::new();
    let mut suggestions = Vec::new();

    for req in required {
        let req_lower = req.to_lowercase();
        if !available_lower.contains(&req_lower) {
            missing.push(req.clone());

            // Try to suggest alternatives
            if let Some(suggestion) = suggest_alternative(&req_lower, &available_lower) {
                suggestions.push(SourceTypeSuggestion {
                    missing_type: req.clone(),
                    suggested_type: suggestion.0,
                    reason: suggestion.1,
                });
            }
        }
    }

    SourceTypeValidation {
        required: required.to_vec(),
        available: available.to_vec(),
        missing: missing.clone(),
        is_valid: missing.is_empty(),
        suggestions,
    }
}

/// Suggest alternative source types based on common mappings
fn suggest_alternative(missing: &str, available: &[String]) -> Option<(String, String)> {
    // Common source type aliases/alternatives
    let alternatives: &[(&[&str], &str)] = &[
        // Windows sources
        (
            &["windows_sysmon", "sysmon"],
            "Process/file/network monitoring",
        ),
        (
            &["windows_security", "wineventlog:security"],
            "Windows Security events",
        ),
        (&["windows_powershell", "powershell"], "PowerShell logging"),
        (
            &[
                "endpoint_edr",
                "edr",
                "crowdstrike",
                "defender_atp",
                "carbon_black",
            ],
            "Endpoint detection",
        ),
        (&["endpoint_process", "process_creation"], "Process events"),
        // Network sources
        (
            &["firewall", "paloalto", "fortinet", "checkpoint"],
            "Firewall logs",
        ),
        (&["proxy", "squid", "zscaler", "bluecoat"], "Web proxy logs"),
        (&["dns", "dns_query"], "DNS query logs"),
        (
            &["network_flow", "netflow", "zeek_conn"],
            "Network flow data",
        ),
        // Auth sources
        (
            &["auth_logs", "okta", "azure_ad", "auth0"],
            "Authentication logs",
        ),
        // Cloud sources
        (&["aws_cloudtrail", "cloudtrail"], "AWS audit logs"),
        (&["azure_activity", "azure_audit"], "Azure audit logs"),
        (&["gcp_audit", "gcp_logging"], "GCP audit logs"),
    ];

    for (group, description) in alternatives {
        if group.contains(&missing) {
            // Check if any alternative is available
            for alt in *group {
                if *alt != missing && available.contains(&alt.to_string()) {
                    return Some((alt.to_string(), description.to_string()));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npl_rule() {
        let content = r#"---
title: test_rule
description: A test detection rule
severity: high
mitre_tactics:
  - TA0001
tags:
  - test
---
source_type=windows_sysmon OR source_type=endpoint_edr
| where action="process_create"
| where process_name="cmd.exe"
"#;

        let rule = parse_npl(content).unwrap();
        assert_eq!(rule.title, "test_rule");
        assert_eq!(rule.severity, Some("high".to_string()));
        assert_eq!(rule.source_types, vec!["windows_sysmon", "endpoint_edr"]);
        assert!(rule.required_fields.contains(&"action".to_string()));
        assert!(rule.required_fields.contains(&"process_name".to_string()));
    }

    #[test]
    fn test_extract_source_types() {
        let query = r#"source_type=windows_sysmon OR source_type="endpoint_edr"
| where action="process_create""#;

        let types = extract_source_types(query);
        assert_eq!(types, vec!["windows_sysmon", "endpoint_edr"]);
    }

    #[test]
    fn test_validate_source_types() {
        let required = vec!["windows_sysmon".to_string(), "okta".to_string()];
        let available = vec!["windows_sysmon".to_string(), "firewall".to_string()];

        let validation = validate_source_types(&required, &available);
        assert!(!validation.is_valid);
        assert_eq!(validation.missing, vec!["okta"]);
    }
}
