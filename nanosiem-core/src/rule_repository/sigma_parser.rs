// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sigma rule parser
//!
//! Parses Sigma YAML rules and extracts metadata, detection logic,
//! and required fields for UDM mapping.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors from Sigma parsing
#[derive(Debug, Error)]
pub enum SigmaParseError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field value for {field}: {message}")]
    InvalidField { field: String, message: String },
}

/// A parsed Sigma rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub logsource: SigmaLogsource,
    pub detection: SigmaDetection,
    pub level: Option<String>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub falsepositives: Vec<String>,
    /// Related rules (for correlation)
    pub related: Vec<SigmaRelated>,
}

/// Log source specification in Sigma
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigmaLogsource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
    pub definition: Option<String>,
}

/// Related rule reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRelated {
    pub id: String,
    #[serde(rename = "type")]
    pub relation_type: String,
}

/// Detection logic in Sigma
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaDetection {
    /// Named selection conditions
    pub selections: HashMap<String, SigmaSelection>,
    /// The condition combining selections (e.g., "selection1 and not filter")
    pub condition: String,
    /// Timeframe for correlation (optional)
    pub timeframe: Option<String>,
}

/// A selection in Sigma detection logic
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SigmaSelection {
    /// Simple field-value pairs
    Simple(HashMap<String, SigmaValue>),
    /// List of alternatives (OR)
    List(Vec<HashMap<String, SigmaValue>>),
}

/// A value in Sigma detection (can be string, list, or number)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SigmaValue {
    String(String),
    List(Vec<String>),
    Number(i64),
    Bool(bool),
}

impl SigmaValue {
    /// Get all string values (flattens lists)
    pub fn as_strings(&self) -> Vec<String> {
        match self {
            SigmaValue::String(s) => vec![s.clone()],
            SigmaValue::List(v) => v.clone(),
            SigmaValue::Number(n) => vec![n.to_string()],
            SigmaValue::Bool(b) => vec![b.to_string()],
        }
    }
}

/// Raw Sigma YAML structure (for parsing)
#[derive(Debug, Deserialize)]
struct RawSigmaRule {
    title: String,
    id: Option<String>,
    status: Option<String>,
    description: Option<String>,
    author: Option<String>,
    date: Option<String>,
    modified: Option<String>,
    logsource: Option<RawLogsource>,
    detection: RawDetection,
    level: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    falsepositives: StringOrList,
    #[serde(default)]
    related: Vec<RawRelated>,
}

#[derive(Debug, Deserialize, Default)]
struct RawLogsource {
    category: Option<String>,
    product: Option<String>,
    service: Option<String>,
    definition: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDetection {
    condition: String,
    #[serde(default)]
    timeframe: Option<String>,
    #[serde(flatten)]
    selections: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct RawRelated {
    id: String,
    #[serde(rename = "type")]
    relation_type: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum StringOrList {
    #[default]
    None,
    String(String),
    List(Vec<String>),
}

impl StringOrList {
    fn into_vec(self) -> Vec<String> {
        match self {
            StringOrList::None => vec![],
            StringOrList::String(s) => vec![s],
            StringOrList::List(v) => v,
        }
    }
}

/// Parse a Sigma rule from YAML
pub fn parse_sigma(yaml: &str) -> Result<SigmaRule, SigmaParseError> {
    let raw: RawSigmaRule = serde_yaml::from_str(yaml)?;

    // Parse selections from the detection block
    let mut selections = HashMap::new();
    for (key, value) in raw.detection.selections {
        // Skip 'condition' and 'timeframe' keys
        if key == "condition" || key == "timeframe" {
            continue;
        }

        let selection = parse_selection(&value)?;
        selections.insert(key, selection);
    }

    Ok(SigmaRule {
        title: raw.title,
        id: raw.id,
        status: raw.status,
        description: raw.description,
        author: raw.author,
        date: raw.date,
        modified: raw.modified,
        logsource: raw
            .logsource
            .map(|l| SigmaLogsource {
                category: l.category,
                product: l.product,
                service: l.service,
                definition: l.definition,
            })
            .unwrap_or_default(),
        detection: SigmaDetection {
            selections,
            condition: raw.detection.condition,
            timeframe: raw.detection.timeframe,
        },
        level: raw.level,
        tags: raw.tags,
        references: raw.references,
        falsepositives: raw.falsepositives.into_vec(),
        related: raw
            .related
            .into_iter()
            .map(|r| SigmaRelated {
                id: r.id,
                relation_type: r.relation_type,
            })
            .collect(),
    })
}

fn parse_selection(value: &serde_yaml::Value) -> Result<SigmaSelection, SigmaParseError> {
    match value {
        serde_yaml::Value::Mapping(map) => {
            let mut fields = HashMap::new();
            for (k, v) in map {
                if let serde_yaml::Value::String(key) = k {
                    let sigma_value = parse_sigma_value(v)?;
                    fields.insert(key.clone(), sigma_value);
                }
            }
            Ok(SigmaSelection::Simple(fields))
        }
        serde_yaml::Value::Sequence(seq) => {
            let mut alternatives = Vec::new();
            for item in seq {
                if let serde_yaml::Value::Mapping(map) = item {
                    let mut fields = HashMap::new();
                    for (k, v) in map {
                        if let serde_yaml::Value::String(key) = k {
                            let sigma_value = parse_sigma_value(v)?;
                            fields.insert(key.clone(), sigma_value);
                        }
                    }
                    alternatives.push(fields);
                }
            }
            Ok(SigmaSelection::List(alternatives))
        }
        _ => Err(SigmaParseError::InvalidField {
            field: "selection".to_string(),
            message: "Expected mapping or sequence".to_string(),
        }),
    }
}

fn parse_sigma_value(value: &serde_yaml::Value) -> Result<SigmaValue, SigmaParseError> {
    match value {
        serde_yaml::Value::String(s) => Ok(SigmaValue::String(s.clone())),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(SigmaValue::Number(i))
            } else {
                Ok(SigmaValue::String(n.to_string()))
            }
        }
        serde_yaml::Value::Bool(b) => Ok(SigmaValue::Bool(*b)),
        serde_yaml::Value::Sequence(seq) => {
            let strings: Vec<String> = seq
                .iter()
                .filter_map(|v| match v {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    serde_yaml::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            Ok(SigmaValue::List(strings))
        }
        serde_yaml::Value::Null => Ok(SigmaValue::String("null".to_string())),
        _ => Err(SigmaParseError::InvalidField {
            field: "value".to_string(),
            message: format!("Unexpected value type: {:?}", value),
        }),
    }
}

/// Extract all field names used in a Sigma rule
pub fn extract_required_fields(rule: &SigmaRule) -> Vec<String> {
    let mut fields = Vec::new();

    for selection in rule.detection.selections.values() {
        match selection {
            SigmaSelection::Simple(map) => {
                for key in map.keys() {
                    // Handle field modifiers like "CommandLine|contains"
                    let field = key.split('|').next().unwrap_or(key);
                    if !fields.contains(&field.to_string()) {
                        fields.push(field.to_string());
                    }
                }
            }
            SigmaSelection::List(alternatives) => {
                for alt in alternatives {
                    for key in alt.keys() {
                        let field = key.split('|').next().unwrap_or(key);
                        if !fields.contains(&field.to_string()) {
                            fields.push(field.to_string());
                        }
                    }
                }
            }
        }
    }

    fields.sort();
    fields
}

/// Map Sigma logsource to suggested NanoSIEM source types
pub fn map_logsource_to_source_types(logsource: &SigmaLogsource) -> Vec<String> {
    let mut source_types = Vec::new();

    // Map category to source types
    if let Some(category) = &logsource.category {
        match category.as_str() {
            "process_creation" => {
                source_types.push("windows_sysmon".to_string());
                source_types.push("windows_security".to_string());
                source_types.push("endpoint_process".to_string());
            }
            "network_connection" => {
                source_types.push("windows_sysmon".to_string());
                source_types.push("network_flow".to_string());
                source_types.push("firewall".to_string());
            }
            "file_event" | "file_change" | "file_access" | "file_delete" | "file_rename" => {
                source_types.push("windows_sysmon".to_string());
                source_types.push("endpoint_file".to_string());
            }
            "registry_event" | "registry_set" | "registry_add" | "registry_delete" => {
                source_types.push("windows_sysmon".to_string());
                source_types.push("endpoint_registry".to_string());
            }
            "dns_query" | "dns" => {
                source_types.push("dns".to_string());
                source_types.push("windows_sysmon".to_string());
            }
            "image_load" => {
                source_types.push("windows_sysmon".to_string());
            }
            "pipe_created" | "create_remote_thread" | "create_stream_hash" => {
                source_types.push("windows_sysmon".to_string());
            }
            "ps_script" | "ps_module" | "ps_classic_start" | "ps_classic_provider_start" => {
                source_types.push("windows_powershell".to_string());
            }
            "webserver" => {
                source_types.push("web_access".to_string());
                source_types.push("apache".to_string());
                source_types.push("nginx".to_string());
            }
            "firewall" => {
                source_types.push("firewall".to_string());
            }
            "proxy" => {
                source_types.push("proxy".to_string());
                source_types.push("web_proxy".to_string());
            }
            "antivirus" => {
                source_types.push("antivirus".to_string());
                source_types.push("endpoint_protection".to_string());
            }
            _ => {}
        }
    }

    // Map product to source types
    if let Some(product) = &logsource.product {
        match product.as_str() {
            "windows" => {
                if source_types.is_empty() {
                    source_types.push("windows_security".to_string());
                }
            }
            "linux" => {
                source_types.push("linux_audit".to_string());
                source_types.push("syslog".to_string());
            }
            "macos" => {
                source_types.push("macos_unified".to_string());
            }
            "aws" | "cloudtrail" => {
                source_types.push("aws_cloudtrail".to_string());
            }
            "azure" => {
                source_types.push("azure_activity".to_string());
                source_types.push("azure_signin".to_string());
            }
            "gcp" => {
                source_types.push("gcp_audit".to_string());
            }
            "okta" => {
                source_types.push("okta".to_string());
            }
            "github" => {
                source_types.push("github_audit".to_string());
            }
            "m365" | "office365" => {
                source_types.push("o365_audit".to_string());
            }
            _ => {}
        }
    }

    // Map service to source types
    if let Some(service) = &logsource.service {
        match service.as_str() {
            "sysmon" => {
                if !source_types.contains(&"windows_sysmon".to_string()) {
                    source_types.push("windows_sysmon".to_string());
                }
            }
            "security" => {
                if !source_types.contains(&"windows_security".to_string()) {
                    source_types.push("windows_security".to_string());
                }
            }
            "system" => {
                source_types.push("windows_system".to_string());
            }
            "powershell" | "powershell-classic" => {
                if !source_types.contains(&"windows_powershell".to_string()) {
                    source_types.push("windows_powershell".to_string());
                }
            }
            "dns-server" => {
                source_types.push("dns_server".to_string());
            }
            _ => {}
        }
    }

    source_types
}

/// Map Sigma severity to NanoSIEM severity
pub fn map_severity(sigma_level: Option<&str>) -> String {
    match sigma_level {
        Some("critical") => "critical".to_string(),
        Some("high") => "high".to_string(),
        Some("medium") => "medium".to_string(),
        Some("low") => "low".to_string(),
        Some("informational") | Some("info") => "informational".to_string(),
        _ => "medium".to_string(), // Default to medium
    }
}

/// Extract MITRE tactics from Sigma tags
pub fn extract_mitre_tactics(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter(|t| t.starts_with("attack.") && !t.contains("t1") && !t.contains("T1"))
        .map(|t| t.strip_prefix("attack.").unwrap_or(t))
        .map(|t| t.replace('_', " "))
        .map(|t| {
            // Convert to title case
            t.split(' ')
                .map(|word| {
                    let mut chars = word.chars();
                    match chars.next() {
                        None => String::new(),
                        Some(first) => first.to_uppercase().chain(chars).collect(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

/// Extract MITRE technique IDs from Sigma tags
pub fn extract_mitre_techniques(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter(|t| t.starts_with("attack.t") || t.starts_with("attack.T"))
        .map(|t| t.strip_prefix("attack.").unwrap_or(t).to_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_sigma() {
        let yaml = r#"
title: Mimikatz Detection
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Detects Mimikatz execution
author: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa'
            - 'kerberos'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1003
"#;

        let rule = parse_sigma(yaml).unwrap();
        assert_eq!(rule.title, "Mimikatz Detection");
        assert_eq!(rule.level, Some("high".to_string()));
        assert!(rule.detection.selections.contains_key("selection"));

        let fields = extract_required_fields(&rule);
        assert!(fields.contains(&"CommandLine".to_string()));

        let source_types = map_logsource_to_source_types(&rule.logsource);
        assert!(source_types.contains(&"windows_sysmon".to_string()));

        let tactics = extract_mitre_tactics(&rule.tags);
        assert!(tactics
            .iter()
            .any(|t| t.to_lowercase().contains("credential")));

        let techniques = extract_mitre_techniques(&rule.tags);
        assert!(techniques.contains(&"T1003".to_string()));
    }
}
