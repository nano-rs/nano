// SPDX-License-Identifier: AGPL-3.0-or-later

/// CSV Parser for UDM Fields
///
/// This module parses the docs/udmfields.csv file and generates structured
/// representations of UDM fields for code generation.
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Represents a parsed UDM field with its metadata
#[derive(Debug, Clone)]
pub struct UdmFieldDefinition {
    pub field_name: String,
    pub snake_case_name: String,
    pub pascal_case_name: String,
    pub data_models: Vec<String>,
    pub inferred_type: UdmDataType,
    pub category: UdmFieldCategory,
}

/// Inferred data types for UDM fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdmDataType {
    String,
    Integer,
    Long,
    Float,
    Boolean,
    IpAddress,
    Timestamp,
    Array,
}

/// Field categories based on data models
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdmFieldCategory {
    Entity,
    Network,
    Authentication,
    Endpoint,
    Process,
    File,
    Email,
    Web,
    Database,
    Malware,
    Intrusion,
    Vulnerability,
    Certificate,
    Dns,
    Performance,
    Inventory,
    Change,
    DataAccess,
    DataLossPrevention,
    Alerts,
    Updates,
    EventSignatures,
    InterprocessMessaging,
    NetworkSessions,
    Custom,
    System,
    Enrichment,
    ThreatIntelligence,
    CustomEnrichment,
    Prevalence,
    Risk,
    Detection,
}

impl UdmFieldCategory {
    /// Determine category from data models
    pub fn from_data_models(data_models: &[String]) -> Self {
        // Priority-based categorization
        for model in data_models {
            let model_lower = model.to_lowercase();

            if model_lower.contains("authentication") {
                return Self::Authentication;
            } else if model_lower.contains("network traffic")
                || model_lower.contains("network sessions")
            {
                return Self::Network;
            } else if model_lower.contains("endpoint") {
                return Self::Endpoint;
            } else if model_lower.contains("email") {
                return Self::Email;
            } else if model_lower.contains("web") {
                return Self::Web;
            } else if model_lower.contains("database") {
                return Self::Database;
            } else if model_lower.contains("malware") {
                return Self::Malware;
            } else if model_lower.contains("intrusion") {
                return Self::Intrusion;
            } else if model_lower.contains("vulnerabilities") {
                return Self::Vulnerability;
            } else if model_lower.contains("certificates") {
                return Self::Certificate;
            } else if model_lower.contains("dns") || model_lower.contains("network resolution") {
                return Self::Dns;
            } else if model_lower.contains("performance") {
                return Self::Performance;
            } else if model_lower.contains("inventory") {
                return Self::Inventory;
            } else if model_lower.contains("change") {
                return Self::Change;
            } else if model_lower.contains("data access") {
                return Self::DataAccess;
            } else if model_lower.contains("data loss prevention") {
                return Self::DataLossPrevention;
            } else if model_lower.contains("alerts") {
                return Self::Alerts;
            } else if model_lower.contains("updates") {
                return Self::Updates;
            } else if model_lower.contains("event signatures") {
                return Self::EventSignatures;
            } else if model_lower.contains("interprocess messaging") {
                return Self::InterprocessMessaging;
            } else if model_lower.contains("network sessions") {
                return Self::NetworkSessions;
            } else if model_lower.contains("system") {
                return Self::System;
            } else if model_lower.contains("enrichment") && !model_lower.contains("custom") {
                return Self::Enrichment;
            } else if model_lower.contains("threat intelligence") {
                return Self::ThreatIntelligence;
            } else if model_lower.contains("custom enrichment") {
                return Self::CustomEnrichment;
            } else if model_lower.contains("prevalence") {
                return Self::Prevalence;
            } else if model_lower.contains("risk") {
                return Self::Risk;
            } else if model_lower.contains("detection") {
                return Self::Detection;
            }
        }

        // Default to Entity for common fields
        Self::Entity
    }
}

impl UdmDataType {
    /// Infer data type from field name
    pub fn infer_from_name(field_name: &str) -> Self {
        let name_lower = field_name.to_lowercase();

        // Array fields (tags, answers)
        if name_lower.ends_with("_tags") {
            return Self::Array;
        }

        // IP address fields
        if name_lower.contains("_ip") || name_lower == "ip" || name_lower.ends_with("_ips") {
            return Self::IpAddress;
        }

        // Timestamp fields
        if name_lower.contains("_time")
            || name_lower.contains("timestamp")
            || name_lower.ends_with("_date")
            || name_lower == "time"
        {
            return Self::Timestamp;
        }

        // Boolean fields
        if name_lower.starts_with("is_")
            || name_lower.starts_with("has_")
            || name_lower.starts_with("should_")
            || name_lower.starts_with("requires_")
            || name_lower.ends_with("_enabled")
            || name_lower.ends_with("_supported")
            || name_lower == "ioc_matched"
        {
            return Self::Boolean;
        }

        // Integer fields (counts, IDs, ports, confidence, prevalence)
        if name_lower.ends_with("_count")
            || name_lower.ends_with("_id")
            || name_lower.ends_with("_port")
            || name_lower.ends_with("_code")
            || name_lower.ends_with("_pid")
            || name_lower == "count"
            || name_lower.ends_with("_confidence")
            || name_lower.starts_with("prevalence_")
        {
            return Self::Integer;
        }

        // Long fields (bytes, sizes)
        if name_lower.contains("bytes")
            || name_lower.ends_with("_size")
            || name_lower.contains("memory")
        {
            return Self::Long;
        }

        // Float fields (percentages, ratios, scores)
        if name_lower.ends_with("_percent")
            || name_lower.ends_with("_ratio")
            || name_lower.ends_with("_score")
            || name_lower.contains("_load")
        {
            return Self::Float;
        }

        // Default to String
        Self::String
    }
}

/// Parse the UDM fields CSV file
pub fn parse_udm_csv<P: AsRef<Path>>(path: P) -> Result<Vec<UdmFieldDefinition>, String> {
    let file = File::open(path).map_err(|e| format!("Failed to open CSV: {}", e))?;
    let reader = BufReader::new(file);
    let mut fields = Vec::new();
    let mut seen_fields = HashSet::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Failed to read line {}: {}", line_num, e))?;

        // Skip header
        if line_num == 0 {
            continue;
        }

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse CSV line
        let parts: Vec<&str> = line.split(',').collect();
        if parts.is_empty() {
            continue;
        }

        let field_name = parts[0].trim();
        if field_name.is_empty() {
            continue;
        }

        // Skip duplicate fields (some fields appear multiple times in CSV)
        if seen_fields.contains(field_name) {
            continue;
        }
        seen_fields.insert(field_name.to_string());

        // Parse data models (second column, comma-separated)
        let data_models: Vec<String> = if parts.len() > 1 {
            parts[1]
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![]
        };

        // Convert to snake_case
        let snake_case_name = to_snake_case(field_name);

        // Convert to PascalCase for enum variant
        let pascal_case_name = to_pascal_case(field_name);

        // Infer data type
        let inferred_type = UdmDataType::infer_from_name(field_name);

        // Determine category
        let category = UdmFieldCategory::from_data_models(&data_models);

        fields.push(UdmFieldDefinition {
            field_name: field_name.to_string(),
            snake_case_name,
            pascal_case_name,
            data_models,
            inferred_type,
            category,
        });
    }

    Ok(fields)
}

/// Convert field name to snake_case
fn to_snake_case(s: &str) -> String {
    s.to_lowercase().replace('-', "_")
}

/// Convert field name to PascalCase for enum variants
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

/// Generate statistics about the parsed fields
pub fn generate_statistics(fields: &[UdmFieldDefinition]) -> String {
    let mut stats = String::new();

    stats.push_str(&format!("Total fields: {}\n\n", fields.len()));

    // Count by category
    let mut category_counts: HashMap<String, usize> = HashMap::new();
    for field in fields {
        let category_name = format!("{:?}", field.category);
        *category_counts.entry(category_name).or_insert(0) += 1;
    }

    stats.push_str("Fields by category:\n");
    let mut categories: Vec<_> = category_counts.iter().collect();
    categories.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (category, count) in categories {
        stats.push_str(&format!("  {}: {}\n", category, count));
    }
    stats.push('\n');

    // Count by data type
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for field in fields {
        let type_name = format!("{:?}", field.inferred_type);
        *type_counts.entry(type_name).or_insert(0) += 1;
    }

    stats.push_str("Fields by inferred type:\n");
    let mut types: Vec<_> = type_counts.iter().collect();
    types.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (data_type, count) in types {
        stats.push_str(&format!("  {}: {}\n", data_type, count));
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("src_ip"), "src_ip");
        assert_eq!(to_snake_case("http_method"), "http_method");
        assert_eq!(to_snake_case("user"), "user");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("src_ip"), "SrcIp");
        assert_eq!(to_pascal_case("http_method"), "HttpMethod");
        assert_eq!(to_pascal_case("user"), "User");
    }

    #[test]
    fn test_infer_ip_address() {
        assert_eq!(
            UdmDataType::infer_from_name("src_ip"),
            UdmDataType::IpAddress
        );
        assert_eq!(
            UdmDataType::infer_from_name("dest_ip"),
            UdmDataType::IpAddress
        );
        assert_eq!(UdmDataType::infer_from_name("ip"), UdmDataType::IpAddress);
    }

    #[test]
    fn test_infer_timestamp() {
        assert_eq!(
            UdmDataType::infer_from_name("start_time"),
            UdmDataType::Timestamp
        );
        assert_eq!(
            UdmDataType::infer_from_name("creation_time"),
            UdmDataType::Timestamp
        );
        assert_eq!(
            UdmDataType::infer_from_name("timestamp"),
            UdmDataType::Timestamp
        );
    }

    #[test]
    fn test_infer_boolean() {
        assert_eq!(
            UdmDataType::infer_from_name("is_rare"),
            UdmDataType::Boolean
        );
        assert_eq!(
            UdmDataType::infer_from_name("has_error"),
            UdmDataType::Boolean
        );
        assert_eq!(
            UdmDataType::infer_from_name("should_update"),
            UdmDataType::Boolean
        );
    }

    #[test]
    fn test_infer_integer() {
        assert_eq!(
            UdmDataType::infer_from_name("host_count"),
            UdmDataType::Integer
        );
        assert_eq!(
            UdmDataType::infer_from_name("process_id"),
            UdmDataType::Integer
        );
        assert_eq!(
            UdmDataType::infer_from_name("src_port"),
            UdmDataType::Integer
        );
    }

    #[test]
    fn test_infer_float() {
        assert_eq!(
            UdmDataType::infer_from_name("cpu_load_percent"),
            UdmDataType::Float
        );
        assert_eq!(
            UdmDataType::infer_from_name("prevalence_score"),
            UdmDataType::Integer
        );
    }
}
