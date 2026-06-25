// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field normalization for mapping source-specific fields to UDM
//!
//! This module provides the FieldNormalizer trait and default implementation
//! for mapping source-specific log fields to the Unified Data Model.
//!
//! Requirements: 2.6, 2.7, 3.1, 3.2, 3.3, 3.4, 3.5

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::UdmField;

/// Transformation functions for field mapping
///
/// These functions transform source field values during normalization.
/// Requirements: 3.3
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransformFn {
    /// Convert string to lowercase
    Lowercase,
    /// Convert string to uppercase
    Uppercase,
    /// Extract substring using regex pattern with capture group
    RegexExtract {
        /// Regex pattern with capture groups
        pattern: String,
        /// Capture group index (0 = full match, 1+ = groups)
        group: usize,
    },
    /// Parse timestamp with specified format string
    ParseTimestamp {
        /// strftime-compatible format string
        format: String,
    },
    /// Replace substring using regex
    RegexReplace {
        /// Regex pattern to match
        pattern: String,
        /// Replacement string (supports $1, $2 for groups)
        replacement: String,
    },
    /// Split string and take element at index
    Split {
        /// Delimiter to split on
        delimiter: String,
        /// Index of element to take (0-based)
        index: usize,
    },
    /// Trim whitespace from string
    Trim,
    /// Parse integer from string
    ParseInt,
    /// Chain multiple transformations
    Chain(Vec<TransformFn>),
    /// No transformation (pass through)
    None,
}

impl Default for TransformFn {
    fn default() -> Self {
        TransformFn::None
    }
}

/// Mapping from a source field to a UDM field
///
/// Defines how a specific source field maps to a UDM field,
/// with optional transformation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdmFieldMapping {
    /// Source field name (supports dot notation for nested fields, e.g., "user.name")
    pub source_field: String,
    /// Target UDM field
    pub udm_field: UdmField,
    /// Optional transformation to apply during mapping
    #[serde(default)]
    pub transform: Option<TransformFn>,
}

impl UdmFieldMapping {
    /// Create a new field mapping without transformation
    pub fn new(source_field: impl Into<String>, udm_field: UdmField) -> Self {
        Self {
            source_field: source_field.into(),
            udm_field,
            transform: None,
        }
    }

    /// Create a new field mapping with transformation
    pub fn with_transform(
        source_field: impl Into<String>,
        udm_field: UdmField,
        transform: TransformFn,
    ) -> Self {
        Self {
            source_field: source_field.into(),
            udm_field,
            transform: Some(transform),
        }
    }
}

/// Field mapping configuration for a log source type
///
/// Contains all field mappings for a specific log source format.
/// Requirements: 3.1, 3.2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Source type identifier (e.g., "syslog", "json", "cef", "leef")
    pub source_type: String,
    /// Human-readable description of this source type
    #[serde(default)]
    pub description: Option<String>,
    /// Field mappings for this source
    pub mappings: Vec<UdmFieldMapping>,
}

impl FieldMapping {
    /// Create a new field mapping configuration
    pub fn new(source_type: impl Into<String>) -> Self {
        Self {
            source_type: source_type.into(),
            description: None,
            mappings: Vec::new(),
        }
    }

    /// Add a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a field mapping
    pub fn add_mapping(mut self, mapping: UdmFieldMapping) -> Self {
        self.mappings.push(mapping);
        self
    }

    /// Add a simple field mapping (no transformation)
    pub fn map_field(mut self, source_field: impl Into<String>, udm_field: UdmField) -> Self {
        self.mappings
            .push(UdmFieldMapping::new(source_field, udm_field));
        self
    }

    /// Add a field mapping with transformation
    pub fn map_field_with_transform(
        mut self,
        source_field: impl Into<String>,
        udm_field: UdmField,
        transform: TransformFn,
    ) -> Self {
        self.mappings.push(UdmFieldMapping::with_transform(
            source_field,
            udm_field,
            transform,
        ));
        self
    }
}

/// Normalized log output containing both original and UDM fields
///
/// Requirements: 2.7 - Original fields preserved alongside normalized fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedLog {
    /// Original metadata preserved (Requirement 2.7)
    pub original: serde_json::Value,
    /// Normalized UDM fields
    pub udm: HashMap<UdmField, serde_json::Value>,
    /// Source type that was used for normalization
    pub source_type: String,
}

impl NormalizedLog {
    /// Get a UDM field value
    pub fn get_udm(&self, field: UdmField) -> Option<&serde_json::Value> {
        self.udm.get(&field)
    }

    /// Get a UDM field value as string
    pub fn get_udm_str(&self, field: UdmField) -> Option<&str> {
        self.udm.get(&field).and_then(|v| v.as_str())
    }

    /// Get a UDM field value as i64
    pub fn get_udm_i64(&self, field: UdmField) -> Option<i64> {
        self.udm.get(&field).and_then(|v| v.as_i64())
    }

    /// Check if a UDM field is present
    pub fn has_udm(&self, field: UdmField) -> bool {
        self.udm.contains_key(&field)
    }

    /// Get all populated UDM fields
    pub fn udm_fields(&self) -> Vec<UdmField> {
        self.udm.keys().copied().collect()
    }
}

/// Error type for normalization failures
#[derive(Debug, Clone, thiserror::Error)]
pub enum NormalizationError {
    #[error("unknown source type: {0}")]
    UnknownSourceType(String),
    #[error("transformation failed for field {field}: {reason}")]
    TransformFailed { field: String, reason: String },
    #[error("invalid regex pattern: {0}")]
    InvalidRegex(String),
    #[error("timestamp parse error: {0}")]
    TimestampParseError(String),
}

/// Trait for field normalization
///
/// Requirements: 2.6, 3.1, 3.2, 3.3
pub trait FieldNormalizer {
    /// Normalize a raw log event to UDM fields
    ///
    /// Maps source-specific fields to UDM fields based on registered mappings.
    /// Original fields are preserved in the output (Requirement 2.7).
    fn normalize(&self, source_type: &str, raw: &serde_json::Value) -> NormalizedLog;

    /// Get mapping for a source type
    fn get_mapping(&self, source_type: &str) -> Option<&FieldMapping>;

    /// Register a new field mapping
    fn register_mapping(&mut self, mapping: FieldMapping);

    /// Get all registered source types
    fn source_types(&self) -> Vec<&str>;

    /// Check if a source type has registered mappings
    fn has_mapping(&self, source_type: &str) -> bool {
        self.get_mapping(source_type).is_some()
    }
}

/// Default implementation of FieldNormalizer
///
/// Provides field normalization with transformation support.
#[derive(Debug, Default, Clone)]
pub struct DefaultFieldNormalizer {
    mappings: HashMap<String, FieldMapping>,
}

impl DefaultFieldNormalizer {
    /// Create a new empty normalizer
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a normalizer with default mappings for common formats
    ///
    /// Includes mappings for: syslog, json, cef, leef
    /// Requirements: 3.4
    pub fn with_defaults() -> Self {
        let mut normalizer = Self::new();
        normalizer.register_default_mappings();
        normalizer
    }

    /// Register default mappings for common log formats
    fn register_default_mappings(&mut self) {
        // Syslog format mappings
        self.register_mapping(create_syslog_mapping());

        // Generic JSON format mappings
        self.register_mapping(create_json_mapping());

        // CEF (Common Event Format) mappings
        self.register_mapping(create_cef_mapping());

        // LEEF (Log Event Extended Format) mappings
        self.register_mapping(create_leef_mapping());
    }
}

impl FieldNormalizer for DefaultFieldNormalizer {
    fn normalize(&self, source_type: &str, raw: &serde_json::Value) -> NormalizedLog {
        let mut udm = HashMap::new();

        if let Some(mapping) = self.mappings.get(source_type) {
            for field_mapping in &mapping.mappings {
                if let Some(value) = get_nested_value(raw, &field_mapping.source_field) {
                    let transformed = apply_transform(value, &field_mapping.transform);
                    udm.insert(field_mapping.udm_field, transformed);
                }
            }
        }

        NormalizedLog {
            original: raw.clone(),
            udm,
            source_type: source_type.to_string(),
        }
    }

    fn get_mapping(&self, source_type: &str) -> Option<&FieldMapping> {
        self.mappings.get(source_type)
    }

    fn register_mapping(&mut self, mapping: FieldMapping) {
        self.mappings.insert(mapping.source_type.clone(), mapping);
    }

    fn source_types(&self) -> Vec<&str> {
        self.mappings.keys().map(|s| s.as_str()).collect()
    }
}

/// Get a nested value from JSON using dot notation
///
/// Supports paths like "user.name" or "network.src.ip"
pub fn get_nested_value<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;

    for part in parts {
        current = current.get(part)?;
    }

    Some(current)
}

/// Apply a transformation function to a value
pub fn apply_transform(
    value: &serde_json::Value,
    transform: &Option<TransformFn>,
) -> serde_json::Value {
    match transform {
        Some(TransformFn::Lowercase) => {
            if let Some(s) = value.as_str() {
                serde_json::Value::String(s.to_lowercase())
            } else {
                value.clone()
            }
        }
        Some(TransformFn::Uppercase) => {
            if let Some(s) = value.as_str() {
                serde_json::Value::String(s.to_uppercase())
            } else {
                value.clone()
            }
        }
        Some(TransformFn::RegexExtract { pattern, group }) => {
            if let Some(s) = value.as_str() {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if let Some(caps) = re.captures(s) {
                        if let Some(m) = caps.get(*group) {
                            return serde_json::Value::String(m.as_str().to_string());
                        }
                    }
                }
            }
            value.clone()
        }
        Some(TransformFn::ParseTimestamp { format }) => {
            if let Some(s) = value.as_str() {
                // Try to parse with the given format
                if let Ok(dt) = NaiveDateTime::parse_from_str(s, format) {
                    let utc_dt: DateTime<Utc> = DateTime::from_naive_utc_and_offset(dt, Utc);
                    return serde_json::Value::String(utc_dt.to_rfc3339());
                }
            }
            value.clone()
        }
        Some(TransformFn::RegexReplace {
            pattern,
            replacement,
        }) => {
            if let Some(s) = value.as_str() {
                if let Ok(re) = regex::Regex::new(pattern) {
                    return serde_json::Value::String(
                        re.replace_all(s, replacement.as_str()).to_string(),
                    );
                }
            }
            value.clone()
        }
        Some(TransformFn::Split { delimiter, index }) => {
            if let Some(s) = value.as_str() {
                let parts: Vec<&str> = s.split(delimiter.as_str()).collect();
                if let Some(part) = parts.get(*index) {
                    return serde_json::Value::String(part.to_string());
                }
            }
            value.clone()
        }
        Some(TransformFn::Trim) => {
            if let Some(s) = value.as_str() {
                serde_json::Value::String(s.trim().to_string())
            } else {
                value.clone()
            }
        }
        Some(TransformFn::ParseInt) => {
            if let Some(s) = value.as_str() {
                if let Ok(n) = s.parse::<i64>() {
                    return serde_json::json!(n);
                }
            }
            value.clone()
        }
        Some(TransformFn::Chain(transforms)) => {
            let mut result = value.clone();
            for t in transforms {
                result = apply_transform(&result, &Some(t.clone()));
            }
            result
        }
        Some(TransformFn::None) | None => value.clone(),
    }
}

// =============================================================================
// Default Mappings for Common Log Formats (Requirement 3.4)
// =============================================================================

/// Create default syslog field mappings
///
/// Maps common syslog fields to UDM fields.
pub fn create_syslog_mapping() -> FieldMapping {
    FieldMapping::new("syslog")
        .with_description("Standard syslog format (RFC 3164/5424)")
        // Entity fields
        .map_field("hostname", UdmField::SrcHost)
        .map_field("host", UdmField::SrcHost)
        .map_field("source_ip", UdmField::SrcIp)
        .map_field("src", UdmField::SrcIp)
        .map_field("dst", UdmField::DestIp)
        .map_field("destination_ip", UdmField::DestIp)
        .map_field("user", UdmField::User)
        .map_field("username", UdmField::User)
        .map_field("timestamp", UdmField::Timestamp)
        .map_field("@timestamp", UdmField::Timestamp)
        // Process fields
        .map_field("program", UdmField::ProcessName)
        .map_field("appname", UdmField::ProcessName)
        .map_field("pid", UdmField::ProcessId)
        .map_field("procid", UdmField::ProcessId)
        // Network fields
        .map_field("src_port", UdmField::SrcPort)
        .map_field("dst_port", UdmField::DestPort)
        .map_field("protocol", UdmField::Protocol)
}

/// Create default JSON field mappings
///
/// Maps common JSON log fields to UDM fields.
/// Supports nested fields with dot notation.
pub fn create_json_mapping() -> FieldMapping {
    FieldMapping::new("json")
        .with_description("Generic JSON log format")
        // Entity fields - common variations
        .map_field("src_ip", UdmField::SrcIp)
        .map_field("source_ip", UdmField::SrcIp)
        .map_field("client_ip", UdmField::SrcIp)
        .map_field("dest_ip", UdmField::DestIp)
        .map_field("destination_ip", UdmField::DestIp)
        .map_field("server_ip", UdmField::DestIp)
        .map_field("src_host", UdmField::SrcHost)
        .map_field("source_host", UdmField::SrcHost)
        .map_field("hostname", UdmField::SrcHost)
        .map_field("dest_host", UdmField::DestHost)
        .map_field("destination_host", UdmField::DestHost)
        .map_field("user", UdmField::User)
        .map_field("username", UdmField::User)
        .map_field("event_type", UdmField::EventType)
        .map_field("action", UdmField::EventType)
        .map_field("status", UdmField::Status)
        .map_field("result", UdmField::Status)
        .map_field("outcome", UdmField::Status)
        .map_field("timestamp", UdmField::Timestamp)
        .map_field("@timestamp", UdmField::Timestamp)
        .map_field("time", UdmField::Timestamp)
        // Network fields
        .map_field("src_port", UdmField::SrcPort)
        .map_field("source_port", UdmField::SrcPort)
        .map_field("dest_port", UdmField::DestPort)
        .map_field("destination_port", UdmField::DestPort)
        .map_field("protocol", UdmField::Protocol)
        .map_field("bytes_in", UdmField::BytesIn)
        .map_field("bytes_received", UdmField::BytesIn)
        .map_field("bytes_out", UdmField::BytesOut)
        .map_field("bytes_sent", UdmField::BytesOut)
        // Authentication fields
        .map_field("auth_type", UdmField::AuthType)
        .map_field("auth_result", UdmField::AuthResult)
        .map_field("session_id", UdmField::SessionId)
        // OpenTelemetry trace-correlation fields (NAN-1528)
        .map_field("trace_id", UdmField::TraceId)
        .map_field("span_id", UdmField::SpanId)
        // Process fields
        .map_field("process_name", UdmField::ProcessName)
        .map_field("process_id", UdmField::ProcessId)
        .map_field("pid", UdmField::ProcessId)
        .map_field("parent_process", UdmField::ParentCommandLine)
        // File fields
        .map_field("file_path", UdmField::FilePath)
        .map_field("path", UdmField::FilePath)
        .map_field("file_name", UdmField::FileName)
        .map_field("filename", UdmField::FileName)
        .map_field("file_hash", UdmField::FileHash)
        .map_field("hash", UdmField::FileHash)
        .map_field("file_action", UdmField::FileAction)
}

/// Create default CEF (Common Event Format) field mappings
///
/// CEF is a standard format used by many security products.
/// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
pub fn create_cef_mapping() -> FieldMapping {
    FieldMapping::new("cef")
        .with_description("ArcSight Common Event Format (CEF)")
        // CEF standard extension fields
        .map_field("src", UdmField::SrcIp)
        .map_field("dst", UdmField::DestIp)
        .map_field("shost", UdmField::SrcHost)
        .map_field("dhost", UdmField::DestHost)
        .map_field("spt", UdmField::SrcPort)
        .map_field("dpt", UdmField::DestPort)
        .map_field("proto", UdmField::Protocol)
        .map_field("suser", UdmField::User)
        .map_field("duser", UdmField::User)
        .map_field("act", UdmField::EventType)
        .map_field("outcome", UdmField::Status)
        .map_field("rt", UdmField::Timestamp)
        .map_field("end", UdmField::Timestamp)
        // CEF network fields
        .map_field("in", UdmField::BytesIn)
        .map_field("out", UdmField::BytesOut)
        // CEF process fields
        .map_field("sproc", UdmField::ProcessName)
        .map_field("dproc", UdmField::ProcessName)
        .map_field("spid", UdmField::ProcessId)
        .map_field("dpid", UdmField::ProcessId)
        // CEF file fields
        .map_field("fname", UdmField::FileName)
        .map_field("filePath", UdmField::FilePath)
        .map_field("fileHash", UdmField::FileHash)
        // CEF auth fields
        .map_field("cs1", UdmField::SessionId) // Often used for session ID
}

/// Create default LEEF (Log Event Extended Format) field mappings
///
/// LEEF is IBM's standard format used by QRadar and other IBM security products.
/// Format: LEEF:Version|Vendor|Product|Version|EventID|Extension
pub fn create_leef_mapping() -> FieldMapping {
    FieldMapping::new("leef")
        .with_description("IBM Log Event Extended Format (LEEF)")
        // LEEF standard fields
        .map_field("src", UdmField::SrcIp)
        .map_field("dst", UdmField::DestIp)
        .map_field("srcPort", UdmField::SrcPort)
        .map_field("dstPort", UdmField::DestPort)
        .map_field("proto", UdmField::Protocol)
        .map_field("usrName", UdmField::User)
        .map_field("accountName", UdmField::User)
        .map_field("action", UdmField::EventType)
        .map_field("devTime", UdmField::Timestamp)
        .map_field("devTimeFormat", UdmField::Timestamp)
        // LEEF network fields
        .map_field("srcBytes", UdmField::BytesIn)
        .map_field("dstBytes", UdmField::BytesOut)
        .map_field("totalBytes", UdmField::BytesOut)
        // LEEF host fields
        .map_field("srcHostName", UdmField::SrcHost)
        .map_field("dstHostName", UdmField::DestHost)
        // LEEF process fields
        .map_field("processName", UdmField::ProcessName)
        .map_field("processId", UdmField::ProcessId)
        .map_field("parentProcessName", UdmField::ParentCommandLine)
        .map_field("commandLine", UdmField::CommandLine)
        // LEEF file fields
        .map_field("fileName", UdmField::FileName)
        .map_field("filePath", UdmField::FilePath)
        .map_field("fileHash", UdmField::FileHash)
        // LEEF auth fields
        .map_field("authType", UdmField::AuthType)
        .map_field("sessionId", UdmField::SessionId)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_field_mapping() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(
            FieldMapping::new("test")
                .map_field("source_ip", UdmField::SrcIp)
                .map_field("user", UdmField::User),
        );

        let raw = json!({
            "source_ip": "192.168.1.1",
            "user": "admin",
            "extra_field": "ignored"
        });

        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::SrcIp), Some("192.168.1.1"));
        assert_eq!(result.get_udm_str(UdmField::User), Some("admin"));
        assert!(result.original.get("extra_field").is_some()); // Original preserved
    }

    #[test]
    fn test_nested_field_mapping() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(
            FieldMapping::new("nested")
                .map_field("source.ip", UdmField::SrcIp)
                .map_field("user.name", UdmField::User),
        );

        let raw = json!({
            "source": { "ip": "10.0.0.1" },
            "user": { "name": "testuser" }
        });

        let result = normalizer.normalize("nested", &raw);

        assert_eq!(result.get_udm_str(UdmField::SrcIp), Some("10.0.0.1"));
        assert_eq!(result.get_udm_str(UdmField::User), Some("testuser"));
    }

    #[test]
    fn test_lowercase_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "user",
            UdmField::User,
            TransformFn::Lowercase,
        ));

        let raw = json!({ "user": "ADMIN" });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::User), Some("admin"));
    }

    #[test]
    fn test_uppercase_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "protocol",
            UdmField::Protocol,
            TransformFn::Uppercase,
        ));

        let raw = json!({ "protocol": "tcp" });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::Protocol), Some("TCP"));
    }

    #[test]
    fn test_regex_extract_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "message",
            UdmField::SrcIp,
            TransformFn::RegexExtract {
                pattern: r"from (\d+\.\d+\.\d+\.\d+)".to_string(),
                group: 1,
            },
        ));

        let raw = json!({ "message": "Connection from 192.168.1.100 accepted" });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::SrcIp), Some("192.168.1.100"));
    }

    #[test]
    fn test_split_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "path",
            UdmField::FileName,
            TransformFn::Split {
                delimiter: "/".to_string(),
                index: 2,
            },
        ));

        let raw = json!({ "path": "/home/user/file.txt" });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::FileName), Some("user"));
    }

    #[test]
    fn test_trim_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "user",
            UdmField::User,
            TransformFn::Trim,
        ));

        let raw = json!({ "user": "  admin  " });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::User), Some("admin"));
    }

    #[test]
    fn test_parse_int_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "port",
            UdmField::SrcPort,
            TransformFn::ParseInt,
        ));

        let raw = json!({ "port": "8080" });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_i64(UdmField::SrcPort), Some(8080));
    }

    #[test]
    fn test_chain_transform() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field_with_transform(
            "user",
            UdmField::User,
            TransformFn::Chain(vec![TransformFn::Trim, TransformFn::Lowercase]),
        ));

        let raw = json!({ "user": "  ADMIN  " });
        let result = normalizer.normalize("test", &raw);

        assert_eq!(result.get_udm_str(UdmField::User), Some("admin"));
    }

    #[test]
    fn test_original_fields_preserved() {
        let mut normalizer = DefaultFieldNormalizer::new();
        normalizer.register_mapping(FieldMapping::new("test").map_field("src_ip", UdmField::SrcIp));

        let raw = json!({
            "src_ip": "192.168.1.1",
            "custom_field": "custom_value",
            "nested": { "data": 123 }
        });

        let result = normalizer.normalize("test", &raw);

        // Original fields should be preserved
        assert_eq!(result.original.get("src_ip").unwrap(), "192.168.1.1");
        assert_eq!(result.original.get("custom_field").unwrap(), "custom_value");
        assert_eq!(result.original["nested"]["data"], 123);
    }

    #[test]
    fn test_unknown_source_type() {
        let normalizer = DefaultFieldNormalizer::new();
        let raw = json!({ "src_ip": "192.168.1.1" });

        let result = normalizer.normalize("unknown", &raw);

        // Should return empty UDM but preserve original
        assert!(result.udm.is_empty());
        assert_eq!(result.original.get("src_ip").unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_default_mappings_registered() {
        let normalizer = DefaultFieldNormalizer::with_defaults();

        assert!(normalizer.has_mapping("syslog"));
        assert!(normalizer.has_mapping("json"));
        assert!(normalizer.has_mapping("cef"));
        assert!(normalizer.has_mapping("leef"));
    }

    #[test]
    fn test_syslog_mapping() {
        let normalizer = DefaultFieldNormalizer::with_defaults();

        let raw = json!({
            "hostname": "server01",
            "source_ip": "10.0.0.1",
            "user": "root",
            "program": "sshd",
            "pid": 1234
        });

        let result = normalizer.normalize("syslog", &raw);

        assert_eq!(result.get_udm_str(UdmField::SrcHost), Some("server01"));
        assert_eq!(result.get_udm_str(UdmField::SrcIp), Some("10.0.0.1"));
        assert_eq!(result.get_udm_str(UdmField::User), Some("root"));
        assert_eq!(result.get_udm_str(UdmField::ProcessName), Some("sshd"));
        assert_eq!(result.get_udm_i64(UdmField::ProcessId), Some(1234));
    }

    #[test]
    fn test_cef_mapping() {
        let normalizer = DefaultFieldNormalizer::with_defaults();

        let raw = json!({
            "src": "192.168.1.100",
            "dst": "10.0.0.1",
            "spt": 54321,
            "dpt": 443,
            "proto": "TCP",
            "suser": "admin",
            "act": "ALLOW"
        });

        let result = normalizer.normalize("cef", &raw);

        assert_eq!(result.get_udm_str(UdmField::SrcIp), Some("192.168.1.100"));
        assert_eq!(result.get_udm_str(UdmField::DestIp), Some("10.0.0.1"));
        assert_eq!(result.get_udm_i64(UdmField::SrcPort), Some(54321));
        assert_eq!(result.get_udm_i64(UdmField::DestPort), Some(443));
        assert_eq!(result.get_udm_str(UdmField::Protocol), Some("TCP"));
        assert_eq!(result.get_udm_str(UdmField::User), Some("admin"));
        assert_eq!(result.get_udm_str(UdmField::EventType), Some("ALLOW"));
    }

    #[test]
    fn test_source_types_list() {
        let normalizer = DefaultFieldNormalizer::with_defaults();
        let types = normalizer.source_types();

        assert!(types.contains(&"syslog"));
        assert!(types.contains(&"json"));
        assert!(types.contains(&"cef"));
        assert!(types.contains(&"leef"));
    }

    #[test]
    fn test_normalized_log_helpers() {
        let mut udm = HashMap::new();
        udm.insert(UdmField::SrcIp, json!("192.168.1.1"));
        udm.insert(UdmField::SrcPort, json!(8080));

        let log = NormalizedLog {
            original: json!({}),
            udm,
            source_type: "test".to_string(),
        };

        assert!(log.has_udm(UdmField::SrcIp));
        assert!(!log.has_udm(UdmField::DestIp));
        assert_eq!(log.get_udm_str(UdmField::SrcIp), Some("192.168.1.1"));
        assert_eq!(log.get_udm_i64(UdmField::SrcPort), Some(8080));

        let fields = log.udm_fields();
        assert!(fields.contains(&UdmField::SrcIp));
        assert!(fields.contains(&UdmField::SrcPort));
    }
}
