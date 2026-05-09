// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Parser
//!
//! Parses raw log data into structured format for storage.
//! Supports multiple log formats: JSON, syslog, CEF, LEEF.
//!
//! Requirements: 1.1 - Parse raw log line and extract metadata fields into JSONB format

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::udm::{DefaultFieldNormalizer, FieldNormalizer, NormalizedLog, UdmField};

/// Errors that can occur during log parsing
#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid timestamp format: {0}")]
    InvalidTimestamp(String),

    #[error("Unsupported log format: {0}")]
    UnsupportedFormat(String),
}

/// A parsed log entry ready for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedLog {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Raw log content for full-text search
    pub message: String,
    /// Parsed metadata as JSON
    pub metadata: serde_json::Value,
    /// Source type (syslog, json, cef, leef, unknown)
    pub source_type: String,
    /// Source/subsystem that generated the log (e.g., auth, detection, firewall)
    pub source: Option<String>,

    // UDM fields
    pub src_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub src_host: Option<String>,
    pub dest_host: Option<String>,
    pub src_port: Option<i32>,
    pub dest_port: Option<i32>,
    pub protocol: Option<String>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub auth_type: Option<String>,
    pub auth_result: Option<String>,
    pub session_id: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<i32>,
    /// Full command line (nano UDM: command_line = path + exe + args)
    pub command_line: Option<String>,
    /// Parent process name (nano UDM: parent_process_name = just the exe)
    pub parent_process_name: Option<String>,
    /// Full parent command line (nano UDM: parent_command_line = path + exe + args)
    pub parent_command_line: Option<String>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_action: Option<String>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub user_agent: Option<String>,
    /// Extended/overflow fields as JSON (stored in ClickHouse ext column)
    pub ext: Option<serde_json::Value>,
}

impl ParsedLog {
    /// Create a ParsedLog from a NormalizedLog
    pub fn from_normalized(message: String, normalized: NormalizedLog) -> Self {
        let source_type = normalized.source_type.clone();
        let timestamp = Self::extract_timestamp(&normalized).unwrap_or_else(Utc::now);
        let src_ip = Self::get_string(&normalized, UdmField::SrcIp);
        let dest_ip = Self::get_string(&normalized, UdmField::DestIp);
        let src_host = Self::get_string(&normalized, UdmField::SrcHost);
        let dest_host = Self::get_string(&normalized, UdmField::DestHost);
        let src_port = Self::get_i32(&normalized, UdmField::SrcPort);
        let dest_port = Self::get_i32(&normalized, UdmField::DestPort);
        let protocol = Self::get_string(&normalized, UdmField::Protocol);
        let user = Self::get_string(&normalized, UdmField::User);
        let action = Self::get_string(&normalized, UdmField::EventType);
        let status = Self::get_string(&normalized, UdmField::Status);
        let auth_type = Self::get_string(&normalized, UdmField::AuthType);
        let auth_result = Self::get_string(&normalized, UdmField::AuthResult);
        let session_id = Self::get_string(&normalized, UdmField::SessionId);
        let process_name = Self::get_string(&normalized, UdmField::ProcessName);
        let process_id = Self::get_i32(&normalized, UdmField::ProcessId);
        // nano UDM: command_line = full command line
        let command_line = Self::get_string(&normalized, UdmField::CommandLine);
        // nano UDM: parent_process_name = just the parent exe filename
        let parent_process_name = Self::get_string(&normalized, UdmField::ParentProcessName);
        // nano UDM: parent_command_line = full parent command line
        let parent_command_line = Self::get_string(&normalized, UdmField::ParentCommandLine);
        let file_path = Self::get_string(&normalized, UdmField::FilePath);
        let file_name = Self::get_string(&normalized, UdmField::FileName);
        let file_hash = Self::get_string(&normalized, UdmField::FileHash);
        let file_action = Self::get_string(&normalized, UdmField::FileAction);
        let bytes_in = Self::get_i64(&normalized, UdmField::BytesIn);
        let bytes_out = Self::get_i64(&normalized, UdmField::BytesOut);

        Self {
            timestamp,
            message,
            metadata: normalized.original,
            source_type,
            source: None,
            src_ip,
            dest_ip,
            src_host,
            dest_host,
            src_port,
            dest_port,
            protocol,
            user,
            action,
            status,
            severity: None, // Extracted from metadata if present, set by detection engine
            auth_type,
            auth_result,
            session_id,
            process_name,
            process_id,
            command_line,
            parent_process_name,
            parent_command_line,
            file_path,
            file_name,
            file_hash,
            file_action,
            bytes_in,
            bytes_out,
            user_agent: None, // Not in UDM, extracted from metadata if present
            ext: None,        // Extended fields, populated by parsers
        }
    }

    fn extract_timestamp(normalized: &NormalizedLog) -> Option<DateTime<Utc>> {
        normalized
            .get_udm(UdmField::Timestamp)
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
    }

    fn get_string(normalized: &NormalizedLog, field: UdmField) -> Option<String> {
        normalized.get_udm_str(field).map(|s| s.to_string())
    }

    fn get_i32(normalized: &NormalizedLog, field: UdmField) -> Option<i32> {
        normalized
            .get_udm_i64(field)
            .and_then(|n| i32::try_from(n).ok())
    }

    fn get_i64(normalized: &NormalizedLog, field: UdmField) -> Option<i64> {
        normalized.get_udm_i64(field)
    }
}

/// Log parser that handles multiple formats
#[derive(Debug, Clone)]
pub struct LogParser {
    normalizer: DefaultFieldNormalizer,
}

impl Default for LogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser {
    /// Create a new log parser with default field mappings
    pub fn new() -> Self {
        Self {
            normalizer: DefaultFieldNormalizer::with_defaults(),
        }
    }

    /// Create a log parser with a custom normalizer
    pub fn with_normalizer(normalizer: DefaultFieldNormalizer) -> Self {
        Self { normalizer }
    }

    /// Parse a raw log string
    ///
    /// Automatically detects the log format and parses accordingly.
    pub fn parse(&self, raw: &str) -> Result<ParsedLog, ParserError> {
        let (source_type, metadata) = self.detect_and_parse(raw)?;
        let normalized = self.normalizer.normalize(&source_type, &metadata);
        Ok(ParsedLog::from_normalized(raw.to_string(), normalized))
    }

    /// Parse a JSON log entry (pre-parsed by Vector)
    ///
    /// This is the primary entry point when receiving logs from Vector's HTTP sink.
    pub fn parse_json(&self, json: serde_json::Value) -> Result<ParsedLog, ParserError> {
        // If the JSON has our expected structure from Vector
        if json.get("message").is_some() {
            return self.parse_vector_format(json);
        }

        // Otherwise, treat it as a raw JSON log
        let message = serde_json::to_string(&json)?;
        let source_type = self.detect_source_type_from_json(&json);
        let normalized = self.normalizer.normalize(&source_type, &json);
        Ok(ParsedLog::from_normalized(message, normalized))
    }

    /// Parse logs in Vector's output format
    fn parse_vector_format(&self, json: serde_json::Value) -> Result<ParsedLog, ParserError> {
        let message = json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let metadata = json
            .get("metadata")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        // Parse metadata if it's a string (JSON-encoded)
        let metadata = if let Some(s) = metadata.as_str() {
            serde_json::from_str(s).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
        } else {
            metadata
        };

        let timestamp = json
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        // Extract UDM fields directly from Vector's output
        Ok(ParsedLog {
            timestamp,
            message,
            metadata,
            source_type: json
                .get("source_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            source: Self::extract_string(&json, "source"),
            src_ip: Self::extract_string(&json, "src_ip"),
            dest_ip: Self::extract_string(&json, "dest_ip"),
            src_host: Self::extract_string(&json, "src_host"),
            dest_host: Self::extract_string(&json, "dest_host"),
            src_port: Self::extract_i32(&json, "src_port"),
            dest_port: Self::extract_i32(&json, "dest_port"),
            protocol: Self::extract_string(&json, "protocol"),
            user: Self::extract_string(&json, "user"),
            // NAN-659: event_type is the canonical name; action kept as legacy synonym
            action: Self::extract_string(&json, "event_type")
                .or_else(|| Self::extract_string(&json, "action")),
            status: Self::extract_string(&json, "status"),
            severity: Self::extract_string(&json, "severity"),
            auth_type: Self::extract_string(&json, "auth_type"),
            auth_result: Self::extract_string(&json, "auth_result"),
            session_id: Self::extract_string(&json, "session_id"),
            process_name: Self::extract_string(&json, "process_name"),
            process_id: Self::extract_i32(&json, "process_id"),
            // nano UDM: command_line = full command line (support old field name "process" for backward compat)
            command_line: Self::extract_string(&json, "command_line")
                .or_else(|| Self::extract_string(&json, "process")),
            // nano UDM: parent_process_name = just the parent exe filename
            parent_process_name: Self::extract_string(&json, "parent_process_name"),
            // nano UDM: parent_command_line = full parent command line (support old name "parent_process")
            parent_command_line: Self::extract_string(&json, "parent_command_line")
                .or_else(|| Self::extract_string(&json, "parent_process")),
            file_path: Self::extract_string(&json, "file_path"),
            file_name: Self::extract_string(&json, "file_name"),
            file_hash: Self::extract_string(&json, "file_hash"),
            file_action: Self::extract_string(&json, "file_action"),
            bytes_in: Self::extract_i64(&json, "bytes_in"),
            bytes_out: Self::extract_i64(&json, "bytes_out"),
            user_agent: Self::extract_string(&json, "user_agent"),
            ext: json.get("ext").cloned(), // Preserve ext from Vector parsers
        })
    }

    fn extract_string(json: &serde_json::Value, field: &str) -> Option<String> {
        json.get(field).and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.as_str().map(|s| s.to_string())
            }
        })
    }

    fn extract_i32(json: &serde_json::Value, field: &str) -> Option<i32> {
        json.get(field).and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.as_i64().and_then(|n| i32::try_from(n).ok())
            }
        })
    }

    fn extract_i64(json: &serde_json::Value, field: &str) -> Option<i64> {
        json.get(field)
            .and_then(|v| if v.is_null() { None } else { v.as_i64() })
    }

    /// Detect log format and parse raw string
    fn detect_and_parse(&self, raw: &str) -> Result<(String, serde_json::Value), ParserError> {
        let trimmed = raw.trim();

        // Try JSON first
        if trimmed.starts_with('{') {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let source_type = self.detect_source_type_from_json(&json);
                return Ok((source_type, json));
            }
        }

        // Try CEF format
        if trimmed.starts_with("CEF:") {
            let metadata = self.parse_cef(trimmed)?;
            return Ok(("cef".to_string(), metadata));
        }

        // Try LEEF format
        if trimmed.starts_with("LEEF:") {
            let metadata = self.parse_leef(trimmed)?;
            return Ok(("leef".to_string(), metadata));
        }

        // Default to syslog-style parsing
        let metadata = self.parse_syslog(trimmed);
        Ok(("syslog".to_string(), metadata))
    }

    /// Detect source type from JSON structure
    fn detect_source_type_from_json(&self, json: &serde_json::Value) -> String {
        // Check for explicit source_type field
        if let Some(st) = json.get("source_type").and_then(|v| v.as_str()) {
            return st.to_string();
        }

        // Check for CEF indicators
        if json.get("cef_version").is_some() || json.get("deviceVendor").is_some() {
            return "cef".to_string();
        }

        // Check for LEEF indicators
        if json.get("leef_version").is_some() {
            return "leef".to_string();
        }

        // Check for syslog indicators
        if json.get("facility").is_some() || json.get("severity").is_some() {
            return "syslog".to_string();
        }

        "json".to_string()
    }

    /// Parse CEF (Common Event Format) log
    fn parse_cef(&self, raw: &str) -> Result<serde_json::Value, ParserError> {
        // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        let parts: Vec<&str> = raw.splitn(8, '|').collect();

        if parts.len() < 8 {
            return Err(ParserError::UnsupportedFormat(
                "Invalid CEF format: not enough pipe-separated fields".to_string(),
            ));
        }

        let mut metadata = serde_json::Map::new();

        // Parse header fields
        let version_part = parts[0].strip_prefix("CEF:").unwrap_or(parts[0]);
        metadata.insert("cef_version".to_string(), serde_json::json!(version_part));
        metadata.insert("deviceVendor".to_string(), serde_json::json!(parts[1]));
        metadata.insert("deviceProduct".to_string(), serde_json::json!(parts[2]));
        metadata.insert("deviceVersion".to_string(), serde_json::json!(parts[3]));
        metadata.insert("signatureId".to_string(), serde_json::json!(parts[4]));
        metadata.insert("name".to_string(), serde_json::json!(parts[5]));
        metadata.insert("severity".to_string(), serde_json::json!(parts[6]));

        // Parse extension fields (key=value pairs)
        let extension = parts[7];
        for pair in extension.split_whitespace() {
            if let Some((key, value)) = pair.split_once('=') {
                metadata.insert(key.to_string(), serde_json::json!(value));
            }
        }

        Ok(serde_json::Value::Object(metadata))
    }

    /// Parse LEEF (Log Event Extended Format) log
    fn parse_leef(&self, raw: &str) -> Result<serde_json::Value, ParserError> {
        // LEEF format: LEEF:Version|Vendor|Product|Version|EventID|Extension
        let parts: Vec<&str> = raw.splitn(6, '|').collect();

        if parts.len() < 6 {
            return Err(ParserError::UnsupportedFormat(
                "Invalid LEEF format: not enough pipe-separated fields".to_string(),
            ));
        }

        let mut metadata = serde_json::Map::new();

        // Parse header fields
        let version_part = parts[0].strip_prefix("LEEF:").unwrap_or(parts[0]);
        metadata.insert("leef_version".to_string(), serde_json::json!(version_part));
        metadata.insert("vendor".to_string(), serde_json::json!(parts[1]));
        metadata.insert("product".to_string(), serde_json::json!(parts[2]));
        metadata.insert("version".to_string(), serde_json::json!(parts[3]));
        metadata.insert("eventId".to_string(), serde_json::json!(parts[4]));

        // Parse extension fields (key=value pairs, tab-separated in LEEF 2.0)
        let extension = parts[5];
        let delimiter = if extension.contains('\t') { '\t' } else { ' ' };

        for pair in extension.split(delimiter) {
            if let Some((key, value)) = pair.split_once('=') {
                metadata.insert(key.to_string(), serde_json::json!(value));
            }
        }

        Ok(serde_json::Value::Object(metadata))
    }

    /// Parse syslog-style log (best effort)
    fn parse_syslog(&self, raw: &str) -> serde_json::Value {
        let mut metadata = serde_json::Map::new();
        metadata.insert("message".to_string(), serde_json::json!(raw));

        // Try to extract common syslog patterns
        // Pattern: <priority>timestamp hostname program[pid]: message
        // or: timestamp hostname program[pid]: message

        let trimmed = raw.trim();

        // Try to extract priority if present
        if trimmed.starts_with('<') {
            if let Some(end) = trimmed.find('>') {
                if let Ok(priority) = trimmed[1..end].parse::<u8>() {
                    metadata.insert("priority".to_string(), serde_json::json!(priority));
                    metadata.insert("facility".to_string(), serde_json::json!(priority / 8));
                    metadata.insert("severity".to_string(), serde_json::json!(priority % 8));
                }
            }
        }

        // Try to extract program name and PID
        if let Some(bracket_start) = trimmed.find('[') {
            if let Some(bracket_end) = trimmed[bracket_start..].find(']') {
                let pid_str = &trimmed[bracket_start + 1..bracket_start + bracket_end];
                if let Ok(pid) = pid_str.parse::<i32>() {
                    metadata.insert("procid".to_string(), serde_json::json!(pid));
                }

                // Extract program name (word before the bracket)
                let before_bracket = &trimmed[..bracket_start];
                if let Some(program) = before_bracket.split_whitespace().last() {
                    metadata.insert("appname".to_string(), serde_json::json!(program));
                }
            }
        }

        serde_json::Value::Object(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_log() {
        let parser = LogParser::new();
        let raw = r#"{"src_ip": "192.168.1.1", "user": "admin", "action": "login"}"#;

        let result = parser.parse(raw).unwrap();

        assert_eq!(result.src_ip, Some("192.168.1.1".to_string()));
        assert_eq!(result.user, Some("admin".to_string()));
        assert_eq!(result.action, Some("login".to_string()));
        assert_eq!(result.source_type, "json");
    }

    #[test]
    fn test_parse_cef_log() {
        let parser = LogParser::new();
        let raw = "CEF:0|Security|Firewall|1.0|100|Connection blocked|5|src=192.168.1.100 dst=10.0.0.1 spt=54321 dpt=443";

        let result = parser.parse(raw).unwrap();

        assert_eq!(result.source_type, "cef");
        assert_eq!(result.src_ip, Some("192.168.1.100".to_string()));
        assert_eq!(result.dest_ip, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_leef_log() {
        let parser = LogParser::new();
        let raw = "LEEF:2.0|IBM|QRadar|7.3|100|src=192.168.1.1\tdst=10.0.0.1\tusrName=admin";

        let result = parser.parse(raw).unwrap();

        assert_eq!(result.source_type, "leef");
        assert_eq!(result.src_ip, Some("192.168.1.1".to_string()));
        assert_eq!(result.user, Some("admin".to_string()));
    }

    #[test]
    fn test_parse_syslog_log() {
        let parser = LogParser::new();
        let raw = "<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for admin";

        let result = parser.parse(raw).unwrap();

        assert_eq!(result.source_type, "syslog");
        assert_eq!(result.process_id, Some(1234));
    }

    #[test]
    fn test_parse_vector_format() {
        let parser = LogParser::new();
        let json = serde_json::json!({
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "Test log message",
            "metadata": {"custom": "field"},
            "src_ip": "192.168.1.1",
            "user": "testuser",
            "action": "test"
        });

        let result = parser.parse_json(json).unwrap();

        assert_eq!(result.message, "Test log message");
        assert_eq!(result.src_ip, Some("192.168.1.1".to_string()));
        assert_eq!(result.user, Some("testuser".to_string()));
    }
}
