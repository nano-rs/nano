// SPDX-License-Identifier: AGPL-3.0-or-later

//! Type definitions for the file parser module.
//!
//! Contains format enums, configuration, parsed records, errors, and results.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Supported file formats for upload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    /// Comma-separated values (or other delimiters)
    Csv,
    /// JSON array of objects
    Json,
    /// Newline-delimited JSON
    Ndjson,
}

impl FileFormat {
    /// Get the format as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
        }
    }

    /// Parse format from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "csv" => Some(Self::Csv),
            "json" => Some(Self::Json),
            "ndjson" | "jsonl" => Some(Self::Ndjson),
            _ => None,
        }
    }

    /// Detect format from file extension
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "csv" | "tsv" => Some(Self::Csv),
            "json" => Some(Self::Json),
            "ndjson" | "jsonl" => Some(Self::Ndjson),
            _ => None,
        }
    }
}

/// Configuration for file parsing
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParserConfig {
    /// File format to parse
    pub format: FileFormat,
    /// CSV delimiter character (default: comma)
    #[serde(default = "default_csv_delimiter")]
    pub csv_delimiter: char,
    /// Whether CSV has a header row (default: true)
    #[serde(default = "default_csv_has_headers")]
    pub csv_has_headers: bool,
    /// Custom column headers (overrides first row if csv_has_headers is true)
    #[serde(default)]
    pub custom_headers: Option<Vec<String>>,
    /// File encoding (default: UTF-8)
    #[serde(default = "default_encoding")]
    pub encoding: String,
    /// Maximum number of records to parse (None = unlimited)
    #[serde(default)]
    pub max_records: Option<usize>,
    /// Whether to skip invalid records instead of failing
    #[serde(default = "default_skip_invalid")]
    pub skip_invalid: bool,
}

fn default_csv_delimiter() -> char {
    ','
}

fn default_csv_has_headers() -> bool {
    true
}

fn default_encoding() -> String {
    "utf-8".to_string()
}

fn default_skip_invalid() -> bool {
    true
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            format: FileFormat::Csv,
            csv_delimiter: ',',
            csv_has_headers: true,
            custom_headers: None,
            encoding: "utf-8".to_string(),
            max_records: None,
            skip_invalid: true,
        }
    }
}

impl ParserConfig {
    /// Create a new CSV parser config
    pub fn csv() -> Self {
        Self {
            format: FileFormat::Csv,
            ..Default::default()
        }
    }

    /// Create a new JSON parser config
    pub fn json() -> Self {
        Self {
            format: FileFormat::Json,
            ..Default::default()
        }
    }

    /// Create a new NDJSON parser config
    pub fn ndjson() -> Self {
        Self {
            format: FileFormat::Ndjson,
            ..Default::default()
        }
    }

    /// Set the CSV delimiter
    pub fn with_delimiter(mut self, delimiter: char) -> Self {
        self.csv_delimiter = delimiter;
        self
    }

    /// Set whether CSV has headers
    pub fn with_headers(mut self, has_headers: bool) -> Self {
        self.csv_has_headers = has_headers;
        self
    }

    /// Set custom headers
    pub fn with_custom_headers(mut self, headers: Vec<String>) -> Self {
        self.custom_headers = Some(headers);
        self
    }

    /// Set the encoding
    pub fn with_encoding(mut self, encoding: &str) -> Self {
        self.encoding = encoding.to_string();
        self
    }

    /// Set maximum records to parse
    pub fn with_max_records(mut self, max: usize) -> Self {
        self.max_records = Some(max);
        self
    }

    /// Set whether to skip invalid records
    pub fn with_skip_invalid(mut self, skip: bool) -> Self {
        self.skip_invalid = skip;
        self
    }
}

/// A single parsed record from a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRecord {
    /// Field name to value mapping
    pub fields: HashMap<String, serde_json::Value>,
    /// Line number in the source file (1-indexed)
    pub line_number: usize,
}

impl ParsedRecord {
    /// Create a new parsed record
    pub fn new(fields: HashMap<String, serde_json::Value>, line_number: usize) -> Self {
        Self {
            fields,
            line_number,
        }
    }

    /// Get a field value as a string
    pub fn get_str(&self, field: &str) -> Option<&str> {
        self.fields.get(field).and_then(|v| v.as_str())
    }

    /// Get a field value as an i64
    pub fn get_i64(&self, field: &str) -> Option<i64> {
        self.fields.get(field).and_then(|v| v.as_i64())
    }

    /// Get a field value as a bool
    pub fn get_bool(&self, field: &str) -> Option<bool> {
        self.fields.get(field).and_then(|v| v.as_bool())
    }

    /// Convert to JSON value
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.fields
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }
}

/// Error information for a failed record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordError {
    /// Line number where the error occurred
    pub line_number: usize,
    /// Error message
    pub error_message: String,
    /// Raw content that failed to parse (if available)
    pub raw: Option<String>,
}

impl RecordError {
    /// Create a new record error
    pub fn new(line_number: usize, message: impl Into<String>) -> Self {
        Self {
            line_number,
            error_message: message.into(),
            raw: None,
        }
    }

    /// Create a record error with raw content
    pub fn with_content(line_number: usize, message: impl Into<String>, content: &str) -> Self {
        Self {
            line_number,
            error_message: message.into(),
            raw: Some(content.to_string()),
        }
    }
}

/// Result of parsing a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult {
    /// Successfully parsed records
    pub records: Vec<ParsedRecord>,
    /// Total number of lines/elements in the source
    pub total_lines: usize,
    /// Number of successfully parsed records
    pub successful: usize,
    /// Number of failed records
    pub failed: usize,
    /// Errors encountered during parsing
    pub errors: Vec<RecordError>,
    /// Column headers (for CSV files)
    pub headers: Option<Vec<String>>,
}

impl ParseResult {
    /// Create a new empty parse result
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            total_lines: 0,
            successful: 0,
            failed: 0,
            errors: Vec::new(),
            headers: None,
        }
    }

    /// Add a successfully parsed record
    pub fn add_record(&mut self, record: ParsedRecord) {
        self.records.push(record);
        self.successful += 1;
    }

    /// Add an error for a failed record
    pub fn add_error(&mut self, error: RecordError) {
        self.errors.push(error);
        self.failed += 1;
    }

    /// Check if parsing was completely successful
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Get the success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_lines == 0 {
            100.0
        } else {
            (self.successful as f64 / self.total_lines as f64) * 100.0
        }
    }
}

impl Default for ParseResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during file parsing
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("CSV parsing error: {0}")]
    CsvError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Empty file")]
    EmptyFile,

    #[error("No valid records found")]
    NoValidRecords,

    #[error("Header mismatch: expected {expected} columns, got {actual}")]
    HeaderMismatch { expected: usize, actual: usize },
}
