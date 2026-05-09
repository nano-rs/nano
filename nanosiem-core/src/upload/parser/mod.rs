// SPDX-License-Identifier: AGPL-3.0-or-later

//! File Parser Module
//!
//! Provides parsing capabilities for uploaded files (CSV, JSON, NDJSON).
//! Handles various encodings, delimiters, and malformed records gracefully.
//!
//! Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6

mod csv_parser;
mod encoding;
mod json_parser;
mod ndjson_parser;
mod serialization;
mod types;

#[cfg(test)]
mod tests;

pub use types::{FileFormat, ParseError, ParseResult, ParsedRecord, ParserConfig, RecordError};

/// File parser for CSV, JSON, and NDJSON formats
#[derive(Debug, Clone, Default)]
pub struct FileParser;

impl FileParser {
    /// Create a new file parser
    pub fn new() -> Self {
        Self
    }

    /// Parse file content with the given configuration
    pub fn parse(&self, content: &[u8], config: &ParserConfig) -> Result<ParseResult, ParseError> {
        // Decode content based on encoding
        let text = self.decode_content(content, &config.encoding)?;

        match config.format {
            FileFormat::Csv => self.parse_csv(&text, config),
            FileFormat::Json => self.parse_json(&text, config),
            FileFormat::Ndjson => self.parse_ndjson(&text, config),
        }
    }

    /// Preview file content (parse first N records)
    pub fn preview(
        &self,
        content: &[u8],
        config: &ParserConfig,
        limit: usize,
    ) -> Result<ParseResult, ParseError> {
        let preview_config = ParserConfig {
            max_records: Some(limit),
            ..config.clone()
        };
        self.parse(content, &preview_config)
    }

    /// Detect file format from content
    pub fn detect_format(content: &[u8]) -> Option<FileFormat> {
        // Try to decode as UTF-8 first
        let text = match std::str::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Check for JSON array
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                return Some(FileFormat::Json);
            }
        }

        // Check for NDJSON (multiple JSON objects on separate lines)
        let first_line = trimmed.lines().next()?;
        if first_line.trim().starts_with('{') {
            if serde_json::from_str::<serde_json::Value>(first_line.trim()).is_ok() {
                return Some(FileFormat::Ndjson);
            }
        }

        // Default to CSV
        Some(FileFormat::Csv)
    }
}
