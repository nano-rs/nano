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
    /// Returns the stable lookup column for a single indicator value.
    pub fn indicator_column(value: &str) -> Option<&'static str> {
        let value = value.trim();
        if value.parse::<std::net::IpAddr>().is_ok() {
            return Some("ip");
        }
        if let Some((address, prefix)) = value.split_once('/') {
            if let (Ok(ip), Ok(bits)) = (address.parse::<std::net::IpAddr>(), prefix.parse::<u8>())
            {
                if bits <= if ip.is_ipv4() { 32 } else { 128 } {
                    return Some("cidr");
                }
            }
        }
        if value.starts_with("http://") || value.starts_with("https://") {
            if url::Url::parse(value)
                .ok()
                .is_some_and(|url| url.host_str().is_some())
            {
                return Some("url");
            }
        }
        if [32, 40, 64].contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some("hash");
        }
        if let Some((local, domain)) = value.split_once('@') {
            if !local.is_empty() && !local.contains(char::is_whitespace) && Self::is_domain(domain)
            {
                return Some("email");
            }
        }
        if Self::is_domain(value) {
            return Some("domain");
        }
        None
    }

    fn is_domain(value: &str) -> bool {
        value.len() <= 253
            && value.contains('.')
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            && value
                .rsplit('.')
                .next()
                .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
    }

    /// Auto-detect headerless single-column indicator feeds; otherwise keep CSV headers.
    pub fn detect_has_header(content: &[u8], delimiter: char) -> bool {
        let Ok(text) = std::str::from_utf8(content) else {
            return true;
        };
        let first = text
            .trim_start_matches('\u{feff}')
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("");
        !(!first.contains(delimiter) && Self::indicator_column(first).is_some())
    }

    pub fn resolve_has_header(content: &[u8], config: &ParserConfig) -> bool {
        config.has_header.unwrap_or_else(|| {
            if !config.csv_has_headers {
                false
            } else {
                Self::detect_has_header(content, config.csv_delimiter)
            }
        })
    }

    /// Preserve a stored single-column schema when an older job first treated
    /// an indicator as a header. The payload remains headerless; no rename occurs.
    pub fn config_for_existing_column(
        content: &[u8],
        config: &ParserConfig,
        column: &str,
    ) -> ParserConfig {
        let mut resolved = config.clone();
        if resolved.format == FileFormat::Csv
            && !Self::resolve_has_header(content, config)
            && resolved.custom_headers.is_none()
            && column != "_placeholder"
            && std::str::from_utf8(content)
                .ok()
                .and_then(|text| text.lines().find(|line| !line.trim().is_empty()))
                .and_then(Self::indicator_column)
                .is_some()
        {
            resolved.has_header = Some(false);
            resolved.custom_headers = Some(vec![column.to_string()]);
        }
        resolved
    }
    /// Create a new file parser
    pub fn new() -> Self {
        Self
    }

    /// Parse file content with the given configuration
    pub fn parse(&self, content: &[u8], config: &ParserConfig) -> Result<ParseResult, ParseError> {
        // Decode content based on encoding
        let text = self.decode_content(content, &config.encoding)?;

        match config.format {
            FileFormat::Csv => {
                let mut resolved = config.clone();
                resolved.csv_has_headers = Self::resolve_has_header(content, config);
                self.parse_csv(&text, &resolved)
            }
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
