// SPDX-License-Identifier: AGPL-3.0-or-later

//! CSV file parsing.
//!
//! Handles CSV parsing with configurable delimiters, headers, and type inference.

use std::collections::HashMap;

use super::types::{ParseError, ParseResult, ParsedRecord, ParserConfig, RecordError};
use super::FileParser;

impl FileParser {
    /// Parse CSV content
    pub(super) fn parse_csv(
        &self,
        text: &str,
        config: &ParserConfig,
    ) -> Result<ParseResult, ParseError> {
        let mut result = ParseResult::new();

        let mut reader_builder = csv::ReaderBuilder::new();
        reader_builder
            .delimiter(config.csv_delimiter as u8)
            .has_headers(config.csv_has_headers)
            .flexible(true); // Allow variable number of fields

        let mut reader = reader_builder.from_reader(text.as_bytes());

        // Get headers
        let headers: Vec<String> = if let Some(ref custom) = config.custom_headers {
            custom.clone()
        } else if config.csv_has_headers {
            reader
                .headers()
                .map_err(|e| ParseError::CsvError(e.to_string()))?
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            // Generate column names: col_0, col_1, etc.
            Vec::new() // Will be populated on first record
        };

        result.headers = Some(headers.clone());
        let mut headers = headers;
        let mut line_number = if config.csv_has_headers { 2 } else { 1 };

        for record_result in reader.records() {
            // Check max records limit
            if let Some(max) = config.max_records {
                if result.successful >= max {
                    break;
                }
            }

            result.total_lines += 1;

            match record_result {
                Ok(record) => {
                    // Generate headers if not set
                    if headers.is_empty() {
                        headers = (0..record.len()).map(|i| format!("col_{}", i)).collect();
                        result.headers = Some(headers.clone());
                    }

                    let mut fields = HashMap::new();
                    for (i, value) in record.iter().enumerate() {
                        let key = headers
                            .get(i)
                            .cloned()
                            .unwrap_or_else(|| format!("col_{}", i));
                        let json_value = Self::infer_json_value(value);
                        fields.insert(key, json_value);
                    }

                    result.add_record(ParsedRecord::new(fields, line_number));
                }
                Err(e) => {
                    if config.skip_invalid {
                        result.add_error(RecordError::new(line_number, e.to_string()));
                    } else {
                        return Err(ParseError::CsvError(format!("Line {}: {}", line_number, e)));
                    }
                }
            }

            line_number += 1;
        }

        if result.records.is_empty() && result.errors.is_empty() {
            return Err(ParseError::EmptyFile);
        }

        Ok(result)
    }

    /// Infer JSON value type from string
    pub(super) fn infer_json_value(s: &str) -> serde_json::Value {
        let trimmed = s.trim();

        // Empty string
        if trimmed.is_empty() {
            return serde_json::Value::Null;
        }

        // Boolean
        if trimmed.eq_ignore_ascii_case("true") {
            return serde_json::Value::Bool(true);
        }
        if trimmed.eq_ignore_ascii_case("false") {
            return serde_json::Value::Bool(false);
        }

        // Null
        if trimmed.eq_ignore_ascii_case("null") || trimmed.eq_ignore_ascii_case("nil") {
            return serde_json::Value::Null;
        }

        // Integer
        if let Ok(n) = trimmed.parse::<i64>() {
            return serde_json::Value::Number(n.into());
        }

        // Float
        if let Ok(n) = trimmed.parse::<f64>() {
            if let Some(num) = serde_json::Number::from_f64(n) {
                return serde_json::Value::Number(num);
            }
        }

        // Default to string
        serde_json::Value::String(s.to_string())
    }
}
