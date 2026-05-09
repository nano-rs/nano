// SPDX-License-Identifier: AGPL-3.0-or-later

//! NDJSON (Newline-Delimited JSON) file parsing.
//!
//! Handles parsing of NDJSON/JSONL files with one JSON object per line.

use std::collections::HashMap;

use super::types::{ParseError, ParseResult, ParsedRecord, ParserConfig, RecordError};
use super::FileParser;

impl FileParser {
    /// Parse NDJSON (newline-delimited JSON) content
    pub(super) fn parse_ndjson(
        &self,
        text: &str,
        config: &ParserConfig,
    ) -> Result<ParseResult, ParseError> {
        let mut result = ParseResult::new();

        let lines: Vec<&str> = text.lines().collect();
        result.total_lines = lines.iter().filter(|l| !l.trim().is_empty()).count();

        for (index, line) in lines.iter().enumerate() {
            let line_number = index + 1;
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Check max records limit
            if let Some(max) = config.max_records {
                if result.successful >= max {
                    break;
                }
            }

            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(serde_json::Value::Object(obj)) => {
                    let fields: HashMap<String, serde_json::Value> = obj.into_iter().collect();
                    result.add_record(ParsedRecord::new(fields, line_number));
                }
                Ok(_) => {
                    if config.skip_invalid {
                        result.add_error(RecordError::with_content(
                            line_number,
                            "Expected JSON object, got other type",
                            trimmed,
                        ));
                    } else {
                        return Err(ParseError::InvalidFormat(format!(
                            "Line {} is not a JSON object",
                            line_number
                        )));
                    }
                }
                Err(e) => {
                    if config.skip_invalid {
                        result.add_error(RecordError::with_content(
                            line_number,
                            format!("Invalid JSON: {}", e),
                            trimmed,
                        ));
                    } else {
                        return Err(ParseError::InvalidJson(e));
                    }
                }
            }
        }

        if result.records.is_empty() && result.errors.is_empty() {
            return Err(ParseError::EmptyFile);
        }

        Ok(result)
    }
}
