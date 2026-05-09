// SPDX-License-Identifier: AGPL-3.0-or-later

//! JSON array file parsing.
//!
//! Handles parsing of JSON files containing arrays of objects.

use std::collections::HashMap;

use super::types::{ParseError, ParseResult, ParsedRecord, ParserConfig, RecordError};
use super::FileParser;

impl FileParser {
    /// Parse JSON array content
    pub(super) fn parse_json(
        &self,
        text: &str,
        config: &ParserConfig,
    ) -> Result<ParseResult, ParseError> {
        let mut result = ParseResult::new();

        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(ParseError::EmptyFile);
        }

        // Parse as JSON array
        let array: Vec<serde_json::Value> = serde_json::from_str(trimmed)?;

        result.total_lines = array.len();

        for (index, value) in array.into_iter().enumerate() {
            // Check max records limit
            if let Some(max) = config.max_records {
                if result.successful >= max {
                    break;
                }
            }

            let line_number = index + 1;

            match value {
                serde_json::Value::Object(obj) => {
                    let fields: HashMap<String, serde_json::Value> = obj.into_iter().collect();
                    result.add_record(ParsedRecord::new(fields, line_number));
                }
                _ => {
                    if config.skip_invalid {
                        result.add_error(RecordError::new(
                            line_number,
                            "Expected JSON object, got other type",
                        ));
                    } else {
                        return Err(ParseError::InvalidFormat(format!(
                            "Element {} is not a JSON object",
                            line_number
                        )));
                    }
                }
            }
        }

        if result.records.is_empty() && result.errors.is_empty() {
            return Err(ParseError::NoValidRecords);
        }

        Ok(result)
    }
}
