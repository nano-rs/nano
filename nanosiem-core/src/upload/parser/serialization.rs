// SPDX-License-Identifier: AGPL-3.0-or-later

//! Record serialization to CSV, JSON, and NDJSON formats.
//!
//! Provides round-trip serialization capabilities for parsed records.

use super::types::{ParseError, ParseResult};
use super::FileParser;

impl FileParser {
    /// Serialize records back to CSV format (for round-trip testing)
    pub fn serialize_to_csv(&self, result: &ParseResult) -> Result<String, ParseError> {
        let mut writer = csv::Writer::from_writer(Vec::new());

        // Write headers
        if let Some(ref headers) = result.headers {
            writer
                .write_record(headers)
                .map_err(|e| ParseError::CsvError(e.to_string()))?;
        }

        // Write records
        for record in &result.records {
            let headers = result.headers.as_ref().ok_or_else(|| {
                ParseError::CsvError("No headers available for serialization".to_string())
            })?;

            let values: Vec<String> = headers
                .iter()
                .map(|h| {
                    record
                        .fields
                        .get(h)
                        .map(|v| Self::json_value_to_string(v))
                        .unwrap_or_default()
                })
                .collect();

            writer
                .write_record(&values)
                .map_err(|e| ParseError::CsvError(e.to_string()))?;
        }

        let bytes = writer
            .into_inner()
            .map_err(|e| ParseError::CsvError(e.to_string()))?;

        String::from_utf8(bytes).map_err(|e| ParseError::EncodingError(e.to_string()))
    }

    /// Serialize records back to JSON array format
    pub fn serialize_to_json(&self, result: &ParseResult) -> Result<String, ParseError> {
        let array: Vec<serde_json::Value> = result.records.iter().map(|r| r.to_json()).collect();
        serde_json::to_string_pretty(&array).map_err(ParseError::InvalidJson)
    }

    /// Serialize records back to NDJSON format
    pub fn serialize_to_ndjson(&self, result: &ParseResult) -> Result<String, ParseError> {
        let lines: Result<Vec<String>, _> = result
            .records
            .iter()
            .map(|r| serde_json::to_string(&r.to_json()))
            .collect();
        Ok(lines?.join("\n"))
    }

    /// Convert JSON value to string for CSV serialization
    pub(super) fn json_value_to_string(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Null => String::new(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => serde_json::to_string(arr).unwrap_or_default(),
            serde_json::Value::Object(obj) => serde_json::to_string(obj).unwrap_or_default(),
        }
    }
}
