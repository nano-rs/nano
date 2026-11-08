// SPDX-License-Identifier: AGPL-3.0-or-later

//! Response parsers for inputlookup
//!
//! This module provides parsers for JSON and CSV responses from external URLs.

use serde_json::{Map, Value};
use thiserror::Error;

use super::types::InputLookupFormat;

/// Errors that can occur during response parsing
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("JSON parse error: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("CSV parse error: {0}")]
    CsvParseError(#[from] csv::Error),

    #[error("Unexpected JSON structure: expected array or object, got {0}")]
    UnexpectedJsonStructure(String),

    #[error("Empty response")]
    EmptyResponse,

    #[error("Maximum row limit exceeded: {count} rows exceeds limit of {limit}")]
    MaxRowsExceeded { count: usize, limit: usize },
}

/// Parse a response body into rows based on the specified format
pub fn parse_response(
    body: &str,
    format: InputLookupFormat,
    max_rows: usize,
) -> Result<Vec<Value>, ParseError> {
    if body.trim().is_empty() {
        return Err(ParseError::EmptyResponse);
    }

    let rows = match format {
        InputLookupFormat::Json => parse_json(body)?,
        InputLookupFormat::Csv => parse_csv(body)?,
    };

    // Check max rows
    if rows.len() > max_rows {
        return Err(ParseError::MaxRowsExceeded {
            count: rows.len(),
            limit: max_rows,
        });
    }

    Ok(rows)
}

/// Parse JSON response
///
/// Handles:
/// - Array of objects: [{"a": 1}, {"a": 2}]
/// - Single object: {"a": 1} -> wrapped in array
/// - Nested data: {"data": [...]} -> extracts data array
/// - Nested objects are flattened with dot notation (e.g., {"a": {"b": 1}} -> {"a.b": 1})
fn parse_json(body: &str) -> Result<Vec<Value>, ParseError> {
    let value: Value = serde_json::from_str(body)?;

    let rows = match value {
        // Array of objects - most common case
        Value::Array(arr) => arr,

        // Single object
        Value::Object(obj) => {
            // Check for common nested data patterns
            if let Some(data) = obj.get("data") {
                if let Value::Array(arr) = data {
                    return Ok(flatten_rows(arr.clone()));
                }
            }
            if let Some(results) = obj.get("results") {
                if let Value::Array(arr) = results {
                    return Ok(flatten_rows(arr.clone()));
                }
            }
            if let Some(items) = obj.get("items") {
                if let Value::Array(arr) = items {
                    return Ok(flatten_rows(arr.clone()));
                }
            }

            // Wrap single object in array
            vec![Value::Object(obj)]
        }

        // Other types are not supported
        other => {
            return Err(ParseError::UnexpectedJsonStructure(format!(
                "{:?}",
                other.as_str().unwrap_or("unknown")
            )))
        }
    };

    Ok(flatten_rows(rows))
}

/// Flatten nested objects in all rows
fn flatten_rows(rows: Vec<Value>) -> Vec<Value> {
    rows.into_iter()
        .map(|row| {
            if let Value::Object(obj) = row {
                let mut flattened = Map::new();
                flatten_object(&obj, "", &mut flattened);
                Value::Object(flattened)
            } else {
                row
            }
        })
        .collect()
}

/// Recursively flatten a JSON object with dot notation
/// e.g., {"a": {"b": 1, "c": {"d": 2}}} -> {"a.b": 1, "a.c.d": 2}
fn flatten_object(obj: &Map<String, Value>, prefix: &str, result: &mut Map<String, Value>) {
    for (key, value) in obj {
        let new_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", prefix, key)
        };

        match value {
            Value::Object(nested) => {
                // Recursively flatten nested objects
                flatten_object(nested, &new_key, result);
            }
            Value::Array(arr) => {
                // For arrays, check if it's an array of primitives or objects
                if arr.iter().all(|v| matches!(v, Value::Object(_))) {
                    // Array of objects - keep as JSON string for now
                    result.insert(new_key, value.clone());
                } else {
                    // Array of primitives - keep as is
                    result.insert(new_key, value.clone());
                }
            }
            _ => {
                // Primitive values - insert directly
                result.insert(new_key, value.clone());
            }
        }
    }
}

/// Parse CSV response
///
/// Expects headers in the first row. Returns objects with header names as keys.
fn parse_csv(body: &str) -> Result<Vec<Value>, ParseError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(body.as_bytes());

    let headers: Vec<String> = reader.headers()?.iter().map(|s| s.to_string()).collect();

    let mut rows = Vec::new();
    for result in reader.records() {
        let record = result?;
        let mut obj = Map::new();

        for (i, value) in record.iter().enumerate() {
            if let Some(header) = headers.get(i) {
                // Try to infer the type
                let parsed_value = infer_value_type(value);
                obj.insert(header.clone(), parsed_value);
            }
        }

        rows.push(Value::Object(obj));
    }

    Ok(rows)
}

/// Infer the type of a CSV value
///
/// Attempts to parse as: boolean, integer, float, null, or string
fn infer_value_type(s: &str) -> Value {
    let trimmed = s.trim();

    // Empty or null values
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("null")
        || trimmed.eq_ignore_ascii_case("na")
    {
        return Value::Null;
    }

    // Boolean values
    if trimmed.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }

    // Try parsing as integer
    if let Ok(n) = trimmed.parse::<i64>() {
        return Value::Number(n.into());
    }

    // Try parsing as float
    if let Ok(f) = trimmed.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return Value::Number(n);
        }
    }

    // Default to string
    Value::String(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_array() {
        let body = r#"[{"ip": "1.1.1.1", "name": "test"}, {"ip": "2.2.2.2", "name": "test2"}]"#;
        let rows = parse_json(body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["ip"], "1.1.1.1");
        assert_eq!(rows[1]["ip"], "2.2.2.2");
    }

    #[test]
    fn test_parse_json_single_object() {
        let body = r#"{"ip": "1.1.1.1", "city": "Mountain View"}"#;
        let rows = parse_json(body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["ip"], "1.1.1.1");
        assert_eq!(rows[0]["city"], "Mountain View");
    }

    #[test]
    fn test_parse_json_nested_data() {
        let body = r#"{"data": [{"id": 1}, {"id": 2}], "total": 2}"#;
        let rows = parse_json(body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], 1);
    }

    #[test]
    fn test_parse_json_nested_results() {
        let body = r#"{"results": [{"id": 1}, {"id": 2}]}"#;
        let rows = parse_json(body).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn test_parse_csv_basic() {
        let body = "ip,name,count\n1.1.1.1,test,10\n2.2.2.2,test2,20";
        let rows = parse_csv(body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["ip"], "1.1.1.1");
        assert_eq!(rows[0]["name"], "test");
        assert_eq!(rows[0]["count"], 10);
        assert_eq!(rows[1]["count"], 20);
    }

    #[test]
    fn test_parse_csv_type_inference() {
        let body = "str,int,float,bool,null\ntest,42,3.14,true,";
        let rows = parse_csv(body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["str"], "test");
        assert_eq!(rows[0]["int"], 42);
        assert_eq!(rows[0]["bool"], true);
        assert!(rows[0]["null"].is_null());
    }

    #[test]
    fn test_parse_csv_quoted_values() {
        let body = r#"name,description
"John Doe","A test user"
"Jane Doe","Another user""#;
        let rows = parse_csv(body).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["name"], "John Doe");
    }

    #[test]
    fn test_parse_response_max_rows() {
        let body = r#"[{"id": 1}, {"id": 2}, {"id": 3}]"#;
        let result = parse_response(body, InputLookupFormat::Json, 2);
        assert!(matches!(
            result,
            Err(ParseError::MaxRowsExceeded { count: 3, limit: 2 })
        ));
    }

    #[test]
    fn test_parse_response_empty() {
        let result = parse_response("", InputLookupFormat::Json, 100);
        assert!(matches!(result, Err(ParseError::EmptyResponse)));
    }

    #[test]
    fn test_infer_value_type() {
        assert_eq!(infer_value_type("true"), Value::Bool(true));
        assert_eq!(infer_value_type("FALSE"), Value::Bool(false));
        assert_eq!(infer_value_type("42"), Value::Number(42.into()));
        assert_eq!(
            infer_value_type("hello"),
            Value::String("hello".to_string())
        );
        assert!(infer_value_type("").is_null());
        assert!(infer_value_type("null").is_null());
        assert!(infer_value_type("NA").is_null());
    }
}
