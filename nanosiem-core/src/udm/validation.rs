// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field value validation and type coercion
//!
//! This module provides validation for UDM field values against their declared types.
//! It supports type coercion for compatible types (e.g., string to integer) and
//! returns clear error messages for validation failures.
//!
//! Requirements: 9.1, 9.2, 9.3, 9.4, 9.5

use super::fields::{UdmDataType, UdmField};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

/// Errors that can occur during field validation
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ValidationError {
    /// Value type doesn't match field type and cannot be coerced
    #[error("Invalid type for field '{field}': expected {expected:?}, got {actual_type}")]
    TypeMismatch {
        field: String,
        expected: UdmDataType,
        actual_type: String,
    },

    /// Value cannot be parsed as the target type
    #[error("Cannot parse value '{value}' as {target_type:?} for field '{field}': {reason}")]
    ParseError {
        field: String,
        value: String,
        target_type: UdmDataType,
        reason: String,
    },

    /// Value is out of range for the target type
    #[error("Value '{value}' is out of range for {target_type:?} in field '{field}'")]
    OutOfRange {
        field: String,
        value: String,
        target_type: UdmDataType,
    },

    /// Empty value provided for a field that requires a value
    #[error("Empty value provided for field '{field}'")]
    EmptyValue { field: String },
}

/// Result type for validation operations
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Represents a validated field value
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatedValue {
    String(String),
    Integer(i32),
    Long(i64),
    Float(f64),
    Boolean(bool),
    IpAddress(IpAddr),
    Timestamp(i64), // Unix timestamp in milliseconds
    Array(Vec<String>),
}

impl ValidatedValue {
    /// Convert the validated value to a string representation
    pub fn to_string(&self) -> String {
        match self {
            ValidatedValue::String(s) => s.clone(),
            ValidatedValue::Integer(i) => i.to_string(),
            ValidatedValue::Long(l) => l.to_string(),
            ValidatedValue::Float(f) => f.to_string(),
            ValidatedValue::Boolean(b) => b.to_string(),
            ValidatedValue::IpAddress(ip) => ip.to_string(),
            ValidatedValue::Timestamp(ts) => ts.to_string(),
            ValidatedValue::Array(arr) => format!("[{}]", arr.join(", ")),
        }
    }

    /// Get the data type of this validated value
    pub fn data_type(&self) -> UdmDataType {
        match self {
            ValidatedValue::String(_) => UdmDataType::String,
            ValidatedValue::Integer(_) => UdmDataType::Integer,
            ValidatedValue::Long(_) => UdmDataType::Long,
            ValidatedValue::Float(_) => UdmDataType::Float,
            ValidatedValue::Boolean(_) => UdmDataType::Boolean,
            ValidatedValue::IpAddress(_) => UdmDataType::IpAddress,
            ValidatedValue::Timestamp(_) => UdmDataType::Timestamp,
            ValidatedValue::Array(_) => UdmDataType::Array,
        }
    }
}

/// Validate a field value against its expected type
///
/// This function checks if the provided value matches the field's declared type.
/// It supports type coercion for compatible types:
/// - String to Integer/Long/Float/Boolean/IpAddress/Timestamp
/// - Integer to Long/Float/String
/// - Long to Integer (if in range)/Float/String
/// - Float to Integer (if whole number)/Long/String
/// - Boolean to String
///
/// # Arguments
/// * `field` - The UDM field to validate against
/// * `value` - The string value to validate
///
/// # Returns
/// * `Ok(ValidatedValue)` - The validated and potentially coerced value
/// * `Err(ValidationError)` - If validation fails
///
/// # Examples
/// ```
/// use nanosiem_core::udm::{UdmField, validate_field_value};
///
/// // Valid integer
/// let result = validate_field_value(UdmField::SrcPort, "8080");
/// assert!(result.is_ok());
///
/// // Invalid integer
/// let result = validate_field_value(UdmField::SrcPort, "not_a_number");
/// assert!(result.is_err());
///
/// // Type coercion: string to integer
/// let result = validate_field_value(UdmField::SrcPort, "443");
/// assert!(result.is_ok());
/// ```
pub fn validate_field_value(field: UdmField, value: &str) -> ValidationResult<ValidatedValue> {
    let field_name = field.column_name();
    let expected_type = field.data_type();

    // Check for empty values
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyValue {
            field: field_name.to_string(),
        });
    }

    match expected_type {
        UdmDataType::String => Ok(ValidatedValue::String(value.to_string())),

        UdmDataType::Integer => validate_integer(field_name, value),

        UdmDataType::Long => validate_long(field_name, value),

        UdmDataType::Float => validate_float(field_name, value),

        UdmDataType::Boolean => validate_boolean(field_name, value),

        UdmDataType::IpAddress => validate_ip_address(field_name, value),

        UdmDataType::Timestamp => validate_timestamp(field_name, value),

        UdmDataType::Array => validate_array(field_name, value),
    }
}

/// Validate and coerce a value to an integer
fn validate_integer(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    // Try direct parsing
    if let Ok(i) = value.parse::<i32>() {
        return Ok(ValidatedValue::Integer(i));
    }

    // Try parsing as float and converting to integer if it's a whole number
    if let Ok(f) = value.parse::<f64>() {
        if f.fract() == 0.0 && f >= i32::MIN as f64 && f <= i32::MAX as f64 {
            return Ok(ValidatedValue::Integer(f as i32));
        } else if f.fract() != 0.0 {
            return Err(ValidationError::ParseError {
                field: field_name.to_string(),
                value: value.to_string(),
                target_type: UdmDataType::Integer,
                reason: "value is not a whole number".to_string(),
            });
        } else {
            return Err(ValidationError::OutOfRange {
                field: field_name.to_string(),
                value: value.to_string(),
                target_type: UdmDataType::Integer,
            });
        }
    }

    Err(ValidationError::ParseError {
        field: field_name.to_string(),
        value: value.to_string(),
        target_type: UdmDataType::Integer,
        reason: "cannot parse as integer".to_string(),
    })
}

/// Validate and coerce a value to a long integer
fn validate_long(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    // Try direct parsing
    if let Ok(l) = value.parse::<i64>() {
        return Ok(ValidatedValue::Long(l));
    }

    // Try parsing as float and converting to long if it's a whole number
    if let Ok(f) = value.parse::<f64>() {
        if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
            return Ok(ValidatedValue::Long(f as i64));
        } else if f.fract() != 0.0 {
            return Err(ValidationError::ParseError {
                field: field_name.to_string(),
                value: value.to_string(),
                target_type: UdmDataType::Long,
                reason: "value is not a whole number".to_string(),
            });
        } else {
            return Err(ValidationError::OutOfRange {
                field: field_name.to_string(),
                value: value.to_string(),
                target_type: UdmDataType::Long,
            });
        }
    }

    Err(ValidationError::ParseError {
        field: field_name.to_string(),
        value: value.to_string(),
        target_type: UdmDataType::Long,
        reason: "cannot parse as long integer".to_string(),
    })
}

/// Validate and coerce a value to a float
fn validate_float(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    match value.parse::<f64>() {
        Ok(f) => {
            if f.is_finite() {
                Ok(ValidatedValue::Float(f))
            } else {
                Err(ValidationError::ParseError {
                    field: field_name.to_string(),
                    value: value.to_string(),
                    target_type: UdmDataType::Float,
                    reason: "value is not finite (NaN or Infinity)".to_string(),
                })
            }
        }
        Err(e) => Err(ValidationError::ParseError {
            field: field_name.to_string(),
            value: value.to_string(),
            target_type: UdmDataType::Float,
            reason: format!("cannot parse as float: {}", e),
        }),
    }
}

/// Validate and coerce a value to a boolean
fn validate_boolean(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    let lower = value.to_lowercase();
    match lower.as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(ValidatedValue::Boolean(true)),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(ValidatedValue::Boolean(false)),
        _ => Err(ValidationError::ParseError {
            field: field_name.to_string(),
            value: value.to_string(),
            target_type: UdmDataType::Boolean,
            reason: "expected true/false, yes/no, 1/0, on/off, or t/f".to_string(),
        }),
    }
}

/// Validate and coerce a value to an IP address
fn validate_ip_address(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    match IpAddr::from_str(value) {
        Ok(ip) => Ok(ValidatedValue::IpAddress(ip)),
        Err(e) => Err(ValidationError::ParseError {
            field: field_name.to_string(),
            value: value.to_string(),
            target_type: UdmDataType::IpAddress,
            reason: format!("invalid IP address: {}", e),
        }),
    }
}

/// Validate and coerce a value to a timestamp
fn validate_timestamp(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    // Try parsing as Unix timestamp (milliseconds)
    if let Ok(ts) = value.parse::<i64>() {
        return Ok(ValidatedValue::Timestamp(ts));
    }

    // Try parsing as ISO 8601 timestamp
    // For now, we'll just accept numeric timestamps
    // Full ISO 8601 parsing would require chrono or similar
    Err(ValidationError::ParseError {
        field: field_name.to_string(),
        value: value.to_string(),
        target_type: UdmDataType::Timestamp,
        reason: "expected Unix timestamp in milliseconds".to_string(),
    })
}

/// Validate and coerce a value to an array
fn validate_array(field_name: &str, value: &str) -> ValidationResult<ValidatedValue> {
    // Try parsing as JSON array
    if let Ok(arr) = serde_json::from_str::<Vec<String>>(value) {
        return Ok(ValidatedValue::Array(arr));
    }

    // Try parsing as comma-separated values
    let items: Vec<String> = value.split(',').map(|s| s.trim().to_string()).collect();
    if !items.is_empty() {
        Ok(ValidatedValue::Array(items))
    } else {
        Err(ValidationError::ParseError {
            field: field_name.to_string(),
            value: value.to_string(),
            target_type: UdmDataType::Array,
            reason: "expected JSON array or comma-separated values".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_string_field() {
        let result = validate_field_value(UdmField::User, "admin");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::String("admin".to_string()));
    }

    #[test]
    fn test_validate_integer_field() {
        let result = validate_field_value(UdmField::SrcPort, "8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Integer(8080));
    }

    #[test]
    fn test_validate_integer_field_invalid() {
        let result = validate_field_value(UdmField::SrcPort, "not_a_number");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_long_field() {
        let result = validate_field_value(UdmField::BytesIn, "1234567890");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Long(1234567890));
    }

    #[test]
    fn test_validate_float_field() {
        let result = validate_field_value(UdmField::CpuLoadPercent, "75.5");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Float(75.5));
    }

    #[test]
    fn test_validate_boolean_field() {
        let result = validate_field_value(UdmField::IocMatched, "true");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Boolean(true));

        let result = validate_field_value(UdmField::IocMatched, "false");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Boolean(false));

        let result = validate_field_value(UdmField::IocMatched, "1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Boolean(true));

        let result = validate_field_value(UdmField::IocMatched, "0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Boolean(false));
    }

    #[test]
    fn test_validate_ip_address_field() {
        let result = validate_field_value(UdmField::SrcIp, "192.168.1.1");
        assert!(result.is_ok());

        let result = validate_field_value(UdmField::SrcIp, "2001:0db8:85a3::8a2e:0370:7334");
        assert!(result.is_ok());

        let result = validate_field_value(UdmField::SrcIp, "not_an_ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_timestamp_field() {
        let result = validate_field_value(UdmField::Timestamp, "1609459200000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Timestamp(1609459200000));
    }

    #[test]
    fn test_type_coercion_string_to_integer() {
        let result = validate_field_value(UdmField::SrcPort, "443");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Integer(443));
    }

    #[test]
    fn test_type_coercion_float_to_integer() {
        let result = validate_field_value(UdmField::SrcPort, "443.0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ValidatedValue::Integer(443));

        let result = validate_field_value(UdmField::SrcPort, "443.5");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_value_error() {
        let result = validate_field_value(UdmField::User, "");
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::EmptyValue { field } => {
                assert_eq!(field, "user");
            }
            _ => panic!("Expected EmptyValue error"),
        }
    }

    #[test]
    fn test_out_of_range_error() {
        // Value too large for i32
        let result = validate_field_value(UdmField::SrcPort, "9999999999999");
        assert!(result.is_err());
    }

    #[test]
    fn test_validated_value_to_string() {
        assert_eq!(
            ValidatedValue::String("test".to_string()).to_string(),
            "test"
        );
        assert_eq!(ValidatedValue::Integer(42).to_string(), "42");
        assert_eq!(ValidatedValue::Long(1234567890).to_string(), "1234567890");
        assert_eq!(ValidatedValue::Float(3.14).to_string(), "3.14");
        assert_eq!(ValidatedValue::Boolean(true).to_string(), "true");
    }

    #[test]
    fn test_validated_value_data_type() {
        assert_eq!(
            ValidatedValue::String("test".to_string()).data_type(),
            UdmDataType::String
        );
        assert_eq!(
            ValidatedValue::Integer(42).data_type(),
            UdmDataType::Integer
        );
        assert_eq!(
            ValidatedValue::Long(1234567890).data_type(),
            UdmDataType::Long
        );
        assert_eq!(ValidatedValue::Float(3.14).data_type(), UdmDataType::Float);
        assert_eq!(
            ValidatedValue::Boolean(true).data_type(),
            UdmDataType::Boolean
        );
    }
}
