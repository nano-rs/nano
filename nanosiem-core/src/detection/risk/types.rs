// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk scoring types and condition evaluation
//!
//! Contains the core types for risk scoring:
//! - `RiskError` - Error types for risk scoring operations
//! - `RiskModifier` - Conditional score modifiers that adjust scores based on event conditions

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Errors that can occur during risk scoring
#[derive(Debug, Error, Clone, PartialEq)]
pub enum RiskError {
    #[error("Risk score {0} is out of bounds (must be 0-100)")]
    ScoreOutOfBounds(i32),

    #[error("Risk weight {0} is out of bounds (must be 0.0-1.0)")]
    WeightOutOfBounds(f64),

    #[error("Invalid modifier condition: {0}")]
    InvalidCondition(String),
}

/// A conditional score modifier for a detection rule
///
/// Modifiers allow adjusting the base risk score based on conditions
/// in the matched events. When multiple modifiers match, the highest
/// score is used.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct RiskModifier {
    /// Condition expression (e.g., "count > 10", "status = failure")
    pub condition: String,

    /// Score to use when condition matches (0-100)
    pub score: i32,
}

impl RiskModifier {
    /// Create a new risk modifier with validation
    pub fn new(condition: String, score: i32) -> Result<Self, RiskError> {
        Self::validate_score(score)?;
        Self::validate_condition(&condition)?;
        Ok(Self { condition, score })
    }

    /// Validate that a score is within bounds (0-100)
    pub fn validate_score(score: i32) -> Result<(), RiskError> {
        if score < 0 || score > 100 {
            return Err(RiskError::ScoreOutOfBounds(score));
        }
        Ok(())
    }

    /// Validate a condition expression
    ///
    /// Supported formats:
    /// - "field > value" (numeric comparison)
    /// - "field < value" (numeric comparison)
    /// - "field >= value" (numeric comparison)
    /// - "field <= value" (numeric comparison)
    /// - "field = value" (equality, string or numeric)
    /// - "field != value" (inequality)
    /// - "field contains value" (string contains)
    pub fn validate_condition(condition: &str) -> Result<(), RiskError> {
        let condition = condition.trim();
        if condition.is_empty() {
            return Err(RiskError::InvalidCondition(
                "Condition cannot be empty".to_string(),
            ));
        }

        // Parse the condition to validate structure
        // Supported operators: >, <, >=, <=, =, !=, contains
        let operators = [">=", "<=", "!=", ">", "<", "=", " contains "];
        let has_operator = operators.iter().any(|op| condition.contains(op));

        if !has_operator {
            return Err(RiskError::InvalidCondition(format!(
                "Condition must contain an operator (>, <, >=, <=, =, !=, contains): {}",
                condition
            )));
        }

        Ok(())
    }

    /// Evaluate this modifier against matched events
    ///
    /// Returns true if the condition matches any of the events
    pub fn evaluate(&self, events: &[Value]) -> bool {
        // Parse the condition
        let condition = self.condition.trim();

        // Try each operator in order of specificity
        if let Some((field, value)) = Self::parse_operator(condition, ">=") {
            return Self::evaluate_numeric_comparison(events, field, value, |a, b| a >= b);
        }
        if let Some((field, value)) = Self::parse_operator(condition, "<=") {
            return Self::evaluate_numeric_comparison(events, field, value, |a, b| a <= b);
        }
        if let Some((field, value)) = Self::parse_operator(condition, "!=") {
            return Self::evaluate_inequality(events, field, value);
        }
        if let Some((field, value)) = Self::parse_operator(condition, ">") {
            return Self::evaluate_numeric_comparison(events, field, value, |a, b| a > b);
        }
        if let Some((field, value)) = Self::parse_operator(condition, "<") {
            return Self::evaluate_numeric_comparison(events, field, value, |a, b| a < b);
        }
        if let Some((field, value)) = Self::parse_operator(condition, "=") {
            return Self::evaluate_equality(events, field, value);
        }
        if let Some((field, value)) = Self::parse_operator(condition, " contains ") {
            return Self::evaluate_contains(events, field, value);
        }

        false
    }

    /// Parse an operator from a condition string
    fn parse_operator<'a>(condition: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
        let parts: Vec<&str> = condition.splitn(2, op).collect();
        if parts.len() == 2 {
            Some((parts[0].trim(), parts[1].trim()))
        } else {
            None
        }
    }

    /// Evaluate a numeric comparison against events
    fn evaluate_numeric_comparison<F>(
        events: &[Value],
        field: &str,
        value: &str,
        compare: F,
    ) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        let target: f64 = match value.parse() {
            Ok(v) => v,
            Err(_) => return false,
        };

        events.iter().any(|event| {
            Self::get_field_value(event, field)
                .and_then(|v| Self::value_to_f64(&v))
                .map(|v| compare(v, target))
                .unwrap_or(false)
        })
    }

    /// Evaluate equality against events
    fn evaluate_equality(events: &[Value], field: &str, value: &str) -> bool {
        let value = value.trim_matches('"').trim_matches('\'');
        events.iter().any(|event| {
            Self::get_field_value(event, field)
                .map(|v| Self::value_equals(&v, value))
                .unwrap_or(false)
        })
    }

    /// Evaluate inequality against events
    fn evaluate_inequality(events: &[Value], field: &str, value: &str) -> bool {
        let value = value.trim_matches('"').trim_matches('\'');
        events.iter().any(|event| {
            Self::get_field_value(event, field)
                .map(|v| !Self::value_equals(&v, value))
                .unwrap_or(true) // Missing field != value is true
        })
    }

    /// Evaluate contains against events
    fn evaluate_contains(events: &[Value], field: &str, value: &str) -> bool {
        let value = value.trim_matches('"').trim_matches('\'');
        events.iter().any(|event| {
            Self::get_field_value(event, field)
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .map(|s| s.contains(value))
                .unwrap_or(false)
        })
    }

    /// Get a field value from an event, supporting nested fields with dot notation
    fn get_field_value(event: &Value, field: &str) -> Option<Value> {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = event;

        for part in parts {
            match current.get(part) {
                Some(v) => current = v,
                None => return None,
            }
        }

        Some(current.clone())
    }

    /// Convert a JSON value to f64 for numeric comparison
    fn value_to_f64(value: &Value) -> Option<f64> {
        match value {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    /// Check if a JSON value equals a string value
    fn value_equals(json_value: &Value, str_value: &str) -> bool {
        match json_value {
            Value::String(s) => s == str_value,
            Value::Number(n) => {
                if let Ok(target) = str_value.parse::<f64>() {
                    n.as_f64()
                        .map(|v| (v - target).abs() < f64::EPSILON)
                        .unwrap_or(false)
                } else {
                    n.to_string() == str_value
                }
            }
            Value::Bool(b) => str_value == "true" && *b || str_value == "false" && !*b,
            Value::Null => str_value == "null",
            _ => false,
        }
    }
}
