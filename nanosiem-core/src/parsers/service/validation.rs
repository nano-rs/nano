// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRL and UDM field validation

use std::str::FromStr;

use super::ParserService;
use crate::parsers::types::{ParserTestResult, VrlValidationResult};
use crate::udm::fields::UdmField;

impl ParserService {
    /// Validate VRL code
    pub fn validate_vrl(&self, vrl_code: &str) -> VrlValidationResult {
        let mut warnings = Vec::new();

        // Check for common issues
        if vrl_code.trim().is_empty() {
            return VrlValidationResult {
                valid: false,
                error: Some("VRL code cannot be empty".to_string()),
                warnings,
            };
        }

        // SECURITY: Check for TOML injection attempts
        // VRL code is wrapped in ''' blocks, so we need to prevent breaking out
        if vrl_code.contains("'''") {
            return VrlValidationResult {
                valid: false,
                error: Some(
                    "VRL code cannot contain triple single quotes (potential TOML injection)"
                        .to_string(),
                ),
                warnings,
            };
        }

        // SECURITY: Block attempts to inject TOML sections
        let toml_section_pattern = regex::Regex::new(r"^\s*\[[\w\._]+\]").unwrap();
        for line in vrl_code.lines() {
            if toml_section_pattern.is_match(line) {
                return VrlValidationResult {
                    valid: false,
                    error: Some(
                        "VRL code cannot contain TOML section headers (potential config injection)"
                            .to_string(),
                    ),
                    warnings,
                };
            }
        }

        // SECURITY: Check for suspicious patterns that might indicate abuse
        let suspicious_patterns = [
            ("\\x", "hex escape sequences"),
            ("\\u", "unicode escape sequences"),
            ("\\0", "null bytes"),
        ];
        for (pattern, desc) in suspicious_patterns {
            if vrl_code.contains(pattern) {
                warnings.push(format!(
                    "VRL contains {} which may indicate obfuscation",
                    desc
                ));
            }
        }

        // SECURITY: Limit VRL code size to prevent resource exhaustion
        const MAX_VRL_SIZE: usize = 1024 * 1024; // 1MB
        if vrl_code.len() > MAX_VRL_SIZE {
            return VrlValidationResult {
                valid: false,
                error: Some(format!(
                    "VRL code exceeds maximum size of {} bytes",
                    MAX_VRL_SIZE
                )),
                warnings,
            };
        }

        // SECURITY: Limit nesting depth to prevent stack overflow
        let max_nesting = vrl_code
            .chars()
            .fold((0i32, 0i32), |(max, current), c| match c {
                '{' | '(' | '[' => (max.max(current + 1), current + 1),
                '}' | ')' | ']' => (max, (current - 1).max(0)),
                _ => (max, current),
            })
            .0;
        if max_nesting > 20 {
            return VrlValidationResult {
                valid: false,
                error: Some("VRL code has excessive nesting depth (max 20 levels)".to_string()),
                warnings,
            };
        }

        // Check for unbalanced braces
        let open_braces = vrl_code.matches('{').count();
        let close_braces = vrl_code.matches('}').count();
        if open_braces != close_braces {
            return VrlValidationResult {
                valid: false,
                error: Some(format!(
                    "Unbalanced braces: {} opening, {} closing",
                    open_braces, close_braces
                )),
                warnings,
            };
        }

        // Check for unbalanced parentheses
        let open_parens = vrl_code.matches('(').count();
        let close_parens = vrl_code.matches(')').count();
        if open_parens != close_parens {
            return VrlValidationResult {
                valid: false,
                error: Some(format!(
                    "Unbalanced parentheses: {} opening, {} closing",
                    open_parens, close_parens
                )),
                warnings,
            };
        }

        // Check for common VRL patterns
        if !vrl_code.contains('.') {
            warnings.push("VRL code doesn't appear to access any fields".to_string());
        }

        // Check for timestamp handling
        if !vrl_code.contains("timestamp") && !vrl_code.contains("now()") {
            warnings.push("Consider adding timestamp handling".to_string());
        }

        // Check for error handling
        if vrl_code.contains("parse_") && !vrl_code.contains("err") {
            warnings.push("Consider adding error handling for parse functions".to_string());
        }

        VrlValidationResult {
            valid: true,
            error: None,
            warnings,
        }
    }

    /// Test a parser against sample input
    ///
    /// This method validates the VRL code and executes it against the sample input.
    /// When Docker is available, it uses Vector's VRL runtime for accurate execution.
    /// Returns a structured result with the transformed output or error details.
    pub async fn test_parser(&self, vrl_code: &str, sample_input: &str) -> ParserTestResult {
        match self.vrl_validator.test_vrl(vrl_code, sample_input).await {
            Ok(result) => result,
            Err(e) => ParserTestResult {
                success: false,
                input: sample_input.to_string(),
                output: None,
                error: Some(e.to_string()),
                duration_ms: 0,
            },
        }
    }

    /// Validate VRL code asynchronously using the VRL validator
    ///
    /// This performs comprehensive validation including:
    /// - Security pattern checks
    /// - Syntax validation
    /// - Docker-based VRL compilation (when available)
    pub async fn validate_vrl_async(&self, vrl_code: &str) -> VrlValidationResult {
        match self.vrl_validator.validate_vrl(vrl_code).await {
            Ok(result) => result,
            Err(e) => VrlValidationResult {
                valid: false,
                error: Some(e.to_string()),
                warnings: vec![],
            },
        }
    }

    /// Validate parser output fields against UDM schema
    ///
    /// This validates that parser VRL code references valid UDM fields.
    /// It extracts field assignments from the VRL code and checks them against
    /// the UDM field schema.
    ///
    /// Returns a validation result with:
    /// - valid: true if all fields are valid or warnings only
    /// - warnings: list of unmapped or unknown fields
    /// - error: critical validation errors (currently none, but reserved for future use)
    ///
    /// Requirements: 4.2, 4.3
    pub fn validate_parser_fields(&self, vrl_code: &str) -> VrlValidationResult {
        let mut warnings = Vec::new();

        // Extract field assignments from VRL code
        // Look for patterns like: .field_name = ...
        let field_pattern = regex::Regex::new(r"\.([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*=|\s*\[)").unwrap();

        let mut found_fields = std::collections::HashSet::new();
        let mut unknown_fields = Vec::new();

        for cap in field_pattern.captures_iter(vrl_code) {
            if let Some(field_match) = cap.get(1) {
                let field_name = field_match.as_str();

                // Skip special fields that are not UDM fields
                if field_name == "metadata" || field_name == "udm" {
                    continue;
                }

                // Skip fields we've already checked
                if found_fields.contains(field_name) {
                    continue;
                }

                found_fields.insert(field_name.to_string());

                // Check if this is a valid UDM field
                match UdmField::from_str(field_name) {
                    Ok(_) => {
                        // Valid UDM field - no action needed
                    }
                    Err(_) => {
                        // Unknown field - add to warnings
                        unknown_fields.push(field_name.to_string());
                    }
                }
            }
        }

        // Generate warnings for unknown fields
        if !unknown_fields.is_empty() {
            warnings.push(format!(
                "Parser references {} field(s) not in UDM schema: {}. These will be preserved in metadata.",
                unknown_fields.len(),
                unknown_fields.join(", ")
            ));

            tracing::debug!(
                "Parser validation: {} unknown fields found: {:?}",
                unknown_fields.len(),
                unknown_fields
            );
        }

        // Log info about valid fields found
        let valid_field_count = found_fields.len() - unknown_fields.len();
        if valid_field_count > 0 {
            tracing::debug!(
                "Parser validation: {} valid UDM fields found",
                valid_field_count
            );
        }

        VrlValidationResult {
            valid: true, // We don't fail on unknown fields, just warn
            error: None,
            warnings,
        }
    }
}
