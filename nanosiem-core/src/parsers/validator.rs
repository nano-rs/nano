// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRL Validator Module
//!
//! Provides VRL (Vector Remap Language) validation and testing capabilities
//! using native VRL compilation (no Docker required).
//!
//! ## Features
//!
//! - **Security validation**: Blocks dangerous patterns before compilation
//! - **Native compilation**: Uses the `vrl` crate for syntax validation
//! - **Test execution**: Run VRL against sample inputs to verify behavior
//!
//! ## Security
//!
//! VRL is sandboxed by design - it cannot execute shell commands or access
//! the filesystem. This validator adds additional security checks for:
//! - TOML injection (VRL is embedded in Vector TOML configs)
//! - Size and complexity limits
//! - Suspicious patterns that may indicate obfuscation

use std::collections::BTreeMap;
use std::time::Instant;
use thiserror::Error;

use super::types::{ParserTestResult, VrlValidationResult};

#[derive(Error, Debug)]
pub enum VrlValidatorError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("VRL syntax error: {0}")]
    SyntaxError(String),
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Dangerous patterns that should be blocked in VRL code
/// Note: These are checked as function calls (with parentheses) to avoid
/// false positives on legitimate field names like "Execution" or "SystemTime"
const DANGEROUS_PATTERNS: &[(&str, &str)] = &[
    ("'''", "Triple single quotes can break TOML structure"),
    ("\\x00", "Null byte injection attempt"),
    ("\\0", "Null byte injection attempt"),
];

/// Dangerous function patterns - checked with word boundaries to avoid
/// false positives on field names like "Execution", "SystemTime", etc.
const DANGEROUS_FUNCTION_PATTERNS: &[(&str, &str)] = &[
    ("exec(", "Potential command execution attempt"),
    ("exec!(", "Potential command execution attempt"),
    ("system(", "Potential system call attempt"),
    ("system!(", "Potential system call attempt"),
    ("shell(", "Potential shell execution attempt"),
    ("shell!(", "Potential shell execution attempt"),
    (
        "get_env_var(",
        "Environment variable access leaks API process secrets",
    ),
    (
        "get_env_var!(",
        "Environment variable access leaks API process secrets",
    ),
    ("http_request(", "Outbound HTTP from API process (SSRF risk)"),
    ("http_request!(", "Outbound HTTP from API process (SSRF risk)"),
    ("dns_lookup(", "DNS query from API process (exfiltration risk)"),
    ("dns_lookup!(", "DNS query from API process (exfiltration risk)"),
    ("reverse_dns(", "DNS query from API process (exfiltration risk)"),
    ("reverse_dns!(", "DNS query from API process (exfiltration risk)"),
    ("get_hostname(", "Host info disclosure from API process"),
    ("get_hostname!(", "Host info disclosure from API process"),
];

/// Suspicious patterns that generate warnings
const SUSPICIOUS_PATTERNS: &[(&str, &str)] = &[
    ("\\x", "Hex escape sequences may indicate obfuscation"),
    ("\\u", "Unicode escape sequences may indicate obfuscation"),
];

/// VRL stdlib functions that are stripped from the compiler/runtime registry
/// regardless of source-level checks. Source-pattern matching is bypassable
/// (string concat, dynamic identifiers, comments); removing the function
/// from the registry means even a successful obfuscation has nothing to call.
///
/// Categories blocked:
/// - Host process info: `get_env_var` (secrets), `get_hostname` (recon).
/// - Network egress: `http_request` (SSRF/exfil), `dns_lookup` /
///   `reverse_dns` (DNS-tunnel exfil).
const BLOCKED_VRL_FUNCTIONS: &[&str] = &[
    "get_env_var",
    "get_hostname",
    "http_request",
    "dns_lookup",
    "reverse_dns",
];

/// Returns the VRL stdlib function set with security-blocked functions removed.
fn safe_vrl_functions() -> Vec<Box<dyn vrl::compiler::Function>> {
    vrl::stdlib::all()
        .into_iter()
        .filter(|f| !BLOCKED_VRL_FUNCTIONS.contains(&f.identifier()))
        .collect()
}

/// Maximum allowed VRL code size (1MB)
const MAX_VRL_SIZE: usize = 1024 * 1024;

/// Maximum allowed nesting depth
const MAX_NESTING_DEPTH: i32 = 20;

/// VRL Validator for syntax checking and security validation
///
/// Uses native VRL compilation for validation - no Docker required.
#[derive(Debug, Clone, Default)]
pub struct VrlValidator {
    // No state needed - VRL functions are retrieved at compile time
}

impl VrlValidator {
    /// Create a new VRL validator
    pub fn new() -> Self {
        Self {}
    }

    /// Create a validator with a custom container name (legacy API, ignored)
    #[deprecated(note = "Docker is no longer used; use new() instead")]
    pub fn with_container(_container_name: impl Into<String>) -> Self {
        Self::new()
    }

    /// Create a validator that doesn't use Docker (legacy API, now same as new())
    #[deprecated(note = "Docker is no longer used; use new() instead")]
    pub fn without_docker() -> Self {
        Self::new()
    }

    /// Validate VRL code for syntax and security issues
    ///
    /// This performs:
    /// 1. Security pattern checks (blocks dangerous patterns)
    /// 2. Size and complexity limits
    /// 3. Basic syntax validation (balanced brackets, etc.)
    /// 4. Native VRL compilation check
    pub async fn validate_vrl(
        &self,
        vrl_code: &str,
    ) -> Result<VrlValidationResult, VrlValidatorError> {
        let mut warnings = Vec::new();

        // Step 1: Check for empty code
        if vrl_code.trim().is_empty() {
            return Ok(VrlValidationResult {
                valid: false,
                error: Some("VRL code cannot be empty".to_string()),
                warnings,
            });
        }

        // Step 2: Check size limits
        if vrl_code.len() > MAX_VRL_SIZE {
            return Ok(VrlValidationResult {
                valid: false,
                error: Some(format!(
                    "VRL code exceeds maximum size of {} bytes (got {} bytes)",
                    MAX_VRL_SIZE,
                    vrl_code.len()
                )),
                warnings,
            });
        }

        // Step 3: Security pattern checks
        if let Err(e) = self.check_security_patterns(vrl_code) {
            return Ok(VrlValidationResult {
                valid: false,
                error: Some(e.to_string()),
                warnings,
            });
        }

        // Step 4: Check for suspicious patterns (warnings only)
        warnings.extend(self.check_suspicious_patterns(vrl_code));

        // Step 5: Check nesting depth
        if let Err(e) = self.check_nesting_depth(vrl_code) {
            return Ok(VrlValidationResult {
                valid: false,
                error: Some(e.to_string()),
                warnings,
            });
        }

        // Step 6: Check balanced brackets
        if let Err(e) = self.check_balanced_brackets(vrl_code) {
            return Ok(VrlValidationResult {
                valid: false,
                error: Some(e.to_string()),
                warnings,
            });
        }

        // Step 7: Check for TOML injection attempts
        if let Err(e) = self.check_toml_injection(vrl_code) {
            return Ok(VrlValidationResult {
                valid: false,
                error: Some(e.to_string()),
                warnings,
            });
        }

        // Step 8: Add helpful warnings
        warnings.extend(self.generate_helpful_warnings(vrl_code));

        // Step 9: Native VRL compilation check
        match self.compile_vrl(vrl_code) {
            Ok(compile_warnings) => {
                warnings.extend(compile_warnings);
            }
            Err(errors) => {
                // Preserve the existing public shape: `error: Option<String>`
                // is a single string with all diagnostics joined. The Vec
                // form is exposed via `validate_vrl_collect_errors` for
                // callers that need to iterate.
                return Ok(VrlValidationResult {
                    valid: false,
                    error: Some(errors.join("\n")),
                    warnings,
                });
            }
        }

        Ok(VrlValidationResult {
            valid: true,
            error: None,
            warnings,
        })
    }

    /// Validate VRL code and return errors as one entry per diagnostic.
    ///
    /// Same checks as [`Self::validate_vrl`], but on compile failure each
    /// VRL diagnostic is returned as a separate `String` rather than
    /// joined into one. Built for the parser-gen retry loop (NAN-641),
    /// which renders a `±5`-line source snippet around each error's
    /// reported line number — joining the diagnostics into one blob
    /// would mean only the first error's line gets a snippet.
    ///
    /// Pre-compile gates (size, security patterns, balanced brackets,
    /// etc.) still produce a single error; they don't go through the VRL
    /// compiler so there's nothing to split. The returned `Vec` will have
    /// one entry in that case.
    pub async fn validate_vrl_collect_errors(
        &self,
        vrl_code: &str,
    ) -> Result<(VrlValidationResult, Vec<String>), VrlValidatorError> {
        let mut warnings = Vec::new();

        // Steps 1-8 mirror `validate_vrl` — pre-compile gates that produce
        // a single error string each. We collect them as a 1-element Vec
        // so the caller's contract stays uniform.
        if vrl_code.trim().is_empty() {
            let msg = "VRL code cannot be empty".to_string();
            return Ok(single_error_result(msg, warnings));
        }

        if vrl_code.len() > MAX_VRL_SIZE {
            let msg = format!(
                "VRL code exceeds maximum size of {} bytes (got {} bytes)",
                MAX_VRL_SIZE,
                vrl_code.len()
            );
            return Ok(single_error_result(msg, warnings));
        }

        if let Err(e) = self.check_security_patterns(vrl_code) {
            return Ok(single_error_result(e.to_string(), warnings));
        }

        warnings.extend(self.check_suspicious_patterns(vrl_code));

        if let Err(e) = self.check_nesting_depth(vrl_code) {
            return Ok(single_error_result(e.to_string(), warnings));
        }

        if let Err(e) = self.check_balanced_brackets(vrl_code) {
            return Ok(single_error_result(e.to_string(), warnings));
        }

        if let Err(e) = self.check_toml_injection(vrl_code) {
            return Ok(single_error_result(e.to_string(), warnings));
        }

        warnings.extend(self.generate_helpful_warnings(vrl_code));

        // Step 9: real compiler — this is where multi-error splitting
        // earns its keep.
        match self.compile_vrl(vrl_code) {
            Ok(compile_warnings) => {
                warnings.extend(compile_warnings);
                Ok((
                    VrlValidationResult {
                        valid: true,
                        error: None,
                        warnings,
                    },
                    Vec::new(),
                ))
            }
            Err(errors) => {
                let joined = errors.join("\n");
                Ok((
                    VrlValidationResult {
                        valid: false,
                        error: Some(joined),
                        warnings,
                    },
                    errors,
                ))
            }
        }
    }

    /// Compile VRL code using the native VRL compiler
    ///
    /// Returns `Ok(warnings)` on success, `Err(errors)` on failure where
    /// `errors` is one formatted block per diagnostic. Callers that need a
    /// single string can `.join("\n")`; callers that need to attach
    /// per-error context (line snippets, etc.) can iterate. Splitting at
    /// the diagnostic boundary is the whole point of NAN-641 — the LLM
    /// retry loop renders each error's source snippet independently, and
    /// joining + re-splitting downstream is fragile because codespan
    /// output is multi-line per diagnostic.
    fn compile_vrl(&self, vrl_code: &str) -> Result<Vec<String>, Vec<String>> {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let fns = safe_vrl_functions();

        match compile(vrl_code, &fns) {
            Ok(result) => {
                let mut warnings = Vec::new();
                // Check for compilation warnings
                for warning in result.warnings {
                    let formatter = Formatter::new(vrl_code, warning.clone());
                    warnings.push(format!("VRL warning: {}", formatter));
                }
                Ok(warnings)
            }
            Err(diagnostics) => {
                // One formatted block per diagnostic — preserves the
                // boundary so callers can render per-error context.
                let errors: Vec<String> = diagnostics
                    .into_iter()
                    .map(|d| {
                        let formatter = Formatter::new(vrl_code, d);
                        formatter.to_string()
                    })
                    .collect();
                Err(errors)
            }
        }
    }

    /// Check for dangerous security patterns
    fn check_security_patterns(&self, vrl_code: &str) -> Result<(), VrlValidatorError> {
        // Check simple dangerous patterns (like triple quotes)
        for (pattern, description) in DANGEROUS_PATTERNS {
            if vrl_code.contains(pattern) {
                return Err(VrlValidatorError::SecurityViolation(format!(
                    "VRL contains forbidden pattern '{}': {}",
                    pattern, description
                )));
            }
        }

        // Check dangerous function patterns (with parentheses to avoid false positives)
        // This prevents blocking legitimate field names like "Execution", "SystemTime"
        let vrl_lower = vrl_code.to_lowercase();
        for (pattern, description) in DANGEROUS_FUNCTION_PATTERNS {
            if vrl_lower.contains(pattern) {
                return Err(VrlValidatorError::SecurityViolation(format!(
                    "VRL contains forbidden function call '{}': {}",
                    pattern.trim_end_matches('(').trim_end_matches('!'),
                    description
                )));
            }
        }
        Ok(())
    }

    /// Check for suspicious patterns and return warnings
    fn check_suspicious_patterns(&self, vrl_code: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        for (pattern, description) in SUSPICIOUS_PATTERNS {
            if vrl_code.contains(pattern) {
                warnings.push(format!("Warning: {}", description));
            }
        }
        warnings
    }

    /// Check nesting depth to prevent stack overflow
    fn check_nesting_depth(&self, vrl_code: &str) -> Result<(), VrlValidatorError> {
        let mut max_depth = 0i32;
        let mut current_depth = 0i32;

        for c in vrl_code.chars() {
            match c {
                '{' | '(' | '[' => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                }
                '}' | ')' | ']' => {
                    current_depth = (current_depth - 1).max(0);
                }
                _ => {}
            }
        }

        if max_depth > MAX_NESTING_DEPTH {
            return Err(VrlValidatorError::SyntaxError(format!(
                "VRL code has excessive nesting depth ({} levels, max {})",
                max_depth, MAX_NESTING_DEPTH
            )));
        }

        Ok(())
    }

    /// Check for balanced brackets
    fn check_balanced_brackets(&self, vrl_code: &str) -> Result<(), VrlValidatorError> {
        let open_braces = vrl_code.matches('{').count();
        let close_braces = vrl_code.matches('}').count();
        if open_braces != close_braces {
            return Err(VrlValidatorError::SyntaxError(format!(
                "Unbalanced braces: {} opening, {} closing",
                open_braces, close_braces
            )));
        }

        let open_parens = vrl_code.matches('(').count();
        let close_parens = vrl_code.matches(')').count();
        if open_parens != close_parens {
            return Err(VrlValidatorError::SyntaxError(format!(
                "Unbalanced parentheses: {} opening, {} closing",
                open_parens, close_parens
            )));
        }

        let open_brackets = vrl_code.matches('[').count();
        let close_brackets = vrl_code.matches(']').count();
        if open_brackets != close_brackets {
            return Err(VrlValidatorError::SyntaxError(format!(
                "Unbalanced square brackets: {} opening, {} closing",
                open_brackets, close_brackets
            )));
        }

        Ok(())
    }

    /// Check for TOML injection attempts
    fn check_toml_injection(&self, vrl_code: &str) -> Result<(), VrlValidatorError> {
        // Check for TOML section headers
        let toml_section_pattern = regex::Regex::new(r"^\s*\[[\w\._]+\]").unwrap();
        for line in vrl_code.lines() {
            if toml_section_pattern.is_match(line) {
                return Err(VrlValidatorError::SecurityViolation(
                    "VRL code cannot contain TOML section headers (potential config injection)"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Generate helpful warnings for common issues
    fn generate_helpful_warnings(&self, vrl_code: &str) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check for field access
        if !vrl_code.contains('.') {
            warnings.push("VRL code doesn't appear to access any fields".to_string());
        }

        // Check for timestamp handling
        if !vrl_code.contains("timestamp") && !vrl_code.contains("now()") {
            warnings.push("Consider adding timestamp handling".to_string());
        }

        // Check for error handling with parse functions
        if vrl_code.contains("parse_") && !vrl_code.contains("err") && !vrl_code.contains("!") {
            warnings.push(
                "Consider adding error handling for parse functions (use ! suffix or handle err)"
                    .to_string(),
            );
        }

        // Check for E651 violations - unnecessary error coalescing after to_string()
        // to_string() cannot fail, so using ?? after it triggers E651 in Vector's strict mode
        warnings.extend(self.check_e651_patterns(vrl_code));

        warnings
    }

    /// Check for E651 (unnecessary error coalescing) patterns
    ///
    /// Vector's strict mode rejects `??` after functions that cannot fail.
    /// This catches common violations before deployment.
    fn check_e651_patterns(&self, vrl_code: &str) -> Vec<String> {
        let mut warnings = Vec::new();

        // Patterns that will cause E651 errors
        // to_string() cannot fail, so `to_string(x) ?? ""` is unnecessary
        let e651_patterns = [
            (
                r"to_string\s*\([^)]+\)\s*\?\?",
                "to_string() cannot fail - remove the ?? operator",
            ),
            (
                r"downcase\s*\([^)]+\)\s*\?\?",
                "downcase() cannot fail - remove the ?? operator",
            ),
            (
                r"upcase\s*\([^)]+\)\s*\?\?",
                "upcase() cannot fail - remove the ?? operator",
            ),
            (
                r"split\s*\([^)]+\)\s*\?\?",
                "split() cannot fail - remove the ?? operator",
            ),
            (
                r"length\s*\([^)]+\)\s*\?\?",
                "length() cannot fail - remove the ?? operator",
            ),
            (
                r"string!\s*\([^)]+\)\s*\?\?",
                "string!() already aborts on error - remove the ?? operator",
            ),
        ];

        for (pattern, message) in e651_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(vrl_code) {
                    warnings.push(format!(
                        "E651 WARNING: {} This will cause Vector to reject the config.",
                        message
                    ));
                }
            }
        }

        warnings
    }

    /// Test VRL code against sample input
    ///
    /// Compiles and executes the VRL code against the provided sample input,
    /// returning the transformed output or an error.
    pub async fn test_vrl(
        &self,
        vrl_code: &str,
        sample_input: &str,
    ) -> Result<ParserTestResult, VrlValidatorError> {
        let start = Instant::now();

        // First validate the VRL code
        let validation = self.validate_vrl(vrl_code).await?;
        if !validation.valid {
            return Ok(ParserTestResult {
                success: false,
                input: sample_input.to_string(),
                output: None,
                error: validation.error,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Validate that sample input is valid JSON
        let input_json: serde_json::Value = match serde_json::from_str(sample_input) {
            Ok(v) => v,
            Err(e) => {
                return Ok(ParserTestResult {
                    success: false,
                    input: sample_input.to_string(),
                    output: None,
                    error: Some(format!("Invalid JSON input: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                });
            }
        };

        // Execute VRL natively
        match self.execute_vrl(vrl_code, &input_json) {
            Ok(output) => Ok(ParserTestResult {
                success: true,
                input: sample_input.to_string(),
                output: Some(output),
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
            }),
            Err(e) => Ok(ParserTestResult {
                success: false,
                input: sample_input.to_string(),
                output: None,
                error: Some(format!("Execution error: {}", e)),
                duration_ms: start.elapsed().as_millis() as u64,
            }),
        }
    }

    /// Test a chain of VRL stages against sample input (NAN-874).
    ///
    /// Each stage runs sequentially: output of stage N becomes input to stage N+1.
    /// This mirrors the production pipeline where an extension transform runs
    /// after the parser's `_parse` transform and feeds its output into `_output`.
    ///
    /// Empty / blank stages are skipped (treated as passthrough), which lets the
    /// caller pass `[parser_vrl, extension_vrl]` even when one of them is empty
    /// (e.g. an extension on a stub log_source with no OOTB parser).
    ///
    /// If any stage fails validation, the chain short-circuits with that stage's
    /// error message prefixed with `stage {i}:` so the UI can point at the
    /// offending transform.
    pub async fn test_vrl_chain(
        &self,
        vrl_stages: &[&str],
        sample_input: &str,
    ) -> Result<ParserTestResult, VrlValidatorError> {
        let start = Instant::now();

        // Filter out blank stages — they're no-ops in the chain.
        let stages: Vec<(usize, &str)> = vrl_stages
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.trim().is_empty())
            .map(|(i, s)| (i, *s))
            .collect();

        if stages.is_empty() {
            // Nothing to run — return the input unchanged as a successful no-op.
            let parsed = serde_json::from_str::<serde_json::Value>(sample_input)
                .unwrap_or_else(|_| serde_json::Value::String(sample_input.to_string()));
            return Ok(ParserTestResult {
                success: true,
                input: sample_input.to_string(),
                output: Some(parsed),
                error: None,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Validate every stage upfront — we don't want to leak partial state on a
        // downstream syntax error.
        for (idx, vrl) in &stages {
            let validation = self.validate_vrl(vrl).await?;
            if !validation.valid {
                return Ok(ParserTestResult {
                    success: false,
                    input: sample_input.to_string(),
                    output: None,
                    error: Some(format!(
                        "stage {}: {}",
                        idx,
                        validation.error.unwrap_or_else(|| "validation failed".into())
                    )),
                    duration_ms: start.elapsed().as_millis() as u64,
                });
            }
        }

        // Parse the sample as JSON; if it isn't JSON, fall through with the raw
        // string as `.message` — same forgiving behavior the Vector pipeline has.
        let mut current: serde_json::Value = match serde_json::from_str(sample_input) {
            Ok(v) => v,
            Err(_) => serde_json::json!({ "message": sample_input }),
        };

        for (idx, vrl) in &stages {
            match self.execute_vrl(vrl, &current) {
                Ok(output) => current = output,
                Err(e) => {
                    return Ok(ParserTestResult {
                        success: false,
                        input: sample_input.to_string(),
                        output: None,
                        error: Some(format!("stage {}: execution error: {}", idx, e)),
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        Ok(ParserTestResult {
            success: true,
            input: sample_input.to_string(),
            output: Some(current),
            error: None,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Execute VRL code against input using the native VRL runtime
    fn execute_vrl(
        &self,
        vrl_code: &str,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        use vrl::compiler::{compile, TargetValue};
        use vrl::diagnostic::Formatter;
        use vrl::value::{Secrets, Value};

        let fns = safe_vrl_functions();

        // Compile the VRL program
        let result = compile(vrl_code, &fns).map_err(|diagnostics| {
            diagnostics
                .into_iter()
                .map(|d| {
                    let formatter = Formatter::new(vrl_code, d);
                    formatter.to_string()
                })
                .collect::<Vec<_>>()
                .join("\n")
        })?;

        // Convert JSON input to VRL Value
        let vrl_input = json_to_vrl_value(input);

        // Create runtime and execute
        let mut target = TargetValue {
            value: vrl_input,
            metadata: Value::Object(BTreeMap::new()),
            secrets: Secrets::default(),
        };

        let timezone = vrl::compiler::TimeZone::Local;
        let mut runtime = vrl::compiler::runtime::Runtime::default();

        match runtime.resolve(&mut target, &result.program, &timezone) {
            Ok(_) => {
                // Convert the transformed value back to JSON
                let output_json = vrl_value_to_json(&target.value);
                Ok(output_json)
            }
            Err(e) => Err(format!("VRL runtime error: {}", e)),
        }
    }
}

// =============================================================================
// NAN-1150: deploy-time encoding-contract guard for enrichment parsers
// =============================================================================

/// Deploy-time encoding-contract guard, dispatched on `enrich_kind` — each
/// enrichment kind writes a different target table with its own invariants.
/// Runs the parser's `normalize_vrl` against representative records and returns
/// `Err(reason)` if it would emit a row that violates the contract, so a
/// malformed parser is rejected BEFORE Vector reloads (the NAN-1120 halt class).
pub(crate) fn validate_enrichment_encoding_contract(
    enrich_kind: &str,
    normalize_vrl: &str,
) -> Result<(), String> {
    match enrich_kind {
        "identity" => validate_identity_contract(normalize_vrl),
        "ip_context" => validate_ip_context_contract(normalize_vrl),
        // A kind we don't yet have a target schema for: can't assert fields we
        // don't know, but the VRL must still compile + run on a record without
        // erroring (catches syntax / runtime breakage at deploy).
        _ => validate_compiles_and_runs(normalize_vrl),
    }
}

/// `user_registry` (identity) contract (NAN-1123): `external_id` required
/// (record with none must abort, not emit an empty id), `version` a non-zero
/// integer-ms, `last_synced_at` formatted `%Y-%m-%d %H:%M:%S%.3f`,
/// `account_status ∈ {active,disabled,deleted,anonymized}`, `groups` an Array —
/// verified on a valid AND a type-corrupt record (the VRL must sanitise).
fn validate_identity_contract(normalize_vrl: &str) -> Result<(), String> {
    // A generic identity-shaped record carrying every common external_id source
    // key (`.external_id` AD, `.id` Graph/Okta/Google, `.Worker_ID` Workday) so
    // any provider parser extracts an id and runs its full envelope.
    let valid = serde_json::json!({
        "external_id": "ENC_CONTRACT_1", "id": "ENC_CONTRACT_1", "Worker_ID": "ENC_CONTRACT_1",
        "userPrincipalName": "u@example.com", "primaryEmail": "u@example.com",
        "profile": { "login": "u@example.com" },
        "account_enabled": true, "status": "ACTIVE", "Active_Status": "Active"
    });
    let out = run_normalize_for_contract(normalize_vrl, &valid)
        .map_err(|e| format!("normalize VRL failed on a valid record: {e}"))?;
    assert_user_registry_contract(&out, "valid record")?;

    // Type-corrupt: the VRL must SANITISE these, not pass them through.
    let mut corrupt = valid.clone();
    corrupt["version"] = serde_json::json!("not-a-number");
    corrupt["groups"] = serde_json::json!("not-an-array");
    corrupt["account_status"] = serde_json::json!("DEFINITELY_NOT_VALID");
    corrupt["account_enabled"] = serde_json::json!("maybe");
    let out = run_normalize_for_contract(normalize_vrl, &corrupt).map_err(|e| {
        format!("normalize VRL errored on a type-corrupt record (it must sanitise, not fail): {e}")
    })?;
    assert_user_registry_contract(&out, "type-corrupt record")?;

    // Missing external_id: the parser MUST reject (abort), not emit an empty id.
    let missing = serde_json::json!({ "username": "no-id", "account_enabled": true });
    match run_normalize_for_contract(normalize_vrl, &missing) {
        Err(_) => Ok(()), // aborted — correct (record dead-letters)
        Ok(out) => {
            let ext = out.get("external_id").and_then(|v| v.as_str()).unwrap_or("");
            if ext.is_empty() {
                Err("normalize VRL emitted a row with empty external_id instead of \
                     aborting — external_id is required (NAN-1123)"
                    .to_string())
            } else {
                Err(format!(
                    "normalize VRL invented an external_id ({ext:?}) for a record that had none \
                     — it must abort on missing external_id"
                ))
            }
        }
    }
}

/// `ip_enrichments` (ip_context, NAN-1137) contract: `network` required + a
/// valid CIDR (record with none/invalid must abort — never a `0.0.0.0/0`
/// default), `source_id` non-empty, `updated_at` formatted `%Y-%m-%d
/// %H:%M:%S%.3f` and NOT far-future (it's the ReplacingMergeTree version AND
/// the dict argMax key — a far-future value permanently wins, NAN-1137),
/// `deleted ∈ {0,1}`. Verified on a valid AND a type-corrupt record.
fn validate_ip_context_contract(normalize_vrl: &str) -> Result<(), String> {
    let valid = serde_json::json!({
        "network": "203.0.113.0/24", "source_id": "greynoise",
        "country": "US", "asn": "AS64496", "as_name": "Example", "deleted": 0
    });
    let out = run_normalize_for_contract(normalize_vrl, &valid)
        .map_err(|e| format!("normalize VRL failed on a valid ip_context record: {e}"))?;
    assert_ip_context_contract(&out, "valid record")?;

    // Type-corrupt: must sanitise (not propagate), not error.
    let mut corrupt = valid.clone();
    corrupt["updated_at"] = serde_json::json!("garbage-not-a-timestamp");
    corrupt["deleted"] = serde_json::json!("maybe");
    let out = run_normalize_for_contract(normalize_vrl, &corrupt).map_err(|e| {
        format!("normalize VRL errored on a type-corrupt ip_context record (must sanitise): {e}")
    })?;
    assert_ip_context_contract(&out, "type-corrupt record")?;

    // Missing/invalid network: the parser MUST reject (abort), not emit a row
    // with an empty or garbage CIDR (a bad CIDR poisons the IP_TRIE dict).
    for bad in [serde_json::json!({ "source_id": "x" }), serde_json::json!({ "network": "not-a-cidr", "source_id": "x" })] {
        match run_normalize_for_contract(normalize_vrl, &bad) {
            Err(_) => {} // aborted — correct
            Ok(out) => {
                let net = out.get("network").and_then(|v| v.as_str()).unwrap_or("");
                if !is_cidr(net) {
                    return Err(format!(
                        "ip_context normalize emitted network {net:?} (not a valid CIDR) instead \
                         of aborting — network must be a validated CIDR (NAN-1137)"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn assert_ip_context_contract(out: &serde_json::Value, ctx: &str) -> Result<(), String> {
    let obj = out
        .as_object()
        .ok_or_else(|| format!("{ctx}: normalize output is not a JSON object"))?;
    let network = obj.get("network").and_then(|v| v.as_str()).unwrap_or("");
    if !is_cidr(network) {
        return Err(format!("{ctx}: network {network:?} is not a valid CIDR"));
    }
    let source_id = obj.get("source_id").and_then(|v| v.as_str()).unwrap_or("");
    if source_id.is_empty() {
        return Err(format!("{ctx}: source_id is missing or empty (the feed discriminator)"));
    }
    let updated_at = obj.get("updated_at").and_then(|v| v.as_str()).unwrap_or("");
    if !last_synced_at_well_formed(updated_at) {
        return Err(format!(
            "{ctx}: updated_at must be formatted '%Y-%m-%d %H:%M:%S%.3f', got {updated_at:?}"
        ));
    }
    // Never far-future: updated_at is the version + dict argMax key (NAN-1137).
    if updated_at.as_bytes().first() == Some(&b'9') {
        return Err(format!(
            "{ctx}: updated_at {updated_at:?} is far-future — it would permanently win the \
             ReplacingMergeTree/dict argMax and bury real updates (NAN-1137)"
        ));
    }
    match obj.get("deleted") {
        Some(d) if d.as_u64() == Some(0) || d.as_u64() == Some(1) => {}
        other => return Err(format!("{ctx}: deleted must be 0 or 1, got {other:?}")),
    }
    Ok(())
}

/// Minimal CIDR check: `<ip>/<prefix>` with a parseable IP and numeric prefix.
fn is_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, prefix)) => {
            ip.parse::<std::net::IpAddr>().is_ok() && prefix.parse::<u8>().is_ok()
        }
        None => false,
    }
}

/// Fallback for kinds without a known target schema: the VRL must compile and
/// run on a representative record without erroring, and emit a JSON object.
fn validate_compiles_and_runs(normalize_vrl: &str) -> Result<(), String> {
    let sample = serde_json::json!({
        "external_id": "X", "id": "X", "network": "203.0.113.0/24", "source_id": "x"
    });
    let out = run_normalize_for_contract(normalize_vrl, &sample)
        .map_err(|e| format!("normalize VRL failed to compile/run: {e}"))?;
    if !out.is_object() {
        return Err("normalize VRL output is not a JSON object".to_string());
    }
    Ok(())
}

/// Assert one normalize output row meets the `user_registry` encoding contract.
fn assert_user_registry_contract(out: &serde_json::Value, ctx: &str) -> Result<(), String> {
    let obj = out
        .as_object()
        .ok_or_else(|| format!("{ctx}: normalize output is not a JSON object"))?;

    let ext = obj.get("external_id").and_then(|v| v.as_str()).unwrap_or("");
    if ext.is_empty() {
        return Err(format!("{ctx}: external_id is missing or empty"));
    }
    // version: integer-ms, non-zero (NAN-1123 — never 0, never a float/string).
    let version = obj
        .get("version")
        .ok_or_else(|| format!("{ctx}: version is missing"))?;
    let v = version
        .as_i64()
        .or_else(|| version.as_u64().map(|u| u as i64))
        .ok_or_else(|| {
            format!("{ctx}: version must be an integer-ms timestamp, got {version} (NAN-1123)")
        })?;
    if v <= 0 {
        return Err(format!("{ctx}: version must be a non-zero integer-ms timestamp, got {v}"));
    }
    // last_synced_at: "YYYY-MM-DD HH:MM:SS.mmm"
    let lsa = obj.get("last_synced_at").and_then(|v| v.as_str()).unwrap_or("");
    if !last_synced_at_well_formed(lsa) {
        return Err(format!(
            "{ctx}: last_synced_at must be formatted '%Y-%m-%d %H:%M:%S%.3f', got {lsa:?}"
        ));
    }
    // account_status enum.
    let status = obj.get("account_status").and_then(|v| v.as_str()).unwrap_or("");
    if !["active", "disabled", "deleted", "anonymized"].contains(&status) {
        return Err(format!(
            "{ctx}: account_status {status:?} not in {{active,disabled,deleted,anonymized}}"
        ));
    }
    // groups must be an Array (the CH column is Array(String)).
    if !obj.get("groups").map(|g| g.is_array()).unwrap_or(false) {
        return Err(format!("{ctx}: groups must be an array"));
    }
    Ok(())
}

fn last_synced_at_well_formed(s: &str) -> bool {
    // %Y-%m-%d %H:%M:%S%.3f — exact width, digits + separators.
    let b = s.as_bytes();
    if b.len() != 23 {
        return false;
    }
    let digit = |i: usize| b[i].is_ascii_digit();
    (0..4).all(digit)
        && b[4] == b'-'
        && digit(5) && digit(6)
        && b[7] == b'-'
        && digit(8) && digit(9)
        && b[10] == b' '
        && digit(11) && digit(12)
        && b[13] == b':'
        && digit(14) && digit(15)
        && b[16] == b':'
        && digit(17) && digit(18)
        && b[19] == b'.'
        && digit(20) && digit(21) && digit(22)
}

/// Compile + run a normalize VRL against one JSON record, returning the
/// transformed JSON (or an error string, which includes the `abort` path).
fn run_normalize_for_contract(
    vrl_code: &str,
    input: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use vrl::compiler::{compile, TargetValue};
    use vrl::diagnostic::Formatter;
    use vrl::value::{Secrets, Value};

    let fns = safe_vrl_functions();
    let result = compile(vrl_code, &fns).map_err(|diagnostics| {
        diagnostics
            .into_iter()
            .map(|d| Formatter::new(vrl_code, d).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })?;

    let mut target = TargetValue {
        value: json_to_vrl_value(input),
        metadata: Value::Object(BTreeMap::new()),
        secrets: Secrets::default(),
    };
    let timezone = vrl::compiler::TimeZone::Local;
    let mut runtime = vrl::compiler::runtime::Runtime::default();
    match runtime.resolve(&mut target, &result.program, &timezone) {
        Ok(_) => Ok(vrl_value_to_json(&target.value)),
        Err(e) => Err(format!("VRL runtime error/abort: {e}")),
    }
}

/// Build a `(VrlValidationResult, Vec<String>)` for the single-error
/// pre-compile failure case. Used by [`VrlValidator::validate_vrl_collect_errors`]
/// so each early-return branch is a one-liner.
fn single_error_result(
    error: String,
    warnings: Vec<String>,
) -> (VrlValidationResult, Vec<String>) {
    let errors = vec![error.clone()];
    (
        VrlValidationResult {
            valid: false,
            error: Some(error),
            warnings,
        },
        errors,
    )
}

/// Convert serde_json::Value to vrl::value::Value
fn json_to_vrl_value(json: &serde_json::Value) -> vrl::value::Value {
    match json {
        serde_json::Value::Null => vrl::value::Value::Null,
        serde_json::Value::Bool(b) => vrl::value::Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                vrl::value::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                vrl::value::Value::Float(
                    vrl::prelude::NotNan::new(f).unwrap_or(vrl::prelude::NotNan::new(0.0).unwrap()),
                )
            } else {
                vrl::value::Value::Null
            }
        }
        serde_json::Value::String(s) => vrl::value::Value::Bytes(s.clone().into()),
        serde_json::Value::Array(arr) => {
            vrl::value::Value::Array(arr.iter().map(json_to_vrl_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let mut map = BTreeMap::new();
            for (k, v) in obj {
                map.insert(vrl::value::KeyString::from(k.clone()), json_to_vrl_value(v));
            }
            vrl::value::Value::Object(map)
        }
    }
}

/// Convert vrl::value::Value to serde_json::Value
fn vrl_value_to_json(value: &vrl::value::Value) -> serde_json::Value {
    match value {
        vrl::value::Value::Null => serde_json::Value::Null,
        vrl::value::Value::Boolean(b) => serde_json::Value::Bool(*b),
        vrl::value::Value::Integer(i) => serde_json::json!(*i),
        vrl::value::Value::Float(f) => serde_json::json!(f.into_inner()),
        vrl::value::Value::Bytes(b) => {
            serde_json::Value::String(String::from_utf8_lossy(b).to_string())
        }
        vrl::value::Value::Regex(r) => serde_json::Value::String(r.to_string()),
        vrl::value::Value::Timestamp(ts) => serde_json::Value::String(ts.to_rfc3339()),
        vrl::value::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(vrl_value_to_json).collect())
        }
        vrl::value::Value::Object(obj) => {
            let mut map = serde_json::Map::new();
            for (k, v) in obj {
                map.insert(k.to_string(), vrl_value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

#[cfg(test)]
mod enrichment_contract_tests {
    use super::validate_enrichment_encoding_contract;

    // identity-kind shorthand for the existing cases.
    fn check(vrl: &str) -> Result<(), String> {
        validate_enrichment_encoding_contract("identity", vrl)
    }

    // A well-formed envelope (mirrors the shipped identity parsers): extracts
    // external_id from any common source key, stamps version/last_synced_at,
    // derives account_status, aborts on missing id.
    const GOOD: &str = r#"
external_id = to_string(.external_id) ?? to_string(.id) ?? to_string(.Worker_ID) ?? ""
if external_id == "" { abort }
version = to_int(.version) ?? 0
if version <= 0 { version = to_unix_timestamp(now(), unit: "milliseconds") }
last_synced_at = format_timestamp!(from_unix_timestamp!(version, unit: "milliseconds"), "%Y-%m-%d %H:%M:%S%.3f")
account_status = downcase(to_string(.account_status) ?? "active")
if !includes(["active","disabled","deleted","anonymized"], account_status) { account_status = "active" }
groups = .groups
if !is_array(groups) { groups = [] }
. = { "external_id": external_id, "version": version, "last_synced_at": last_synced_at, "account_status": account_status, "groups": groups }
"#;

    #[test]
    fn accepts_a_well_formed_envelope() {
        assert!(check(GOOD).is_ok(), "{:?}", check(GOOD));
    }

    #[test]
    fn rejects_zero_version() {
        // Emits version 0 (NAN-1123 violation: must be non-zero integer-ms).
        let vrl = r#"
external_id = to_string(.external_id) ?? to_string(.id) ?? ""
if external_id == "" { abort }
. = { "external_id": external_id, "version": 0, "last_synced_at": "2026-01-01 00:00:00.000", "account_status": "active", "groups": [] }
"#;
        assert!(check(vrl).unwrap_err().contains("version"));
    }

    #[test]
    fn rejects_bad_account_status() {
        let vrl = r#"
external_id = to_string(.external_id) ?? to_string(.id) ?? ""
if external_id == "" { abort }
. = { "external_id": external_id, "version": 1717000000000, "last_synced_at": "2026-01-01 00:00:00.000", "account_status": "BOGUS", "groups": [] }
"#;
        assert!(check(vrl).unwrap_err().contains("account_status"));
    }

    #[test]
    fn rejects_non_array_groups() {
        let vrl = r#"
external_id = to_string(.external_id) ?? to_string(.id) ?? ""
if external_id == "" { abort }
. = { "external_id": external_id, "version": 1717000000000, "last_synced_at": "2026-01-01 00:00:00.000", "account_status": "active", "groups": "nope" }
"#;
        assert!(check(vrl).unwrap_err().contains("groups"));
    }

    #[test]
    fn rejects_parser_that_does_not_require_external_id() {
        // No abort on missing id → emits an empty external_id row.
        let vrl = r#"
external_id = to_string(.external_id) ?? to_string(.id) ?? ""
. = { "external_id": external_id, "version": 1717000000000, "last_synced_at": "2026-01-01 00:00:00.000", "account_status": "active", "groups": [] }
"#;
        assert!(check(vrl).unwrap_err().contains("external_id"));
    }

    #[test]
    fn rejects_malformed_last_synced_at() {
        let vrl = r#"
external_id = to_string(.external_id) ?? to_string(.id) ?? ""
if external_id == "" { abort }
. = { "external_id": external_id, "version": 1717000000000, "last_synced_at": "2026/01/01T00:00:00", "account_status": "active", "groups": [] }
"#;
        assert!(check(vrl).unwrap_err().contains("last_synced_at"));
    }

    #[test]
    fn rejects_uncompilable_vrl() {
        assert!(check("this is not ( valid vrl").is_err());
    }

    // ---- ip_context (NAN-1137) contract -------------------------------------

    // A well-formed ip_context envelope: requires + validates the CIDR, carries
    // source_id, stamps a non-far-future updated_at, normalizes deleted to 0/1.
    const GOOD_IP: &str = r#"
network = to_string(.network) ?? ""
if !match(network, r'^[0-9a-fA-F:.]+/[0-9]+$') { abort }
source_id = to_string(.source_id) ?? ""
if source_id == "" { abort }
updated_at = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
deleted = to_int(.deleted) ?? 0
if deleted != 1 { deleted = 0 }
. = { "network": network, "source_id": source_id, "country": to_string(.country) ?? "", "asn": to_string(.asn) ?? "", "as_name": to_string(.as_name) ?? "", "updated_at": updated_at, "deleted": deleted }
"#;

    #[test]
    fn accepts_well_formed_ip_context() {
        let r = validate_enrichment_encoding_contract("ip_context", GOOD_IP);
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn rejects_ip_context_with_invalid_cidr() {
        // No CIDR guard → emits a bad network for the "not-a-cidr" sample.
        let vrl = r#"
network = to_string(.network) ?? ""
source_id = to_string(.source_id) ?? "x"
. = { "network": network, "source_id": source_id, "updated_at": format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f"), "deleted": 0 }
"#;
        assert!(validate_enrichment_encoding_contract("ip_context", vrl)
            .unwrap_err()
            .contains("CIDR"));
    }

    #[test]
    fn rejects_ip_context_far_future_updated_at() {
        let vrl = r#"
network = to_string(.network) ?? ""
if !match(network, r'^[0-9a-fA-F:.]+/[0-9]+$') { abort }
. = { "network": network, "source_id": to_string(.source_id) ?? "x", "updated_at": "9999-12-31 23:59:59.999", "deleted": 0 }
"#;
        assert!(validate_enrichment_encoding_contract("ip_context", vrl)
            .unwrap_err()
            .contains("far-future"));
    }

    #[test]
    fn unknown_kind_only_requires_compile_and_object() {
        // A future kind with no known schema: passes if it compiles + emits an
        // object, without the identity/ip_context field assertions.
        let vrl = r#". = { "anything": "goes", "x": to_int(.whatever) ?? 0 }"#;
        assert!(validate_enrichment_encoding_contract("some_future_kind", vrl).is_ok());
        // ...but a non-compiling one is still rejected.
        assert!(validate_enrichment_encoding_contract("some_future_kind", "((").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator() -> VrlValidator {
        VrlValidator::new()
    }

    #[tokio::test]
    async fn test_empty_vrl_rejected() {
        let v = validator();
        let result = v.validate_vrl("").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("empty"));
    }

    #[tokio::test]
    async fn test_whitespace_only_rejected() {
        let v = validator();
        let result = v.validate_vrl("   \n\t  ").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("empty"));
    }

    #[tokio::test]
    async fn test_triple_quotes_blocked() {
        let v = validator();
        let result = v.validate_vrl(".foo = '''bar'''").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Triple single quotes"));
    }

    #[tokio::test]
    async fn test_exec_function_blocked() {
        let v = validator();
        let result = v.validate_vrl(".foo = exec('ls')").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("exec"));
    }

    #[tokio::test]
    async fn test_exec_bang_function_blocked() {
        let v = validator();
        let result = v.validate_vrl(".foo = exec!('ls')").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("exec"));
    }

    #[tokio::test]
    async fn test_execution_field_name_allowed() {
        // Field names like "Execution" should NOT be blocked
        let v = validator();
        let result = v
            .validate_vrl(
                r#"
            .timestamp = now()
            .metadata = {}
            .metadata.test = "Execution field name test"
        "#,
            )
            .await
            .unwrap();
        assert!(
            result.valid,
            "Field name 'Execution' should be allowed: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_system_function_blocked() {
        let v = validator();
        let result = v.validate_vrl(".foo = system('ls')").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("system"));
    }

    #[tokio::test]
    async fn test_system_field_name_allowed() {
        // Field names like "system" or "System" should NOT be blocked
        let v = validator();
        let result = v
            .validate_vrl(
                r#"
            .timestamp = now()
            .metadata = {}
            .metadata.channel = "System"
        "#,
            )
            .await
            .unwrap();
        assert!(
            result.valid,
            "Field name 'system' should be allowed: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_shell_pattern_blocked() {
        let v = validator();
        let result = v.validate_vrl(".foo = shell('ls')").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("shell"));
    }

    #[tokio::test]
    async fn test_blocked_functions_rejected_at_validation() {
        let v = validator();
        let cases = [
            (r#".leak = get_env_var!("PATH")"#, "get_env_var"),
            (r#".host = get_hostname!()"#, "get_hostname"),
            (
                r#".r = http_request("https://attacker", "GET", {})"#,
                "http_request",
            ),
            (r#".r = dns_lookup("attacker.com")"#, "dns_lookup"),
            (r#".r = reverse_dns!("1.2.3.4")"#, "reverse_dns"),
        ];
        for (vrl, ident) in cases {
            let result = v.validate_vrl(vrl).await.unwrap();
            assert!(!result.valid, "{} must be blocked, not warned", ident);
            assert!(
                result.error.as_deref().unwrap_or("").contains(ident),
                "error should name {}: {:?}",
                ident,
                result.error
            );
        }
    }

    #[tokio::test]
    async fn test_blocked_functions_stripped_from_registry() {
        // Defense-in-depth: even if the source-pattern check is bypassed,
        // the function is stripped from the compiler's function set so it
        // cannot resolve.
        let fns = safe_vrl_functions();
        for blocked in BLOCKED_VRL_FUNCTIONS {
            assert!(
                !fns.iter().any(|f| f.identifier() == *blocked),
                "safe_vrl_functions() must not include {}",
                blocked
            );
        }
    }

    #[tokio::test]
    async fn test_get_env_var_blocked_via_test_endpoint() {
        // Verify via the public API that test_vrl rejects the canonical
        // exfiltration payload from the original NAN-662 finding.
        let v = VrlValidator::new();
        let result = v
            .test_vrl(r#".leak = get_env_var!("PATH")"#, "{}")
            .await
            .unwrap();
        assert!(!result.success);
    }

    #[tokio::test]
    async fn test_blocked_function_names_as_field_values_allowed() {
        // String values like .action = "http_request" appear in legitimate
        // parsers (see migrations/archive/029_seed_parser_library.sql). Field
        // names matching blocked identifiers should also pass: the pattern
        // check requires a trailing `(`, and the function-set strip only
        // affects function calls.
        let v = validator();
        let result = v
            .validate_vrl(
                r#"
            .timestamp = now()
            .action = "http_request"
            .metadata = {}
            .metadata.get_env_var = "literal field name"
            .source = "dns_lookup"
        "#,
            )
            .await
            .unwrap();
        assert!(
            result.valid,
            "Blocked identifiers as string values / field names should be allowed: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_legitimate_parser_still_validates() {
        // Negative case: a realistic parser snippet must continue to work
        // after the function set is restricted.
        let v = validator();
        let result = v
            .validate_vrl(
                r#"
            parsed = parse_json(.message) ?? {}
            .timestamp = now()
            .src_ip = parsed.source_ip
            .user = parsed.username
        "#,
            )
            .await
            .unwrap();
        assert!(
            result.valid,
            "Legitimate parser should validate: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_unbalanced_braces_rejected() {
        let v = validator();
        let result = v.validate_vrl(".foo = { bar").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Unbalanced braces"));
    }

    #[tokio::test]
    async fn test_unbalanced_parens_rejected() {
        let v = validator();
        let result = v.validate_vrl(".foo = parse_json(bar").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Unbalanced parentheses"));
    }

    #[tokio::test]
    async fn test_unbalanced_brackets_rejected() {
        let v = validator();
        let result = v.validate_vrl(".foo = [1, 2, 3").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Unbalanced square brackets"));
    }

    #[tokio::test]
    async fn test_excessive_nesting_rejected() {
        let v = validator();
        // Create deeply nested structure
        let deep_nesting = "{".repeat(25) + &"}".repeat(25);
        let vrl = format!(".foo = {}", deep_nesting);
        let result = v.validate_vrl(&vrl).await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("nesting depth"));
    }

    #[tokio::test]
    async fn test_toml_section_blocked() {
        let v = validator();
        let result = v.validate_vrl("[sources.evil]\n.foo = .bar").await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("TOML section"));
    }

    #[tokio::test]
    async fn test_valid_vrl_accepted() {
        let v = validator();
        let result = v
            .validate_vrl(".timestamp = now()\n.message = .message")
            .await
            .unwrap();
        assert!(
            result.valid,
            "Valid VRL should be accepted: {:?}",
            result.error
        );
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_complex_valid_vrl() {
        let v = validator();
        let vrl = r#"
            .message = encode_json(.)
            .udm = {}
            .udm.timestamp = now()
            .udm.src_ip = .source_ip
            .udm.dest_ip = .destination_ip
            .udm.user = .username
            .source_type = "test"
        "#;
        let result = v.validate_vrl(vrl).await.unwrap();
        assert!(
            result.valid,
            "Complex VRL should be valid: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_warnings_for_no_field_access() {
        let v = validator();
        let result = v.validate_vrl("timestamp = now()").await.unwrap();
        // Note: This may or may not be valid depending on VRL version
        // The warning check is still valid
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("doesn't appear to access any fields")));
    }

    #[tokio::test]
    async fn test_warnings_for_hex_escapes() {
        let v = validator();
        let result = v
            .validate_vrl(".foo = \"\\x41\"\n.timestamp = now()")
            .await
            .unwrap();
        assert!(result.warnings.iter().any(|w| w.contains("Hex escape")));
    }

    #[tokio::test]
    async fn test_size_limit() {
        let v = validator();
        let large_vrl = ".foo = \"".to_string() + &"a".repeat(MAX_VRL_SIZE + 1) + "\"";
        let result = v.validate_vrl(&large_vrl).await.unwrap();
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("exceeds maximum size"));
    }

    #[tokio::test]
    async fn test_vrl_invalid_json_input() {
        let v = validator();
        let result = v
            .test_vrl(".foo = .bar\n.timestamp = now()", "not valid json")
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Invalid JSON"));
    }

    #[tokio::test]
    async fn test_vrl_with_valid_input() {
        let v = validator();
        let result = v
            .test_vrl(
                ".processed = true\n.timestamp = now()",
                r#"{"message": "test"}"#,
            )
            .await
            .unwrap();
        assert!(
            result.success,
            "VRL execution should succeed: {:?}",
            result.error
        );
        assert!(result.output.is_some());
    }

    #[tokio::test]
    async fn test_native_vrl_compilation_catches_errors() {
        let v = validator();
        // Invalid VRL syntax that only the compiler can catch
        let result = v.validate_vrl(".foo = undefined_function()").await.unwrap();
        assert!(!result.valid, "Invalid function should be rejected");
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_e651_to_string_warning() {
        let v = validator();
        let vrl = r#"
            pair_str = to_string(pair) ?? ""
            .timestamp = now()
        "#;
        let result = v.validate_vrl(vrl).await.unwrap();
        // Note: This may fail compilation due to undefined 'pair' variable
        // The E651 check happens before compilation
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("E651") && w.contains("to_string")),
            "Should warn about E651 for to_string(): {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn test_e651_downcase_warning() {
        let v = validator();
        let vrl = r#"
            lower = downcase(value) ?? ""
            .timestamp = now()
        "#;
        let result = v.validate_vrl(vrl).await.unwrap();
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("E651") && w.contains("downcase")),
            "Should warn about E651 for downcase(): {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn test_no_e651_for_valid_coalescing() {
        let v = validator();
        // parse_json CAN fail, so ?? is valid here
        let vrl = r#"
            parsed = parse_json!(.message) ?? {}
            .timestamp = now()
        "#;
        let result = v.validate_vrl(vrl).await.unwrap();
        assert!(
            !result.warnings.iter().any(|w| w.contains("E651")),
            "Should NOT warn about E651 for parse_json(): {:?}",
            result.warnings
        );
    }

    // ----- NAN-874: parser extension chain tests -----

    #[tokio::test]
    async fn test_vrl_chain_single_element_matches_single() {
        let v = validator();
        let vrl = ".processed = true";
        let sample = r#"{"message": "x"}"#;

        let chain = v.test_vrl_chain(&[vrl], sample).await.unwrap();
        let single = v.test_vrl(vrl, sample).await.unwrap();

        assert!(chain.success, "chain error: {:?}", chain.error);
        assert!(single.success, "single error: {:?}", single.error);
        assert_eq!(chain.output, single.output);
    }

    #[tokio::test]
    async fn test_vrl_chain_parser_plus_extension() {
        let v = validator();
        let parser = ".udm.user = .raw_user";
        let extension = ".team = \"soc\"";
        let sample = r#"{"raw_user": "alice"}"#;

        let r = v
            .test_vrl_chain(&[parser, extension], sample)
            .await
            .unwrap();
        assert!(r.success, "chain failed: {:?}", r.error);
        let out = r.output.expect("output");
        assert_eq!(out.get("team").and_then(|v| v.as_str()), Some("soc"));
        // Extension sees the parser's output — udm.user was set by parser stage.
        assert_eq!(
            out.pointer("/udm/user").and_then(|v| v.as_str()),
            Some("alice")
        );
    }

    #[tokio::test]
    async fn test_vrl_chain_empty_stage_skipped() {
        let v = validator();
        // Mimics the stub case: no OOTB parser, just an extension.
        let r = v
            .test_vrl_chain(&["", ".team = \"soc\""], r#"{"raw": "x"}"#)
            .await
            .unwrap();
        assert!(r.success, "should succeed with empty first stage: {:?}", r.error);
        assert_eq!(
            r.output.unwrap().get("team").and_then(|v| v.as_str()),
            Some("soc")
        );
    }

    #[tokio::test]
    async fn test_vrl_chain_runtime_error_surfaces_stage_index() {
        let v = validator();
        // Stage 1 succeeds; stage 2 has a runtime error (abort).
        let parser = ".step1 = true";
        let extension = "abort";
        let r = v
            .test_vrl_chain(&[parser, extension], r#"{"x": 1}"#)
            .await
            .unwrap();
        assert!(!r.success);
        let err = r.error.expect("error string");
        // The validator may either flag this at validation time (stage 1, because
        // index in the filtered list) or at runtime — both forms of message
        // should make it clear which stage broke. Check that a stage index is
        // present and the message names "abort".
        assert!(err.contains("stage "), "should mention stage: {err}");
    }

    #[tokio::test]
    async fn test_vrl_chain_blocks_dangerous_function() {
        let v = validator();
        let r = v
            .test_vrl_chain(
                &[".x = 1", ".y = get_env_var!(\"NANOS_API_KEY\")"],
                r#"{"x": 1}"#,
            )
            .await
            .unwrap();
        assert!(!r.success, "dangerous function should be blocked");
        let err = r.error.unwrap();
        assert!(
            err.contains("get_env_var") || err.contains("not allowed") || err.contains("blocked"),
            "error should mention the blocked function: {err}"
        );
    }
}
