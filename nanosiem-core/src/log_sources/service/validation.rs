// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRL validation operations for log sources

use uuid::Uuid;

use super::helpers::truncate;
use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    LiveTestResult, ParserTestResult, VrlDiagnostic, VrlValidationResult,
};

/// Count top-level keys in a JSON object output. Returns 0 if `output` is None
/// or not a JSON object.
fn count_extracted_fields(output: &Option<serde_json::Value>) -> u32 {
    match output.as_ref().and_then(|v| v.as_object()) {
        Some(obj) => obj.len() as u32,
        None => 0,
    }
}

/// Try to extract a `line:col` position from the start of a VRL diagnostic
/// message. The Vector VRL `Formatter` produces multi-line output that begins
/// with `error[E###]: <message>` and includes a `┌─ <path>:<line>:<col>` arrow
/// line. Returns `(line, col)` if found, otherwise `(None, None)`.
fn extract_line_col(text: &str) -> (Option<u32>, Option<u32>) {
    // Look for the canonical `┌─ ...:LINE:COL` arrow line.
    for line in text.lines() {
        if let Some(idx) = line.find("┌─") {
            let rest = &line[idx + "┌─".len()..];
            // Format is roughly: " <path>:<line>:<col>"
            let trimmed = rest.trim();
            // Parse from the right: split off two ":<num>" suffixes
            let mut parts = trimmed.rsplitn(3, ':');
            let col = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            let line_num = parts.next().and_then(|s| s.trim().parse::<u32>().ok());
            if line_num.is_some() {
                return (line_num, col);
            }
        }
    }
    (None, None)
}

/// Try to extract a diagnostic code like `E203` or `W003` from the first
/// `error[E###]` / `warning[W###]` line.
fn extract_code(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.trim_start();
        for prefix in &["error[", "warning[", "note["] {
            if let Some(start) = lower.find(prefix) {
                let after = &lower[start + prefix.len()..];
                if let Some(end) = after.find(']') {
                    return Some(after[..end].to_string());
                }
            }
        }
    }
    None
}

/// Convert a free-form error string (often a multi-line VRL formatter dump)
/// into a structured diagnostic.
fn diagnostic_from_error(message: &str) -> VrlDiagnostic {
    let (line, col) = extract_line_col(message);
    VrlDiagnostic {
        severity: "error".to_string(),
        line,
        col,
        code: extract_code(message),
        message: message.to_string(),
        hint: None,
    }
}

/// Convert a warning string into a structured diagnostic. Strips a leading
/// "Warning: " prefix if present so the message doesn't double-up.
fn diagnostic_from_warning(message: &str) -> VrlDiagnostic {
    let stripped = message
        .strip_prefix("Warning: ")
        .or_else(|| message.strip_prefix("VRL warning: "))
        .unwrap_or(message)
        .to_string();
    let (line, col) = extract_line_col(&stripped);
    VrlDiagnostic {
        severity: "warn".to_string(),
        line,
        col,
        code: extract_code(&stripped),
        message: stripped,
        hint: None,
    }
}

impl LogSourceService {
    /// Validate VRL code without saving
    pub async fn validate_vrl(&self, vrl_code: &str) -> VrlValidationResult {
        match self.vrl_validator.validate_vrl(vrl_code).await {
            Ok(result) => {
                let mut errors = Vec::new();
                let mut diagnostics = Vec::new();
                if let Some(ref err) = result.error {
                    errors.push(err.clone());
                    diagnostics.push(diagnostic_from_error(err));
                }
                for warning in &result.warnings {
                    errors.push(format!("Warning: {}", warning));
                    diagnostics.push(diagnostic_from_warning(warning));
                }
                VrlValidationResult {
                    valid: result.valid,
                    errors,
                    diagnostics,
                }
            }
            Err(e) => {
                let msg = e.to_string();
                VrlValidationResult {
                    valid: false,
                    errors: vec![msg.clone()],
                    diagnostics: vec![diagnostic_from_error(&msg)],
                }
            }
        }
    }

    /// Test VRL against a sample log
    pub async fn test_vrl(&self, vrl_code: &str, sample_log: &str) -> ParserTestResult {
        self.test_vrl_chain(vrl_code, None, sample_log).await
    }

    /// Test a parser VRL plus an optional extension overlay (NAN-874) against a
    /// sample log. When `extension_vrl` is `None` or blank, this is identical
    /// to the single-stage `test_vrl`. When provided, the chain mirrors the
    /// production pipeline: parse → extension → (downstream).
    pub async fn test_vrl_chain(
        &self,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        sample_log: &str,
    ) -> ParserTestResult {
        let input_json = serde_json::json!({
            "message": sample_log
        });
        let input_str = serde_json::to_string(&input_json).unwrap_or_default();

        // Pick the right validator method to avoid the chain wrapper's empty-stage
        // bookkeeping when no extension is in play.
        let result = match extension_vrl {
            Some(ext) if !ext.trim().is_empty() => {
                self.vrl_validator
                    .test_vrl_chain(&[parser_vrl, ext], &input_str)
                    .await
            }
            _ => self.vrl_validator.test_vrl(parser_vrl, &input_str).await,
        };

        match result {
            Ok(result) => {
                let extracted_field_count = count_extracted_fields(&result.output);
                ParserTestResult {
                    input: truncate(sample_log, 200),
                    success: result.success,
                    output: result.output,
                    error: result.error,
                    extracted_field_count,
                }
            }
            Err(e) => ParserTestResult {
                input: truncate(sample_log, 200),
                success: false,
                output: None,
                error: Some(format!("VRL execution error: {}", e)),
                extracted_field_count: 0,
            },
        }
    }

    /// Test VRL against real events from ClickHouse, comparing current vs new parse.
    ///
    /// Fetches recent raw messages for the given source_type and runs BOTH the
    /// current (deployed) VRL and the new (edited) VRL against each event.
    /// Returns per-event comparison results so the user can see what changed.
    pub async fn test_vrl_live(
        &self,
        new_vrl: &str,
        current_vrl: Option<&str>,
        source_type: &str,
        limit: usize,
    ) -> Result<Vec<LiveTestResult>, LogSourceServiceError> {
        let ch_client = self.ch_client.as_ref().ok_or_else(|| {
            LogSourceServiceError::InvalidVrl(
                "ClickHouse not available — live testing requires ClickHouse".into(),
            )
        })?;

        let limit = limit.min(20);
        let safe_source_type = source_type.replace('\'', "''");
        let sql = format!(
            "SELECT message FROM {} WHERE source_type = '{}' AND message != '' ORDER BY timestamp DESC LIMIT {}",
            self.logs_table, safe_source_type, limit
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct MessageRow {
            message: String,
        }

        let rows: Vec<MessageRow> = ch_client.query(&sql).fetch_all().await.map_err(|e| {
            LogSourceServiceError::InvalidVrl(format!("Failed to fetch sample events: {}", e))
        })?;

        if rows.is_empty() {
            return Err(LogSourceServiceError::InvalidSourceType(format!(
                "No events found for source_type '{}'",
                source_type
            )));
        }

        let mut results = Vec::with_capacity(rows.len());
        for row in &rows {
            let new_result = self.test_vrl(new_vrl, &row.message).await;
            let current_result = match current_vrl {
                Some(vrl) if !vrl.is_empty() => Some(self.test_vrl(vrl, &row.message).await),
                _ => None,
            };

            results.push(LiveTestResult {
                input: row.message.clone(),
                new_parse: new_result,
                current_parse: current_result,
            });
        }

        Ok(results)
    }

    /// Validate a log source's VRL and update its validation status
    pub async fn validate_log_source(
        &self,
        id: Uuid,
    ) -> Result<VrlValidationResult, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;
        let result = self.validate_vrl(&log_source.parser_vrl).await;

        let error_msg = if result.valid {
            None
        } else {
            Some(result.errors.join("; "))
        };

        self.repository()
            .set_validation_status(id, result.valid, error_msg.as_deref())
            .await?;

        Ok(result)
    }
}
