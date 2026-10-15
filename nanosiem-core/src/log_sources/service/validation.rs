// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRL validation operations for log sources

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::helpers::truncate;
use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    LiveTestResult, LogSource, ParserTestResult, VrlDiagnostic, VrlValidationResult,
};

const OCSF_DEPLOY_MAX_SAMPLES: usize = 50;
const OCSF_DEPLOY_MAX_SAMPLE_BYTES: usize = 256 * 1024;
const OCSF_DEPLOY_MAX_TOTAL_SAMPLE_BYTES: usize = 2 * 1024 * 1024;

/// `test-live` is an interactive endpoint behind a 30-second upstream
/// deadline. A one-day window keeps the raw-message read on recent partitions
/// and matches the feature's purpose: testing against events arriving now.
const LIVE_SAMPLE_LOOKBACK_HOURS: u32 = 24;

/// Leave enough of the upstream request budget for VRL execution and response
/// serialization if ClickHouse is unhealthy or cannot prune the query.
const LIVE_SAMPLE_MAX_EXECUTION_TIME_SECS: u32 = 10;

/// Build the raw-sample SQL behind `POST /api/log-sources/test-live`.
///
/// NAN-2058: extracted as a pure function so the source-scope boundary on this
/// raw-log read is unit-testable. The rows this selects are returned VERBATIM to
/// the caller in `LiveTestResult.input`, so the deny-set predicate here is the
/// only thing standing between a `log_sources:view` caller and the raw contents
/// of a restricted feed (or the `audit` trail). An unrestricted caller appends
/// nothing and the SQL is byte-identical to the pre-scoping form.
fn build_live_sample_sql(
    logs_table: &str,
    source_type: &str,
    limit: usize,
    scope: &crate::auth::ScopeSet,
) -> String {
    let safe_source_type = crate::sql_hygiene::escape_sql_string(source_type);
    let scope_and =
        crate::search::service::source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|p| format!(" AND {p}"))
            .unwrap_or_default();
    format!(
        "SELECT message FROM {} WHERE source_type = '{}' AND timestamp >= now() - INTERVAL {} HOUR AND message != ''{} ORDER BY timestamp DESC LIMIT {}",
        logs_table, safe_source_type, LIVE_SAMPLE_LOOKBACK_HOURS, scope_and, limit
    )
}

/// Count top-level keys in a JSON object output. Returns 0 if `output` is None
/// or not a JSON object.
fn count_extracted_fields(output: &Option<serde_json::Value>) -> u32 {
    match output.as_ref().and_then(|v| v.as_object()) {
        Some(obj) => obj.len() as u32,
        None => 0,
    }
}

fn live_parser_result(
    sample_log: &str,
    result: crate::parsers::ParserTestResult,
) -> ParserTestResult {
    let extracted_field_count = count_extracted_fields(&result.output);
    ParserTestResult {
        input: truncate(sample_log, 200),
        success: result.success,
        output: result.output,
        error: result.error,
        extracted_field_count,
        schema_validation: None,
    }
}

/// Convert the VRL engine's result into the Log Sources response, applying the
/// OCSF contract only after VRL compiled and executed successfully.
pub(crate) fn parser_test_result(
    sample_log: &str,
    result: crate::parsers::ParserTestResult,
    validate_ocsf: bool,
) -> ParserTestResult {
    let extracted_field_count = count_extracted_fields(&result.output);
    let schema_validation = if validate_ocsf && result.success {
        result
            .output
            .as_ref()
            .map(crate::parsers::validate_ocsf_event)
    } else {
        None
    };
    let schema_error = schema_validation
        .as_ref()
        .filter(|validation| !validation.valid)
        .map(|validation| {
            validation
                .errors
                .iter()
                .take(5)
                .map(|error| format!("{}: {}", error.attribute_path, error.message))
                .collect::<Vec<_>>()
                .join("; ")
        });

    ParserTestResult {
        input: truncate(sample_log, 200),
        success: result.success && schema_error.is_none(),
        output: result.output,
        error: result
            .error
            .or_else(|| schema_error.map(|error| format!("OCSF validation failed: {error}"))),
        extracted_field_count,
        schema_validation,
    }
}

fn distinct_current_vrl<'a>(new_vrl: &str, current_vrl: Option<&'a str>) -> Option<&'a str> {
    current_vrl.filter(|vrl| !vrl.trim().is_empty() && *vrl != new_vrl)
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn ocsf_parser_sha256(log_source: &LogSource) -> String {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"nano.log-source.ocsf-parser-attestation.v1");
    hash_part(
        &mut digest,
        crate::parsers::OCSF_VALIDATION_VERSION.as_bytes(),
    );
    hash_part(&mut digest, log_source.parser_vrl.as_bytes());
    hash_part(&mut digest, &[u8::from(log_source.extension_enabled)]);
    if log_source.extension_enabled {
        hash_part(
            &mut digest,
            log_source.extension_vrl.as_deref().unwrap_or("").as_bytes(),
        );
    }
    hex::encode(digest.finalize())
}

fn ocsf_samples_sha256(samples: &[String]) -> String {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"nano.log-source.ocsf-samples.v1");
    for sample in samples {
        hash_part(&mut digest, sample.as_bytes());
    }
    hex::encode(digest.finalize())
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
pub(crate) fn diagnostic_from_error(message: &str) -> VrlDiagnostic {
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
pub(crate) fn diagnostic_from_warning(message: &str) -> VrlDiagnostic {
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
    /// Persist a receipt for the current stored parser after the interactive
    /// test endpoint successfully validates one raw sample. If the caller was
    /// testing an unsaved editor buffer, return `false` and leave the stored
    /// generation untouched.
    pub async fn record_ocsf_test_attestation(
        &self,
        id: Uuid,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        sample: &str,
    ) -> Result<bool, LogSourceServiceError> {
        let profile = crate::schema::active_profile_from_env()
            .map_err(LogSourceServiceError::OcsfValidationFailed)?;
        if profile.id() != crate::schema::SchemaId::Ocsf {
            return Ok(false);
        }
        let log_source = self.repository().find_by_id(id).await?;
        if log_source.kind != "log" || log_source.parser_vrl != parser_vrl {
            return Ok(false);
        }
        let stored_extension = log_source
            .extension_enabled
            .then_some(log_source.extension_vrl.as_deref())
            .flatten()
            .filter(|value| !value.trim().is_empty());
        let tested_extension = extension_vrl.filter(|value| !value.trim().is_empty());
        if stored_extension != tested_extension {
            return Ok(false);
        }
        if sample.len() > OCSF_DEPLOY_MAX_SAMPLE_BYTES {
            return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                "a sample exceeds the {} byte limit",
                OCSF_DEPLOY_MAX_SAMPLE_BYTES
            )));
        }
        self.repository()
            .set_ocsf_validation_attestation(
                id,
                crate::parsers::OCSF_VALIDATION_VERSION,
                &ocsf_parser_sha256(&log_source),
                &ocsf_samples_sha256(&[sample.to_string()]),
                1,
            )
            .await?;
        Ok(true)
    }

    /// The representative raw events a first-party library parser shipped with.
    ///
    /// NAN-2361: the OCSF deploy gate is a real bound — an unvalidated parser must
    /// not reach the lake — but it was rejecting library parsers that already
    /// carry their own evidence. 50 of the 64 parsers on the `ocsf-1.9` branch
    /// ship a `samples:` block, and those are the same events
    /// `scripts/validate-ocsf.sh` certifies upstream. This is NOT a bypass: the
    /// caller still executes the parser over each sample and validates the emitted
    /// event against the OCSF contract before any receipt is written.
    ///
    /// The parser is matched by EXACT `parser_vrl`, which is copied verbatim at
    /// import. That is the property we want: edit the VRL and the match stops
    /// resolving, so a hand-modified parser is once again required to supply its
    /// own sample rather than inheriting the library's.
    ///
    /// Best-effort by design — any lookup or parse failure returns empty and the
    /// caller falls through to asking the operator for a sample.
    async fn library_parser_samples(&self, log_source: &LogSource) -> Vec<String> {
        if log_source.parser_vrl.trim().is_empty() {
            return Vec::new();
        }
        let rows: Vec<(String,)> = match sqlx::query_as(
            "SELECT raw_content FROM repository_parsers \
             WHERE parser_vrl = $1 ORDER BY updated_at DESC LIMIT 4",
        )
        .bind(&log_source.parser_vrl)
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(
                    log_source_id = %log_source.id,
                    %error,
                    "could not look up bundled parser samples"
                );
                return Vec::new();
            }
        };
        for (raw_content,) in rows {
            let Ok(parsed) = crate::parser_repository::parse_parser_yaml(&raw_content) else {
                continue;
            };
            let samples: Vec<String> = parsed
                .samples
                .unwrap_or_default()
                .into_iter()
                .map(|sample| sample.raw)
                .filter(|raw| !raw.trim().is_empty() && raw.len() <= OCSF_DEPLOY_MAX_SAMPLE_BYTES)
                .take(OCSF_DEPLOY_MAX_SAMPLES)
                .collect();
            if !samples.is_empty() {
                tracing::info!(
                    log_source_id = %log_source.id,
                    samples = samples.len(),
                    "validating the OCSF deploy receipt against the parser's bundled samples"
                );
                return samples;
            }
        }
        Vec::new()
    }

    /// Enforce the deploy-bound OCSF receipt. An unchanged parser can reuse a
    /// prior receipt; a new parser generation must supply representative raw
    /// samples and pass VRL execution followed by OCSF validation.
    pub(super) async fn enforce_ocsf_deploy_attestation(
        &self,
        log_source: &LogSource,
        samples: &[String],
    ) -> Result<(), LogSourceServiceError> {
        let profile = crate::schema::active_profile_from_env()
            .map_err(LogSourceServiceError::OcsfValidationFailed)?;
        if profile.id() != crate::schema::SchemaId::Ocsf || log_source.kind != "log" {
            return Ok(());
        }

        let parser_sha256 = ocsf_parser_sha256(log_source);
        // Samples the caller supplied win. With none, an unchanged parser reuses
        // its receipt, and a library parser falls back to the samples it shipped
        // with (see `library_parser_samples`). Only a parser with neither is
        // asked for a raw event.
        let bundled: Vec<String>;
        let samples: &[String] = if samples.is_empty() {
            let current = self
                .repository()
                .has_ocsf_validation_attestation(
                    log_source.id,
                    crate::parsers::OCSF_VALIDATION_VERSION,
                    &parser_sha256,
                )
                .await?;
            if current {
                return Ok(());
            }
            bundled = self.library_parser_samples(log_source).await;
            if bundled.is_empty() {
                return Err(LogSourceServiceError::OcsfValidationFailed(
                    "this parser generation has no OCSF sample-validation receipt; supply at least one representative raw event"
                        .to_string(),
                ));
            }
            &bundled
        } else {
            samples
        };

        if samples.len() > OCSF_DEPLOY_MAX_SAMPLES {
            return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                "at most {OCSF_DEPLOY_MAX_SAMPLES} samples may be validated per deployment"
            )));
        }
        let total_bytes = samples.iter().try_fold(0_usize, |total, sample| {
            if sample.len() > OCSF_DEPLOY_MAX_SAMPLE_BYTES {
                return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                    "a sample exceeds the {} byte limit",
                    OCSF_DEPLOY_MAX_SAMPLE_BYTES
                )));
            }
            total.checked_add(sample.len()).ok_or_else(|| {
                LogSourceServiceError::OcsfValidationFailed(
                    "sample payload size overflow".to_string(),
                )
            })
        })?;
        if total_bytes > OCSF_DEPLOY_MAX_TOTAL_SAMPLE_BYTES {
            return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                "sample payload exceeds the {} byte deployment limit",
                OCSF_DEPLOY_MAX_TOTAL_SAMPLE_BYTES
            )));
        }

        let extension_vrl = log_source
            .extension_enabled
            .then_some(log_source.extension_vrl.as_deref())
            .flatten();
        // NAN-2385: one compile of the chain for the whole sample set. Looping
        // `test_vrl_chain` per sample compiled the parser once per sample (and
        // twice at that), which for a 1k-line OCSF parser pushed a deploy past
        // the UI's request timeout.
        for (index, result) in self
            .test_vrl_chain_batch(&log_source.parser_vrl, extension_vrl, samples, true)
            .await
            .into_iter()
            .enumerate()
        {
            if !result.success {
                return Err(LogSourceServiceError::OcsfValidationFailed(format!(
                    "sample {} failed: {}",
                    index + 1,
                    result
                        .error
                        .as_deref()
                        .unwrap_or("unknown validation error")
                )));
            }
        }

        self.repository()
            .set_ocsf_validation_attestation(
                log_source.id,
                crate::parsers::OCSF_VALIDATION_VERSION,
                &parser_sha256,
                &ocsf_samples_sha256(samples),
                samples.len() as i32,
            )
            .await?;
        Ok(())
    }

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
        self.test_vrl_chain(vrl_code, None, sample_log, false).await
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
        validate_ocsf: bool,
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
            Ok(result) => parser_test_result(sample_log, result, validate_ocsf),
            Err(e) => ParserTestResult {
                input: truncate(sample_log, 200),
                success: false,
                output: None,
                error: Some(format!("VRL execution error: {}", e)),
                extracted_field_count: 0,
                schema_validation: None,
            },
        }
    }

    /// Run the parser (+ optional extension) chain over many raw samples with a
    /// single compile (NAN-2385). Results are index-aligned with `sample_logs`.
    pub async fn test_vrl_chain_batch(
        &self,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        sample_logs: &[String],
        validate_ocsf: bool,
    ) -> Vec<ParserTestResult> {
        let inputs: Vec<String> = sample_logs
            .iter()
            .map(|sample_log| {
                serde_json::to_string(&serde_json::json!({ "message": sample_log }))
                    .unwrap_or_default()
            })
            .collect();
        let stages: Vec<&str> = match extension_vrl {
            Some(ext) if !ext.trim().is_empty() => vec![parser_vrl, ext],
            _ => vec![parser_vrl],
        };
        match self.vrl_validator.test_vrl_chain_batch(&stages, &inputs).await {
            Ok(results) => sample_logs
                .iter()
                .zip(results)
                .map(|(sample_log, result)| parser_test_result(sample_log, result, validate_ocsf))
                .collect(),
            Err(e) => sample_logs
                .iter()
                .map(|sample_log| ParserTestResult {
                    input: truncate(sample_log, 200),
                    success: false,
                    output: None,
                    error: Some(format!("VRL execution error: {}", e)),
                    extracted_field_count: 0,
                    schema_validation: None,
                })
                .collect(),
        }
    }

    /// Test VRL against real events from ClickHouse, comparing current vs new parse.
    ///
    /// Fetches recent raw messages for the given source_type and runs BOTH the
    /// current (deployed) VRL and the new (edited) VRL against each event.
    /// Returns per-event comparison results so the user can see what changed.
    ///
    /// NAN-2058: `scope` is the CALLER's effective source deny-set. The returned
    /// `LiveTestResult.input` is the UNREDACTED raw event, so this is a raw-log
    /// read surface and carries the same per-source boundary as canonical
    /// search. A denied `source_type` matches no rows and takes the existing
    /// "no events found" path — byte-identical to an allowed source with no
    /// data, so this never becomes an existence oracle for restricted feeds.
    /// Pass [`ScopeSet::unrestricted`](crate::auth::ScopeSet::unrestricted) for
    /// SYSTEM callers.
    pub async fn test_vrl_live(
        &self,
        new_vrl: &str,
        current_vrl: Option<&str>,
        source_type: &str,
        limit: usize,
        scope: &crate::auth::ScopeSet,
    ) -> Result<Vec<LiveTestResult>, LogSourceServiceError> {
        let ch_client = self.ch_client.as_ref().ok_or_else(|| {
            LogSourceServiceError::InvalidVrl(
                "ClickHouse not available — live testing requires ClickHouse".into(),
            )
        })?;

        let limit = limit.min(20);
        let sql = build_live_sample_sql(self.logs_table, source_type, limit, scope);

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct MessageRow {
            message: String,
        }

        let rows: Vec<MessageRow> = ch_client
            .query(&sql)
            .with_option(
                "max_execution_time",
                LIVE_SAMPLE_MAX_EXECUTION_TIME_SECS.to_string(),
            )
            .fetch_all()
            .await
            .map_err(|e| {
                LogSourceServiceError::InvalidVrl(format!(
                    "Failed to fetch recent sample events: {}",
                    e
                ))
            })?;

        if rows.is_empty() {
            return Err(LogSourceServiceError::InvalidSourceType(format!(
                "No events found for source_type '{}' in the last {} hours",
                source_type, LIVE_SAMPLE_LOOKBACK_HOURS
            )));
        }

        let sample_inputs = rows
            .iter()
            .map(|row| {
                serde_json::to_string(&serde_json::json!({ "message": row.message }))
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let new_parses = self
            .vrl_validator
            .test_vrl_batch(new_vrl, &sample_inputs)
            .await
            .map_err(|e| {
                LogSourceServiceError::InvalidVrl(format!("VRL execution error: {}", e))
            })?;

        // The editor sends the deployed parser even when it is byte-identical
        // to the edited parser. Avoid compiling and running the same program
        // twice; `None` also tells the UI there is no meaningful comparison.
        let current_parses = match distinct_current_vrl(new_vrl, current_vrl) {
            Some(vrl) => Some(
                self.vrl_validator
                    .test_vrl_batch(vrl, &sample_inputs)
                    .await
                    .map_err(|e| {
                        LogSourceServiceError::InvalidVrl(format!("VRL execution error: {}", e))
                    })?,
            ),
            _ => None,
        };

        let mut results = Vec::with_capacity(rows.len());
        for (index, (row, new_parse)) in rows.iter().zip(new_parses).enumerate() {
            let current_parse = current_parses
                .as_ref()
                .and_then(|parses| parses.get(index))
                .cloned()
                .map(|result| live_parser_result(&row.message, result));
            results.push(LiveTestResult {
                input: row.message.clone(),
                new_parse: live_parser_result(&row.message, new_parse),
                current_parse,
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

#[cfg(test)]
mod tests {
    use super::{
        build_live_sample_sql, distinct_current_vrl, ocsf_parser_sha256, ocsf_samples_sha256,
        parser_test_result,
    };
    use crate::auth::ScopeSet;
    use std::collections::BTreeSet;

    fn deny(items: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(items.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>())
    }

    #[test]
    fn unrestricted_caller_gets_bounded_recent_query() {
        let sql = build_live_sample_sql(
            "nanosiem.logs",
            "windows_sysmon",
            10,
            &ScopeSet::unrestricted(),
        );
        assert_eq!(
            sql,
            "SELECT message FROM nanosiem.logs WHERE source_type = 'windows_sysmon' \
             AND timestamp >= now() - INTERVAL 24 HOUR AND message != '' \
             ORDER BY timestamp DESC LIMIT 10"
        );
    }

    #[test]
    fn live_sample_query_always_has_a_timestamp_bound() {
        let sql = build_live_sample_sql("nanosiem.logs", "windows_sysmon", 10, &deny(&["audit"]));
        let where_at = sql.find(" WHERE ").expect("WHERE clause present");
        assert_eq!(sql.matches(" WHERE ").count(), 1, "got: {sql}");
        assert!(
            sql[where_at..].contains("timestamp >= now() - INTERVAL 24 HOUR"),
            "got: {sql}"
        );
    }

    #[test]
    fn denied_source_cannot_return_raw_events() {
        // The finding's exact repro: a `log_sources:view` key asked for the
        // `audit` feed and got raw audit records back. The predicate has to make
        // that request match zero rows — which the handler then reports as the
        // ordinary "no events found for this source" error, indistinguishable
        // from an allowed-but-idle source (no existence oracle).
        let sql = build_live_sample_sql("nanosiem.logs", "audit", 10, &deny(&["audit"]));
        assert!(sql.contains("lower(source_type) != 'audit'"), "got: {sql}");
        // The requested source is still bound literally — the deny predicate is
        // ANDed on top rather than replacing the caller's filter.
        assert!(sql.contains("source_type = 'audit'"), "got: {sql}");
    }

    #[test]
    fn scope_predicate_precedes_order_and_limit() {
        // A predicate appended AFTER `ORDER BY ... LIMIT` would be a syntax
        // error; one appended after `LIMIT` silently truncated. Pin the order.
        let sql = build_live_sample_sql(
            "nanosiem.logs",
            "windows_sysmon",
            5,
            &deny(&["audit", "insider_threat"]),
        );
        let scope_at = sql.find("NOT IN").expect("scope predicate present");
        let order_at = sql.find("ORDER BY").expect("order clause present");
        assert!(scope_at < order_at, "got: {sql}");
        assert!(sql.ends_with("LIMIT 5"), "got: {sql}");
    }

    #[test]
    fn source_type_stays_escaped_under_scoping() {
        // The scope work must not disturb the existing quote-breakout defense.
        let sql = build_live_sample_sql("nanosiem.logs", "a'b", 1, &deny(&["audit"]));
        assert!(!sql.contains("'a'b'"), "got: {sql}");
    }

    #[test]
    fn identical_or_blank_current_vrl_is_not_retested() {
        assert_eq!(distinct_current_vrl(".ok = true", None), None);
        assert_eq!(distinct_current_vrl(".ok = true", Some("  \n")), None);
        assert_eq!(distinct_current_vrl(".ok = true", Some(".ok = true")), None);
        assert_eq!(
            distinct_current_vrl(".ok = true", Some(".ok = false")),
            Some(".ok = false")
        );
    }

    fn parser_result(
        success: bool,
        output: Option<serde_json::Value>,
        error: Option<&str>,
    ) -> crate::parsers::ParserTestResult {
        crate::parsers::ParserTestResult {
            success,
            input: r#"{"message":"sample"}"#.to_string(),
            output,
            error: error.map(str::to_string),
            duration_ms: 1,
        }
    }

    #[test]
    fn ocsf_validation_does_not_run_after_vrl_failure() {
        let result = parser_test_result(
            "sample",
            parser_result(false, None, Some("VRL compilation failed")),
            true,
        );

        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("VRL compilation failed"));
        assert!(result.schema_validation.is_none());
    }

    #[test]
    fn invalid_ocsf_output_fails_the_sample_with_structured_paths() {
        let result = parser_test_result(
            "sample",
            parser_result(true, Some(serde_json::json!({"class_uid": 4002})), None),
            true,
        );

        assert!(!result.success);
        let validation = result.schema_validation.expect("OCSF result");
        assert!(!validation.valid);
        assert!(validation
            .errors
            .iter()
            .any(|diagnostic| diagnostic.attribute_path == "metadata"));
        assert!(result.error.as_deref().is_some_and(|error| {
            error.starts_with("OCSF validation failed:") && error.contains("metadata")
        }));
    }

    #[test]
    fn valid_ocsf_output_passes_after_vrl_success() {
        let event = serde_json::json!({
            "activity_id": 3,
            "category_uid": 4,
            "class_uid": 4002,
            "type_uid": 400203,
            "severity_id": 1,
            "time": 1786406400000_i64,
            "metadata": {
                "product": {"name": "Nano", "vendor_name": "Nanos"},
                "version": "1.9.0"
            },
            "http_request": {
                "http_method": "GET",
                "url": {"path": "/"}
            }
        });
        let result = parser_test_result("sample", parser_result(true, Some(event), None), true);

        assert!(result.success, "{:?}", result.error);
        assert!(result
            .schema_validation
            .is_some_and(|validation| validation.valid));
    }

    #[test]
    fn sample_receipt_is_framed_and_order_sensitive() {
        assert_ne!(
            ocsf_samples_sha256(&["ab".to_string(), "c".to_string()]),
            ocsf_samples_sha256(&["a".to_string(), "bc".to_string()])
        );
        assert_ne!(
            ocsf_samples_sha256(&["first".to_string(), "second".to_string()]),
            ocsf_samples_sha256(&["second".to_string(), "first".to_string()])
        );
    }

    #[test]
    fn parser_receipt_changes_when_enabled_extension_changes() {
        let base = crate::log_sources::types::LogSource {
            id: uuid::Uuid::nil(),
            name: "test".to_string(),
            description: None,
            namespace: "default".to_string(),
            timezone: "UTC".to_string(),
            source_type: "routed".to_string(),
            dispatch_source_config_id: None,
            dispatch_source_config_type: None,
            parser_vrl: ".class_uid = 4002".to_string(),
            output_fields: None,
            extension_vrl: Some(".metadata.uid = \"one\"".to_string()),
            extension_enabled: true,
            category: None,
            vendor: None,
            product: None,
            icon: None,
            color: None,
            match_field: None,
            match_pattern: None,
            match_values: None,
            validated: false,
            validation_error: None,
            deployed: false,
            deployed_at: None,
            enabled: false,
            lifecycle_status: "draft".to_string(),
            stale_alert_enabled: false,
            stale_threshold_minutes: 60,
            sampling_ratio: None,
            sampling_exclude_condition: None,
            kind: "log".to_string(),
            enrich_kind: None,
            enrich_source: None,
            target_table: None,
            normalize_vrl: None,
            source_parser_repository_id: None,
            source_parser_path: None,
            source_parser_linked: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let first = ocsf_parser_sha256(&base);
        let mut changed = base.clone();
        changed.extension_vrl = Some(".metadata.uid = \"two\"".to_string());
        assert_ne!(first, ocsf_parser_sha256(&changed));
        changed.extension_enabled = false;
        let disabled = ocsf_parser_sha256(&changed);
        changed.extension_vrl = Some("ignored while disabled".to_string());
        assert_eq!(disabled, ocsf_parser_sha256(&changed));
    }
}
