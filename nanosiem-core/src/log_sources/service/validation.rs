// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRL validation operations for log sources

use uuid::Uuid;

use super::helpers::truncate;
use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    LiveTestResult, ParserTestResult, VrlDiagnostic, VrlValidationResult,
};
use crate::parsers::VrlValidatorError;

/// A live test's execution error: busy workers stay distinguishable (429).
fn live_test_error(error: VrlValidatorError) -> LogSourceServiceError {
    match error {
        VrlValidatorError::Busy(message) => LogSourceServiceError::ParserTestBusy(message),
        other => LogSourceServiceError::InvalidVrl(format!("VRL execution error: {}", other)),
    }
}

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
///
/// NAN-5347: profile-aware. `logs_table` is the active profile's events table
/// ([`live_sample_table`]). UDM stays byte-identical. On OCSF two things
/// differ:
/// - the sample is the ORIGINAL event: `raw_data` when set, else `message`.
///   OCSF producers keep the original in `raw_data` and often leave `message`
///   empty or set it to a summary, so reading `message` alone reported "no
///   events" or re-ran a parser against a summary. The expression is aliased
///   `sample`, never `message`: a ClickHouse alias shadows the same-named
///   column everywhere in the statement.
/// - `source_type` is not lowercased at ingest (direct writers can send mixed
///   case, NAN-1384), so it compares `lower(source_type)` against the lowered
///   key, exactly as search does.
fn build_live_sample_sql(
    schema: crate::schema::SchemaId,
    logs_table: &str,
    source_type: &str,
    limit: usize,
    scope: &crate::auth::ScopeSet,
) -> String {
    let ocsf = schema == crate::schema::SchemaId::Ocsf;
    let (projection, source_filter, present) = if ocsf {
        (
            OCSF_SAMPLE_PROJECTION,
            format!(
                "lower(source_type) = '{}'",
                crate::sql_hygiene::escape_sql_string(&source_type.to_lowercase())
            ),
            "(raw_data != '' OR message != '')",
        )
    } else {
        (
            "message",
            format!(
                "source_type = '{}'",
                crate::sql_hygiene::escape_sql_string(source_type)
            ),
            "message != ''",
        )
    };
    let scope_and =
        crate::search::service::source_scope_sql_predicate("source_type", scope.deny_set())
            .map(|p| format!(" AND {p}"))
            .unwrap_or_default();
    format!(
        "SELECT {} FROM {} WHERE {} AND timestamp >= now() - INTERVAL {} HOUR AND {}{} ORDER BY timestamp DESC LIMIT {}",
        projection, logs_table, source_filter, LIVE_SAMPLE_LOOKBACK_HOURS, present, scope_and, limit
    )
}

/// The OCSF sample: the original event (`raw_data`) when the producer kept
/// it, else `message`.
const OCSF_SAMPLE_PROJECTION: &str = "if(raw_data != '', raw_data, message) AS sample";

/// The events table the live sample read targets: the profile's store
/// (`logs` / `ocsf_logs`), routed through the `_distributed` wrapper on a
/// cluster so every shard's recent events are candidates (NAN-5347).
fn live_sample_table(schema: crate::schema::SchemaId, tables: &crate::db::TableNames) -> String {
    tables.read_bare(crate::schema::logs_table_for(schema))
}

/// Count top-level keys in a JSON object output. Returns 0 if `output` is None
/// or not a JSON object.
fn count_extracted_fields(output: &Option<serde_json::Value>) -> u32 {
    match output.as_ref().and_then(|v| v.as_object()) {
        Some(obj) => obj.len() as u32,
        None => 0,
    }
}

pub(super) fn live_parser_result(
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

fn distinct_current_vrl<'a>(new_vrl: &str, current_vrl: Option<&'a str>) -> Option<&'a str> {
    current_vrl.filter(|vrl| !vrl.trim().is_empty() && *vrl != new_vrl)
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

/// The checks before any compile: Vector env-interpolation syntax is refused
/// like a save refuses it (NAN-4953), and validation sees the text the
/// renderer writes (NAN-5057: a lone `\r` becomes a line break there, ending a
/// VRL comment early). `Err` is the refusal, already a result.
fn prepare_for_validation(vrl_code: &str) -> Result<String, VrlValidationResult> {
    if let Err(msg) = crate::vector_env::reject_vrl_interpolation("parser_vrl", vrl_code) {
        return Err(VrlValidationResult {
            valid: false,
            errors: vec![msg.clone()],
            diagnostics: vec![diagnostic_from_error(&msg)],
        });
    }
    Ok(crate::parsers::vrl_safety::as_rendered(vrl_code).into_owned())
}

/// The endpoint's shape for a validator verdict: the error, then every
/// warning as `Warning: ...`, each with a diagnostic.
fn validation_result(
    result: Result<crate::parsers::VrlValidationResult, VrlValidatorError>,
) -> VrlValidationResult {
    match result {
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

impl LogSourceService {
    /// Validate VRL code without saving
    pub async fn validate_vrl(&self, vrl_code: &str) -> VrlValidationResult {
        let rendered = match prepare_for_validation(vrl_code) {
            Ok(rendered) => rendered,
            Err(refused) => return refused,
        };
        validation_result(self.vrl_validator.validate_vrl(&rendered).await)
    }

    /// [`Self::validate_vrl`] for `POST /api/log-sources/validate-vrl`
    /// (NAN-5400): the same result, but the tenant program compiles only in
    /// the bounded parser-test worker, never in this process. `Err` only when
    /// no worker is free ([`LogSourceServiceError::ParserTestBusy`], a 429).
    pub async fn validate_vrl_isolated(
        &self,
        vrl_code: &str,
    ) -> Result<VrlValidationResult, LogSourceServiceError> {
        let rendered = match prepare_for_validation(vrl_code) {
            Ok(rendered) => rendered,
            Err(refused) => return Ok(refused),
        };
        match self.vrl_validator.validate_vrl_isolated(&rendered).await {
            Err(VrlValidatorError::Busy(message)) => Err(LogSourceServiceError::ParserTestBusy(message)),
            other => Ok(validation_result(other)),
        }
    }

    /// Test VRL against a sample log. `Err` only when every parser-test
    /// worker is busy ([`LogSourceServiceError::ParserTestBusy`], a 429).
    pub async fn test_vrl(
        &self,
        vrl_code: &str,
        sample_log: &str,
    ) -> Result<ParserTestResult, LogSourceServiceError> {
        self.test_vrl_chain(vrl_code, None, sample_log).await
    }

    /// Test a parser VRL plus an optional extension overlay (NAN-874) against a
    /// sample log. When `extension_vrl` is `None` or blank, this is identical
    /// to the single-stage `test_vrl`. When provided, the chain mirrors the
    /// production pipeline: parse → extension → (downstream). `Err` only when
    /// every parser-test worker is busy (NAN-5234).
    pub async fn test_vrl_chain(
        &self,
        parser_vrl: &str,
        extension_vrl: Option<&str>,
        sample_log: &str,
    ) -> Result<ParserTestResult, LogSourceServiceError> {
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

        Ok(match result {
            Ok(result) => {
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
            Err(VrlValidatorError::Busy(message)) => {
                return Err(LogSourceServiceError::ParserTestBusy(message))
            }
            Err(e) => ParserTestResult {
                input: truncate(sample_log, 200),
                success: false,
                output: None,
                error: Some(format!("VRL execution error: {}", e)),
                extracted_field_count: 0,
                schema_validation: None,
            },
        })
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
        let rows = self
            .fetch_recent_messages(source_type, limit.min(20), scope)
            .await?;

        let sample_inputs = rows
            .iter()
            .map(|row| {
                serde_json::to_string(&serde_json::json!({ "message": row }))
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let new_parses = self
            .vrl_validator
            .test_vrl_batch(new_vrl, &sample_inputs)
            .await
            .map_err(live_test_error)?;

        // The editor sends the deployed parser even when it is byte-identical
        // to the edited parser. Avoid compiling and running the same program
        // twice; `None` also tells the UI there is no meaningful comparison.
        let current_parses = match distinct_current_vrl(new_vrl, current_vrl) {
            Some(vrl) => Some(
                self.vrl_validator
                    .test_vrl_batch(vrl, &sample_inputs)
                    .await
                    .map_err(live_test_error)?,
            ),
            _ => None,
        };

        let mut results = Vec::with_capacity(rows.len());
        for (index, (row, new_parse)) in rows.iter().zip(new_parses).enumerate() {
            let current_parse = current_parses
                .as_ref()
                .and_then(|parses| parses.get(index))
                .cloned()
                .map(|result| live_parser_result(row, result));
            results.push(LiveTestResult {
                input: row.clone(),
                new_parse: live_parser_result(row, new_parse),
                current_parse,
            });
        }

        Ok(results)
    }

    /// Recent raw `message`s of one source from ClickHouse (newest first),
    /// filtered by the caller's source scope: the shared read behind the live
    /// test lab and Nano Pipe samples (NAN-2058 / NAN-4919). A denied
    /// `source_type` matches no rows, exactly like an empty source.
    pub(crate) async fn fetch_recent_messages(
        &self,
        source_type: &str,
        limit: usize,
        scope: &crate::auth::ScopeSet,
    ) -> Result<Vec<String>, LogSourceServiceError> {
        let ch_client = self.ch_client.as_ref().ok_or_else(|| {
            LogSourceServiceError::InvalidVrl(
                "ClickHouse not available — live testing requires ClickHouse".into(),
            )
        })?;

        let limit = limit.min(100);
        let table = live_sample_table(self.schema, &self.table_names);
        let sql = build_live_sample_sql(self.schema, &table, source_type, limit, scope);

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct MessageRow {
            message: String,
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct SampleRow {
            sample: String,
        }

        let query = ch_client.query(&sql).with_option(
            "max_execution_time",
            LIVE_SAMPLE_MAX_EXECUTION_TIME_SECS.to_string(),
        );
        let fetched = if self.schema == crate::schema::SchemaId::Ocsf {
            query
                .fetch_all::<SampleRow>()
                .await
                .map(|rows| rows.into_iter().map(|r| r.sample).collect::<Vec<_>>())
        } else {
            query
                .fetch_all::<MessageRow>()
                .await
                .map(|rows| rows.into_iter().map(|r| r.message).collect::<Vec<_>>())
        };
        let rows = fetched.map_err(|e| {
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

        Ok(rows)
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
    use super::{build_live_sample_sql, distinct_current_vrl, live_sample_table};
    use crate::auth::ScopeSet;
    use crate::db::TableNames;
    use crate::schema::SchemaId::{Ocsf, Udm};
    use std::collections::BTreeSet;

    fn deny(items: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(items.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>())
    }

    #[test]
    fn unrestricted_caller_gets_bounded_recent_query() {
        let sql = build_live_sample_sql(
            Udm,
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
        let sql = build_live_sample_sql(Udm, "nanosiem.logs", "windows_sysmon", 10, &deny(&["audit"]));
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
        let sql = build_live_sample_sql(Udm, "nanosiem.logs", "audit", 10, &deny(&["audit"]));
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
            Udm,
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
        let sql = build_live_sample_sql(Udm, "nanosiem.logs", "a'b", 1, &deny(&["audit"]));
        assert!(!sql.contains("'a'b'"), "got: {sql}");
    }

    #[test]
    fn ocsf_samples_read_the_ocsf_store() {
        // NAN-5347: the live test lab and Nano Pipe samples read `logs` on every
        // profile, so an OCSF install (which writes `ocsf_logs`) never found a
        // sample. The table follows the profile, cluster-routed like search.
        assert_eq!(live_sample_table(Ocsf, &TableNames::new(false)), "ocsf_logs");
        assert_eq!(
            live_sample_table(Ocsf, &TableNames::new(true)),
            "ocsf_logs_distributed"
        );
        // UDM unchanged: the same names `DualPool::logs_table()` returned.
        assert_eq!(live_sample_table(Udm, &TableNames::new(false)), "logs");
        assert_eq!(live_sample_table(Udm, &TableNames::new(true)), "logs_distributed");
    }

    #[test]
    fn ocsf_sample_query_folds_source_type_and_keeps_its_bounds() {
        // `source_type` is not lowercased at ingest on OCSF (direct writers),
        // so the key compares through `lower()`, as search does.
        let sql = build_live_sample_sql(
            Ocsf,
            "ocsf_logs",
            "Windows_Sysmon",
            10,
            &deny(&["audit"]),
        );
        assert_eq!(
            sql,
            "SELECT if(raw_data != '', raw_data, message) AS sample FROM ocsf_logs \
             WHERE lower(source_type) = 'windows_sysmon' \
             AND timestamp >= now() - INTERVAL 24 HOUR AND (raw_data != '' OR message != '') \
             AND lower(source_type) != 'audit' ORDER BY timestamp DESC LIMIT 10"
        );
        assert!(!sql.to_uppercase().contains("PREWHERE"), "{sql}");
        let evil = build_live_sample_sql(Ocsf, "ocsf_logs", "a'b", 1, &ScopeSet::unrestricted());
        assert!(!evil.contains("'a'b'"), "got: {evil}");
    }

    /// Live: the OCSF sample read returns the raw messages an OCSF install
    /// stores, where the UDM read finds no `logs` table at all. Point
    /// `NANO_OCSF_TEST_CH_URL` at a throwaway ClickHouse whose
    /// `nanosiem.ocsf_logs` was created from `clickhouse/ocsf/init.sql`.
    #[tokio::test]
    #[ignore = "requires NANO_OCSF_TEST_CH_URL (a ClickHouse with nanosiem.ocsf_logs)"]
    async fn ocsf_live_samples_come_from_ocsf_logs() {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct MessageRow {
            message: String,
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct SampleRow {
            sample: String,
        }
        let client = clickhouse::Client::default()
            .with_url(std::env::var("NANO_OCSF_TEST_CH_URL").expect("NANO_OCSF_TEST_CH_URL"))
            .with_database("nanosiem")
            // Plain HTTP: a stock server image's LZ4 reply did not decompress.
            .with_compression(clickhouse::Compression::None);
        let tag = uuid::Uuid::now_v7().simple().to_string();
        let source = format!("nan5347_live_{tag}");
        client
            .query(&format!(
                "INSERT INTO nanosiem.ocsf_logs (timestamp, source_type, class_uid, message, raw_data) VALUES \
                 (now64(3) - INTERVAL 5 MINUTE, '{source}', 1007, '<Event>{tag}</Event>', ''), \
                 (now64(3) - INTERVAL 4 MINUTE, '{source}', 1007, '', '<Raw>{tag}</Raw>'), \
                 (now64(3) - INTERVAL 3 MINUTE, '{source}', 1007, 'Process launched', '<Original>{tag}</Original>'), \
                 (now64(3) - INTERVAL 2 MINUTE, '{source}', 1007, '', ''), \
                 (now64(3) - INTERVAL 2 DAY, '{source}', 1007, 'too old', '')"
            ))
            .execute()
            .await
            .expect("fixture insert");
        let tables = TableNames::new(false);

        let before = build_live_sample_sql(
            Udm,
            &live_sample_table(Udm, &tables),
            &source,
            10,
            &ScopeSet::unrestricted(),
        );
        assert!(
            client.query(&before).fetch_all::<MessageRow>().await.is_err(),
            "the UDM sample read should find no `logs` table on an OCSF store"
        );

        let sql = build_live_sample_sql(
            Ocsf,
            &live_sample_table(Ocsf, &tables),
            // Mixed case: the lane key folds like search does.
            &source.to_uppercase(),
            10,
            &ScopeSet::unrestricted(),
        );
        let rows: Vec<SampleRow> = client.query(&sql).fetch_all().await.expect("OCSF sample read");
        let samples: Vec<String> = rows.into_iter().map(|r| r.sample).collect();
        // Newest first. The original (`raw_data`) wins over a summary
        // `message`; a raw_data-only row is a sample; a message-only row
        // still is; an empty row and the out-of-window row are not.
        assert_eq!(
            samples,
            vec![
                format!("<Original>{tag}</Original>"),
                format!("<Raw>{tag}</Raw>"),
                format!("<Event>{tag}</Event>"),
            ]
        );

        let denied = build_live_sample_sql(
            Ocsf,
            &live_sample_table(Ocsf, &tables),
            &source,
            10,
            &deny(&[&source]),
        );
        let rows: Vec<SampleRow> = client.query(&denied).fetch_all().await.expect("scoped read");
        assert!(rows.is_empty(), "a denied source returned raw samples");
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
}
