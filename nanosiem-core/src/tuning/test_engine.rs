// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test Engine for AI Detection Auto-Tuning
//!
//! This module provides the TestEngine that validates tuning proposals by:
//! - Replaying original and proposed queries through production evaluation windows
//! - Comparing alert volumes and patterns
//! - Validating that known true positives still trigger
//! - Calculating improvement metrics
//!
//! Requirements: 5.1, 5.2, 5.3, 5.4, 5.5

use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::Semaphore;

use crate::detection::service::{
    tuning_test_windows, TuningReplayBudget, TuningWindowEvidence,
    MAX_AUTONOMOUS_TUNING_TOTAL_BYTES, MAX_AUTONOMOUS_TUNING_TOTAL_ROWS,
};
use crate::detection::DetectionService;
use crate::query::{extract_time_modifier_tokens, parse_query, Command, Query};
use crate::search::TimeRangeInput;
use crate::tuning::types::{
    ComparisonMetrics, PatternChange, TestResults, TuningProposal, TuningValidationProof,
    TuningValidationWindow,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

const VALIDATION_HORIZON_HOURS: i64 = 24;
const TRUE_POSITIVE_CORPUS_LIMIT: usize = 10_000;
const VALIDATION_PROOF_VERSION: u32 = 1;
const SOURCE_IDENTITY_MODE: &str = "physical_id_uuid_v1";
const AUTONOMOUS_VALIDATION_TIMEOUT_SECS: u64 = 300;
static AUTONOMOUS_VALIDATION_ADMISSION: Semaphore = Semaphore::const_new(1);

/// Error type for test engine operations
#[derive(Debug, thiserror::Error)]
pub enum TestEngineError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Query parse error: {0}")]
    QueryParse(String),

    #[error("Search error: {0}")]
    Search(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

/// Test Engine for validating tuning proposals
///
/// The TestEngine validates tuning proposals by:
/// 1. Replaying raw identity-preserving queries through production evaluation
/// 2. Using the rule's exact cron cadence and lookback windows
/// 3. Comparing alert volumes and patterns
/// 4. Verifying known true positives still trigger
/// 5. Calculating improvement metrics
///
/// Validation Criteria:
/// - ✅ Pass: 30-80% reduction in alert volume
/// - ❌ Fail: <10% reduction (not effective)
/// - ❌ Fail: >80% reduction (too aggressive)
pub struct TestEngine {
    /// Production detection evaluator used by scheduled rule execution.
    detection_service: Arc<DetectionService>,
    /// PostgreSQL stores analyst dispositions and their matched-event corpus.
    pg_pool: PgPool,
}

impl TestEngine {
    /// Create a new Test Engine
    ///
    /// # Arguments
    /// * `detection_service` - Production detection evaluator
    /// * `pg_pool` - PostgreSQL pool used to load analyst-confirmed true positives
    pub fn new(detection_service: Arc<DetectionService>, pg_pool: PgPool) -> Self {
        Self {
            detection_service,
            pg_pool,
        }
    }

    /// Test a tuning proposal against historical data
    ///
    /// This is the main entry point for testing. It:
    /// 1. Executes the original query over production schedule/lookback windows
    /// 2. Executes the proposed query against the same time range
    /// 3. Compares the results
    /// 4. Validates the reduction is within acceptable bounds (30-80%)
    ///
    /// # Arguments
    /// * `proposal` - The tuning proposal to test
    ///
    /// # Returns
    /// Test results with comparison metrics and validation status
    ///
    /// Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
    pub async fn test_proposal(
        &self,
        proposal: &TuningProposal,
        dataset: Option<&str>,
        schedule_cron: Option<&str>,
        lookback_minutes: Option<i64>,
    ) -> Result<TestResults, TestEngineError> {
        tracing::info!(
            "Starting test for proposal {} (rule {})",
            proposal.id,
            proposal.rule_id
        );

        if query_has_inline_time_modifiers(&proposal.original_query)
            || query_has_inline_time_modifiers(&proposal.proposed_query)
        {
            return Err(TestEngineError::Validation(
                "Autonomous validation does not allow inline earliest/latest modifiers; the rule schedule and explicit production lookback define every replay window"
                    .to_string(),
            ));
        }

        if !query_preserves_physical_source_identity(&proposal.original_query)?
            || !query_preserves_physical_source_identity(&proposal.proposed_query)?
        {
            return Err(TestEngineError::Validation(
                "Autonomous validation requires raw identity-preserving queries; aggregation, projection, eval, rename, lookup, and other row-shaping commands require human review"
                    .to_string(),
            ));
        }

        // The horizon selects cron ticks; every tick is replayed against the
        // rule's production lookback window.
        let end_time = Utc::now();
        let start_time = end_time - Duration::hours(VALIDATION_HORIZON_HOURS);
        let time_range = TimeRangeInput::new(start_time, end_time);
        let plan = tuning_test_windows(&time_range, schedule_cron, lookback_minutes)
            .map_err(|error| TestEngineError::Validation(error.to_string()))?;
        if plan.windows.is_empty() {
            return Err(TestEngineError::Validation(
                "The validation horizon contains no production schedule ticks".to_string(),
            ));
        }

        tracing::info!(
            "Test time range: {} to {}",
            crate::sql_hygiene::format_ch_bound(&start_time),
            crate::sql_hygiene::format_ch_bound(&end_time)
        );

        let validation_id = Uuid::now_v7();
        let original_query_id_prefix = format!("tuning-{validation_id}-original");
        let proposed_query_id_prefix = format!("tuning-{validation_id}-proposed");
        let execution = tokio::time::timeout(
            StdDuration::from_secs(AUTONOMOUS_VALIDATION_TIMEOUT_SECS),
            async {
                let _admission = AUTONOMOUS_VALIDATION_ADMISSION
                    .acquire()
                    .await
                    .map_err(|_| {
                        TestEngineError::Validation(
                            "Autonomous tuning validation admission is unavailable".to_string(),
                        )
                    })?;

                // Analyst-confirmed matches are the preservation corpus. An
                // empty corpus is not evidence of preservation and cannot pass.
                let true_positive_corpus = self
                    .load_true_positive_corpus(proposal.rule_id, &time_range)
                    .await?;

                tracing::info!(
                    "Loaded {} analyst-confirmed true-positive events for validation",
                    true_positive_corpus.event_count
                );

                let original_results = self
                    .detection_service
                    .evaluate_tuning_windows(
                        &proposal.original_query,
                        &plan.windows,
                        dataset.map(str::to_owned),
                        TuningReplayBudget {
                            rows: MAX_AUTONOMOUS_TUNING_TOTAL_ROWS,
                            bytes: MAX_AUTONOMOUS_TUNING_TOTAL_BYTES,
                        },
                        &original_query_id_prefix,
                    )
                    .await;
                let tuned_results = if evidence_is_exact(&original_results) {
                    self.detection_service
                        .evaluate_tuning_windows(
                            &proposal.proposed_query,
                            &plan.windows,
                            dataset.map(str::to_owned),
                            remaining_replay_budget(&original_results),
                            &proposed_query_id_prefix,
                        )
                        .await
                } else {
                    // There is no value in spending a second ClickHouse replay
                    // after the first one has already made exact validation
                    // impossible. Mark the skipped side non-exact so the proof
                    // remains explicitly fail-closed.
                    TuningWindowEvidence {
                        failed_windows: 1,
                        ..TuningWindowEvidence::default()
                    }
                };

                Ok::<_, TestEngineError>((true_positive_corpus, original_results, tuned_results))
            },
        )
        .await;
        let (true_positive_corpus, original_results, tuned_results) = match execution {
            Ok(result) => result?,
            Err(_) => {
                if let Err(error) = self
                    .detection_service
                    .cancel_tuning_replays(
                        &[&original_query_id_prefix, &proposed_query_id_prefix],
                        plan.windows.len(),
                    )
                    .await
                {
                    tracing::error!(
                        validation_id = %validation_id,
                        error = %error,
                        "Failed to explicitly cancel timed-out tuning validation"
                    );
                }
                return Err(TestEngineError::Validation(format!(
                    "Autonomous tuning validation exceeded its {AUTONOMOUS_VALIDATION_TIMEOUT_SECS}-second admission and execution budget"
                )));
            }
        };

        tracing::info!(
            windows = plan.windows.len(),
            original_total = original_results.total_matches,
            tuned_total = tuned_results.total_matches,
            original_truncated_windows = original_results.truncated_windows,
            tuned_truncated_windows = tuned_results.truncated_windows,
            "Completed stepped tuning validation"
        );

        let counts_exact = evidence_is_exact(&original_results)
            && evidence_is_exact(&tuned_results)
            && !true_positive_corpus.truncated
            && true_positive_corpus.identity_complete;

        let true_positives_preserved = counts_exact
            && corpus_is_preserved(
                &true_positive_corpus.source_ids,
                &original_results.source_ids,
                &tuned_results.source_ids,
            );

        let mut comparison_metrics = self
            .compare_results(
                &original_results.sample_events,
                &tuned_results.sample_events,
            )
            .await?;

        let original_count = count_as_i64(original_results.total_matches);
        let tuned_count = count_as_i64(tuned_results.total_matches);
        comparison_metrics.alerts_removed = original_count - tuned_count;
        comparison_metrics.alerts_preserved = tuned_count;
        let reduction_percentage = if original_count > 0 {
            ((original_count - tuned_count) as f64 / original_count as f64) * 100.0
        } else {
            0.0
        };

        let volume_validation_passed = reduction_percentage >= 30.0 && reduction_percentage <= 80.0;
        let validation_passed = counts_exact && volume_validation_passed;

        let windows = plan
            .windows
            .iter()
            .map(|window| TuningValidationWindow {
                start: window.start,
                end: window.end,
            })
            .collect::<Vec<_>>();
        let validation_proof = TuningValidationProof {
            proof_version: VALIDATION_PROOF_VERSION,
            original_query_sha256: sha256_hex(proposal.original_query.as_bytes()),
            proposed_query_sha256: sha256_hex(proposal.proposed_query.as_bytes()),
            dataset: dataset.unwrap_or("logs").to_ascii_lowercase(),
            schedule_cron: plan.schedule_cron,
            lookback_minutes: plan.lookback_minutes,
            evaluation_start: time_range.start,
            evaluation_end: time_range.end,
            windows_sha256: digest_windows(&windows),
            windows,
            corpus_count: true_positive_corpus.event_count,
            corpus_sha256: true_positive_corpus.digest,
            corpus_revision: true_positive_corpus.revision,
            corpus_unique_source_count: u64::try_from(true_positive_corpus.source_ids.len())
                .unwrap_or(u64::MAX),
            corpus_source_ids_sha256: digest_source_ids(&true_positive_corpus.source_ids),
            corpus_truncated: true_positive_corpus.truncated,
            corpus_identity_complete: true_positive_corpus.identity_complete,
            original_match_count: original_results.total_matches,
            proposed_match_count: tuned_results.total_matches,
            original_source_ids_sha256: digest_source_ids(&original_results.source_ids),
            proposed_source_ids_sha256: digest_source_ids(&tuned_results.source_ids),
            original_failed_windows: original_results.failed_windows,
            proposed_failed_windows: tuned_results.failed_windows,
            original_truncated_windows: original_results.truncated_windows,
            proposed_truncated_windows: tuned_results.truncated_windows,
            original_identity_errors: original_results.identity_errors,
            proposed_identity_errors: tuned_results.identity_errors,
            original_rows_examined: original_results.rows_examined,
            proposed_rows_examined: tuned_results.rows_examined,
            original_bytes_examined: original_results.bytes_examined,
            proposed_bytes_examined: tuned_results.bytes_examined,
            original_budget_exceeded: original_results.budget_exceeded,
            proposed_budget_exceeded: tuned_results.budget_exceeded,
            counts_exact,
            true_positives_preserved,
            identity_mode: SOURCE_IDENTITY_MODE.to_string(),
        };

        tracing::info!(
            "Alert reduction: {} -> {} ({:.1}% reduction; exact={})",
            original_count,
            tuned_count,
            reduction_percentage,
            counts_exact
        );

        if !validation_passed {
            if reduction_percentage < 10.0 {
                tracing::warn!(
                    "Validation FAILED: Reduction too small ({:.1}% < 10%)",
                    reduction_percentage
                );
            } else if reduction_percentage > 80.0 {
                tracing::warn!(
                    "Validation FAILED: Reduction too aggressive ({:.1}% > 80%)",
                    reduction_percentage
                );
            } else {
                tracing::warn!(
                    "Validation FAILED: Reduction outside acceptable range ({:.1}% not in 30-80%)",
                    reduction_percentage
                );
            }
        } else {
            tracing::info!(
                "Validation PASSED: Reduction within acceptable range ({:.1}% in 30-80%)",
                reduction_percentage
            );
        }

        if !true_positives_preserved {
            tracing::warn!(
                proposal_id = %proposal.id,
                corpus_size = true_positive_corpus.event_count,
                "Validation FAILED: analyst-confirmed true positives were not preserved"
            );
        }

        Ok(TestResults {
            proposal_id: proposal.id,
            tested_at: Utc::now(),
            original_alert_count: original_count,
            tuned_alert_count: tuned_count,
            reduction_percentage,
            true_positives_preserved,
            validation_passed,
            comparison_metrics,
            validation_proof: Some(validation_proof),
        })
    }

    async fn load_true_positive_corpus(
        &self,
        rule_id: uuid::Uuid,
        time_range: &TimeRangeInput,
    ) -> Result<TruePositiveCorpus, TestEngineError> {
        let mut tx = self.pg_pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        let revision = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COALESCE(
                (SELECT revision
                 FROM tuning_tp_corpus_revisions
                 WHERE rule_id = $1),
                0
            )
            "#,
        )
        .bind(rule_id)
        .fetch_one(&mut *tx)
        .await?;
        let mut rows = sqlx::query_scalar::<_, serde_json::Value>(
            r#"
            SELECT event.value
            FROM detection_matches AS dm
            CROSS JOIN LATERAL jsonb_array_elements(dm.matched_events) AS event(value)
            WHERE dm.rule_id = $1
              AND dm.disposition = 'true_positive'
              AND dm.detected_at >= $2
              AND dm.detected_at <= $3
            ORDER BY dm.detected_at DESC
            LIMIT $4
            "#,
        )
        .bind(rule_id)
        .bind(time_range.start)
        .bind(time_range.end)
        .bind(i64::try_from(TRUE_POSITIVE_CORPUS_LIMIT + 1).unwrap_or(i64::MAX))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let truncated = rows.len() > TRUE_POSITIVE_CORPUS_LIMIT;
        if truncated {
            rows.truncate(TRUE_POSITIVE_CORPUS_LIMIT);
        }

        let digest = digest_corpus(&rows);
        let mut source_ids = HashSet::new();
        let mut identity_complete = true;
        for row in &rows {
            match row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
            {
                Some(id) => {
                    source_ids.insert(id);
                }
                None => identity_complete = false,
            }
        }

        Ok(TruePositiveCorpus {
            event_count: u64::try_from(rows.len()).unwrap_or(u64::MAX),
            source_ids,
            digest,
            revision,
            truncated,
            identity_complete,
        })
    }

    /// Compare results between original and tuned queries
    ///
    /// Calculates detailed comparison metrics including:
    /// - Number of alerts removed vs preserved
    /// - Unique entities removed
    /// - Severity distribution changes
    /// - Pattern changes
    ///
    /// # Arguments
    /// * `original` - Results from original query
    /// * `tuned` - Results from tuned query
    ///
    /// # Returns
    /// Detailed comparison metrics
    ///
    /// Requirements: 5.3
    pub async fn compare_results(
        &self,
        original: &[serde_json::Value],
        tuned: &[serde_json::Value],
    ) -> Result<ComparisonMetrics, TestEngineError> {
        let original_count = original.len() as i64;
        let tuned_count = tuned.len() as i64;
        let alerts_removed = original_count - tuned_count;
        let alerts_preserved = tuned_count;

        // Calculate unique entities removed
        let original_entities = self.extract_unique_entities(original);
        let tuned_entities = self.extract_unique_entities(tuned);
        let unique_entities_removed = original_entities.difference(&tuned_entities).count() as i64;

        tracing::debug!(
            "Entity comparison: {} original, {} tuned, {} removed",
            original_entities.len(),
            tuned_entities.len(),
            unique_entities_removed
        );

        // Calculate severity distribution changes
        let original_severity = self.calculate_severity_distribution(original);
        let tuned_severity = self.calculate_severity_distribution(tuned);
        let mut severity_distribution_change = HashMap::new();

        for (severity, original_count) in &original_severity {
            let tuned_count = tuned_severity.get(severity).copied().unwrap_or(0);
            let change = tuned_count - original_count;
            if change != 0 {
                severity_distribution_change.insert(severity.clone(), change);
            }
        }

        // Add any new severities in tuned results
        for (severity, tuned_count) in &tuned_severity {
            if !original_severity.contains_key(severity) {
                severity_distribution_change.insert(severity.clone(), *tuned_count);
            }
        }

        tracing::debug!(
            "Severity distribution changes: {:?}",
            severity_distribution_change
        );

        // Calculate pattern changes
        let pattern_changes = self.calculate_pattern_changes(original, tuned);

        tracing::debug!("Identified {} pattern changes", pattern_changes.len());

        Ok(ComparisonMetrics {
            alerts_removed,
            alerts_preserved,
            unique_entities_removed,
            severity_distribution_change,
            pattern_changes,
        })
    }

    /// Extract unique entities from results
    ///
    /// Extracts unique combinations of entity-related fields like:
    /// - src_ip, dst_ip
    /// - user_name
    /// - host_name
    /// - process_name
    fn extract_unique_entities(
        &self,
        results: &[serde_json::Value],
    ) -> std::collections::HashSet<String> {
        use std::collections::HashSet;

        let mut entities = HashSet::new();

        for result in results {
            // Extract common entity fields
            let mut entity_parts = Vec::new();

            if let Some(src_ip) = result.get("src_ip").and_then(|v| v.as_str()) {
                entity_parts.push(format!("src_ip:{}", src_ip));
            }
            if let Some(dst_ip) = result.get("dst_ip").and_then(|v| v.as_str()) {
                entity_parts.push(format!("dst_ip:{}", dst_ip));
            }
            if let Some(user_name) = result.get("user_name").and_then(|v| v.as_str()) {
                entity_parts.push(format!("user:{}", user_name));
            }
            if let Some(host_name) = result.get("host_name").and_then(|v| v.as_str()) {
                entity_parts.push(format!("host:{}", host_name));
            }
            if let Some(process_name) = result.get("process_name").and_then(|v| v.as_str()) {
                entity_parts.push(format!("process:{}", process_name));
            }

            // Create a unique entity identifier
            if !entity_parts.is_empty() {
                entities.insert(entity_parts.join("|"));
            }
        }

        entities
    }

    /// Calculate severity distribution from results
    fn calculate_severity_distribution(
        &self,
        results: &[serde_json::Value],
    ) -> HashMap<String, i64> {
        let mut distribution = HashMap::new();

        for result in results {
            if let Some(severity) = result.get("severity").and_then(|v| v.as_str()) {
                *distribution.entry(severity.to_string()).or_insert(0) += 1;
            }
        }

        distribution
    }

    /// Calculate pattern changes between original and tuned results
    ///
    /// Identifies which field values changed in frequency
    fn calculate_pattern_changes(
        &self,
        original: &[serde_json::Value],
        tuned: &[serde_json::Value],
    ) -> Vec<PatternChange> {
        // Track field value counts in both result sets
        let original_patterns = self.extract_field_patterns(original);
        let tuned_patterns = self.extract_field_patterns(tuned);

        let mut changes = Vec::new();

        // Find patterns that changed
        for ((field, value), original_count) in &original_patterns {
            let tuned_count = tuned_patterns
                .get(&(field.clone(), value.clone()))
                .copied()
                .unwrap_or(0);

            // Only include significant changes (>10% difference)
            let change_pct = if *original_count > 0 {
                ((original_count - tuned_count) as f64 / *original_count as f64).abs() * 100.0
            } else {
                0.0
            };

            if change_pct > 10.0 {
                changes.push(PatternChange {
                    field_name: field.clone(),
                    field_value: value.clone(),
                    before_count: *original_count,
                    after_count: tuned_count,
                });
            }
        }

        // Sort by magnitude of change
        changes.sort_by(|a, b| {
            let a_change = (a.before_count - a.after_count).abs();
            let b_change = (b.before_count - b.after_count).abs();
            b_change.cmp(&a_change)
        });

        // Return top 10 changes
        changes.truncate(10);
        changes
    }

    /// Extract field patterns from results
    ///
    /// Returns a map of (field_name, field_value) -> count
    fn extract_field_patterns(
        &self,
        results: &[serde_json::Value],
    ) -> HashMap<(String, String), i64> {
        let mut patterns = HashMap::new();

        // Fields to track for pattern analysis
        let tracked_fields = vec![
            "src_ip",
            "dst_ip",
            "user_name",
            "host_name",
            "process_name",
            "event_type",
            "action",
        ];

        for result in results {
            for field in &tracked_fields {
                if let Some(value) = result.get(field).and_then(|v| v.as_str()) {
                    let key = (field.to_string(), value.to_string());
                    *patterns.entry(key).or_insert(0) += 1;
                }
            }
        }

        patterns
    }
}

fn count_as_i64(count: u64) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

struct TruePositiveCorpus {
    event_count: u64,
    source_ids: HashSet<Uuid>,
    digest: String,
    revision: i64,
    truncated: bool,
    identity_complete: bool,
}

fn evidence_is_exact(evidence: &TuningWindowEvidence) -> bool {
    evidence.failed_windows == 0
        && evidence.truncated_windows == 0
        && evidence.identity_errors == 0
        && !evidence.budget_exceeded
}

fn remaining_replay_budget(evidence: &TuningWindowEvidence) -> TuningReplayBudget {
    TuningReplayBudget {
        rows: MAX_AUTONOMOUS_TUNING_TOTAL_ROWS.saturating_sub(evidence.rows_examined),
        bytes: MAX_AUTONOMOUS_TUNING_TOTAL_BYTES.saturating_sub(evidence.bytes_examined),
    }
}

fn corpus_is_preserved(
    corpus_ids: &HashSet<Uuid>,
    original_ids: &HashSet<Uuid>,
    tuned_ids: &HashSet<Uuid>,
) -> bool {
    !corpus_ids.is_empty() && corpus_ids.is_subset(original_ids) && corpus_ids.is_subset(tuned_ids)
}

fn query_preserves_physical_source_identity(query: &str) -> Result<bool, TestEngineError> {
    let parsed =
        parse_query(query).map_err(|error| TestEngineError::QueryParse(error.to_string()))?;

    fn preserves_identity(query: &Query) -> bool {
        match query {
            Query::Search(_) => true,
            Query::Piped { source, command } => {
                preserves_identity(source)
                    && matches!(
                        command,
                        Command::Where { .. }
                            | Command::Sort { .. }
                            | Command::Head { .. }
                            | Command::Tail { .. }
                            | Command::Dedup { .. }
                    )
            }
        }
    }

    Ok(preserves_identity(&parsed))
}

fn query_has_inline_time_modifiers(query: &str) -> bool {
    !extract_time_modifier_tokens(query).is_empty()
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn digest_source_ids(source_ids: &HashSet<Uuid>) -> String {
    let mut source_ids = source_ids.iter().copied().collect::<Vec<_>>();
    source_ids.sort_unstable();

    let mut digest = Sha256::new();
    for source_id in source_ids {
        digest.update(source_id.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn digest_windows(windows: &[TuningValidationWindow]) -> String {
    sha256_hex(&serde_json::to_vec(windows).unwrap_or_default())
}

fn digest_corpus(corpus: &[serde_json::Value]) -> String {
    let mut encoded = corpus
        .iter()
        .map(canonicalize_event)
        .map(|event| serde_json::to_vec(&event).unwrap_or_default())
        .collect::<Vec<_>>();
    encoded.sort_unstable();

    let mut digest = Sha256::new();
    for event in encoded {
        digest.update(u64::try_from(event.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(event);
    }
    hex::encode(digest.finalize())
}

fn canonicalize_event(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));

            let mut canonical = serde_json::Map::new();
            for (key, child) in entries {
                canonical.insert(key.clone(), canonicalize_event(child));
            }
            serde_json::Value::Object(canonical)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize_event).collect())
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_unique_entities_logic() {
        // Test the entity extraction logic without needing a full TestEngine
        let results = vec![
            serde_json::json!({
                "src_ip": "192.168.1.1",
                "user_name": "alice"
            }),
            serde_json::json!({
                "src_ip": "192.168.1.1",
                "user_name": "alice"
            }),
            serde_json::json!({
                "src_ip": "192.168.1.2",
                "user_name": "bob"
            }),
        ];

        // Manually extract entities using the same logic
        use std::collections::HashSet;
        let mut entities = HashSet::new();

        for result in &results {
            let mut entity_parts = Vec::new();

            if let Some(src_ip) = result.get("src_ip").and_then(|v| v.as_str()) {
                entity_parts.push(format!("src_ip:{}", src_ip));
            }
            if let Some(user_name) = result.get("user_name").and_then(|v| v.as_str()) {
                entity_parts.push(format!("user:{}", user_name));
            }

            if !entity_parts.is_empty() {
                entities.insert(entity_parts.join("|"));
            }
        }

        // Should have 2 unique entities
        assert_eq!(entities.len(), 2);
    }

    #[test]
    fn test_severity_distribution_logic() {
        let results = vec![
            serde_json::json!({"severity": "high"}),
            serde_json::json!({"severity": "high"}),
            serde_json::json!({"severity": "medium"}),
        ];

        // Manually calculate distribution using the same logic
        let mut distribution = HashMap::new();

        for result in &results {
            if let Some(severity) = result.get("severity").and_then(|v| v.as_str()) {
                *distribution.entry(severity.to_string()).or_insert(0) += 1;
            }
        }

        assert_eq!(distribution.get("high"), Some(&2));
        assert_eq!(distribution.get("medium"), Some(&1));
    }

    #[test]
    fn test_reduction_percentage_calculation() {
        // Test various reduction scenarios

        // 50% reduction (should pass)
        let original_count = 100;
        let tuned_count = 50;
        let reduction = ((original_count - tuned_count) as f64 / original_count as f64) * 100.0;
        assert_eq!(reduction, 50.0);
        assert!(reduction >= 30.0 && reduction <= 80.0);

        // 90% reduction (should fail - too aggressive)
        let original_count = 100;
        let tuned_count = 10;
        let reduction = ((original_count - tuned_count) as f64 / original_count as f64) * 100.0;
        assert_eq!(reduction, 90.0);
        assert!(reduction > 80.0);

        // 5% reduction (should fail - not effective)
        let original_count = 100;
        let tuned_count = 95;
        let reduction = ((original_count - tuned_count) as f64 / original_count as f64) * 100.0;
        assert_eq!(reduction, 5.0);
        assert!(reduction < 10.0);
    }

    #[test]
    fn test_validation_bounds() {
        // Test the validation logic for different reduction percentages

        // Test lower bound (30%)
        let reduction = 30.0;
        assert!(reduction >= 30.0 && reduction <= 80.0);

        // Test upper bound (80%)
        let reduction = 80.0;
        assert!(reduction >= 30.0 && reduction <= 80.0);

        // Test below lower bound (29.9%)
        let reduction = 29.9;
        assert!(!(reduction >= 30.0 && reduction <= 80.0));

        // Test above upper bound (80.1%)
        let reduction = 80.1;
        assert!(!(reduction >= 30.0 && reduction <= 80.0));
    }

    #[test]
    fn preservation_requires_a_nonempty_confirmed_corpus() {
        let event_id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let results = HashSet::from([event_id]);
        assert!(!corpus_is_preserved(&HashSet::new(), &results, &results));
    }

    #[test]
    fn preservation_requires_each_confirmed_event_in_both_executions() {
        let tp_one = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let tp_two = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        let corpus = HashSet::from([tp_one, tp_two]);

        assert!(corpus_is_preserved(&corpus, &corpus, &corpus));
        assert!(!corpus_is_preserved(
            &corpus,
            &corpus,
            &HashSet::from([tp_one])
        ));
    }

    #[test]
    fn corpus_digest_is_order_independent_but_binds_all_fields() {
        let first = serde_json::json!({"id": "a", "nested": {"b": 2, "a": 1}});
        let second = serde_json::json!({"id": "b", "src_ip": "10.0.0.2"});
        assert_eq!(
            digest_corpus(&[first.clone(), second.clone()]),
            digest_corpus(&[second.clone(), first.clone()])
        );

        let changed = serde_json::json!({"id": "a", "nested": {"b": 3, "a": 1}});
        assert_ne!(
            digest_corpus(&[first, second.clone()]),
            digest_corpus(&[changed, second])
        );
    }

    #[test]
    fn autonomous_queries_must_preserve_physical_rows() {
        for query in [
            "src_ip=10.0.0.1",
            "src_ip=10.0.0.1 | where dest_port=443",
            "* | sort -timestamp | head 100 | dedup id",
        ] {
            assert!(
                query_preserves_physical_source_identity(query).unwrap(),
                "{query}"
            );
        }

        for query in [
            "* | stats count by src_ip",
            "* | table id, src_ip",
            "* | fields id, src_ip",
            "* | eval id=src_ip",
            "* | rename src_ip as id",
            "* | lookup assets src_ip OUTPUT owner",
        ] {
            assert!(
                !query_preserves_physical_source_identity(query).unwrap(),
                "{query}"
            );
        }
    }

    #[test]
    fn autonomous_queries_reject_inline_time_modifiers() {
        assert!(query_has_inline_time_modifiers(
            "src_ip=10.0.0.1 earliest=-12h"
        ));
        assert!(query_has_inline_time_modifiers(
            "src_ip=10.0.0.1 LATEST=now"
        ));
        assert!(!query_has_inline_time_modifiers(
            "message=\"latest=release\" | where src_ip=10.0.0.1"
        ));
    }

    #[test]
    fn exact_evidence_fails_closed_on_partial_or_capped_results() {
        let exact = TuningWindowEvidence {
            total_matches: 1,
            ..TuningWindowEvidence::default()
        };
        assert!(evidence_is_exact(&exact));

        let mut failed = exact.clone();
        failed.failed_windows = 1;
        assert!(!evidence_is_exact(&failed));

        let mut truncated = exact.clone();
        truncated.truncated_windows = 1;
        assert!(!evidence_is_exact(&truncated));

        let mut identity_error = exact;
        identity_error.identity_errors = 1;
        assert!(!evidence_is_exact(&identity_error));

        let mut over_budget = TuningWindowEvidence::default();
        over_budget.budget_exceeded = true;
        assert!(!evidence_is_exact(&over_budget));
    }

    #[test]
    fn original_and_proposed_replays_share_one_total_budget() {
        let evidence = TuningWindowEvidence {
            rows_examined: MAX_AUTONOMOUS_TUNING_TOTAL_ROWS - 7,
            bytes_examined: MAX_AUTONOMOUS_TUNING_TOTAL_BYTES - 11,
            ..TuningWindowEvidence::default()
        };
        let remaining = remaining_replay_budget(&evidence);
        assert_eq!(remaining.rows, 7);
        assert_eq!(remaining.bytes, 11);
    }
}
