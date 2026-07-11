// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persisted execution-validation results for autonomous tuning.

use super::TuningRepository;
use crate::detection::service::{
    AUTONOMOUS_TUNING_REPLAY_QUERY_COUNT, MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW,
    MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW, MAX_AUTONOMOUS_TUNING_TOTAL_BYTES,
    MAX_AUTONOMOUS_TUNING_TOTAL_ROWS, MAX_AUTONOMOUS_TUNING_TOTAL_SCAN_SECONDS,
    MAX_AUTONOMOUS_TUNING_WINDOWS,
};
use crate::tuning::types::{TestResults, TuningValidationProof};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

impl TuningRepository {
    /// Persist the historical execution and true-positive preservation result.
    pub async fn create_test_result(&self, results: &TestResults) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let comparison_metrics = serde_json::to_value(&results.comparison_metrics)
            .context("Failed to serialize tuning comparison metrics")?;
        let validation_proof = results
            .validation_proof
            .as_ref()
            .context("Autonomous tuning test result is missing its validation proof")?;
        let validation_proof = serde_json::to_value(validation_proof)
            .context("Failed to serialize tuning validation proof")?;

        sqlx::query(
            r#"
            INSERT INTO tuning_test_results (
                id,
                proposal_id,
                tested_at,
                original_alert_count,
                tuned_alert_count,
                reduction_percentage,
                true_positives_preserved,
                validation_passed,
                comparison_metrics,
                validation_proof
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(id)
        .bind(results.proposal_id)
        .bind(results.tested_at)
        .bind(results.original_alert_count)
        .bind(results.tuned_alert_count)
        .bind(results.reduction_percentage)
        .bind(results.true_positives_preserved)
        .bind(results.validation_passed)
        .bind(comparison_metrics)
        .bind(validation_proof)
        .execute(&self.pool)
        .await
        .context("Failed to persist tuning test result")?;

        Ok(id)
    }

    /// Verify the exact persisted row used to authorize an autonomous apply.
    ///
    /// Checking by both IDs prevents an unrelated passing result from being
    /// used as evidence for this proposal.
    pub async fn persisted_test_result_passed(
        &self,
        proposal_id: Uuid,
        test_result_id: Uuid,
        expected_proof: &TuningValidationProof,
    ) -> Result<bool> {
        let row = sqlx::query_as::<_, PersistedValidation>(
            r#"
            SELECT
                original_alert_count,
                tuned_alert_count,
                reduction_percentage,
                validation_passed,
                true_positives_preserved,
                validation_proof
            FROM tuning_test_results
            WHERE id = $1
              AND proposal_id = $2
            "#,
        )
        .bind(test_result_id)
        .bind(proposal_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to verify persisted tuning test result")?;

        let Some(row) = row else {
            return Ok(false);
        };
        let Some(stored_proof) = row.validation_proof else {
            return Ok(false);
        };
        let stored_proof = serde_json::from_value::<TuningValidationProof>(stored_proof)
            .context("Failed to deserialize persisted tuning validation proof")?;

        Ok(row.validation_passed
            && row.true_positives_preserved
            && row.original_alert_count == count_as_i64(stored_proof.original_match_count)
            && row.tuned_alert_count == count_as_i64(stored_proof.proposed_match_count)
            && row.reduction_percentage.to_bits()
                == proof_reduction_percentage(&stored_proof).to_bits()
            && stored_proof == *expected_proof
            && proof_allows_autonomous_apply(&stored_proof))
    }
}

#[derive(sqlx::FromRow)]
struct PersistedValidation {
    original_alert_count: i64,
    tuned_alert_count: i64,
    reduction_percentage: f64,
    validation_passed: bool,
    true_positives_preserved: bool,
    validation_proof: Option<serde_json::Value>,
}

pub(super) fn proof_allows_autonomous_apply(proof: &TuningValidationProof) -> bool {
    proof.proof_version == 1
        && proof.identity_mode == "physical_id_uuid_v1"
        && matches!(proof.dataset.as_str(), "logs" | "spans" | "metrics")
        && !proof.schedule_cron.trim().is_empty()
        && proof.lookback_minutes > 0
        && proof.evaluation_start < proof.evaluation_end
        && !proof.windows.is_empty()
        && proof.windows.len() <= MAX_AUTONOMOUS_TUNING_WINDOWS
        && proof
            .windows
            .iter()
            .try_fold(0_i64, |total, window| {
                total.checked_add((window.end - window.start).num_seconds())
            })
            .and_then(|seconds| seconds.checked_mul(AUTONOMOUS_TUNING_REPLAY_QUERY_COUNT))
            .is_some_and(|seconds| seconds <= MAX_AUTONOMOUS_TUNING_TOTAL_SCAN_SECONDS)
        && proof.windows.iter().all(|window| {
            window.start < window.end
                && window.end >= proof.evaluation_start
                && window.end <= proof.evaluation_end
                && window.end - window.start == chrono::Duration::minutes(proof.lookback_minutes)
        })
        && proof.windows_sha256 == digest_windows(&proof.windows)
        && is_sha256(&proof.original_query_sha256)
        && is_sha256(&proof.proposed_query_sha256)
        && is_sha256(&proof.windows_sha256)
        && is_sha256(&proof.corpus_sha256)
        && proof.corpus_revision >= 0
        && is_sha256(&proof.corpus_source_ids_sha256)
        && is_sha256(&proof.original_source_ids_sha256)
        && is_sha256(&proof.proposed_source_ids_sha256)
        && proof.counts_exact
        && proof.corpus_count > 0
        && proof.corpus_unique_source_count > 0
        && proof.corpus_unique_source_count <= proof.corpus_count
        && !proof.corpus_truncated
        && proof.corpus_identity_complete
        && proof.true_positives_preserved
        && proof_reduction_percentage(proof) >= 30.0
        && proof_reduction_percentage(proof) <= 80.0
        && proof.original_failed_windows == 0
        && proof.proposed_failed_windows == 0
        && proof.original_truncated_windows == 0
        && proof.proposed_truncated_windows == 0
        && proof.original_identity_errors == 0
        && proof.proposed_identity_errors == 0
        && !proof.original_budget_exceeded
        && !proof.proposed_budget_exceeded
        && proof.original_match_count <= proof.original_rows_examined
        && proof.proposed_match_count <= proof.proposed_rows_examined
        && proof.original_rows_examined
            <= (proof.windows.len() as u64).saturating_mul(MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW)
        && proof.proposed_rows_examined
            <= (proof.windows.len() as u64).saturating_mul(MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW)
        && proof.original_bytes_examined
            <= (proof.windows.len() as u64).saturating_mul(MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW)
        && proof.proposed_bytes_examined
            <= (proof.windows.len() as u64).saturating_mul(MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW)
        && proof
            .original_rows_examined
            .checked_add(proof.proposed_rows_examined)
            .is_some_and(|rows| rows <= MAX_AUTONOMOUS_TUNING_TOTAL_ROWS)
        && proof
            .original_bytes_examined
            .checked_add(proof.proposed_bytes_examined)
            .is_some_and(|bytes| bytes <= MAX_AUTONOMOUS_TUNING_TOTAL_BYTES)
}

pub(super) fn count_as_i64(count: u64) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

pub(super) fn proof_reduction_percentage(proof: &TuningValidationProof) -> f64 {
    if proof.original_match_count == 0 {
        return 0.0;
    }
    ((proof.original_match_count as f64 - proof.proposed_match_count as f64)
        / proof.original_match_count as f64)
        * 100.0
}

fn digest_windows(windows: &[crate::tuning::types::TuningValidationWindow]) -> String {
    let encoded = serde_json::to_vec(windows).unwrap_or_default();
    hex::encode(Sha256::digest(encoded))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tuning::types::{TuningValidationProof, TuningValidationWindow};
    use chrono::{Duration, TimeZone, Utc};

    fn valid_proof() -> TuningValidationProof {
        let evaluation_start = Utc.with_ymd_and_hms(2026, 7, 9, 0, 0, 0).unwrap();
        let evaluation_end = evaluation_start + Duration::hours(24);
        let windows = vec![TuningValidationWindow {
            start: evaluation_start - Duration::minutes(4),
            end: evaluation_start + Duration::minutes(1),
        }];

        TuningValidationProof {
            proof_version: 1,
            original_query_sha256: "a".repeat(64),
            proposed_query_sha256: "b".repeat(64),
            dataset: "logs".to_string(),
            schedule_cron: "* * * * *".to_string(),
            lookback_minutes: 5,
            evaluation_start,
            evaluation_end,
            windows_sha256: digest_windows(&windows),
            windows,
            corpus_count: 1,
            corpus_sha256: "c".repeat(64),
            corpus_revision: 7,
            corpus_unique_source_count: 1,
            corpus_source_ids_sha256: "f".repeat(64),
            corpus_truncated: false,
            corpus_identity_complete: true,
            original_match_count: 100,
            proposed_match_count: 50,
            original_source_ids_sha256: "d".repeat(64),
            proposed_source_ids_sha256: "e".repeat(64),
            original_failed_windows: 0,
            proposed_failed_windows: 0,
            original_truncated_windows: 0,
            proposed_truncated_windows: 0,
            original_identity_errors: 0,
            proposed_identity_errors: 0,
            original_rows_examined: 100,
            proposed_rows_examined: 50,
            original_bytes_examined: 10_000,
            proposed_bytes_examined: 5_000,
            original_budget_exceeded: false,
            proposed_budget_exceeded: false,
            counts_exact: true,
            true_positives_preserved: true,
            identity_mode: "physical_id_uuid_v1".to_string(),
        }
    }

    #[test]
    fn complete_bound_proof_allows_autonomous_apply() {
        assert!(proof_allows_autonomous_apply(&valid_proof()));
    }

    #[test]
    fn altered_or_incomplete_proof_fails_closed() {
        let mut proof = valid_proof();
        proof.windows[0].end += Duration::minutes(1);
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.corpus_truncated = true;
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.corpus_revision = -1;
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.original_identity_errors = 1;
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.proposed_budget_exceeded = true;
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.original_rows_examined = MAX_AUTONOMOUS_TUNING_TOTAL_ROWS;
        proof.proposed_rows_examined = 1;
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.original_bytes_examined = MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW + 1;
        assert!(!proof_allows_autonomous_apply(&proof));

        let mut proof = valid_proof();
        proof.windows = vec![proof.windows[0].clone(); MAX_AUTONOMOUS_TUNING_WINDOWS + 1];
        proof.windows_sha256 = digest_windows(&proof.windows);
        assert!(!proof_allows_autonomous_apply(&proof));
    }
}
