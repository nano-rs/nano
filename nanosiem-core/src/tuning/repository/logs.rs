// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log entry operations for the tuning repository.

use super::TuningRepository;
use crate::tuning::types::{
    ProposalType, TestResults, TuningLogEntry, TuningProposal, TuningStatus,
};
use anyhow::{Context, Result};
use sqlx::Row;
use uuid::Uuid;

impl TuningRepository {
    /// Create a new tuning log entry
    ///
    /// Persists a tuning activity to the audit log with all relevant information
    /// including the proposal, test results, and current status.
    ///
    /// # Arguments
    /// * `entry` - The tuning log entry to create
    ///
    /// # Returns
    /// The UUID of the created log entry
    pub async fn create_log_entry(&self, entry: TuningLogEntry) -> Result<Uuid> {
        // Validate serialization (but don't use the results since we store references)
        let _proposal_json =
            serde_json::to_value(&entry.proposal).context("Failed to serialize proposal")?;

        let _test_results_json = entry
            .test_results
            .as_ref()
            .map(|tr| serde_json::to_value(tr))
            .transpose()
            .context("Failed to serialize test results")?;

        let _staging_deployment_json = entry
            .staging_deployment
            .as_ref()
            .map(|sd| serde_json::to_value(sd))
            .transpose()
            .context("Failed to serialize staging deployment")?;

        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO tuning_logs (
                id,
                rule_id,
                rule_name,
                triggered_at,
                trigger_reason,
                proposal_id,
                test_results_id,
                applied_version_id,
                status,
                reverted_at,
                reverted_by,
                reverted_to_version_id,
                revert_reason
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id
            "#,
        )
        .bind(&entry.id)
        .bind(&entry.rule_id)
        .bind(&entry.rule_name)
        .bind(&entry.triggered_at)
        .bind(&entry.trigger_reason)
        .bind(&entry.proposal.id)
        .bind(entry.test_results.as_ref().map(|tr| tr.proposal_id))
        .bind(entry.staging_deployment.as_ref().map(|sd| sd.version_id))
        .bind(entry.status.to_string())
        .bind(&entry.reverted_at)
        .bind(&entry.reverted_by)
        .bind(
            entry
                .staging_deployment
                .as_ref()
                .and_then(|sd| entry.reverted_at.map(|_| sd.version_id)),
        )
        .bind(&entry.revert_reason)
        .fetch_one(&self.pool)
        .await
        .context("Failed to create tuning log entry")?;

        Ok(id)
    }

    /// Get a tuning log entry by ID
    ///
    /// Retrieves a complete tuning log entry including the proposal, test results,
    /// and staging deployment information.
    ///
    /// # Arguments
    /// * `id` - The UUID of the log entry to retrieve
    ///
    /// # Returns
    /// The tuning log entry if found, None otherwise
    pub async fn get_log_entry(&self, id: Uuid) -> Result<Option<TuningLogEntry>> {
        let row = sqlx::query(
            r#"
            SELECT
                tl.id,
                tl.rule_id,
                tl.rule_name,
                tl.triggered_at,
                tl.trigger_reason,
                tl.status,
                tl.reverted_at,
                tl.reverted_by,
                tl.revert_reason,
                tp.id as proposal_id,
                tp.created_at as proposal_created_at,
                tp.original_query,
                tp.proposed_query,
                tp.rationale,
                tp.confidence_score,
                tp.changes_summary,
                tp.affected_patterns,
                tp.safety_validation,
                ttr.id as test_id,
                ttr.tested_at,
                ttr.original_alert_count,
                ttr.tuned_alert_count,
                ttr.reduction_percentage,
                ttr.true_positives_preserved,
                ttr.validation_passed,
                ttr.comparison_metrics
            FROM tuning_logs tl
            INNER JOIN tuning_proposals tp ON tl.proposal_id = tp.id
            LEFT JOIN tuning_test_results ttr ON tl.test_results_id = ttr.id
            WHERE tl.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch tuning log entry")?;

        if let Some(row) = row {
            let proposal = TuningProposal {
                id: row.try_get("proposal_id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: None,
                created_at: row.try_get("proposal_created_at")?,
                proposal_type: ProposalType::QueryTuning,
                original_query: row.try_get("original_query")?,
                proposed_query: row.try_get("proposed_query")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                changes_summary: serde_json::from_value(row.try_get("changes_summary")?)
                    .context("Failed to deserialize changes_summary")?,
                affected_patterns: serde_json::from_value(row.try_get("affected_patterns")?)
                    .context("Failed to deserialize affected_patterns")?,
                safety_validation: serde_json::from_value(row.try_get("safety_validation")?)
                    .context("Failed to deserialize safety_validation")?,
                status: TuningStatus::Proposed, // Default status for historical records
                current_hints: None,
                proposed_hints: None,
                hints_diff: None,
            };

            let test_results = if let Ok(_test_id) = row.try_get::<Uuid, _>("test_id") {
                Some(TestResults {
                    proposal_id: row.try_get("proposal_id")?,
                    tested_at: row.try_get("tested_at")?,
                    original_alert_count: row.try_get("original_alert_count")?,
                    tuned_alert_count: row.try_get("tuned_alert_count")?,
                    reduction_percentage: row.try_get("reduction_percentage")?,
                    true_positives_preserved: row.try_get("true_positives_preserved")?,
                    validation_passed: row.try_get("validation_passed")?,
                    comparison_metrics: serde_json::from_value(row.try_get("comparison_metrics")?)
                        .context("Failed to deserialize comparison_metrics")?,
                })
            } else {
                None
            };

            let status_str: String = row.try_get("status")?;
            let status = match status_str.as_str() {
                "proposed" => TuningStatus::Proposed,
                "testing" => TuningStatus::Testing,
                "test_passed" => TuningStatus::TestPassed,
                "test_failed" => TuningStatus::TestFailed,
                "staging" => TuningStatus::Staging,
                "promoted" => TuningStatus::Promoted,
                "reverted" => TuningStatus::Reverted,
                "manually_approved" => TuningStatus::ManuallyApproved,
                "rejected" => TuningStatus::Rejected,
                _ => TuningStatus::Proposed,
            };

            Ok(Some(TuningLogEntry {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: row.try_get("rule_name")?,
                triggered_at: row.try_get("triggered_at")?,
                trigger_reason: row.try_get("trigger_reason")?,
                proposal,
                test_results,
                staging_deployment: None, // TODO: Implement staging deployment retrieval
                status,
                reverted_at: row.try_get("reverted_at")?,
                reverted_by: row.try_get("reverted_by")?,
                revert_reason: row.try_get("revert_reason")?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get all tuning log entries for a specific rule
    ///
    /// Returns the complete tuning history for a detection rule, ordered by
    /// most recent first.
    ///
    /// # Arguments
    /// * `rule_id` - The UUID of the rule
    ///
    /// # Returns
    /// Vector of tuning log entries for the rule
    pub async fn get_logs_for_rule(&self, rule_id: Uuid) -> Result<Vec<TuningLogEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT
                tl.id,
                tl.rule_id,
                tl.rule_name,
                tl.triggered_at,
                tl.trigger_reason,
                tl.status,
                tl.reverted_at,
                tl.reverted_by,
                tl.revert_reason,
                tp.id as proposal_id,
                tp.created_at as proposal_created_at,
                tp.original_query,
                tp.proposed_query,
                tp.rationale,
                tp.confidence_score,
                tp.changes_summary,
                tp.affected_patterns,
                tp.safety_validation,
                ttr.id as test_id,
                ttr.tested_at,
                ttr.original_alert_count,
                ttr.tuned_alert_count,
                ttr.reduction_percentage,
                ttr.true_positives_preserved,
                ttr.validation_passed,
                ttr.comparison_metrics
            FROM tuning_logs tl
            INNER JOIN tuning_proposals tp ON tl.proposal_id = tp.id
            LEFT JOIN tuning_test_results ttr ON tl.test_results_id = ttr.id
            WHERE tl.rule_id = $1
            ORDER BY tl.triggered_at DESC
            "#,
        )
        .bind(rule_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch tuning logs for rule")?;

        let mut entries = Vec::new();
        for row in rows {
            let proposal = TuningProposal {
                id: row.try_get("proposal_id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: None,
                created_at: row.try_get("proposal_created_at")?,
                proposal_type: ProposalType::QueryTuning,
                original_query: row.try_get("original_query")?,
                proposed_query: row.try_get("proposed_query")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                changes_summary: serde_json::from_value(row.try_get("changes_summary")?)
                    .context("Failed to deserialize changes_summary")?,
                affected_patterns: serde_json::from_value(row.try_get("affected_patterns")?)
                    .context("Failed to deserialize affected_patterns")?,
                safety_validation: serde_json::from_value(row.try_get("safety_validation")?)
                    .context("Failed to deserialize safety_validation")?,
                status: TuningStatus::Proposed, // Default status for historical records
                current_hints: None,
                proposed_hints: None,
                hints_diff: None,
            };

            let test_results = if let Ok(_test_id) = row.try_get::<Uuid, _>("test_id") {
                Some(TestResults {
                    proposal_id: row.try_get("proposal_id")?,
                    tested_at: row.try_get("tested_at")?,
                    original_alert_count: row.try_get("original_alert_count")?,
                    tuned_alert_count: row.try_get("tuned_alert_count")?,
                    reduction_percentage: row.try_get("reduction_percentage")?,
                    true_positives_preserved: row.try_get("true_positives_preserved")?,
                    validation_passed: row.try_get("validation_passed")?,
                    comparison_metrics: serde_json::from_value(row.try_get("comparison_metrics")?)
                        .context("Failed to deserialize comparison_metrics")?,
                })
            } else {
                None
            };

            let status_str: String = row.try_get("status")?;
            let status = match status_str.as_str() {
                "proposed" => TuningStatus::Proposed,
                "testing" => TuningStatus::Testing,
                "test_passed" => TuningStatus::TestPassed,
                "test_failed" => TuningStatus::TestFailed,
                "staging" => TuningStatus::Staging,
                "promoted" => TuningStatus::Promoted,
                "reverted" => TuningStatus::Reverted,
                "manually_approved" => TuningStatus::ManuallyApproved,
                "rejected" => TuningStatus::Rejected,
                _ => TuningStatus::Proposed,
            };

            entries.push(TuningLogEntry {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: row.try_get("rule_name")?,
                triggered_at: row.try_get("triggered_at")?,
                trigger_reason: row.try_get("trigger_reason")?,
                proposal,
                test_results,
                staging_deployment: None,
                status,
                reverted_at: row.try_get("reverted_at")?,
                reverted_by: row.try_get("reverted_by")?,
                revert_reason: row.try_get("revert_reason")?,
            });
        }

        Ok(entries)
    }

    /// Get recent tuning log entries across all rules
    ///
    /// Returns the most recent tuning activities for display in dashboards
    /// and summary views.
    ///
    /// # Arguments
    /// * `limit` - Maximum number of entries to return
    ///
    /// # Returns
    /// Vector of recent tuning log entries
    pub async fn get_recent_logs(&self, limit: i32) -> Result<Vec<TuningLogEntry>> {
        let rows = sqlx::query(
            r#"
            SELECT
                tl.id,
                tl.rule_id,
                tl.rule_name,
                tl.triggered_at,
                tl.trigger_reason,
                tl.status,
                tl.reverted_at,
                tl.reverted_by,
                tl.revert_reason,
                tp.id as proposal_id,
                tp.created_at as proposal_created_at,
                tp.original_query,
                tp.proposed_query,
                tp.rationale,
                tp.confidence_score,
                tp.changes_summary,
                tp.affected_patterns,
                tp.safety_validation,
                ttr.id as test_id,
                ttr.tested_at,
                ttr.original_alert_count,
                ttr.tuned_alert_count,
                ttr.reduction_percentage,
                ttr.true_positives_preserved,
                ttr.validation_passed,
                ttr.comparison_metrics
            FROM tuning_logs tl
            INNER JOIN tuning_proposals tp ON tl.proposal_id = tp.id
            LEFT JOIN tuning_test_results ttr ON tl.test_results_id = ttr.id
            ORDER BY tl.triggered_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch recent tuning logs")?;

        let mut entries = Vec::new();
        for row in rows {
            let proposal = TuningProposal {
                id: row.try_get("proposal_id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: None,
                created_at: row.try_get("proposal_created_at")?,
                proposal_type: ProposalType::QueryTuning,
                original_query: row.try_get("original_query")?,
                proposed_query: row.try_get("proposed_query")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                changes_summary: serde_json::from_value(row.try_get("changes_summary")?)
                    .context("Failed to deserialize changes_summary")?,
                affected_patterns: serde_json::from_value(row.try_get("affected_patterns")?)
                    .context("Failed to deserialize affected_patterns")?,
                safety_validation: serde_json::from_value(row.try_get("safety_validation")?)
                    .context("Failed to deserialize safety_validation")?,
                status: TuningStatus::Proposed, // Default status for historical records
                current_hints: None,
                proposed_hints: None,
                hints_diff: None,
            };

            let test_results = if let Ok(_test_id) = row.try_get::<Uuid, _>("test_id") {
                Some(TestResults {
                    proposal_id: row.try_get("proposal_id")?,
                    tested_at: row.try_get("tested_at")?,
                    original_alert_count: row.try_get("original_alert_count")?,
                    tuned_alert_count: row.try_get("tuned_alert_count")?,
                    reduction_percentage: row.try_get("reduction_percentage")?,
                    true_positives_preserved: row.try_get("true_positives_preserved")?,
                    validation_passed: row.try_get("validation_passed")?,
                    comparison_metrics: serde_json::from_value(row.try_get("comparison_metrics")?)
                        .context("Failed to deserialize comparison_metrics")?,
                })
            } else {
                None
            };

            let status_str: String = row.try_get("status")?;
            let status = match status_str.as_str() {
                "proposed" => TuningStatus::Proposed,
                "testing" => TuningStatus::Testing,
                "test_passed" => TuningStatus::TestPassed,
                "test_failed" => TuningStatus::TestFailed,
                "staging" => TuningStatus::Staging,
                "promoted" => TuningStatus::Promoted,
                "reverted" => TuningStatus::Reverted,
                "manually_approved" => TuningStatus::ManuallyApproved,
                "rejected" => TuningStatus::Rejected,
                _ => TuningStatus::Proposed,
            };

            entries.push(TuningLogEntry {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: row.try_get("rule_name")?,
                triggered_at: row.try_get("triggered_at")?,
                trigger_reason: row.try_get("trigger_reason")?,
                proposal,
                test_results,
                staging_deployment: None,
                status,
                reverted_at: row.try_get("reverted_at")?,
                reverted_by: row.try_get("reverted_by")?,
                revert_reason: row.try_get("revert_reason")?,
            });
        }

        Ok(entries)
    }

    /// Update the status of a tuning log entry
    ///
    /// Updates the status as the tuning progresses through different stages
    /// (proposed -> testing -> test_passed -> staging -> promoted).
    ///
    /// # Arguments
    /// * `id` - The UUID of the log entry to update
    /// * `status` - The new status
    ///
    /// # Returns
    /// Ok(()) if successful
    pub async fn update_log_status(&self, id: Uuid, status: TuningStatus) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tuning_logs
            SET status = $1
            WHERE id = $2
            "#,
        )
        .bind(status.to_string())
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update tuning log status")?;

        Ok(())
    }

    /// Update revert information for a tuning log entry
    ///
    /// Records when a tuning was reverted, who reverted it, and why.
    ///
    /// # Arguments
    /// * `id` - The UUID of the log entry to update
    /// * `reverted_by` - The UUID of the user who performed the revert
    /// * `revert_reason` - The reason for the revert
    ///
    /// # Returns
    /// Ok(()) if successful
    pub async fn update_revert_info(
        &self,
        id: Uuid,
        reverted_by: Uuid,
        revert_reason: String,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tuning_logs
            SET
                status = 'reverted',
                reverted_at = NOW(),
                reverted_by = $1,
                revert_reason = $2
            WHERE id = $3
            "#,
        )
        .bind(reverted_by)
        .bind(revert_reason)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update revert information")?;

        Ok(())
    }
}
