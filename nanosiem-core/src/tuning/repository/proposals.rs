// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proposal operations for the tuning repository.

use super::{ProposalHistorySummary, TuningRepository};
use crate::models::AiTriageHints;
use crate::tuning::types::{HintsDiff, ProposalType, TuningProposal, TuningStatus};
use anyhow::{Context, Result};
use sqlx::Row;
use uuid::Uuid;

impl TuningRepository {
    /// Create a new tuning proposal
    ///
    /// # Arguments
    /// * `proposal` - The tuning proposal to create
    pub async fn create_proposal(&self, proposal: &TuningProposal) -> Result<()> {
        let affected_patterns_json = serde_json::to_value(&proposal.affected_patterns)
            .context("Failed to serialize affected patterns")?;

        let safety_validation_json = serde_json::to_value(&proposal.safety_validation)
            .context("Failed to serialize safety validation")?;

        let current_hints_json = proposal
            .current_hints
            .as_ref()
            .map(|h| serde_json::to_value(h))
            .transpose()
            .context("Failed to serialize current hints")?;

        let proposed_hints_json = proposal
            .proposed_hints
            .as_ref()
            .map(|h| serde_json::to_value(h))
            .transpose()
            .context("Failed to serialize proposed hints")?;

        let hints_diff_json = proposal
            .hints_diff
            .as_ref()
            .map(|d| serde_json::to_value(d))
            .transpose()
            .context("Failed to serialize hints diff")?;

        let changes_summary_json = serde_json::to_value(&proposal.changes_summary)
            .context("Failed to serialize changes summary")?;

        sqlx::query(
            r#"
            INSERT INTO tuning_proposals (
                id,
                rule_id,
                created_at,
                proposal_type,
                original_query,
                proposed_query,
                rationale,
                confidence_score,
                changes_summary,
                affected_patterns,
                safety_validation,
                status,
                current_hints,
                proposed_hints,
                hints_diff
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(&proposal.id)
        .bind(&proposal.rule_id)
        .bind(&proposal.created_at)
        .bind(proposal.proposal_type.to_string())
        .bind(&proposal.original_query)
        .bind(&proposal.proposed_query)
        .bind(&proposal.rationale)
        .bind(proposal.confidence_score)
        .bind(changes_summary_json)
        .bind(affected_patterns_json)
        .bind(safety_validation_json)
        .bind(proposal.status.to_string())
        .bind(current_hints_json)
        .bind(proposed_hints_json)
        .bind(hints_diff_json)
        .execute(&self.pool)
        .await
        .context(format!(
            "Failed to create tuning proposal for rule_id={}, proposal_id={}",
            proposal.rule_id, proposal.id
        ))?;

        Ok(())
    }

    /// Update proposal status
    ///
    /// # Arguments
    /// * `proposal_id` - The UUID of the proposal
    /// * `status` - The new status
    pub async fn update_proposal_status(
        &self,
        proposal_id: Uuid,
        status: TuningStatus,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET status = $1
            WHERE id = $2
            "#,
        )
        .bind(status.to_string())
        .bind(proposal_id)
        .execute(&self.pool)
        .await
        .context("Failed to update proposal status")?;

        Ok(())
    }

    /// Upgrade an open silent-rule proposal in place when the rule crosses to
    /// a higher tier (NAN-880). Updates the descriptive fields without
    /// resetting `created_at`, so the analyst sees how long the rule has been
    /// queued and that it just escalated.
    ///
    /// Caller is responsible for ensuring the proposal is still in
    /// `proposed` / `test_passed`; calling this on an actioned row is a no-op
    /// but technically allowed.
    pub async fn upgrade_silent_proposal(
        &self,
        proposal_id: Uuid,
        rationale: &str,
        confidence_score: f64,
        changes_summary: &[String],
    ) -> Result<()> {
        let changes_summary_json = serde_json::to_value(changes_summary)
            .context("Failed to serialize changes summary")?;

        sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET rationale = $1,
                confidence_score = $2,
                changes_summary = $3
            WHERE id = $4
            "#,
        )
        .bind(rationale)
        .bind(confidence_score)
        .bind(changes_summary_json)
        .bind(proposal_id)
        .execute(&self.pool)
        .await
        .context("Failed to upgrade silent proposal")?;

        Ok(())
    }

    /// List tuning proposals with optional filters
    ///
    /// # Arguments
    /// * `rule_id` - Optional rule ID filter
    /// * `status` - Optional status filter
    /// * `proposal_type` - Optional proposal type filter
    /// * `limit` - Maximum number of proposals to return
    /// * `offset` - Offset for pagination
    ///
    /// # Returns
    /// Vector of tuning proposals matching the filters
    pub async fn list_proposals(
        &self,
        rule_id: Option<Uuid>,
        status: Option<TuningStatus>,
        proposal_type: Option<ProposalType>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TuningProposal>> {
        let mut query = String::from(
            r#"
            SELECT
                id,
                rule_id,
                created_at,
                COALESCE(proposal_type, 'query_tuning') as proposal_type,
                original_query,
                proposed_query,
                rationale,
                confidence_score,
                changes_summary,
                affected_patterns,
                safety_validation,
                status,
                current_hints,
                proposed_hints,
                hints_diff
            FROM tuning_proposals
            WHERE 1=1
            "#,
        );

        let mut bindings: Vec<String> = vec![];
        let mut param_count = 1;

        if let Some(rid) = rule_id {
            query.push_str(&format!(" AND rule_id = ${}", param_count));
            bindings.push(rid.to_string());
            param_count += 1;
        }

        if let Some(s) = status {
            query.push_str(&format!(" AND status = ${}", param_count));
            bindings.push(s.to_string());
            param_count += 1;
        }

        if let Some(pt) = proposal_type {
            query.push_str(&format!(" AND proposal_type = ${}", param_count));
            bindings.push(pt.to_string());
            param_count += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count,
            param_count + 1
        ));

        let mut sqlx_query = sqlx::query(&query);

        for binding in bindings {
            sqlx_query = sqlx_query.bind(binding);
        }

        sqlx_query = sqlx_query.bind(limit).bind(offset);

        let rows = sqlx_query
            .fetch_all(&self.pool)
            .await
            .context("Failed to list tuning proposals")?;

        let mut proposals = Vec::new();
        for row in rows {
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

            let proposal_type_str: String = row.try_get("proposal_type")?;
            let proposal_type = proposal_type_str
                .parse::<ProposalType>()
                .unwrap_or(ProposalType::QueryTuning);

            let current_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("current_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let proposed_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("proposed_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let hints_diff: Option<HintsDiff> = row
                .try_get::<Option<serde_json::Value>, _>("hints_diff")?
                .and_then(|v| serde_json::from_value(v).ok());

            proposals.push(TuningProposal {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                created_at: row.try_get("created_at")?,
                proposal_type,
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
                status,
                current_hints,
                proposed_hints,
                hints_diff,
            });
        }

        Ok(proposals)
    }

    /// Get a specific tuning proposal by ID
    ///
    /// # Arguments
    /// * `proposal_id` - The UUID of the proposal
    ///
    /// # Returns
    /// The tuning proposal if found, None otherwise
    pub async fn get_proposal(&self, proposal_id: Uuid) -> Result<Option<TuningProposal>> {
        let row = sqlx::query(
            r#"
            SELECT
                id,
                rule_id,
                created_at,
                COALESCE(proposal_type, 'query_tuning') as proposal_type,
                original_query,
                proposed_query,
                rationale,
                confidence_score,
                changes_summary,
                affected_patterns,
                safety_validation,
                status,
                current_hints,
                proposed_hints,
                hints_diff
            FROM tuning_proposals
            WHERE id = $1
            "#,
        )
        .bind(proposal_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch tuning proposal")?;

        if let Some(row) = row {
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

            let proposal_type_str: String = row.try_get("proposal_type")?;
            let proposal_type = proposal_type_str
                .parse::<ProposalType>()
                .unwrap_or(ProposalType::QueryTuning);

            let current_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("current_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let proposed_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("proposed_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let hints_diff: Option<HintsDiff> = row
                .try_get::<Option<serde_json::Value>, _>("hints_diff")?
                .and_then(|v| serde_json::from_value(v).ok());

            Ok(Some(TuningProposal {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                created_at: row.try_get("created_at")?,
                proposal_type,
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
                status,
                current_hints,
                proposed_hints,
                hints_diff,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get proposal history for a rule, including reviewer notes.
    ///
    /// Used by tuning agents to learn from prior accepted/rejected proposals
    /// and avoid re-proposing rejected approaches.
    pub async fn get_proposal_history(
        &self,
        rule_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ProposalHistorySummary>> {
        let rows = sqlx::query(
            r#"
            SELECT status, rationale, confidence_score, proposed_query,
                   reviewer_notes, created_at
            FROM tuning_proposals
            WHERE rule_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(rule_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch proposal history")?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(ProposalHistorySummary {
                status: row.try_get("status")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                proposed_query: row.try_get("proposed_query")?,
                reviewer_notes: row.try_get("reviewer_notes")?,
                created_at: row.try_get("created_at")?,
            });
        }

        Ok(summaries)
    }

    /// Update reviewer notes on a proposal (set on approval/rejection).
    pub async fn set_reviewer_notes(&self, proposal_id: Uuid, notes: &str) -> Result<()> {
        sqlx::query("UPDATE tuning_proposals SET reviewer_notes = $1 WHERE id = $2")
            .bind(notes)
            .bind(proposal_id)
            .execute(&self.pool)
            .await
            .context("Failed to set reviewer notes")?;

        Ok(())
    }
}
