// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case workflow persistence (NAN-415).
//!
//! Backs the first-class close-note / escalation / handoff / workflow-event
//! tables introduced in migration 152. Sibling to `CaseRepository`; share a
//! PgPool so callers can hold one cloneable service that routes both.

use sqlx::PgPool;
use uuid::Uuid;

use super::CaseRepositoryError;
use crate::models::case::{
    CaseCloseNote, CaseEscalation, CaseHandoff, CaseWorkflowEvent, NewCaseCloseNote,
    NewCaseEscalation, NewCaseHandoff, NewCaseWorkflowEvent,
};

/// Repository for case workflow tables (close notes, escalations, handoffs,
/// workflow events). Distinct from `CaseRepository` to keep each file bounded.
#[derive(Clone)]
pub struct CaseWorkflowRepository {
    pool: PgPool,
}

impl CaseWorkflowRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ==================== CLOSE NOTES ====================

    /// Insert a new close note, superseding any currently-active note for the
    /// same case in a single transaction.
    pub async fn insert_close_note(
        &self,
        note: &NewCaseCloseNote,
    ) -> Result<CaseCloseNote, CaseRepositoryError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE case_close_notes
               SET superseded_at = NOW()
             WHERE case_id = $1
               AND superseded_at IS NULL
            "#,
        )
        .bind(note.case_id)
        .execute(&mut *tx)
        .await?;

        let result = sqlx::query_as::<_, CaseCloseNote>(
            r#"
            INSERT INTO case_close_notes (
                case_id, created_by, close_reason, title, summary, emits,
                tuning_action, escalation_target, duplicate_primary_case_number,
                duplicate_primary_case_id, ack_audit, audit_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING *
            "#,
        )
        .bind(note.case_id)
        .bind(note.created_by)
        .bind(&note.close_reason)
        .bind(&note.title)
        .bind(&note.summary)
        .bind(&note.emits)
        .bind(&note.tuning_action)
        .bind(&note.escalation_target)
        .bind(note.duplicate_primary_case_number)
        .bind(note.duplicate_primary_case_id)
        .bind(note.ack_audit)
        .bind(&note.audit_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(result)
    }

    /// Fetch the currently-active (non-superseded) close note for a case.
    pub async fn get_active_close_note(
        &self,
        case_id: Uuid,
    ) -> Result<Option<CaseCloseNote>, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseCloseNote>(
            r#"
            SELECT * FROM case_close_notes
             WHERE case_id = $1
               AND superseded_at IS NULL
             LIMIT 1
            "#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Mark the currently-active close note (if any) as superseded. Used on
    /// reopen when no new close note replaces the old one.
    pub async fn supersede_active_close_note(
        &self,
        case_id: Uuid,
    ) -> Result<(), CaseRepositoryError> {
        sqlx::query(
            r#"
            UPDATE case_close_notes
               SET superseded_at = NOW()
             WHERE case_id = $1
               AND superseded_at IS NULL
            "#,
        )
        .bind(case_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ==================== ESCALATIONS ====================

    /// Insert a new structured escalation record.
    pub async fn insert_escalation(
        &self,
        escalation: &NewCaseEscalation,
    ) -> Result<CaseEscalation, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseEscalation>(
            r#"
            INSERT INTO case_escalations (
                case_id, source_user_id, target_user_id, target_group_id,
                target_label, reason, previous_assigned_to, previous_assigned_group
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(escalation.case_id)
        .bind(escalation.source_user_id)
        .bind(escalation.target_user_id)
        .bind(escalation.target_group_id)
        .bind(&escalation.target_label)
        .bind(&escalation.reason)
        .bind(escalation.previous_assigned_to)
        .bind(escalation.previous_assigned_group)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// List escalations for a case, newest first.
    pub async fn list_escalations(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<CaseEscalation>, CaseRepositoryError> {
        let results = sqlx::query_as::<_, CaseEscalation>(
            r#"
            SELECT * FROM case_escalations
             WHERE case_id = $1
             ORDER BY created_at DESC
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    // ==================== HANDOFFS ====================

    /// Insert a new handoff record (state defaults to 'pending').
    pub async fn insert_handoff(
        &self,
        handoff: &NewCaseHandoff,
    ) -> Result<CaseHandoff, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseHandoff>(
            r#"
            INSERT INTO case_handoffs (
                case_id, source_user_id, target_user_id, target_group_id,
                target_label, reason, context_payload
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(handoff.case_id)
        .bind(handoff.source_user_id)
        .bind(handoff.target_user_id)
        .bind(handoff.target_group_id)
        .bind(&handoff.target_label)
        .bind(&handoff.reason)
        .bind(&handoff.context_payload)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// List handoffs for a case, newest first.
    pub async fn list_handoffs(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<CaseHandoff>, CaseRepositoryError> {
        let results = sqlx::query_as::<_, CaseHandoff>(
            r#"
            SELECT * FROM case_handoffs
             WHERE case_id = $1
             ORDER BY created_at DESC
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Accept a pending handoff. Scoped by case_id so a handoff from a
    /// different case can't be mutated through this case's endpoint
    /// (defense in depth — the handlers also gate on case access).
    pub async fn accept_handoff(
        &self,
        case_id: Uuid,
        handoff_id: Uuid,
        accepting_user: Uuid,
    ) -> Result<CaseHandoff, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseHandoff>(
            r#"
            UPDATE case_handoffs
               SET state = 'accepted',
                   accepted_at = NOW(),
                   accepted_by = $3
             WHERE id = $1
               AND case_id = $2
               AND state = 'pending'
             RETURNING *
            "#,
        )
        .bind(handoff_id)
        .bind(case_id)
        .bind(accepting_user)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            CaseRepositoryError::InvalidStateTransition(format!(
                "handoff {handoff_id} on case {case_id} is not in pending state"
            ))
        })?;

        Ok(result)
    }

    /// Bounce a pending handoff with a reason. Scoped by case_id.
    pub async fn bounce_handoff(
        &self,
        case_id: Uuid,
        handoff_id: Uuid,
        bouncing_user: Uuid,
        reason: &str,
    ) -> Result<CaseHandoff, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseHandoff>(
            r#"
            UPDATE case_handoffs
               SET state = 'bounced',
                   bounced_at = NOW(),
                   bounced_by = $3,
                   bounce_reason = $4
             WHERE id = $1
               AND case_id = $2
               AND state = 'pending'
             RETURNING *
            "#,
        )
        .bind(handoff_id)
        .bind(case_id)
        .bind(bouncing_user)
        .bind(reason)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            CaseRepositoryError::InvalidStateTransition(format!(
                "handoff {handoff_id} on case {case_id} is not in pending state"
            ))
        })?;

        Ok(result)
    }

    /// Cancel a pending handoff (source-initiated withdrawal). Scoped by case_id.
    pub async fn cancel_handoff(
        &self,
        case_id: Uuid,
        handoff_id: Uuid,
    ) -> Result<CaseHandoff, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseHandoff>(
            r#"
            UPDATE case_handoffs
               SET state = 'canceled',
                   canceled_at = NOW()
             WHERE id = $1
               AND case_id = $2
               AND state = 'pending'
             RETURNING *
            "#,
        )
        .bind(handoff_id)
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            CaseRepositoryError::InvalidStateTransition(format!(
                "handoff {handoff_id} on case {case_id} is not in pending state"
            ))
        })?;

        Ok(result)
    }

    /// Fetch a single handoff scoped to its case. Used for permission checks;
    /// rejects cross-case lookups (handoff UUID from Case B cannot be read
    /// through Case A's endpoint).
    pub async fn find_handoff_by_id(
        &self,
        case_id: Uuid,
        handoff_id: Uuid,
    ) -> Result<CaseHandoff, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseHandoff>(
            r#"SELECT * FROM case_handoffs WHERE id = $1 AND case_id = $2"#,
        )
        .bind(handoff_id)
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(handoff_id))?;

        Ok(result)
    }

    // ==================== WORKFLOW EVENTS ====================

    /// Insert a workflow event (the audit spine for the workflow bar).
    pub async fn insert_workflow_event(
        &self,
        event: &NewCaseWorkflowEvent,
    ) -> Result<CaseWorkflowEvent, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseWorkflowEvent>(
            r#"
            INSERT INTO case_workflow_events (
                case_id, actor_id, event_kind, from_status, to_status,
                reason, metadata, close_note_id, escalation_id, handoff_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(event.case_id)
        .bind(event.actor_id)
        .bind(&event.event_kind)
        .bind(&event.from_status)
        .bind(&event.to_status)
        .bind(&event.reason)
        .bind(&event.metadata)
        .bind(event.close_note_id)
        .bind(event.escalation_id)
        .bind(event.handoff_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Insert a `mention_added` workflow event idempotently. Returns the new
    /// row when this is the first mention of `mentioned_user_id` on the case;
    /// returns `None` when a prior mention already exists (the partial unique
    /// index in migration 160 enforces this — `ON CONFLICT DO NOTHING` swallows
    /// the duplicate so callers can fire the notification side-effect on every
    /// mention but only emit one thread row per (case, mentioned user)).
    pub async fn insert_mention_event_idempotent(
        &self,
        case_id: Uuid,
        mentioner_user_id: Uuid,
        mentioner_name: &str,
        mentioned_user_id: Uuid,
        mentioned_name: &str,
    ) -> Result<Option<CaseWorkflowEvent>, CaseRepositoryError> {
        let metadata = serde_json::json!({
            "mentioned_user_id": mentioned_user_id.to_string(),
            "mentioned_name": mentioned_name,
            "mentioner_user_id": mentioner_user_id.to_string(),
            "mentioner_name": mentioner_name,
        });

        let result = sqlx::query_as::<_, CaseWorkflowEvent>(
            r#"
            INSERT INTO case_workflow_events (
                case_id, actor_id, event_kind, metadata
            )
            VALUES ($1, $2, 'mention_added', $3)
            ON CONFLICT DO NOTHING
            RETURNING *
            "#,
        )
        .bind(case_id)
        .bind(mentioner_user_id)
        .bind(&metadata)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// List workflow events for a case, newest first, limited.
    pub async fn list_workflow_events(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<Vec<CaseWorkflowEvent>, CaseRepositoryError> {
        let results = sqlx::query_as::<_, CaseWorkflowEvent>(
            r#"
            SELECT * FROM case_workflow_events
             WHERE case_id = $1
             ORDER BY created_at DESC
             LIMIT $2
            "#,
        )
        .bind(case_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
