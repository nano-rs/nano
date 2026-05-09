// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case alert operations: add, remove, get alerts for a case

use uuid::Uuid;

use super::{AddAlertToCase, CaseAlert, CaseAlertDetail, CaseRepository, CaseRepositoryError};

impl CaseRepository {
    // ==================== CASE ALERTS ====================

    /// Add an alert to a case
    ///
    /// Uses INSERT ON CONFLICT to atomically prevent duplicates (race-condition safe)
    /// All operations are wrapped in a transaction to ensure consistency.
    pub async fn add_alert(
        &self,
        case_id: Uuid,
        add: &AddAlertToCase,
    ) -> Result<CaseAlert, CaseRepositoryError> {
        // Start transaction to ensure all updates are atomic
        let mut tx = self.pool.begin().await?;

        // Atomic insert with conflict detection - no race condition window
        let result = sqlx::query_as::<_, CaseAlert>(
            r#"
            INSERT INTO case_alerts (case_id, alert_id, added_by, is_primary)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (case_id, alert_id) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(case_id)
        .bind(add.alert_id)
        .bind(add.added_by)
        .bind(add.is_primary)
        .fetch_optional(&mut *tx)
        .await?;

        let result = match result {
            Some(case_alert) => case_alert,
            None => return Err(CaseRepositoryError::AlertAlreadyInCase),
        };

        // Update alert's case_id reference
        sqlx::query(r#"UPDATE alerts SET case_id = $1 WHERE id = $2"#)
            .bind(case_id)
            .bind(add.alert_id)
            .execute(&mut *tx)
            .await?;

        // Update case timestamps
        sqlx::query(
            r#"
            UPDATE cases SET
                updated_at = NOW(),
                last_activity_at = NOW(),
                first_activity_at = COALESCE(first_activity_at, NOW())
            WHERE id = $1
            "#,
        )
        .bind(case_id)
        .execute(&mut *tx)
        .await?;

        // Commit transaction
        tx.commit().await?;

        Ok(result)
    }

    /// Remove an alert from a case
    ///
    /// All operations are wrapped in a transaction to ensure consistency.
    pub async fn remove_alert(
        &self,
        case_id: Uuid,
        alert_id: Uuid,
    ) -> Result<(), CaseRepositoryError> {
        // Start transaction to ensure all updates are atomic
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query(r#"DELETE FROM case_alerts WHERE case_id = $1 AND alert_id = $2"#)
            .bind(case_id)
            .bind(alert_id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::AlertNotFound(alert_id));
        }

        // Clear alert's case_id reference
        sqlx::query(r#"UPDATE alerts SET case_id = NULL WHERE id = $1"#)
            .bind(alert_id)
            .execute(&mut *tx)
            .await?;

        // Update case timestamps to reflect modification
        sqlx::query(r#"UPDATE cases SET updated_at = NOW() WHERE id = $1"#)
            .bind(case_id)
            .execute(&mut *tx)
            .await?;

        // Commit transaction
        tx.commit().await?;

        Ok(())
    }

    /// Get alerts for a case
    pub async fn get_case_alerts(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<CaseAlertDetail>, CaseRepositoryError> {
        let results = sqlx::query_as::<_, CaseAlertDetail>(
            r#"
            SELECT
                ca.id, ca.alert_id, a.rule_id, r.name as rule_name, a.severity, a.status,
                a.disposition, a.matched_event_count, a.created_at, ca.added_at,
                ca.is_primary, t.verdict_type as triage_verdict, t.confidence as triage_confidence,
                r.risk_score as score_contribution,
                COALESCE(r.mitre_tactics, ARRAY[]::text[]) as mitre_tactics
            FROM case_alerts ca
            JOIN alerts a ON ca.alert_id = a.id
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN LATERAL (
                SELECT verdict_type, confidence
                FROM alert_triage_results
                WHERE alert_id = a.id AND status = 'completed'
                ORDER BY created_at DESC
                LIMIT 1
            ) t ON true
            WHERE ca.case_id = $1
            ORDER BY ca.is_primary DESC, a.created_at DESC
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
