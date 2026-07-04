// SPDX-License-Identifier: AGPL-3.0-or-later

//! Create, read, update, and delete operations for detection rules

use uuid::Uuid;

use crate::models::{
    AlertMode, DetectionMode, DetectionRule, NewDetectionRule, RuleMode, UpdateDetectionRule,
};

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Create a new detection rule
    pub async fn create(
        &self,
        rule: &NewDetectionRule,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            INSERT INTO detection_rules (name, description, query, severity, mitre_tactics, mitre_techniques, schedule_cron, mode, narrative, reference_url, author, tags, ai_generated, realtime_enabled, risk_score, risk_entity_field, risk_modifiers, detection_mode, lookback_minutes, auto_tuning_enabled, auto_tuning_min_confidence, auto_tuning_critical, ai_triage_hints, folder, case_visibility, alert_mode, case_assigned_group, playbook_selector_mode, playbook_id, dataset)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
            RETURNING *
            "#,
        )
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(&rule.query)
        .bind(&rule.severity)
        .bind(rule.mitre_tactics.as_ref().unwrap_or(&vec![]))
        .bind(rule.mitre_techniques.as_ref().unwrap_or(&vec![]))
        .bind(&rule.schedule_cron)
        .bind(rule.mode.unwrap_or(RuleMode::Staging))
        .bind(&rule.narrative)
        .bind(&rule.reference_url)
        .bind(&rule.author)
        .bind(rule.tags.as_ref().unwrap_or(&vec![]))
        .bind(rule.ai_generated.unwrap_or(false))
        .bind(rule.realtime_enabled.unwrap_or(false))
        .bind(&rule.risk_score)
        .bind(&rule.risk_entity_field)
        .bind(sqlx::types::Json(rule.risk_modifiers.as_ref().unwrap_or(&vec![])))
        // detection_mode is NOT NULL with a DB default of 'scheduled'; binding the
        // raw Option would send an explicit NULL (overriding the default) and 500 on
        // a create that omits it. Default it here like alert_mode/realtime_enabled (NAN-1665).
        .bind(rule.detection_mode.unwrap_or(DetectionMode::Scheduled))
        .bind(&rule.lookback_minutes)
        .bind(rule.auto_tuning_enabled.unwrap_or(true))
        .bind(rule.auto_tuning_min_confidence.unwrap_or(0.8))
        .bind(rule.auto_tuning_critical.unwrap_or(false))
        .bind(sqlx::types::Json(rule.ai_triage_hints.clone().unwrap_or_default()))
        .bind(&rule.folder)
        .bind(rule.case_visibility.as_deref().unwrap_or("public"))
        .bind(rule.alert_mode.unwrap_or(AlertMode::Grouped))
        .bind(rule.case_assigned_group)
        .bind(rule.playbook_selector_mode.as_deref().unwrap_or("none"))
        .bind(rule.playbook_id)
        .bind(&rule.dataset)
        .fetch_one(&self.pool)
        .await?;

        // If case_visibility is 'group', add the group associations (batch insert)
        if rule.case_visibility.as_deref() == Some("group") {
            if let Some(ref group_ids) = rule.case_group_ids {
                if !group_ids.is_empty() {
                    sqlx::query(
                        r#"
                        INSERT INTO detection_rule_case_groups (rule_id, group_id)
                        SELECT $1, unnest($2::uuid[])
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(result.id)
                    .bind(group_ids)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        Self::notify_rule_change(&self.pool, result.id).await;

        Ok(result)
    }

    /// Find a detection rule by ID
    pub async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result =
            sqlx::query_as::<_, DetectionRule>(r#"SELECT * FROM detection_rules WHERE id = $1"#)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(DetectionRuleRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Update a detection rule with optimistic locking
    ///
    /// Uses the rule's current updated_at timestamp to detect concurrent modifications.
    /// If the rule was modified by another request between the read and update,
    /// returns ConcurrentModification error.
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateDetectionRule,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        // First fetch the rule to get its current updated_at for optimistic locking
        let existing = self.find_by_id(id).await?;

        // Update with optimistic locking - include updated_at in WHERE clause
        // If another request modified the rule, this will return no rows
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                query = COALESCE($4, query),
                severity = COALESCE($5, severity),
                mitre_tactics = COALESCE($6, mitre_tactics),
                mitre_techniques = COALESCE($7, mitre_techniques),
                schedule_cron = COALESCE($8, schedule_cron),
                mode = COALESCE($9, mode),
                narrative = COALESCE($10, narrative),
                reference_url = COALESCE($11, reference_url),
                author = COALESCE($12, author),
                tags = COALESCE($13, tags),
                ai_generated = COALESCE($14, ai_generated),
                realtime_enabled = COALESCE($15, realtime_enabled),
                detection_mode = COALESCE($16, detection_mode),
                materialized_view_name = COALESCE($17, materialized_view_name),
                risk_score = COALESCE($18, risk_score),
                risk_entity_field = COALESCE($19, risk_entity_field),
                risk_modifiers = COALESCE($20, risk_modifiers),
                archived = COALESCE($21, archived),
                lookback_minutes = COALESCE($22, lookback_minutes),
                auto_tuning_enabled = COALESCE($23, auto_tuning_enabled),
                auto_tuning_min_confidence = COALESCE($24, auto_tuning_min_confidence),
                auto_tuning_critical = COALESCE($25, auto_tuning_critical),
                ai_triage_hints = COALESCE($26, ai_triage_hints),
                folder = COALESCE($27, folder),
                case_visibility = COALESCE($28, case_visibility),
                alert_mode = COALESCE($29, alert_mode),
                case_assigned_group = $30,
                playbook_selector_mode = COALESCE($32, playbook_selector_mode),
                playbook_id = CASE
                    WHEN COALESCE($32, playbook_selector_mode) = 'specific'
                        THEN COALESCE($33, playbook_id)
                    ELSE NULL
                END,
                dataset = COALESCE($34, dataset),
                updated_at = NOW()
            WHERE id = $1 AND updated_at = $31
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.query)
        .bind(&update.severity)
        .bind(&update.mitre_tactics)
        .bind(&update.mitre_techniques)
        .bind(&update.schedule_cron)
        .bind(&update.mode)
        .bind(&update.narrative)
        .bind(&update.reference_url)
        .bind(&update.author)
        .bind(&update.tags)
        .bind(&update.ai_generated)
        .bind(&update.realtime_enabled)
        .bind(&update.detection_mode)
        .bind(&update.materialized_view_name)
        .bind(&update.risk_score)
        .bind(&update.risk_entity_field)
        .bind(update.risk_modifiers.as_ref().map(|m| sqlx::types::Json(m)))
        .bind(&update.archived)
        .bind(&update.lookback_minutes)
        .bind(&update.auto_tuning_enabled)
        .bind(&update.auto_tuning_min_confidence)
        .bind(&update.auto_tuning_critical)
        .bind(
            update
                .ai_triage_hints
                .as_ref()
                .map(|h| sqlx::types::Json(h)),
        )
        .bind(&update.folder)
        .bind(&update.case_visibility)
        .bind(&update.alert_mode)
        .bind(&update.case_assigned_group)
        .bind(existing.updated_at) // $31: optimistic locking timestamp
        .bind(&update.playbook_selector_mode) // $32
        .bind(&update.playbook_id) // $33
        .bind(&update.dataset) // $34
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DetectionRuleRepositoryError::ConcurrentModification(id))?;

        // If case_group_ids is provided, update the group associations atomically
        // Uses a CTE to delete and insert in a single atomic operation (race-condition safe)
        if let Some(ref group_ids) = update.case_group_ids {
            let visibility = update
                .case_visibility
                .as_deref()
                .unwrap_or(&result.case_visibility);
            if visibility == "group" && !group_ids.is_empty() {
                // Atomic delete + insert using CTE
                sqlx::query(
                    r#"
                    WITH deleted AS (
                        DELETE FROM detection_rule_case_groups WHERE rule_id = $1
                    )
                    INSERT INTO detection_rule_case_groups (rule_id, group_id)
                    SELECT $1, unnest($2::uuid[])
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(id)
                .bind(group_ids)
                .execute(&self.pool)
                .await?;
            } else {
                // Just clear existing group associations if not group visibility
                sqlx::query(r#"DELETE FROM detection_rule_case_groups WHERE rule_id = $1"#)
                    .bind(id)
                    .execute(&self.pool)
                    .await?;
            }
        }

        Self::notify_rule_change(&self.pool, id).await;

        Ok(result)
    }

    /// Delete a detection rule
    pub async fn delete(&self, id: Uuid) -> Result<(), DetectionRuleRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM detection_rules WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DetectionRuleRepositoryError::NotFound(id));
        }

        Self::notify_rule_change(&self.pool, id).await;

        Ok(())
    }
}
