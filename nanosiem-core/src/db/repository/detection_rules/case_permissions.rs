// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case visibility and group association management for detection rules

use uuid::Uuid;

use crate::models::{DetectionRule, SharedGroup, UpdateRuleCasePermissionsRequest};

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Get groups that cases from this rule will be shared with
    pub async fn get_case_groups(
        &self,
        rule_id: Uuid,
    ) -> Result<Vec<SharedGroup>, DetectionRuleRepositoryError> {
        let groups = sqlx::query_as::<_, SharedGroup>(
            r#"
            SELECT g.id, g.name
            FROM groups g
            JOIN detection_rule_case_groups drcg ON drcg.group_id = g.id
            WHERE drcg.rule_id = $1
            ORDER BY g.name
            "#,
        )
        .bind(rule_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(groups)
    }

    /// Update case permissions for a rule
    pub async fn update_case_permissions(
        &self,
        id: Uuid,
        request: &UpdateRuleCasePermissionsRequest,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        // First check if rule exists
        self.find_by_id(id).await?;

        // Update visibility and assigned group
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules
            SET case_visibility = $2, case_assigned_group = $3, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&request.case_visibility)
        .bind(request.case_assigned_group)
        .fetch_one(&self.pool)
        .await?;

        // Update group associations atomically using CTE (race-condition safe)
        if request.case_visibility == "group" {
            if let Some(ref group_ids) = request.case_group_ids {
                if !group_ids.is_empty() {
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
                    // Clear if empty list provided
                    sqlx::query(r#"DELETE FROM detection_rule_case_groups WHERE rule_id = $1"#)
                        .bind(id)
                        .execute(&self.pool)
                        .await?;
                }
            }
        } else {
            // Clear existing group associations if not group visibility
            sqlx::query(r#"DELETE FROM detection_rule_case_groups WHERE rule_id = $1"#)
                .bind(id)
                .execute(&self.pool)
                .await?;
        }

        Ok(result)
    }
}
