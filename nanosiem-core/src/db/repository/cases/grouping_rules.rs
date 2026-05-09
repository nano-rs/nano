// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case grouping rule operations: list, get, create, update, delete

use uuid::Uuid;

use super::{
    CaseGroupingRule, CaseRepository, CaseRepositoryError, NewCaseGroupingRule,
    UpdateCaseGroupingRule,
};

impl CaseRepository {
    // ==================== GROUPING RULES ====================

    /// List all grouping rules
    pub async fn list_grouping_rules(&self) -> Result<Vec<CaseGroupingRule>, CaseRepositoryError> {
        let results = sqlx::query_as::<_, CaseGroupingRule>(
            r#"
            SELECT * FROM case_grouping_rules
            ORDER BY priority DESC, created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List enabled grouping rules by priority
    pub async fn list_enabled_grouping_rules(
        &self,
    ) -> Result<Vec<CaseGroupingRule>, CaseRepositoryError> {
        let results = sqlx::query_as::<_, CaseGroupingRule>(
            r#"
            SELECT * FROM case_grouping_rules
            WHERE enabled = true
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get a grouping rule by ID
    pub async fn get_grouping_rule(
        &self,
        id: Uuid,
    ) -> Result<CaseGroupingRule, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseGroupingRule>(
            r#"SELECT * FROM case_grouping_rules WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::GroupingRuleNotFound(id))?;

        Ok(result)
    }

    /// Create a grouping rule
    pub async fn create_grouping_rule(
        &self,
        rule: &NewCaseGroupingRule,
    ) -> Result<CaseGroupingRule, CaseRepositoryError> {
        let match_type_str = rule.match_type.to_string();
        let severity_rule_str = format!("{:?}", rule.case_severity_rule).to_lowercase();

        let result = sqlx::query_as::<_, CaseGroupingRule>(
            r#"
            INSERT INTO case_grouping_rules (
                name, description, enabled, priority, match_type, match_conditions,
                time_window_minutes, min_alerts, max_alerts, auto_create_case,
                case_title_template, case_severity_rule, auto_assign_to
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.enabled)
        .bind(rule.priority)
        .bind(&match_type_str)
        .bind(&rule.match_conditions)
        .bind(rule.time_window_minutes)
        .bind(rule.min_alerts)
        .bind(rule.max_alerts)
        .bind(rule.auto_create_case)
        .bind(&rule.case_title_template)
        .bind(&severity_rule_str)
        .bind(rule.auto_assign_to)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Update a grouping rule
    pub async fn update_grouping_rule(
        &self,
        id: Uuid,
        update: &UpdateCaseGroupingRule,
    ) -> Result<CaseGroupingRule, CaseRepositoryError> {
        let match_type_str = update.match_type.as_ref().map(|m| m.to_string());
        let severity_rule_str = update
            .case_severity_rule
            .as_ref()
            .map(|s| format!("{:?}", s).to_lowercase());

        let result = sqlx::query_as::<_, CaseGroupingRule>(
            r#"
            UPDATE case_grouping_rules SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                enabled = COALESCE($4, enabled),
                priority = COALESCE($5, priority),
                match_type = COALESCE($6, match_type),
                match_conditions = COALESCE($7, match_conditions),
                time_window_minutes = COALESCE($8, time_window_minutes),
                min_alerts = COALESCE($9, min_alerts),
                max_alerts = COALESCE($10, max_alerts),
                auto_create_case = COALESCE($11, auto_create_case),
                case_title_template = COALESCE($12, case_title_template),
                case_severity_rule = COALESCE($13, case_severity_rule),
                auto_assign_to = COALESCE($14, auto_assign_to),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(update.enabled)
        .bind(update.priority)
        .bind(&match_type_str)
        .bind(&update.match_conditions)
        .bind(update.time_window_minutes)
        .bind(update.min_alerts)
        .bind(update.max_alerts)
        .bind(update.auto_create_case)
        .bind(&update.case_title_template)
        .bind(&severity_rule_str)
        .bind(update.auto_assign_to)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::GroupingRuleNotFound(id))?;

        Ok(result)
    }

    /// Delete a grouping rule
    pub async fn delete_grouping_rule(&self, id: Uuid) -> Result<(), CaseRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM case_grouping_rules WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::GroupingRuleNotFound(id));
        }

        Ok(())
    }
}
