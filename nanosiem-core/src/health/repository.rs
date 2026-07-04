// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health issue tracking repository

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::types::HealthIssue;

#[derive(Error, Debug)]
pub enum HealthRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Issue not found: {0}")]
    NotFound(String),
}

pub struct HealthRepository {
    pool: PgPool,
}

impl HealthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find an active (unresolved) issue by type and key
    pub async fn find_active_issue(
        &self,
        issue_type: &str,
        issue_key: &str,
    ) -> Result<Option<HealthIssue>, HealthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, issue_type, issue_key, first_detected_at, resolved_at, notification_sent
            FROM health_issue_tracker
            WHERE issue_type = $1 AND issue_key = $2 AND resolved_at IS NULL
            "#,
        )
        .bind(issue_type)
        .bind(issue_key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| HealthIssue {
            id: r.get("id"),
            issue_type: r.get("issue_type"),
            issue_key: r.get("issue_key"),
            first_detected_at: r.get("first_detected_at"),
            resolved_at: r.get("resolved_at"),
            notification_sent: r.get("notification_sent"),
        }))
    }

    /// Create a new health issue
    pub async fn create_issue(
        &self,
        issue_type: &str,
        issue_key: &str,
    ) -> Result<HealthIssue, HealthRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO health_issue_tracker (issue_type, issue_key)
            VALUES ($1, $2)
            ON CONFLICT (issue_type, issue_key) DO UPDATE
                SET resolved_at = NULL, first_detected_at = NOW(), notification_sent = false
            RETURNING id, issue_type, issue_key, first_detected_at, resolved_at, notification_sent
            "#,
        )
        .bind(issue_type)
        .bind(issue_key)
        .fetch_one(&self.pool)
        .await?;

        Ok(HealthIssue {
            id: row.get("id"),
            issue_type: row.get("issue_type"),
            issue_key: row.get("issue_key"),
            first_detected_at: row.get("first_detected_at"),
            resolved_at: row.get("resolved_at"),
            notification_sent: row.get("notification_sent"),
        })
    }

    /// Mark an issue as resolved
    pub async fn resolve_issue(
        &self,
        issue_type: &str,
        issue_key: &str,
    ) -> Result<(), HealthRepositoryError> {
        sqlx::query(
            r#"
            UPDATE health_issue_tracker
            SET resolved_at = NOW()
            WHERE issue_type = $1 AND issue_key = $2 AND resolved_at IS NULL
            "#,
        )
        .bind(issue_type)
        .bind(issue_key)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark that a notification was sent for an issue
    pub async fn mark_notification_sent(
        &self,
        issue_id: Uuid,
    ) -> Result<(), HealthRepositoryError> {
        sqlx::query(
            r#"
            UPDATE health_issue_tracker
            SET notification_sent = true
            WHERE id = $1
            "#,
        )
        .bind(issue_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List all active issues
    pub async fn list_active_issues(&self) -> Result<Vec<HealthIssue>, HealthRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, issue_type, issue_key, first_detected_at, resolved_at, notification_sent
            FROM health_issue_tracker
            WHERE resolved_at IS NULL
            ORDER BY first_detected_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| HealthIssue {
                id: r.get("id"),
                issue_type: r.get("issue_type"),
                issue_key: r.get("issue_key"),
                first_detected_at: r.get("first_detected_at"),
                resolved_at: r.get("resolved_at"),
                notification_sent: r.get("notification_sent"),
            })
            .collect())
    }

    /// Get users with the Admin role for notifications
    /// Finds users who have Admin role through group membership (via user_groups -> group_roles)
    pub async fn get_admin_user_ids(&self) -> Result<Vec<Uuid>, HealthRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT u.id
            FROM users u
            WHERE u.status = 'active'
              AND EXISTS (
                  SELECT 1 FROM user_groups ug
                  JOIN group_roles gr ON gr.group_id = ug.group_id
                  JOIN roles r ON r.id = gr.role_id
                  WHERE ug.user_id = u.id AND r.name = 'Admin'
              )
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(|r| r.get("id")).collect())
    }

    /// Check if AI provider monitoring is enabled in system settings
    pub async fn is_ai_monitoring_enabled(&self) -> Result<bool, HealthRepositoryError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(ai_monitoring_enabled, false) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        // Missing settings row → disabled. AI provider monitoring polls the
        // provider on a schedule and costs API tokens, so it must be opt-in;
        // defaulting a missing row to enabled re-introduced the token drain
        // this setting is meant to gate (NAN-1685).
        .unwrap_or(false);

        Ok(enabled)
    }

    /// Check if feed staleness monitoring is enabled in system settings
    pub async fn is_feed_monitoring_enabled(&self) -> Result<bool, HealthRepositoryError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(feed_monitoring_enabled, true) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }
}
