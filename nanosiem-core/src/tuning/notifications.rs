// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notification Service for AI Detection Auto-Tuning
//!
//! Sends notifications to admins and detection engineers about tuning activities.
//! Requirements: 7.1, 7.2, 7.3, 7.4

use crate::auth::repository::groups::GroupRepository;
use crate::tuning::types::{
    Notification, NotificationType, StagingDeployment, TestResults, TuningProposal,
};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

/// Error types for notification operations
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Group not found: {0}")]
    GroupNotFound(String),

    #[error("Invalid notification type: {0}")]
    InvalidType(String),
}

/// Service for managing tuning notifications
pub struct NotificationService {
    db_pool: PgPool,
    group_repo: Arc<GroupRepository>,
}

impl NotificationService {
    /// Create a new notification service
    pub fn new(db_pool: PgPool) -> Self {
        let group_repo = Arc::new(GroupRepository::new(db_pool.clone()));
        Self {
            db_pool,
            group_repo,
        }
    }

    /// Notify when auto-tuning is triggered
    /// Requirements: 7.1, 7.2, 7.3
    pub async fn notify_tuning_triggered(
        &self,
        proposal: &TuningProposal,
        rule_name: &str,
        breach_reason: &str,
    ) -> Result<Vec<Uuid>, NotificationError> {
        let title = format!("Auto-Tuning Triggered: {}", rule_name);
        let message = format!(
            "Detection rule '{}' has triggered auto-tuning due to {}. \
            Confidence: {:.0}%. Proposed changes: {}",
            rule_name,
            breach_reason,
            proposal.confidence_score * 100.0,
            proposal.changes_summary.join(", ")
        );
        let link = format!("/tuning/{}", proposal.id);

        self.send_to_admin_groups(
            NotificationType::TuningTriggered,
            &title,
            &message,
            &link,
            Some(proposal.id),
        )
        .await
    }

    /// Notify when validation testing completes
    /// Requirements: 7.2, 7.3
    pub async fn notify_validation_complete(
        &self,
        proposal: &TuningProposal,
        results: &TestResults,
        rule_name: &str,
    ) -> Result<Vec<Uuid>, NotificationError> {
        let fully_passed = results.validation_passed && results.true_positives_preserved;
        let status = if fully_passed { "PASSED" } else { "FAILED" };

        let title = format!("Validation {}: {}", status, rule_name);
        let message = format!(
            "Tuning validation for '{}' has {}. \
            Alert reduction: {:.1}% ({} → {}). \
            True positives preserved: {}",
            rule_name,
            if fully_passed { "passed" } else { "failed" },
            results.reduction_percentage,
            results.original_alert_count,
            results.tuned_alert_count,
            if results.true_positives_preserved {
                "Yes"
            } else {
                "No"
            }
        );
        let link = format!("/tuning/{}", proposal.id);

        self.send_to_admin_groups(
            NotificationType::ValidationComplete,
            &title,
            &message,
            &link,
            Some(proposal.id),
        )
        .await
    }

    /// Notify when tuning is deployed to staging
    /// Requirements: 7.2, 7.3
    pub async fn notify_staging_deployed(
        &self,
        deployment: &StagingDeployment,
        rule_name: &str,
    ) -> Result<Vec<Uuid>, NotificationError> {
        let title = format!("Staging Deployed: {}", rule_name);
        let message = format!(
            "Tuning for '{}' has been deployed to staging. \
            Monitoring period ends at {}. \
            Review and approve to promote to production.",
            rule_name,
            deployment.staging_ends_at.format("%Y-%m-%d %H:%M UTC")
        );
        let link = format!("/tuning/{}", deployment.proposal_id);

        self.send_to_admin_groups(
            NotificationType::StagingDeployed,
            &title,
            &message,
            &link,
            Some(deployment.proposal_id),
        )
        .await
    }

    /// Notify when tuning is promoted to production
    /// Requirements: 7.4
    pub async fn notify_promoted(
        &self,
        deployment: &StagingDeployment,
        rule_name: &str,
    ) -> Result<Vec<Uuid>, NotificationError> {
        let title = format!("Promoted to Production: {}", rule_name);
        let message = format!(
            "Tuning for '{}' has been promoted to production. \
            The new rule version is now active.",
            rule_name
        );
        let link = format!("/tuning/{}", deployment.proposal_id);

        self.send_to_admin_groups(
            NotificationType::Promoted,
            &title,
            &message,
            &link,
            Some(deployment.proposal_id),
        )
        .await
    }

    /// Notify when tuning is reverted
    /// Requirements: 7.4
    pub async fn notify_reverted(
        &self,
        proposal_id: Uuid,
        rule_name: &str,
        reason: &str,
        _reverted_by: Option<Uuid>,
    ) -> Result<Vec<Uuid>, NotificationError> {
        let title = format!("Tuning Reverted: {}", rule_name);
        let message = format!(
            "Tuning for '{}' has been reverted. Reason: {}. \
            Auto-tuning will be disabled for this rule for 7 days.",
            rule_name, reason
        );
        let link = format!("/tuning/{}", proposal_id);

        self.send_to_admin_groups(
            NotificationType::Reverted,
            &title,
            &message,
            &link,
            Some(proposal_id),
        )
        .await
    }

    /// Get pending notifications for a user
    /// Requirements: 7.5, 10.1
    pub async fn get_pending_notifications(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Notification>, NotificationError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                user_id,
                notification_type,
                title,
                message,
                link,
                created_at,
                read_at
            FROM notifications
            WHERE user_id = $1 AND read_at IS NULL
              AND notification_type LIKE 'tuning_%'
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;

        let notifications = rows
            .into_iter()
            .map(|row| Self::row_to_notification(row))
            .collect();

        Ok(notifications)
    }

    /// Get all notifications for a user (including read ones)
    pub async fn get_user_notifications(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Notification>, NotificationError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                user_id,
                notification_type,
                title,
                message,
                link,
                created_at,
                read_at
            FROM notifications
            WHERE user_id = $1
              AND notification_type LIKE 'tuning_%'
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        let notifications = rows
            .into_iter()
            .map(|row| Self::row_to_notification(row))
            .collect();

        Ok(notifications)
    }

    /// Mark a notification as read
    pub async fn mark_as_read(&self, notification_id: Uuid) -> Result<(), NotificationError> {
        sqlx::query(
            r#"
            UPDATE notifications
            SET read_at = NOW()
            WHERE id = $1 AND read_at IS NULL
            "#,
        )
        .bind(notification_id)
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Mark all tuning notifications as read for a user
    pub async fn mark_all_as_read(&self, user_id: Uuid) -> Result<i64, NotificationError> {
        let result = sqlx::query(
            r#"
            UPDATE notifications
            SET read_at = NOW()
            WHERE user_id = $1 AND read_at IS NULL
              AND notification_type LIKE 'tuning_%'
            "#,
        )
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Get count of unread tuning notifications for a user
    pub async fn get_unread_count(&self, user_id: Uuid) -> Result<i64, NotificationError> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM notifications
            WHERE user_id = $1 AND read_at IS NULL
              AND notification_type LIKE 'tuning_%'
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;

        let count: i64 = row.get("count");
        Ok(count)
    }

    /// Map a database row from the `notifications` table to the tuning `Notification` type
    fn row_to_notification(row: sqlx::postgres::PgRow) -> Notification {
        let notification_type_str: String = row.get("notification_type");
        let notification_type = match notification_type_str.as_str() {
            "tuning_triggered" => NotificationType::TuningTriggered,
            "tuning_validation_complete" => NotificationType::ValidationComplete,
            "tuning_staging_deployed" => NotificationType::StagingDeployed,
            "tuning_promoted" => NotificationType::Promoted,
            "tuning_reverted" => NotificationType::Reverted,
            // Legacy values from old tuning_notifications table
            "validation_complete" => NotificationType::ValidationComplete,
            "staging_deployed" => NotificationType::StagingDeployed,
            "promoted" => NotificationType::Promoted,
            "reverted" => NotificationType::Reverted,
            _ => NotificationType::TuningTriggered, // Default fallback
        };

        let message: Option<String> = row.get("message");
        let link: Option<String> = row.get("link");

        Notification {
            id: row.get("id"),
            user_id: row.get("user_id"),
            notification_type,
            title: row.get("title"),
            message: message.unwrap_or_default(),
            link: link.unwrap_or_default(),
            created_at: row.get("created_at"),
            read_at: row.get("read_at"),
        }
    }

    /// Send notification to admin and detection engineer groups
    /// Requirements: 7.1
    async fn send_to_admin_groups(
        &self,
        notification_type: NotificationType,
        title: &str,
        message: &str,
        link: &str,
        tuning_log_id: Option<Uuid>,
    ) -> Result<Vec<Uuid>, NotificationError> {
        // Get users with Admin role (via direct assignment or group membership)
        let admin_users = self.get_users_with_role("Admin").await?;
        // Get users from Detection Engineers group (user-created group)
        let engineer_users = self.get_group_users_by_name("Detection Engineers").await?;

        // Combine and deduplicate users
        let mut all_users = admin_users;
        for user in engineer_users {
            if !all_users.contains(&user) {
                all_users.push(user);
            }
        }

        // Send notification to each user
        let mut notification_ids = Vec::new();
        for user_id in all_users {
            let notification_id = self
                .create_notification(
                    user_id,
                    notification_type,
                    title,
                    message,
                    link,
                    tuning_log_id,
                )
                .await?;
            notification_ids.push(notification_id);
        }

        Ok(notification_ids)
    }

    /// Get all user IDs from a group by name
    async fn get_group_users_by_name(
        &self,
        group_name: &str,
    ) -> Result<Vec<Uuid>, NotificationError> {
        // First, get the group ID by name
        let group_row = sqlx::query(
            r#"
            SELECT id
            FROM groups
            WHERE name = $1
            "#,
        )
        .bind(group_name)
        .fetch_optional(&self.db_pool)
        .await?;

        let group_id = match group_row {
            Some(row) => row.get::<Uuid, _>("id"),
            None => {
                // Group doesn't exist, return empty list (not an error)
                return Ok(Vec::new());
            }
        };

        // Get all users in the group
        let users = self
            .group_repo
            .get_group_members(group_id)
            .await
            .map_err(|e| NotificationError::Database(sqlx::Error::Protocol(e.to_string())))?;

        Ok(users.into_iter().map(|u| u.id).collect())
    }

    /// Get all user IDs who have a specific role
    /// Finds users who have the role through group membership (via user_groups -> group_roles)
    async fn get_users_with_role(&self, role_name: &str) -> Result<Vec<Uuid>, NotificationError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT u.id
            FROM users u
            WHERE u.status = 'active'
              AND EXISTS (
                  SELECT 1 FROM user_groups ug
                  JOIN group_roles gr ON gr.group_id = ug.group_id
                  JOIN roles r ON r.id = gr.role_id
                  WHERE ug.user_id = u.id AND r.name = $1
              )
            "#,
        )
        .bind(role_name)
        .fetch_all(&self.db_pool)
        .await?;

        Ok(rows.iter().map(|r| r.get("id")).collect())
    }

    /// Create a notification record in the main notifications table
    async fn create_notification(
        &self,
        user_id: Uuid,
        notification_type: NotificationType,
        title: &str,
        message: &str,
        link: &str,
        tuning_log_id: Option<Uuid>,
    ) -> Result<Uuid, NotificationError> {
        let type_str = notification_type.to_string();
        let metadata = match tuning_log_id {
            Some(id) => serde_json::json!({ "tuning_log_id": id }),
            None => serde_json::json!({}),
        };

        let notification_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO notifications (
                user_id, notification_type, title, message, link, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(user_id)
        .bind(type_str)
        .bind(title)
        .bind(message)
        .bind(link)
        .bind(metadata)
        .fetch_one(&self.db_pool)
        .await?;

        Ok(notification_id)
    }

    /// Process pending notifications (batching)
    ///
    /// This method is called by the scheduler to batch and send pending notifications.
    /// Currently, notifications are sent immediately when created, so this method
    /// just returns the count of unread notifications across all users.
    ///
    /// In a future enhancement, this could batch notifications and send them via email.
    ///
    /// # Returns
    /// * `usize` - Number of pending notifications processed
    pub async fn process_pending_notifications(&self) -> Result<usize, NotificationError> {
        // Count all unread tuning notifications
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM notifications
            WHERE read_at IS NULL
              AND notification_type LIKE 'tuning_%'
            "#,
        )
        .fetch_one(&self.db_pool)
        .await?;

        let count: i64 = row.get("count");

        // In a future enhancement, this is where we would:
        // 1. Group notifications by user
        // 2. Send batched email notifications
        // 3. Mark notifications as sent

        // For now, we just return the count
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_type_display() {
        assert_eq!(
            NotificationType::TuningTriggered.to_string(),
            "tuning_triggered"
        );
        assert_eq!(
            NotificationType::ValidationComplete.to_string(),
            "tuning_validation_complete"
        );
        assert_eq!(
            NotificationType::StagingDeployed.to_string(),
            "tuning_staging_deployed"
        );
        assert_eq!(NotificationType::Promoted.to_string(), "tuning_promoted");
        assert_eq!(NotificationType::Reverted.to_string(), "tuning_reverted");
    }
}
