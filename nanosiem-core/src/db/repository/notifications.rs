// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notifications Repository
//!
//! Stores and retrieves user notifications from PostgreSQL.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::models::{NewNotification, Notification};

#[derive(Debug, Error)]
pub enum NotificationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Notification not found: {0}")]
    NotFound(Uuid),
}

/// Notifications repository
pub struct NotificationRepository {
    pool: PgPool,
}

impl NotificationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new notification
    pub async fn create(
        &self,
        notification: &NewNotification,
    ) -> Result<Notification, NotificationError> {
        let result = sqlx::query_as::<_, Notification>(
            r#"
            INSERT INTO notifications (user_id, notification_type, title, message, link, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(notification.user_id)
        .bind(notification.notification_type.to_string())
        .bind(&notification.title)
        .bind(&notification.message)
        .bind(&notification.link)
        .bind(&notification.metadata)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get notification by ID
    pub async fn get(&self, id: Uuid) -> Result<Notification, NotificationError> {
        let result = sqlx::query_as::<_, Notification>(
            r#"
            SELECT * FROM notifications WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotificationError::NotFound(id))?;

        Ok(result)
    }

    /// List notifications for a user
    pub async fn list_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
        unread_only: bool,
    ) -> Result<Vec<Notification>, NotificationError> {
        let notifications = if unread_only {
            sqlx::query_as::<_, Notification>(
                r#"
                SELECT * FROM notifications
                WHERE user_id = $1 AND read_at IS NULL
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, Notification>(
                r#"
                SELECT * FROM notifications
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(notifications)
    }

    /// Get unread notification count for a user
    pub async fn get_unread_count(&self, user_id: Uuid) -> Result<i64, NotificationError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM notifications
            WHERE user_id = $1 AND read_at IS NULL
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Mark a notification as read
    pub async fn mark_read(&self, id: Uuid) -> Result<Notification, NotificationError> {
        let result = sqlx::query_as::<_, Notification>(
            r#"
            UPDATE notifications
            SET read_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(NotificationError::NotFound(id))?;

        Ok(result)
    }

    /// Mark all notifications as read for a user
    pub async fn mark_all_read(&self, user_id: Uuid) -> Result<i64, NotificationError> {
        let result = sqlx::query(
            r#"
            UPDATE notifications
            SET read_at = NOW()
            WHERE user_id = $1 AND read_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Delete old notifications (for cleanup)
    pub async fn delete_old(&self, days: i64) -> Result<i64, NotificationError> {
        let result = sqlx::query(
            r#"
            DELETE FROM notifications
            WHERE created_at < NOW() - INTERVAL '1 day' * $1
            "#,
        )
        .bind(days)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }
}
