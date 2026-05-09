// SPDX-License-Identifier: AGPL-3.0-or-later

//! User Recent Activity Repository
//!
//! Tracks recently viewed items (detections, alerts, cases, dashboards) per user
//! to power the "Continue Working" feature on the home dashboard.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RecentActivityError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Item types that can be tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecentItemType {
    Detection,
    Alert,
    Case,
    Dashboard,
}

impl RecentItemType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Alert => "alert",
            Self::Case => "case",
            Self::Dashboard => "dashboard",
        }
    }
}

impl std::fmt::Display for RecentItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A recent activity entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RecentActivityEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub item_type: String,
    pub item_id: Uuid,
    pub item_title: Option<String>,
    pub item_metadata: JsonValue,
    pub accessed_at: DateTime<Utc>,
}

/// Unified recent activity item for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentActivityItem {
    pub item_type: String,
    pub item_id: Uuid,
    pub title: String,
    pub metadata: JsonValue,
    pub accessed_at: DateTime<Utc>,
}

impl From<RecentActivityEntry> for RecentActivityItem {
    fn from(entry: RecentActivityEntry) -> Self {
        Self {
            item_type: entry.item_type,
            item_id: entry.item_id,
            title: entry.item_title.unwrap_or_else(|| "Untitled".to_string()),
            metadata: entry.item_metadata,
            accessed_at: entry.accessed_at,
        }
    }
}

/// Recent activity repository
pub struct RecentActivityRepository {
    pool: PgPool,
}

impl RecentActivityRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a user viewing an item
    /// Uses upsert to update timestamp if already exists, with automatic pruning
    pub async fn record(
        &self,
        user_id: Uuid,
        item_type: RecentItemType,
        item_id: Uuid,
        item_title: Option<&str>,
        item_metadata: Option<JsonValue>,
    ) -> Result<(), RecentActivityError> {
        // Use the database function for atomic upsert + pruning
        sqlx::query(
            r#"
            SELECT record_user_activity($1, $2, $3, $4, $5)
            "#,
        )
        .bind(user_id)
        .bind(item_type.as_str())
        .bind(item_id)
        .bind(item_title)
        .bind(item_metadata.unwrap_or(JsonValue::Object(serde_json::Map::new())))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all recent activity for a user (most recent first)
    /// Returns items across all types, interleaved by time
    pub async fn get_all(
        &self,
        user_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<RecentActivityItem>, RecentActivityError> {
        let limit = limit.unwrap_or(20);

        let entries = sqlx::query_as::<_, RecentActivityEntry>(
            r#"
            SELECT * FROM user_recent_activity
            WHERE user_id = $1
            ORDER BY accessed_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries.into_iter().map(Into::into).collect())
    }

    /// Get recent activity for a specific item type
    pub async fn get_by_type(
        &self,
        user_id: Uuid,
        item_type: RecentItemType,
        limit: Option<i64>,
    ) -> Result<Vec<RecentActivityItem>, RecentActivityError> {
        let limit = limit.unwrap_or(10);

        let entries = sqlx::query_as::<_, RecentActivityEntry>(
            r#"
            SELECT * FROM user_recent_activity
            WHERE user_id = $1 AND item_type = $2
            ORDER BY accessed_at DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(item_type.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries.into_iter().map(Into::into).collect())
    }

    /// Remove a specific item from history (e.g., when item is deleted)
    pub async fn remove(
        &self,
        item_type: RecentItemType,
        item_id: Uuid,
    ) -> Result<u64, RecentActivityError> {
        let result = sqlx::query(
            r#"
            DELETE FROM user_recent_activity
            WHERE item_type = $1 AND item_id = $2
            "#,
        )
        .bind(item_type.as_str())
        .bind(item_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Clear all activity for a user
    pub async fn clear_all(&self, user_id: Uuid) -> Result<u64, RecentActivityError> {
        let result = sqlx::query(
            r#"
            DELETE FROM user_recent_activity
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Cleanup old entries (called by scheduler)
    pub async fn cleanup_old(&self) -> Result<i32, RecentActivityError> {
        let count = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT cleanup_old_user_activity()
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }
}
