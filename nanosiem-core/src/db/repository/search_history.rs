// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search History Repository
//!
//! Stores and retrieves per-user search history from PostgreSQL.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SearchHistoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Search history entry not found: {0}")]
    NotFound(Uuid),
}

/// A search history entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SearchHistoryEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new search history entry
#[derive(Debug, Clone, Deserialize)]
pub struct NewSearchHistoryEntry {
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
}

/// Search history repository
pub struct SearchHistoryRepository {
    pool: PgPool,
}

impl SearchHistoryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Add a search to history for a user
    /// Automatically deduplicates consecutive identical queries
    pub async fn add(
        &self,
        user_id: Uuid,
        entry: &NewSearchHistoryEntry,
    ) -> Result<SearchHistoryEntry, SearchHistoryError> {
        let mut entry = entry.clone();
        entry.query = crate::inputlookup::storage_policy::redact_url_credentials(&entry.query);
        // Check if the most recent entry is the same query (dedup)
        let recent = sqlx::query_scalar::<_, String>(
            r#"
            SELECT query FROM search_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(last_query) = recent {
            if last_query == entry.query {
                // Return the existing entry instead of creating duplicate
                let existing = sqlx::query_as::<_, SearchHistoryEntry>(
                    r#"
                    SELECT * FROM search_history
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT 1
                    "#,
                )
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
                return Ok(existing);
            }
        }

        let result = sqlx::query_as::<_, SearchHistoryEntry>(
            r#"
            INSERT INTO search_history (user_id, query, query_mode, time_range_type, time_range_preset, time_range_start, time_range_end)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(&entry.query)
        .bind(&entry.query_mode)
        .bind(&entry.time_range_type)
        .bind(&entry.time_range_preset)
        .bind(entry.time_range_start)
        .bind(entry.time_range_end)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// List search history for a user (most recent first)
    pub async fn list(
        &self,
        user_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<SearchHistoryEntry>, SearchHistoryError> {
        let limit = limit.unwrap_or(100);

        let entries = sqlx::query_as::<_, SearchHistoryEntry>(
            r#"
            SELECT * FROM search_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    /// Delete a specific history entry (user must own it)
    pub async fn delete(&self, user_id: Uuid, entry_id: Uuid) -> Result<bool, SearchHistoryError> {
        let result = sqlx::query(
            r#"
            DELETE FROM search_history
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(entry_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Clear all history for a user
    pub async fn clear_all(&self, user_id: Uuid) -> Result<u64, SearchHistoryError> {
        let result = sqlx::query(
            r#"
            DELETE FROM search_history
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// History rows feeding search-autocomplete field ranking (NAN-3812).
    ///
    /// `Some(user)` reads that user's own piped queries (the "Recent" group);
    /// `None` reads every user's piped queries in this deployment (the
    /// "Popular" group). Open core is one tenant per deployment, so the
    /// deployment-wide read is the tenant-wide read. Callers keep only field
    /// names (see `search::field_usage`); query text never leaves the server.
    pub async fn field_usage_rows(
        &self,
        user_id: Option<Uuid>,
        limit: i64,
        window_days: i64,
    ) -> Result<Vec<crate::search::field_usage::FieldUsageRow>, SearchHistoryError> {
        let rows = sqlx::query_as::<_, crate::search::field_usage::FieldUsageRow>(
            r#"
            SELECT user_id, query, created_at FROM search_history
            WHERE query_mode = 'piped'
              AND created_at >= NOW() - make_interval(days => $3::int)
              AND ($1::uuid IS NULL OR user_id = $1)
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(window_days as i32)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Get user's history enabled preference
    pub async fn is_history_enabled(&self, user_id: Uuid) -> Result<bool, SearchHistoryError> {
        let enabled = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT search_history_enabled FROM users WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }

    /// Set user's history enabled preference
    pub async fn set_history_enabled(
        &self,
        user_id: Uuid,
        enabled: bool,
    ) -> Result<(), SearchHistoryError> {
        sqlx::query(
            r#"
            UPDATE users SET search_history_enabled = $1 WHERE id = $2
            "#,
        )
        .bind(enabled)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
