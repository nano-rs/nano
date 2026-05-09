// SPDX-License-Identifier: AGPL-3.0-or-later

//! Folder Settings Repository
//!
//! Per-folder display metadata (icon) for the rule-editor folder rail.
//! Folders themselves are derived from `detection_rules.folder` strings — this
//! table just stores presentation overrides keyed by folder name. Folders
//! without a row fall back to the frontend's default icon mapping.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FolderSettingsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// A persisted folder display setting.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct FolderSetting {
    pub name: String,
    pub icon: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Folder settings repository.
#[derive(Clone)]
pub struct FolderSettingsRepository {
    pool: PgPool,
}

impl FolderSettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List every folder setting. The table is small (one row per
    /// user-customized folder) and the API returns the whole map, so we
    /// don't bother with pagination.
    pub async fn list(&self) -> Result<Vec<FolderSetting>, FolderSettingsError> {
        let rows = sqlx::query_as::<_, FolderSetting>(
            "SELECT name, icon, created_at, updated_at \
             FROM folder_settings \
             ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Upsert a folder's icon. Returns the updated row.
    pub async fn set_icon(
        &self,
        name: &str,
        icon: &str,
    ) -> Result<FolderSetting, FolderSettingsError> {
        let row = sqlx::query_as::<_, FolderSetting>(
            "INSERT INTO folder_settings (name, icon) \
             VALUES ($1, $2) \
             ON CONFLICT (name) DO UPDATE \
             SET icon = EXCLUDED.icon, updated_at = NOW() \
             RETURNING name, icon, created_at, updated_at",
        )
        .bind(name)
        .bind(icon)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Delete a folder setting. Returns whether a row was actually removed
    /// (so handlers can audit "cleared" only when something changed).
    pub async fn delete(&self, name: &str) -> Result<bool, FolderSettingsError> {
        let res = sqlx::query("DELETE FROM folder_settings WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }
}
