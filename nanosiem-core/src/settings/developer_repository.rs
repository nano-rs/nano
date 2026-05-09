// SPDX-License-Identifier: AGPL-3.0-or-later

//! Developer Settings Repository
//!
//! Provides access to developer settings for controlling background schedulers.
//! These settings allow disabling schedulers during development to prevent
//! ClickHouse Cloud from being kept alive unnecessarily.

use sqlx::PgPool;
use thiserror::Error;

/// Errors that can occur when working with developer settings
#[derive(Debug, Error)]
pub enum DeveloperSettingsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// All scheduler settings combined
#[derive(Debug, Clone)]
pub struct SchedulerSettings {
    pub detection_scheduler_enabled: bool,
    pub tuning_scheduler_enabled: bool,
    pub enrichment_sync_scheduler_enabled: bool,
    pub custom_enrichment_scheduler_enabled: bool,
    pub ai_monitoring_enabled: bool,
    pub feed_monitoring_enabled: bool,
    pub model_catalog_sync_scheduler_enabled: bool,
}

impl Default for SchedulerSettings {
    fn default() -> Self {
        Self {
            detection_scheduler_enabled: true,
            tuning_scheduler_enabled: true,
            enrichment_sync_scheduler_enabled: true,
            custom_enrichment_scheduler_enabled: true,
            ai_monitoring_enabled: false,
            feed_monitoring_enabled: true,
            model_catalog_sync_scheduler_enabled: true,
        }
    }
}

/// Repository for developer settings
#[derive(Clone)]
pub struct DeveloperSettingsRepository {
    pool: PgPool,
}

impl DeveloperSettingsRepository {
    /// Create a new developer settings repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get all scheduler settings
    pub async fn get_scheduler_settings(
        &self,
    ) -> Result<SchedulerSettings, DeveloperSettingsError> {
        let row = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool, bool)>(
            r#"
            SELECT
                COALESCE(detection_scheduler_enabled, true),
                COALESCE(tuning_scheduler_enabled, true),
                COALESCE(enrichment_sync_scheduler_enabled, true),
                COALESCE(custom_enrichment_scheduler_enabled, true),
                COALESCE(ai_monitoring_enabled, false),
                COALESCE(feed_monitoring_enabled, true),
                COALESCE(model_catalog_sync_scheduler_enabled, true)
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            Some((detection, tuning, enrichment, custom, ai, feed, model_catalog)) => {
                SchedulerSettings {
                    detection_scheduler_enabled: detection,
                    tuning_scheduler_enabled: tuning,
                    enrichment_sync_scheduler_enabled: enrichment,
                    custom_enrichment_scheduler_enabled: custom,
                    ai_monitoring_enabled: ai,
                    feed_monitoring_enabled: feed,
                    model_catalog_sync_scheduler_enabled: model_catalog,
                }
            }
            None => SchedulerSettings::default(),
        })
    }

    /// Check if the detection scheduler is enabled
    pub async fn is_detection_scheduler_enabled(&self) -> Result<bool, DeveloperSettingsError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(detection_scheduler_enabled, true) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }

    /// Check if the tuning scheduler is enabled
    pub async fn is_tuning_scheduler_enabled(&self) -> Result<bool, DeveloperSettingsError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(tuning_scheduler_enabled, true) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }

    /// Check if the enrichment sync scheduler is enabled
    pub async fn is_enrichment_sync_scheduler_enabled(
        &self,
    ) -> Result<bool, DeveloperSettingsError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(enrichment_sync_scheduler_enabled, true) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }

    /// Check if the custom enrichment scheduler is enabled
    pub async fn is_custom_enrichment_scheduler_enabled(
        &self,
    ) -> Result<bool, DeveloperSettingsError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(custom_enrichment_scheduler_enabled, true) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }

    /// Check if the model catalog sync scheduler is enabled
    pub async fn is_model_catalog_sync_scheduler_enabled(
        &self,
    ) -> Result<bool, DeveloperSettingsError> {
        let enabled: bool = sqlx::query_scalar(
            "SELECT COALESCE(model_catalog_sync_scheduler_enabled, true) FROM system_settings WHERE id = 'default'"
        )
        .fetch_optional(&self.pool)
        .await?
        .unwrap_or(true);

        Ok(enabled)
    }

    /// Update scheduler settings (partial update - only updates provided fields)
    pub async fn update_scheduler_settings(
        &self,
        detection: Option<bool>,
        tuning: Option<bool>,
        enrichment_sync: Option<bool>,
        custom_enrichment: Option<bool>,
    ) -> Result<SchedulerSettings, DeveloperSettingsError> {
        // Update each field if provided
        if let Some(enabled) = detection {
            sqlx::query(
                "UPDATE system_settings SET detection_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
            )
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        }

        if let Some(enabled) = tuning {
            sqlx::query(
                "UPDATE system_settings SET tuning_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
            )
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        }

        if let Some(enabled) = enrichment_sync {
            sqlx::query(
                "UPDATE system_settings SET enrichment_sync_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
            )
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        }

        if let Some(enabled) = custom_enrichment {
            sqlx::query(
                "UPDATE system_settings SET custom_enrichment_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
            )
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        }

        // Return the updated settings
        self.get_scheduler_settings().await
    }
}
