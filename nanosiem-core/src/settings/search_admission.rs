// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search admission control settings
//!
//! Admin-configurable settings for search query concurrency limits
//! and per-priority ClickHouse resource settings. Stored in the
//! `system_settings` table, overriding env var defaults.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Search admission control configuration
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchAdmissionConfig {
    // Admission limits
    /// Maximum concurrent ad-hoc queries (1-500, default 30)
    pub global_adhoc_limit: u32,
    /// Maximum concurrent queries per user (1-50, default 5)
    pub per_user_limit: u32,
    /// Maximum queue depth (10-1000, default 100)
    pub max_queue_depth: u32,
    /// Queue timeout in seconds (10-600, default 120)
    pub queue_timeout_seconds: u32,

    // Per-priority ClickHouse settings
    /// Interactive: max execution time in seconds (30-3600, default 300)
    pub interactive_max_execution_time: u32,
    /// Interactive: max memory in GB (1-100, default 20)
    pub interactive_max_memory_gb: u32,
    /// Analytics: max execution time in seconds (60-7200, default 3600)
    pub analytics_max_execution_time: u32,
    /// Analytics: max memory in GB (5-200, default 50)
    pub analytics_max_memory_gb: u32,
    /// Realtime/Detection: max execution time in seconds (5-120, default 30)
    pub realtime_max_execution_time: u32,
    /// Realtime/Detection: max memory in GB (1-20, default 5)
    pub realtime_max_memory_gb: u32,
}

impl Default for SearchAdmissionConfig {
    fn default() -> Self {
        Self {
            global_adhoc_limit: 30,
            per_user_limit: 5,
            max_queue_depth: 100,
            // NAN-714: aligned with interactive_max_execution_time below.
            queue_timeout_seconds: 300,
            interactive_max_execution_time: 300,
            interactive_max_memory_gb: 20,
            analytics_max_execution_time: 3600,
            analytics_max_memory_gb: 50,
            realtime_max_execution_time: 30,
            realtime_max_memory_gb: 5,
        }
    }
}

/// Errors for search admission settings operations
#[derive(Debug, thiserror::Error)]
pub enum SearchAdmissionSettingsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Repository for search admission settings in system_settings table
pub struct SearchAdmissionSettings {
    pool: PgPool,
}

impl SearchAdmissionSettings {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get current search admission configuration
    pub async fn get_config(&self) -> Result<SearchAdmissionConfig, SearchAdmissionSettingsError> {
        let row = sqlx::query_as::<_, (i32, i32, i32, i32, i32, i32, i32, i32, i32, i32)>(
            r#"
            SELECT
                search_global_adhoc_limit,
                search_per_user_limit,
                search_max_queue_depth,
                search_queue_timeout_seconds,
                search_interactive_max_execution_time,
                search_interactive_max_memory_gb,
                search_analytics_max_execution_time,
                search_analytics_max_memory_gb,
                search_realtime_max_execution_time,
                search_realtime_max_memory_gb
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((
                global_adhoc_limit,
                per_user_limit,
                max_queue_depth,
                queue_timeout_seconds,
                interactive_max_execution_time,
                interactive_max_memory_gb,
                analytics_max_execution_time,
                analytics_max_memory_gb,
                realtime_max_execution_time,
                realtime_max_memory_gb,
            )) => Ok(SearchAdmissionConfig {
                global_adhoc_limit: global_adhoc_limit as u32,
                per_user_limit: per_user_limit as u32,
                max_queue_depth: max_queue_depth as u32,
                queue_timeout_seconds: queue_timeout_seconds as u32,
                interactive_max_execution_time: interactive_max_execution_time as u32,
                interactive_max_memory_gb: interactive_max_memory_gb as u32,
                analytics_max_execution_time: analytics_max_execution_time as u32,
                analytics_max_memory_gb: analytics_max_memory_gb as u32,
                realtime_max_execution_time: realtime_max_execution_time as u32,
                realtime_max_memory_gb: realtime_max_memory_gb as u32,
            }),
            None => Ok(SearchAdmissionConfig::default()),
        }
    }

    /// Update search admission configuration
    pub async fn update_config(
        &self,
        config: SearchAdmissionConfig,
    ) -> Result<SearchAdmissionConfig, SearchAdmissionSettingsError> {
        self.validate(&config)?;

        sqlx::query(
            r#"
            UPDATE system_settings SET
                search_global_adhoc_limit = $1,
                search_per_user_limit = $2,
                search_max_queue_depth = $3,
                search_queue_timeout_seconds = $4,
                search_interactive_max_execution_time = $5,
                search_interactive_max_memory_gb = $6,
                search_analytics_max_execution_time = $7,
                search_analytics_max_memory_gb = $8,
                search_realtime_max_execution_time = $9,
                search_realtime_max_memory_gb = $10,
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(config.global_adhoc_limit as i32)
        .bind(config.per_user_limit as i32)
        .bind(config.max_queue_depth as i32)
        .bind(config.queue_timeout_seconds as i32)
        .bind(config.interactive_max_execution_time as i32)
        .bind(config.interactive_max_memory_gb as i32)
        .bind(config.analytics_max_execution_time as i32)
        .bind(config.analytics_max_memory_gb as i32)
        .bind(config.realtime_max_execution_time as i32)
        .bind(config.realtime_max_memory_gb as i32)
        .execute(&self.pool)
        .await?;

        Ok(config)
    }

    /// Validate configuration ranges
    fn validate(&self, config: &SearchAdmissionConfig) -> Result<(), SearchAdmissionSettingsError> {
        if config.global_adhoc_limit < 1 || config.global_adhoc_limit > 500 {
            return Err(SearchAdmissionSettingsError::Validation(
                "global_adhoc_limit must be between 1 and 500".to_string(),
            ));
        }
        if config.per_user_limit < 1 || config.per_user_limit > 50 {
            return Err(SearchAdmissionSettingsError::Validation(
                "per_user_limit must be between 1 and 50".to_string(),
            ));
        }
        if config.per_user_limit > config.global_adhoc_limit {
            return Err(SearchAdmissionSettingsError::Validation(
                "per_user_limit must be <= global_adhoc_limit".to_string(),
            ));
        }
        if config.max_queue_depth < 10 || config.max_queue_depth > 1000 {
            return Err(SearchAdmissionSettingsError::Validation(
                "max_queue_depth must be between 10 and 1000".to_string(),
            ));
        }
        if config.queue_timeout_seconds < 10 || config.queue_timeout_seconds > 600 {
            return Err(SearchAdmissionSettingsError::Validation(
                "queue_timeout_seconds must be between 10 and 600".to_string(),
            ));
        }
        if config.interactive_max_execution_time < 30
            || config.interactive_max_execution_time > 3600
        {
            return Err(SearchAdmissionSettingsError::Validation(
                "interactive_max_execution_time must be between 30 and 3600".to_string(),
            ));
        }
        if config.interactive_max_memory_gb < 1 || config.interactive_max_memory_gb > 100 {
            return Err(SearchAdmissionSettingsError::Validation(
                "interactive_max_memory_gb must be between 1 and 100".to_string(),
            ));
        }
        if config.analytics_max_execution_time < 60 || config.analytics_max_execution_time > 7200 {
            return Err(SearchAdmissionSettingsError::Validation(
                "analytics_max_execution_time must be between 60 and 7200".to_string(),
            ));
        }
        if config.analytics_max_memory_gb < 5 || config.analytics_max_memory_gb > 200 {
            return Err(SearchAdmissionSettingsError::Validation(
                "analytics_max_memory_gb must be between 5 and 200".to_string(),
            ));
        }
        if config.realtime_max_execution_time < 5 || config.realtime_max_execution_time > 120 {
            return Err(SearchAdmissionSettingsError::Validation(
                "realtime_max_execution_time must be between 5 and 120".to_string(),
            ));
        }
        if config.realtime_max_memory_gb < 1 || config.realtime_max_memory_gb > 20 {
            return Err(SearchAdmissionSettingsError::Validation(
                "realtime_max_memory_gb must be between 1 and 20".to_string(),
            ));
        }
        Ok(())
    }
}
