// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search query safety limit settings
//!
//! Admin-configurable limits for query-level OOM protection.
//! These control bounded array aggregation, mvexpand limits,
//! post-processing buffer caps, and optional cost analysis enforcement.
//! Stored in the `system_settings` table.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Search query safety limit configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchQueryLimitsConfig {
    /// Max elements in groupArray/groupUniqArray per group (100-1_000_000, default 100)
    pub max_group_array_size: u32,
    /// Default row limit for mvexpand when user doesn't specify one (1_000-10_000_000, default 100_000)
    pub max_mvexpand_rows: u32,
    /// Max groups in Rust-side post-processing HashMap (10_000-10_000_000, default 1_000_000)
    pub max_post_processing_groups: u32,
    /// Max rows to buffer for streaming result cache (1_000-1_000_000, default 50_000)
    pub max_streaming_cache_rows: u32,
    /// Whether to block queries that trigger Error-severity cost analysis warnings (default: false)
    pub block_on_cost_errors: bool,
}

impl Default for SearchQueryLimitsConfig {
    fn default() -> Self {
        Self {
            max_group_array_size: 100,
            max_mvexpand_rows: 100_000,
            max_post_processing_groups: 1_000_000,
            max_streaming_cache_rows: 50_000,
            block_on_cost_errors: false,
        }
    }
}

/// Errors for search query limit settings operations
#[derive(Debug, thiserror::Error)]
pub enum SearchQueryLimitsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Repository for search query limit settings in system_settings table
pub struct SearchQueryLimitsSettings {
    pool: PgPool,
}

impl SearchQueryLimitsSettings {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get current search query limits configuration
    pub async fn get_config(&self) -> Result<SearchQueryLimitsConfig, SearchQueryLimitsError> {
        let row = sqlx::query_as::<_, (i32, i32, i32, i32, bool)>(
            r#"
            SELECT
                search_max_group_array_size,
                search_max_mvexpand_rows,
                search_max_post_processing_groups,
                search_max_streaming_cache_rows,
                search_block_on_cost_errors
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((
                max_group_array_size,
                max_mvexpand_rows,
                max_post_processing_groups,
                max_streaming_cache_rows,
                block_on_cost_errors,
            )) => Ok(SearchQueryLimitsConfig {
                max_group_array_size: max_group_array_size as u32,
                max_mvexpand_rows: max_mvexpand_rows as u32,
                max_post_processing_groups: max_post_processing_groups as u32,
                max_streaming_cache_rows: max_streaming_cache_rows as u32,
                block_on_cost_errors,
            }),
            None => Ok(SearchQueryLimitsConfig::default()),
        }
    }

    /// Update search query limits configuration
    pub async fn update_config(
        &self,
        config: SearchQueryLimitsConfig,
    ) -> Result<SearchQueryLimitsConfig, SearchQueryLimitsError> {
        self.validate(&config)?;

        sqlx::query(
            r#"
            UPDATE system_settings SET
                search_max_group_array_size = $1,
                search_max_mvexpand_rows = $2,
                search_max_post_processing_groups = $3,
                search_max_streaming_cache_rows = $4,
                search_block_on_cost_errors = $5,
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(config.max_group_array_size as i32)
        .bind(config.max_mvexpand_rows as i32)
        .bind(config.max_post_processing_groups as i32)
        .bind(config.max_streaming_cache_rows as i32)
        .bind(config.block_on_cost_errors)
        .execute(&self.pool)
        .await?;

        Ok(config)
    }

    /// Validate configuration ranges
    fn validate(&self, config: &SearchQueryLimitsConfig) -> Result<(), SearchQueryLimitsError> {
        if config.max_group_array_size < 100 || config.max_group_array_size > 1_000_000 {
            return Err(SearchQueryLimitsError::Validation(
                "max_group_array_size must be between 100 and 1,000,000".to_string(),
            ));
        }
        if config.max_mvexpand_rows < 1_000 || config.max_mvexpand_rows > 10_000_000 {
            return Err(SearchQueryLimitsError::Validation(
                "max_mvexpand_rows must be between 1,000 and 10,000,000".to_string(),
            ));
        }
        if config.max_post_processing_groups < 10_000
            || config.max_post_processing_groups > 10_000_000
        {
            return Err(SearchQueryLimitsError::Validation(
                "max_post_processing_groups must be between 10,000 and 10,000,000".to_string(),
            ));
        }
        if config.max_streaming_cache_rows < 1_000 || config.max_streaming_cache_rows > 1_000_000 {
            return Err(SearchQueryLimitsError::Validation(
                "max_streaming_cache_rows must be between 1,000 and 1,000,000".to_string(),
            ));
        }
        Ok(())
    }
}
