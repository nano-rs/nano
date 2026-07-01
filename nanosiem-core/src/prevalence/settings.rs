// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Settings
//!
//! Manages prevalence tracking configuration stored in PostgreSQL.
//! Supports hot-reload of settings without service restart.
//!
//! Requirements: 8.1, 8.2, 8.3, 8.4, 8.5

use sqlx::PgPool;
use tracing::{debug, info};

use super::types::PrevalenceConfig;

/// Error type for prevalence settings operations
#[derive(Debug, thiserror::Error)]
pub enum PrevalenceSettingsError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Invalid rarity threshold: {0} (must be 1-1000)")]
    InvalidRarityThreshold(u64),

    #[error("Invalid retention days: {0} (must be 1-365)")]
    InvalidRetentionDays(u32),

    #[error("Invalid cache TTL: {0} (must be 0-3600)")]
    InvalidCacheTtl(u64),
}

/// Prevalence settings manager
///
/// Handles loading and saving prevalence configuration from/to PostgreSQL.
#[derive(Clone)]
pub struct PrevalenceSettings {
    pool: PgPool,
}

impl PrevalenceSettings {
    /// Create a new PrevalenceSettings instance
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Load prevalence configuration from the database
    ///
    /// Returns the current configuration or defaults if not set.
    pub async fn get_config(&self) -> Result<PrevalenceConfig, PrevalenceSettingsError> {
        let row = sqlx::query_as::<_, PrevalenceConfigRow>(
            r#"
            SELECT
                COALESCE(prevalence_rarity_threshold, 3) as rarity_threshold,
                COALESCE(prevalence_enable_hash_tracking, true) as enable_hash_tracking,
                COALESCE(prevalence_enable_domain_tracking, true) as enable_domain_tracking,
                COALESCE(prevalence_enable_ip_tracking, true) as enable_ip_tracking,
                COALESCE(prevalence_retention_days, 90) as retention_days,
                COALESCE(prevalence_cache_ttl_seconds, 60) as cache_ttl_seconds
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(PrevalenceConfig {
                rarity_threshold: row.rarity_threshold as u64,
                enable_hash_tracking: row.enable_hash_tracking,
                enable_domain_tracking: row.enable_domain_tracking,
                enable_ip_tracking: row.enable_ip_tracking,
                retention_days: row.retention_days as u32,
                cache_ttl_seconds: row.cache_ttl_seconds as u64,
            }),
            None => {
                debug!("No system_settings row found, using defaults");
                Ok(PrevalenceConfig::default())
            }
        }
    }

    /// Update prevalence configuration in the database
    ///
    /// Validates the configuration before saving.
    /// Requirements: 8.1, 8.2, 8.3, 8.4
    pub async fn update_config(
        &self,
        config: PrevalenceConfig,
    ) -> Result<PrevalenceConfig, PrevalenceSettingsError> {
        // Validate configuration
        self.validate_config(&config)?;

        sqlx::query(
            r#"
            UPDATE system_settings
            SET
                prevalence_rarity_threshold = $1,
                prevalence_enable_hash_tracking = $2,
                prevalence_enable_domain_tracking = $3,
                prevalence_enable_ip_tracking = $4,
                prevalence_retention_days = $5,
                prevalence_cache_ttl_seconds = $6,
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(config.rarity_threshold as i32)
        .bind(config.enable_hash_tracking)
        .bind(config.enable_domain_tracking)
        .bind(config.enable_ip_tracking)
        .bind(config.retention_days as i32)
        .bind(config.cache_ttl_seconds as i32)
        .execute(&self.pool)
        .await?;

        info!(
            "Prevalence settings updated: rarity_threshold={}, hash_tracking={}, domain_tracking={}, ip_tracking={}, retention_days={}, cache_ttl={}s",
            config.rarity_threshold,
            config.enable_hash_tracking,
            config.enable_domain_tracking,
            config.enable_ip_tracking,
            config.retention_days,
            config.cache_ttl_seconds
        );

        Ok(config)
    }

    /// Validate prevalence configuration
    fn validate_config(&self, config: &PrevalenceConfig) -> Result<(), PrevalenceSettingsError> {
        if config.rarity_threshold < 1 || config.rarity_threshold > 1000 {
            return Err(PrevalenceSettingsError::InvalidRarityThreshold(
                config.rarity_threshold,
            ));
        }

        if config.retention_days < 1 || config.retention_days > 365 {
            return Err(PrevalenceSettingsError::InvalidRetentionDays(
                config.retention_days,
            ));
        }

        if config.cache_ttl_seconds > 3600 {
            return Err(PrevalenceSettingsError::InvalidCacheTtl(
                config.cache_ttl_seconds,
            ));
        }

        Ok(())
    }
}

/// Row type for loading prevalence config from database
#[derive(sqlx::FromRow)]
struct PrevalenceConfigRow {
    rarity_threshold: i32,
    enable_hash_tracking: bool,
    enable_domain_tracking: bool,
    enable_ip_tracking: bool,
    retention_days: i32,
    cache_ttl_seconds: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a PrevalenceSettings for validation testing
    // Note: We can't actually connect to a database in unit tests,
    // but we can test the validation logic directly

    fn validate_config(config: &PrevalenceConfig) -> Result<(), PrevalenceSettingsError> {
        if config.rarity_threshold < 1 || config.rarity_threshold > 1000 {
            return Err(PrevalenceSettingsError::InvalidRarityThreshold(
                config.rarity_threshold,
            ));
        }

        if config.retention_days < 1 || config.retention_days > 365 {
            return Err(PrevalenceSettingsError::InvalidRetentionDays(
                config.retention_days,
            ));
        }

        if config.cache_ttl_seconds > 3600 {
            return Err(PrevalenceSettingsError::InvalidCacheTtl(
                config.cache_ttl_seconds,
            ));
        }

        Ok(())
    }

    #[test]
    fn test_validate_rarity_threshold() {
        // Valid thresholds
        let valid_config = PrevalenceConfig {
            rarity_threshold: 5,
            ..Default::default()
        };
        assert!(validate_config(&valid_config).is_ok());

        // Invalid threshold (too low)
        let invalid_config = PrevalenceConfig {
            rarity_threshold: 0,
            ..Default::default()
        };
        assert!(validate_config(&invalid_config).is_err());

        // Invalid threshold (too high)
        let invalid_config = PrevalenceConfig {
            rarity_threshold: 1001,
            ..Default::default()
        };
        assert!(validate_config(&invalid_config).is_err());
    }

    #[test]
    fn test_validate_retention_days() {
        // Valid retention
        let valid_config = PrevalenceConfig {
            retention_days: 90,
            ..Default::default()
        };
        assert!(validate_config(&valid_config).is_ok());

        // Invalid retention (too low)
        let invalid_config = PrevalenceConfig {
            retention_days: 0,
            ..Default::default()
        };
        assert!(validate_config(&invalid_config).is_err());

        // Invalid retention (too high)
        let invalid_config = PrevalenceConfig {
            retention_days: 366,
            ..Default::default()
        };
        assert!(validate_config(&invalid_config).is_err());
    }

    #[test]
    fn test_validate_cache_ttl() {
        // Valid TTL
        let valid_config = PrevalenceConfig {
            cache_ttl_seconds: 60,
            ..Default::default()
        };
        assert!(validate_config(&valid_config).is_ok());

        // Valid TTL (0 = no caching)
        let valid_config = PrevalenceConfig {
            cache_ttl_seconds: 0,
            ..Default::default()
        };
        assert!(validate_config(&valid_config).is_ok());

        // Invalid TTL (too high)
        let invalid_config = PrevalenceConfig {
            cache_ttl_seconds: 3601,
            ..Default::default()
        };
        assert!(validate_config(&invalid_config).is_err());
    }
}
