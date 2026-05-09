// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database connection pool management

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use thiserror::Error;

use super::DatabaseConfig;

/// Database connection errors
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Failed to connect to database: {0}")]
    ConnectionError(#[from] sqlx::Error),
    #[error("Database health check failed: {0}")]
    HealthCheckError(String),
}

/// Database connection pool wrapper with health check support
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let mut pool_options = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
            .test_before_acquire(config.test_before_acquire);

        // Set max lifetime if configured
        if config.max_lifetime_secs > 0 {
            pool_options = pool_options.max_lifetime(Duration::from_secs(config.max_lifetime_secs));
        }

        let pool = pool_options.connect(&config.url).await?;

        Ok(Self { pool })
    }

    /// Connect to database using a URL string with default settings
    pub async fn connect(url: &str) -> Result<Self, DatabaseError> {
        let config = DatabaseConfig {
            url: url.to_string(),
            ..Default::default()
        };
        Self::new(&config).await
    }

    /// Get a reference to the underlying connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Check if the database connection is healthy
    pub async fn health_check(&self) -> Result<(), DatabaseError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| DatabaseError::HealthCheckError(e.to_string()))?;
        Ok(())
    }

    /// Close all connections in the pool
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
