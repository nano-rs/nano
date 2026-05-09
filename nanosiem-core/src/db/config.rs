// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database configuration

use serde::{Deserialize, Serialize};

/// Database configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of connections to maintain
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
    /// Idle connection timeout in seconds
    pub idle_timeout_secs: u64,
    /// Maximum lifetime of a connection in seconds (0 = unlimited)
    pub max_lifetime_secs: u64,
    /// Test connections before use
    pub test_before_acquire: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/nanosiem".to_string(),
            max_connections: 20, // Increased for tuning workload
            min_connections: 2,  // Increased to maintain ready connections
            connect_timeout_secs: 30,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800, // 30 minutes
            test_before_acquire: true,
        }
    }
}

impl DatabaseConfig {
    /// Create a new configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/nanosiem".to_string()),
            max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20),
            min_connections: std::env::var("DATABASE_MIN_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            connect_timeout_secs: std::env::var("DATABASE_CONNECT_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            idle_timeout_secs: std::env::var("DATABASE_IDLE_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            max_lifetime_secs: std::env::var("DATABASE_MAX_LIFETIME")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1800),
            test_before_acquire: std::env::var("DATABASE_TEST_BEFORE_ACQUIRE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(true),
        }
    }
}
