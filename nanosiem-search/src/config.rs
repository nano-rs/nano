// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration for the Search Service
//!
//! Loads configuration from environment variables.

/// Configuration for the Search Service
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Port to listen on (default: 3002)
    pub port: u16,
    /// Allowed CORS origins (comma-separated list, or "*" for all - NOT recommended for production)
    pub cors_origins: Vec<String>,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            port: 3002,
            cors_origins: vec![],
        }
    }
}

impl SearchConfig {
    /// Load configuration from environment variables
    ///
    /// Environment variables:
    /// - `SEARCH_PORT`: Port to listen on (default: 3002)
    /// - `CORS_ORIGINS`: Comma-separated list of allowed origins (default: none - requires explicit config)
    pub fn from_env() -> Self {
        let port = std::env::var("SEARCH_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3002);

        // Parse CORS origins from environment - empty by default (secure default)
        let cors_origins = std::env::var("CORS_ORIGINS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Self { port, cors_origins }
    }
}
