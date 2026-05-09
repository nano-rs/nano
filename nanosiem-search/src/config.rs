// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration for the Search Service
//!
//! Loads configuration from environment variables.

/// Configuration for the Search Service
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Port to listen on (default: 3002)
    pub port: u16,
    /// Default limit for search results
    pub default_limit: usize,
    /// Maximum limit for search results
    pub max_limit: usize,
    /// Query timeout in milliseconds
    pub query_timeout_ms: u64,
    /// Allowed CORS origins (comma-separated list, or "*" for all - NOT recommended for production)
    pub cors_origins: Vec<String>,
    /// Global ad-hoc query concurrency limit (default: 30)
    pub global_adhoc_limit: u32,
    /// Per-user query concurrency limit (default: 5)
    pub per_user_limit: u32,
    /// Maximum queue depth before rejecting new queries (default: 100)
    pub max_queue_depth: u32,
    /// Queue timeout in milliseconds (default: 120000)
    pub queue_timeout_ms: u64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            port: 3002,
            default_limit: 100,
            max_limit: 10000,
            query_timeout_ms: 30000,
            cors_origins: vec![],
            global_adhoc_limit: 30,
            per_user_limit: 5,
            max_queue_depth: 100,
            // NAN-714: aligned with Interactive priority's max_execution_time
            // (300s) — see admission.rs:default for the full reasoning.
            queue_timeout_ms: 300_000,
        }
    }
}

impl SearchConfig {
    /// Load configuration from environment variables
    ///
    /// Environment variables:
    /// - `SEARCH_PORT`: Port to listen on (default: 3002)
    /// - `SEARCH_DEFAULT_LIMIT`: Default result limit (default: 100)
    /// - `SEARCH_MAX_LIMIT`: Maximum result limit (default: 10000)
    /// - `SEARCH_QUERY_TIMEOUT_MS`: Query timeout in milliseconds (default: 30000)
    /// - `CORS_ORIGINS`: Comma-separated list of allowed origins (default: none - requires explicit config)
    pub fn from_env() -> Self {
        let port = std::env::var("SEARCH_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3002);

        let default_limit = std::env::var("SEARCH_DEFAULT_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let max_limit = std::env::var("SEARCH_MAX_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10000);

        let query_timeout_ms = std::env::var("SEARCH_QUERY_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30000);

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

        let global_adhoc_limit = std::env::var("SEARCH_GLOBAL_ADHOC_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let per_user_limit = std::env::var("SEARCH_PER_USER_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        let max_queue_depth = std::env::var("SEARCH_MAX_QUEUE_DEPTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        let queue_timeout_ms_val = std::env::var("SEARCH_QUEUE_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            // NAN-714: 300_000 (5 min) matches Interactive max_execution_time
            // — see admission.rs:default for the rationale.
            .unwrap_or(300_000u64);

        Self {
            port,
            default_limit,
            max_limit,
            query_timeout_ms,
            cors_origins,
            global_adhoc_limit,
            per_user_limit,
            max_queue_depth,
            queue_timeout_ms: queue_timeout_ms_val,
        }
    }
}
