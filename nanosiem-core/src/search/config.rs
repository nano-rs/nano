// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search service configuration

/// Configuration for the search service
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Default limit for search results
    pub default_limit: usize,
    /// Maximum limit for search results
    pub max_limit: usize,
    /// Number of top values to return for each field
    pub top_values_count: usize,
    /// Query timeout in milliseconds
    pub timeout_ms: u64,
    /// Whether to block queries that trigger Error-severity cost analysis warnings (default: false)
    pub block_on_cost_errors: bool,
    /// Max elements in groupArray/groupUniqArray for SQL generation (default: 100)
    pub max_group_array_size: usize,
    /// Default row limit for mvexpand when user doesn't specify one (default: 100_000)
    pub max_mvexpand_rows: usize,
    /// Max groups in Rust-side post-processing HashMap (default: 1_000_000)
    pub max_post_processing_groups: usize,
    /// Max rows to buffer for streaming cache (default: 50_000)
    pub max_streaming_cache_rows: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            default_limit: 100,
            max_limit: 1000000,
            top_values_count: 100,
            timeout_ms: 30000,
            block_on_cost_errors: false,
            max_group_array_size: 100,
            max_mvexpand_rows: 100_000,
            max_post_processing_groups: 1_000_000,
            max_streaming_cache_rows: 50_000,
        }
    }
}

/// Backend type for the search service
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchBackend {
    /// Use ClickHouse for log queries
    ClickHouse,
}

impl Default for SearchBackend {
    fn default() -> Self {
        Self::ClickHouse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_config_default() {
        let config = SearchConfig::default();
        assert_eq!(config.default_limit, 100);
        assert_eq!(config.max_limit, 1000000);
        assert_eq!(config.top_values_count, 100);
        assert_eq!(config.timeout_ms, 30000);
    }

    #[test]
    fn test_search_backend_default() {
        assert_eq!(SearchBackend::default(), SearchBackend::ClickHouse);
    }

    #[test]
    fn test_search_backend_equality() {
        assert_eq!(SearchBackend::ClickHouse, SearchBackend::ClickHouse);
    }
}
