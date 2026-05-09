// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configuration types for the inputlookup command
//!
//! This module defines the configuration structures for URL-based lookup enrichment.
//! Note: InputLookupFormat and UrlTemplate are defined in query::ast for use in parsing.

use serde::{Deserialize, Serialize};

// Re-export the AST types for convenience
pub use crate::query::{InputLookupFormat, UrlTemplate};

/// Configuration for the inputlookup service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputLookupConfig {
    /// Maximum response size in bytes (default: 10MB)
    #[serde(default = "default_max_response_size")]
    pub max_response_size: usize,

    /// Default request timeout in seconds (default: 30)
    #[serde(default = "default_timeout_secs")]
    pub default_timeout_secs: u32,

    /// Default cache TTL in seconds (default: 300)
    #[serde(default = "default_cache_ttl_secs")]
    pub default_cache_ttl_secs: u32,

    /// Default maximum rows to return (default: 10000)
    #[serde(default = "default_max_rows")]
    pub default_max_rows: usize,

    /// Rate limit: requests per minute per user (default: 60)
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,

    /// Allowed domains (empty = allow all non-blocked)
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// Blocked domains (applied even if in allowed list)
    #[serde(default)]
    pub blocked_domains: Vec<String>,

    /// Whether to allow HTTP (non-HTTPS) URLs (default: false)
    #[serde(default)]
    pub allow_http: bool,

    /// User agent string for requests
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
}

fn default_max_response_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_timeout_secs() -> u32 {
    30
}

fn default_cache_ttl_secs() -> u32 {
    300 // 5 minutes
}

fn default_max_rows() -> usize {
    10000
}

fn default_rate_limit_per_minute() -> u32 {
    60
}

fn default_user_agent() -> String {
    "NanoSIEM/1.0 InputLookup".to_string()
}

impl Default for InputLookupConfig {
    fn default() -> Self {
        Self {
            max_response_size: default_max_response_size(),
            default_timeout_secs: default_timeout_secs(),
            default_cache_ttl_secs: default_cache_ttl_secs(),
            default_max_rows: default_max_rows(),
            rate_limit_per_minute: default_rate_limit_per_minute(),
            allowed_domains: Vec::new(),
            blocked_domains: Vec::new(),
            allow_http: false,
            user_agent: default_user_agent(),
        }
    }
}

/// Parameters for an inputlookup command execution
#[derive(Debug, Clone)]
pub struct InputLookupParams {
    /// URL template to fetch
    pub url: UrlTemplate,
    /// Response format
    pub format: InputLookupFormat,
    /// Field to join on (enables enrichment mode)
    pub key_field: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u32,
    /// Maximum rows to return
    pub max_rows: usize,
    /// Cache TTL in seconds (0 = no cache)
    pub cache_ttl_secs: u32,
}

impl InputLookupParams {
    /// Check if this is data source mode (no key field, fetch URL as results)
    pub fn is_data_source_mode(&self) -> bool {
        self.key_field.is_none()
    }

    /// Check if this is enrichment mode (has key field, join with results)
    pub fn is_enrichment_mode(&self) -> bool {
        self.key_field.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_template_no_placeholders() {
        let template = UrlTemplate::new("https://api.example.com/data.json");
        assert!(!template.has_placeholders());
        assert!(template.fields.is_empty());
    }

    #[test]
    fn test_url_template_with_placeholders() {
        let template = UrlTemplate::new("https://api.ipinfo.io/{src_ip}/json");
        assert!(template.has_placeholders());
        assert_eq!(template.fields, vec!["src_ip"]);
    }

    #[test]
    fn test_url_template_multiple_placeholders() {
        let template = UrlTemplate::new("https://api.example.com/{user}/{action}");
        assert!(template.has_placeholders());
        assert_eq!(template.fields, vec!["user", "action"]);
    }

    #[test]
    fn test_url_template_substitute() {
        let template = UrlTemplate::new("https://api.ipinfo.io/{ip}/json");
        let mut values = std::collections::HashMap::new();
        values.insert("ip".to_string(), "8.8.8.8".to_string());
        let result = template.substitute(&values);
        assert_eq!(
            result,
            Some("https://api.ipinfo.io/8.8.8.8/json".to_string())
        );
    }

    #[test]
    fn test_url_template_substitute_missing_field() {
        let template = UrlTemplate::new("https://api.ipinfo.io/{ip}/json");
        let values = std::collections::HashMap::new();
        let result = template.substitute(&values);
        assert!(result.is_none());
    }

    #[test]
    fn test_url_template_substitute_url_encoded() {
        let template = UrlTemplate::new("https://api.example.com/search?q={query}");
        let mut values = std::collections::HashMap::new();
        values.insert("query".to_string(), "hello world".to_string());
        let result = template.substitute(&values);
        assert_eq!(
            result,
            Some("https://api.example.com/search?q=hello%20world".to_string())
        );
    }

    #[test]
    fn test_format_from_str() {
        assert_eq!(
            InputLookupFormat::from_str("json"),
            Some(InputLookupFormat::Json)
        );
        assert_eq!(
            InputLookupFormat::from_str("JSON"),
            Some(InputLookupFormat::Json)
        );
        assert_eq!(
            InputLookupFormat::from_str("csv"),
            Some(InputLookupFormat::Csv)
        );
        assert_eq!(
            InputLookupFormat::from_str("CSV"),
            Some(InputLookupFormat::Csv)
        );
        assert_eq!(InputLookupFormat::from_str("xml"), None);
    }
}
