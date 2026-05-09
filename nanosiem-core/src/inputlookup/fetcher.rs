// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP fetcher for inputlookup with SSRF protection, caching, and rate limiting
//!
//! This module provides a secure HTTP client that:
//! - Validates URLs against SSRF attacks
//! - Caches responses with configurable TTL
//! - Applies rate limiting per user
//! - Follows redirects safely

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use reqwest::{redirect::Policy, Client, Response};
use thiserror::Error;
use tracing::{debug, warn};

use super::ssrf::{SsrfConfig, SsrfError, SsrfValidator};
use super::types::InputLookupConfig;

/// Errors that can occur during URL fetching
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("SSRF validation failed: {0}")]
    SsrfValidation(#[from] SsrfError),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Rate limit exceeded. Please wait before making more requests")]
    RateLimitExceeded,

    #[error("Response too large: {size} bytes exceeds limit of {limit} bytes")]
    ResponseTooLarge { size: usize, limit: usize },

    #[error("HTTP error {status}: {message}")]
    HttpStatus { status: u16, message: String },

    #[error("Request timeout after {timeout_secs} seconds")]
    Timeout { timeout_secs: u32 },

    #[error("Failed to read response body: {0}")]
    BodyReadError(String),
}

/// Cached response entry
struct CacheEntry {
    /// The response body
    body: String,
    /// When this entry was created
    created_at: Instant,
    /// TTL for this entry
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// HTTP fetcher with SSRF protection, caching, and rate limiting
pub struct UrlFetcher {
    /// HTTP client
    client: Client,
    /// SSRF validator
    validator: SsrfValidator,
    /// Response cache (URL -> cached response)
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Rate limiter (requests per minute)
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// Configuration
    config: InputLookupConfig,
}

impl UrlFetcher {
    /// Create a new URL fetcher with the given configuration
    pub fn new(config: InputLookupConfig) -> Self {
        // Build HTTP client with custom redirect policy
        let client = Client::builder()
            .user_agent(&config.user_agent)
            // We handle redirects manually to validate each redirect target
            .redirect(Policy::none())
            .timeout(Duration::from_secs(config.default_timeout_secs as u64))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        // Create SSRF validator
        let ssrf_config = SsrfConfig {
            allow_http: config.allow_http,
            blocked_domains: config.blocked_domains.clone(),
            max_redirects: 5,
            ..Default::default()
        };
        let validator = SsrfValidator::new(ssrf_config);

        // Create rate limiter
        let quota = Quota::per_minute(
            std::num::NonZeroU32::new(config.rate_limit_per_minute)
                .unwrap_or(std::num::NonZeroU32::new(60).unwrap()),
        );
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        // Create cache
        let cache = Arc::new(DashMap::new());

        Self {
            client,
            validator,
            cache,
            rate_limiter,
            config,
        }
    }

    /// Fetch a URL with SSRF validation, caching, and rate limiting
    ///
    /// # Arguments
    /// * `url` - The URL to fetch
    /// * `timeout_secs` - Optional custom timeout (uses default if None)
    /// * `cache_ttl_secs` - Cache TTL in seconds (0 = no cache)
    pub async fn fetch(
        &self,
        url: &str,
        timeout_secs: Option<u32>,
        cache_ttl_secs: u32,
    ) -> Result<FetchResult, FetchError> {
        // Check cache first (if caching is enabled)
        if cache_ttl_secs > 0 {
            if let Some(cached) = self.get_cached(url) {
                debug!("Cache hit for URL: {}", url);
                return Ok(FetchResult {
                    body: cached,
                    from_cache: true,
                    status_code: None,
                    fetch_duration: None,
                });
            }
        }

        // Check rate limit
        if self.rate_limiter.check().is_err() {
            warn!("Rate limit exceeded for inputlookup");
            return Err(FetchError::RateLimitExceeded);
        }

        // Validate URL with DNS resolution
        let validated_url = self.validator.validate_with_dns(url).await?;

        // Perform the fetch
        let start = Instant::now();
        let timeout =
            Duration::from_secs(timeout_secs.unwrap_or(self.config.default_timeout_secs) as u64);

        let response = self
            .fetch_with_redirects(validated_url.as_str(), timeout, 0)
            .await?;
        let status = response.status();

        // Check status code
        if !status.is_success() {
            return Err(FetchError::HttpStatus {
                status: status.as_u16(),
                message: status.canonical_reason().unwrap_or("Unknown").to_string(),
            });
        }

        // Read body with size limit
        let body = self.read_body_limited(response).await?;
        let fetch_duration = start.elapsed();

        // Cache the response if caching is enabled
        if cache_ttl_secs > 0 {
            self.set_cached(url, &body, Duration::from_secs(cache_ttl_secs as u64));
        }

        Ok(FetchResult {
            body,
            from_cache: false,
            status_code: Some(status.as_u16()),
            fetch_duration: Some(fetch_duration),
        })
    }

    /// Fetch with redirect handling
    fn fetch_with_redirects<'a>(
        &'a self,
        url: &'a str,
        timeout: Duration,
        redirect_count: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, FetchError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if redirect_count > 5 {
                return Err(FetchError::HttpStatus {
                    status: 310,
                    message: "Too many redirects".to_string(),
                });
            }

            let response = self.client.get(url).timeout(timeout).send().await?;

            // Handle redirects
            if response.status().is_redirection() {
                if let Some(location) = response.headers().get("location") {
                    let redirect_url = location.to_str().map_err(|_| FetchError::HttpStatus {
                        status: response.status().as_u16(),
                        message: "Invalid redirect location header".to_string(),
                    })?;

                    // Resolve relative URLs
                    let base =
                        url::Url::parse(url).map_err(|e| SsrfError::InvalidUrl(e.to_string()))?;
                    let redirect_url = base
                        .join(redirect_url)
                        .map_err(|e| SsrfError::InvalidUrl(e.to_string()))?;

                    // Validate redirect target — resolves DNS and rejects redirects whose
                    // hostname resolves to a private/link-local/metadata IP.
                    let validated = self
                        .validator
                        .validate_redirect(redirect_url.as_str())
                        .await?;

                    debug!("Following redirect to: {}", validated);
                    return self
                        .fetch_with_redirects(validated.as_str(), timeout, redirect_count + 1)
                        .await;
                }
            }

            Ok(response)
        })
    }

    /// Read response body with size limit
    async fn read_body_limited(&self, response: Response) -> Result<String, FetchError> {
        // Check Content-Length header if available
        if let Some(content_length) = response.content_length() {
            if content_length as usize > self.config.max_response_size {
                return Err(FetchError::ResponseTooLarge {
                    size: content_length as usize,
                    limit: self.config.max_response_size,
                });
            }
        }

        // Read body in chunks with size tracking
        let bytes = response
            .bytes()
            .await
            .map_err(|e| FetchError::BodyReadError(e.to_string()))?;

        if bytes.len() > self.config.max_response_size {
            return Err(FetchError::ResponseTooLarge {
                size: bytes.len(),
                limit: self.config.max_response_size,
            });
        }

        String::from_utf8(bytes.to_vec())
            .map_err(|e| FetchError::BodyReadError(format!("Invalid UTF-8: {}", e)))
    }

    /// Get a cached response if available and not expired
    fn get_cached(&self, url: &str) -> Option<String> {
        self.cache.get(url).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.body.clone())
            }
        })
    }

    /// Set a cached response
    fn set_cached(&self, url: &str, body: &str, ttl: Duration) {
        self.cache.insert(
            url.to_string(),
            CacheEntry {
                body: body.to_string(),
                created_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Clean up expired cache entries
    pub fn cleanup_cache(&self) {
        self.cache.retain(|_, entry| !entry.is_expired());
    }

    /// Clear all cached entries
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        let total = self.cache.len();
        let expired = self.cache.iter().filter(|e| e.is_expired()).count();
        CacheStats {
            total_entries: total,
            expired_entries: expired,
            active_entries: total - expired,
        }
    }
}

/// Result of a URL fetch operation
#[derive(Debug)]
pub struct FetchResult {
    /// The response body as a string
    pub body: String,
    /// Whether the result came from cache
    pub from_cache: bool,
    /// HTTP status code (if not from cache)
    pub status_code: Option<u16>,
    /// Time taken to fetch (if not from cache)
    pub fetch_duration: Option<Duration>,
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cache entries
    pub total_entries: usize,
    /// Number of expired entries
    pub expired_entries: usize,
    /// Number of active (non-expired) entries
    pub active_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry {
            body: "test".to_string(),
            created_at: Instant::now() - Duration::from_secs(10),
            ttl: Duration::from_secs(5),
        };
        assert!(entry.is_expired());

        let fresh_entry = CacheEntry {
            body: "test".to_string(),
            created_at: Instant::now(),
            ttl: Duration::from_secs(60),
        };
        assert!(!fresh_entry.is_expired());
    }

    #[tokio::test]
    async fn test_fetcher_rejects_private_ip() {
        let config = InputLookupConfig {
            allow_http: true,
            ..Default::default()
        };
        let fetcher = UrlFetcher::new(config);

        let result = fetcher.fetch("http://192.168.1.1/", None, 0).await;
        assert!(matches!(result, Err(FetchError::SsrfValidation(_))));
    }

    #[tokio::test]
    async fn test_fetcher_rejects_localhost() {
        let config = InputLookupConfig {
            allow_http: true,
            ..Default::default()
        };
        let fetcher = UrlFetcher::new(config);

        let result = fetcher.fetch("http://127.0.0.1/", None, 0).await;
        assert!(matches!(result, Err(FetchError::SsrfValidation(_))));
    }
}
