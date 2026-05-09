// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search Result Cache — Dragonfly/Redis-backed full result caching
//!
//! Caches complete search responses (including AI enrichment) so that
//! shared links, page refreshes, and repeat queries return instantly
//! without re-executing SQL or calling the LLM.

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use nanosiem_core::{SearchRequest, SearchResponse};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tracing::{debug, info, warn};

/// TTL for cached search results (7 days)
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Max result size to cache (1MB compressed)
const MAX_CACHE_SIZE: usize = 1_024 * 1_024;

/// Max rows to cache (results larger than this are not cached)
const MAX_CACHEABLE_ROWS: usize = 10_000;

/// Search result cache backed by Dragonfly/Redis
#[derive(Clone)]
pub struct SearchResultCache {
    conn: ConnectionManager,
}

impl SearchResultCache {
    /// Connect to Dragonfly/Redis. Returns None if connection fails (graceful degradation).
    pub async fn connect(redis_url: &str) -> Option<Self> {
        let client = match redis::Client::open(redis_url) {
            Ok(c) => c,
            Err(e) => {
                warn!("Search result cache: failed to create Redis client: {}", e);
                return None;
            }
        };

        match ConnectionManager::new(client).await {
            Ok(conn) => {
                info!("Search result cache connected to {}", redis_url);
                Some(Self { conn })
            }
            Err(e) => {
                warn!(
                    "Search result cache: failed to connect to {} (caching disabled): {}",
                    redis_url, e
                );
                None
            }
        }
    }

    /// Compute a deterministic cache key from the search request.
    /// Includes all query-affecting fields so that different source_type,
    /// table_view, or skip_histogram settings produce distinct cache entries.
    /// Uses SHA-256 for collision resistance.
    pub fn cache_key(request: &SearchRequest) -> String {
        let mut hasher = Sha256::new();
        hasher.update(request.query.as_bytes());
        hasher.update(b"|");
        hasher.update(request.time_range.start.timestamp().to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(request.time_range.end.timestamp().to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(request.limit.unwrap_or(100).to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(request.offset.unwrap_or(0).to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(if request.table_view { "tv1" } else { "tv0" }.as_bytes());
        hasher.update(b"|");
        hasher.update(if request.skip_histogram { "sh1" } else { "sh0" }.as_bytes());
        hasher.update(b"|");
        hasher.update(
            if request.skip_field_stats {
                "sf1"
            } else {
                "sf0"
            }
            .as_bytes(),
        );
        let hash = hasher.finalize();
        format!("search:{}", hex::encode(hash))
    }

    /// Try to get a cached search response.
    pub async fn get(&self, request: &SearchRequest) -> Option<SearchResponse> {
        let key = Self::cache_key(request);
        let mut conn = self.conn.clone();

        let data: Option<Vec<u8>> = match conn.get::<_, Option<Vec<u8>>>(&key).await {
            Ok(d) => {
                if d.is_none() {
                    info!(cache_key = %key, "Search cache MISS");
                }
                d
            }
            Err(e) => {
                debug!("Cache GET error for {}: {}", key, e);
                return None;
            }
        };

        let compressed = data?;

        // Decompress
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut json_bytes = Vec::new();
        if let Err(e) = decoder.read_to_end(&mut json_bytes) {
            warn!("Cache decompression error for {}: {}", key, e);
            return None;
        }

        // Deserialize
        match serde_json::from_slice::<SearchResponse>(&json_bytes) {
            Ok(response) => {
                info!(
                    cache_key = %key,
                    result_count = response.results.len(),
                    compressed_kb = format_args!("{:.1}", compressed.len() as f64 / 1024.0),
                    "Search cache HIT"
                );
                Some(response)
            }
            Err(e) => {
                warn!("Cache deserialization error for {}: {}", key, e);
                None
            }
        }
    }

    /// Cache-aware search execution: returns a cached response on hit;
    /// on miss runs `run_search`, returns the live response, and populates
    /// the cache in the background via `tokio::spawn` so the caller isn't
    /// blocked on the Redis SET.
    ///
    /// NAN-702: used by `nanosiem-api/src/handlers/dashboards/query.rs:panel_query`
    /// so dashboards reuse the same compressed cache the search handler
    /// already populates. The search HTTP handler itself does not use this
    /// helper — it needs to record hit-vs-miss in different Prometheus
    /// labels (`piped_cached` vs `piped`), which would force this helper
    /// to grow a metrics-aware return shape. The duplication that's left
    /// (~10 lines, structurally similar) is small enough that visual
    /// review catches drift.
    pub async fn execute_or_cache<F, Fut, E>(
        &self,
        request: &SearchRequest,
        run_search: F,
    ) -> Result<SearchResponse, E>
    where
        F: FnOnce(SearchRequest) -> Fut,
        Fut: std::future::Future<Output = Result<SearchResponse, E>>,
    {
        if let Some(cached) = self.get(request).await {
            return Ok(cached);
        }
        let response = run_search(request.clone()).await?;
        let cache = self.clone();
        let req = request.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set(&req, &resp).await;
        });
        Ok(response)
    }

    /// Store a search response in the cache.
    pub async fn set(&self, request: &SearchRequest, response: &SearchResponse) {
        // Don't cache oversized results
        if response.results.len() > MAX_CACHEABLE_ROWS {
            debug!(
                "Skipping cache: {} rows exceeds limit of {}",
                response.results.len(),
                MAX_CACHEABLE_ROWS
            );
            return;
        }

        let key = Self::cache_key(request);
        let mut conn = self.conn.clone();

        // Serialize
        let json_bytes = match serde_json::to_vec(response) {
            Ok(b) => b,
            Err(e) => {
                debug!("Cache serialization error: {}", e);
                return;
            }
        };

        // Compress
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        if let Err(e) = encoder.write_all(&json_bytes) {
            debug!("Cache compression error: {}", e);
            return;
        }
        let compressed = match encoder.finish() {
            Ok(c) => c,
            Err(e) => {
                debug!("Cache compression finish error: {}", e);
                return;
            }
        };

        if compressed.len() > MAX_CACHE_SIZE {
            debug!(
                "Skipping cache: compressed size {}KB exceeds limit of {}KB",
                compressed.len() / 1024,
                MAX_CACHE_SIZE / 1024
            );
            return;
        }

        let ttl = CACHE_TTL_SECS as i64;
        match conn
            .set_ex::<_, _, ()>(&key, &compressed[..], ttl as u64)
            .await
        {
            Ok(()) => {
                info!(
                    cache_key = %key,
                    result_count = response.results.len(),
                    raw_kb = format_args!("{:.1}", json_bytes.len() as f64 / 1024.0),
                    compressed_kb = format_args!("{:.1}", compressed.len() as f64 / 1024.0),
                    "Search cache SET"
                );
            }
            Err(e) => {
                warn!("Cache SET error for {}: {}", key, e);
            }
        }
    }
}
