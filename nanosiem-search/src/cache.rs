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
use serde::Serialize;
use serde::de::DeserializeOwned;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tracing::{debug, info, warn};

/// TTL for cached search results.
///
/// NAN-1027: shortened from 7 days to 90 seconds. SIEM data is live —
/// late-arriving events change query results constantly. A multi-day cache
/// risks serving "we're clean" results long after a real detection lands
/// in the data. 90s is enough to dedupe page refreshes / dashboard panel
/// re-renders / shared-link follows within a working session.
const CACHE_TTL_SECS: u64 = 90;

/// Max result size to cache (1MB compressed)
const MAX_CACHE_SIZE: usize = 1_024 * 1_024;

/// Max rows to cache (results larger than this are not cached)
const MAX_CACHEABLE_ROWS: usize = 10_000;

/// Decide whether a response is cacheable. Returns `Some(reason)` when the
/// response should be skipped, or `None` when it's safe to cache.
///
/// NAN-1027: empty results are never cached. For a SIEM a stale "0 hits"
/// is the most dangerous cache entry — analysts conclude "we're clean"
/// when late-arriving data would actually match. The recompute cost on
/// an empty query is trivial vs. the correctness risk.
fn skip_cache_reason(response: &SearchResponse) -> Option<&'static str> {
    if response.results.is_empty() {
        return Some("empty result set (NAN-1027)");
    }
    if response.results.len() > MAX_CACHEABLE_ROWS {
        return Some("result row count exceeds MAX_CACHEABLE_ROWS");
    }
    None
}

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
        // Length-prefixed components (see `companion_key`): the query is
        // free-form and contains `|`, so a delimiter join is collision-prone.
        Self::companion_key(
            "search",
            &[
                request.query.as_bytes(),
                request.time_range.start.timestamp_micros().to_string().as_bytes(),
                request.time_range.end.timestamp_micros().to_string().as_bytes(),
                request.limit.unwrap_or(100).to_string().as_bytes(),
                request.offset.unwrap_or(0).to_string().as_bytes(),
                if request.table_view { b"tv1" } else { b"tv0" },
                if request.skip_histogram { b"sh1" } else { b"sh0" },
                if request.skip_field_stats { b"sf1" } else { b"sf0" },
                // NAN-1569: the same nPL string runs against different physical
                // tables per dataset (logs / otel_spans / otel_metrics). Without
                // this, a query cached for one dataset is served for another →
                // cross-dataset cache poisoning.
                request.dataset.as_deref().unwrap_or("logs").as_bytes(),
            ],
        )
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
        if let Some(reason) = skip_cache_reason(response) {
            debug!("Skipping cache: {}", reason);
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

    // ── Generic companion-endpoint caching (NAN-1593) ──
    //
    // Only the main search response went through this cache. Companion
    // endpoints the search page also fires on every load / shared-link follow
    // — retro rollups (`/api/search/retro`) and field-stats (`/field-stats`) —
    // bypassed it, so each reload re-ran their full SQL. These generic helpers
    // give any serializable response the same compressed, TTL-bounded caching
    // under a caller-chosen keyspace. Callers build a deterministic key with
    // [`Self::companion_key`].
    //
    // Unlike NAN-1027's "never cache empties" rule for the main search, a
    // *zero-result* companion is the EXPENSIVE case worth caching — a retro
    // that scanned all data to prove a negative, or field-stats over a wide
    // window — so companions cache unconditionally, with the same short TTL
    // bounding staleness from late-arriving data.

    /// Build a deterministic cache key from a keyspace prefix and ordered
    /// components. The prefix keeps each companion's keyspace disjoint from
    /// search (`search:`) and from the others.
    ///
    /// Components are **length-prefixed**, not delimiter-joined. A naive `|`
    /// delimiter is unsafe here: nPL queries contain `|` (`ioc=x | retro`) and
    /// several callers pass free-form JSON components (`filters`, `identities`),
    /// so `["a|b","c"]` and `["a","b|c"]` would hash identically — a different
    /// request served from the wrong cache entry (false results from a SIEM).
    /// Prefixing each component with its byte length makes the boundary
    /// unambiguous regardless of content.
    pub fn companion_key(prefix: &str, components: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        for c in components {
            hasher.update((c.len() as u64).to_le_bytes());
            hasher.update(c);
        }
        format!("{}:{}", prefix, hex::encode(hasher.finalize()))
    }

    /// Fetch and decompress a cached companion response. Returns `None` on
    /// miss, connection error, or any decode failure (graceful degradation).
    pub async fn get_cached<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let mut conn = self.conn.clone();
        let compressed: Vec<u8> = match conn.get::<_, Option<Vec<u8>>>(key).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                info!(cache_key = %key, "Companion cache MISS");
                return None;
            }
            Err(e) => {
                debug!("Companion cache GET error for {}: {}", key, e);
                return None;
            }
        };

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut json_bytes = Vec::new();
        if let Err(e) = decoder.read_to_end(&mut json_bytes) {
            warn!("Companion cache decompression error for {}: {}", key, e);
            return None;
        }

        match serde_json::from_slice::<T>(&json_bytes) {
            Ok(value) => {
                info!(
                    cache_key = %key,
                    compressed_kb = format_args!("{:.1}", compressed.len() as f64 / 1024.0),
                    "Companion cache HIT"
                );
                Some(value)
            }
            Err(e) => {
                warn!("Companion cache deserialization error for {}: {}", key, e);
                None
            }
        }
    }

    /// Compress and store a companion response under `key` with the shared TTL.
    pub async fn set_cached<T: Serialize>(&self, key: &str, value: &T) {
        let mut conn = self.conn.clone();
        let json_bytes = match serde_json::to_vec(value) {
            Ok(b) => b,
            Err(e) => {
                debug!("Companion cache serialization error: {}", e);
                return;
            }
        };

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        if encoder.write_all(&json_bytes).is_err() {
            return;
        }
        let compressed = match encoder.finish() {
            Ok(c) => c,
            Err(e) => {
                debug!("Companion cache compression finish error: {}", e);
                return;
            }
        };

        if compressed.len() > MAX_CACHE_SIZE {
            debug!(
                "Skipping companion cache: compressed size {}KB exceeds limit of {}KB",
                compressed.len() / 1024,
                MAX_CACHE_SIZE / 1024
            );
            return;
        }

        match conn
            .set_ex::<_, _, ()>(key, &compressed[..], CACHE_TTL_SECS)
            .await
        {
            Ok(()) => {
                info!(
                    cache_key = %key,
                    compressed_kb = format_args!("{:.1}", compressed.len() as f64 / 1024.0),
                    "Companion cache SET"
                );
            }
            Err(e) => {
                warn!("Companion cache SET error for {}: {}", key, e);
            }
        }
    }

    /// Age (in whole seconds) of the cached entry under `key`, derived from its
    /// remaining Redis TTL — no timestamp is stored in the payload. Returns
    /// `None` when the key is absent (-2) or has no expiry (-1). Used to stamp
    /// the `x-nano-cache-age` response header so every view (including a
    /// shared-link follower whose client cache is cold) can show how stale a
    /// served-from-cache result is (NAN-1595).
    pub async fn age_secs(&self, key: &str) -> Option<u64> {
        let mut conn = self.conn.clone();
        let pttl_ms: i64 = conn.pttl(key).await.ok()?;
        if pttl_ms < 0 {
            return None;
        }
        let remaining_secs = (pttl_ms as u64).div_ceil(1000);
        Some(CACHE_TTL_SECS.saturating_sub(remaining_secs))
    }
}

// ── Cache-transparency HTTP contract (NAN-1595) ─────────────────────────────

/// Response header: `hit` when the body was served from the cache, else `miss`.
pub const HEADER_CACHE_STATUS: &str = "x-nano-cache";
/// Response header: age in seconds of a cache `hit` (omitted on `miss`).
pub const HEADER_CACHE_AGE: &str = "x-nano-cache-age";
/// Request header: when `1`/`true`, skip the cache read and recompute live
/// (the "refresh/reset" affordance), repopulating the cache for the next caller.
pub const HEADER_CACHE_BYPASS: &str = "x-nano-cache-bypass";

/// Build the cache-status response headers for a handler result.
pub fn cache_status_headers(hit: bool, age_secs: Option<u64>) -> axum::http::HeaderMap {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(HEADER_CACHE_STATUS),
        HeaderValue::from_static(if hit { "hit" } else { "miss" }),
    );
    if let Some(age) = age_secs {
        headers.insert(HeaderName::from_static(HEADER_CACHE_AGE), HeaderValue::from(age));
    }
    headers
}

/// Axum extractor for the `x-nano-cache-bypass` request header. `CacheBypass(true)`
/// means the caller asked for a live recompute (refresh), so the handler must
/// skip its cache read.
#[derive(Clone, Copy, Debug)]
pub struct CacheBypass(pub bool);

impl<S: Sync> axum::extract::FromRequestParts<S> for CacheBypass {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let bypass = parts
            .headers
            .get(HEADER_CACHE_BYPASS)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            })
            .unwrap_or(false);
        Ok(CacheBypass(bypass))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::search::TimeRangeInput;

    fn make_response(rows: usize) -> SearchResponse {
        let results: Vec<serde_json::Value> = (0..rows)
            .map(|i| serde_json::json!({ "id": format!("row-{}", i) }))
            .collect();
        SearchResponse {
            results,
            total_count: rows as u64,
            execution_time_ms: 10,
            fields: Vec::new(),
            generated_sql: None,
            histogram: None,
            warnings: None,
            cost_score: None,
            display_type: None,
            column_order: None,
        }
    }

    #[test]
    fn empty_response_is_not_cached() {
        // NAN-1027: a stale "0 hits" cached for hours/days is the worst
        // possible cache entry for a SIEM — analysts get false-clear signal.
        let resp = make_response(0);
        assert_eq!(
            skip_cache_reason(&resp),
            Some("empty result set (NAN-1027)")
        );
    }

    #[test]
    fn non_empty_response_is_cached() {
        for n in [1, 2, 3, 5, 100, MAX_CACHEABLE_ROWS] {
            let resp = make_response(n);
            assert_eq!(
                skip_cache_reason(&resp),
                None,
                "n={n} should be cacheable"
            );
        }
    }

    #[test]
    fn oversized_response_is_not_cached() {
        let resp = make_response(MAX_CACHEABLE_ROWS + 1);
        assert_eq!(
            skip_cache_reason(&resp),
            Some("result row count exceeds MAX_CACHEABLE_ROWS")
        );
    }

    #[test]
    fn cache_ttl_does_not_outlive_a_working_session() {
        // NAN-1027: live SIEM data invalidates results constantly. Cache
        // must dedupe page refreshes / shared links, not survive overnight.
        assert!(
            CACHE_TTL_SECS <= 300,
            "TTL {CACHE_TTL_SECS}s risks serving stale 'no hits' for an hour+ \
             after late-arriving data lands"
        );
    }

    #[test]
    fn cache_key_distinguishes_limit() {
        let mk = |limit: usize| SearchRequest {
            query: "foo".into(),
            time_range: TimeRangeInput {
                start: chrono::Utc::now(),
                end: chrono::Utc::now() + chrono::Duration::hours(1),
            },
            limit: Some(limit),
            offset: None,
            include_sql: None,
            skip_histogram: false,
            skip_field_stats: false,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        };
        assert_ne!(
            SearchResultCache::cache_key(&mk(1)),
            SearchResultCache::cache_key(&mk(2))
        );
        assert_ne!(
            SearchResultCache::cache_key(&mk(2)),
            SearchResultCache::cache_key(&mk(3))
        );
    }

    #[test]
    fn cache_key_distinguishes_dataset() {
        // NAN-1569: the same nPL string on different datasets hits different
        // physical tables, so it must NOT share a cache entry.
        // Fixed timestamps: the key now uses microsecond precision, so two
        // separate `Utc::now()` calls would differ and mask the dataset check.
        let start = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mk = |dataset: Option<&str>| SearchRequest {
            query: "foo".into(),
            time_range: TimeRangeInput {
                start,
                end: start + chrono::Duration::hours(1),
            },
            limit: Some(100),
            offset: None,
            include_sql: None,
            skip_histogram: false,
            skip_field_stats: false,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: dataset.map(String::from),
        };
        // logs (None) vs spans vs metrics are all distinct.
        assert_ne!(
            SearchResultCache::cache_key(&mk(None)),
            SearchResultCache::cache_key(&mk(Some("spans")))
        );
        assert_ne!(
            SearchResultCache::cache_key(&mk(Some("spans"))),
            SearchResultCache::cache_key(&mk(Some("metrics")))
        );
        // None and the explicit "logs" default collapse to the same key (byte-identical).
        assert_eq!(
            SearchResultCache::cache_key(&mk(None)),
            SearchResultCache::cache_key(&mk(Some("logs")))
        );
    }

    #[test]
    fn companion_key_is_deterministic_and_keyspace_isolated() {
        // NAN-1593: same prefix + same components → identical key.
        let a = SearchResultCache::companion_key("retro", &[b"ioc=1.2.3.4", b"100", b"200"]);
        let b = SearchResultCache::companion_key("retro", &[b"ioc=1.2.3.4", b"100", b"200"]);
        assert_eq!(a, b);

        // A changed component → different key.
        let c = SearchResultCache::companion_key("retro", &[b"ioc=1.2.3.4", b"100", b"201"]);
        assert_ne!(a, c);

        // Different keyspace prefixes never collide, even with identical
        // components — retro / field-stats / search stay disjoint.
        let retro = SearchResultCache::companion_key("retro", &[b"q", b"t"]);
        let fstats = SearchResultCache::companion_key("fstats", &[b"q", b"t"]);
        assert_ne!(retro, fstats);
        assert!(retro.starts_with("retro:"));
        assert!(fstats.starts_with("fstats:"));

        // Component boundaries are unambiguous: ["ab","c"] != ["a","bc"].
        assert_ne!(
            SearchResultCache::companion_key("x", &[b"ab", b"c"]),
            SearchResultCache::companion_key("x", &[b"a", b"bc"]),
        );

        // Poisoning regression: a `|` inside a component (nPL queries contain
        // pipes) must NOT shift the boundary. With a naive `|`-delimiter join
        // these two would hash identically — a different query served from the
        // wrong cache entry. Length-prefixing keeps them distinct.
        assert_ne!(
            SearchResultCache::companion_key("retro", &[b"ioc=x | retro", b"100"]),
            SearchResultCache::companion_key("retro", &[b"ioc=x", b" retro|100"]),
        );
    }
}
