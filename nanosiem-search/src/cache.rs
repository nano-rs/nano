// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search Result Cache — Dragonfly/Redis-backed full result caching
//!
//! Caches complete search responses (including AI enrichment) so that
//! shared links, page refreshes, and repeat queries return instantly
//! without re-executing SQL or calling the LLM.

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use nanosiem_core::auth::ScopeSet;
use nanosiem_core::search::{SearchTenantScope, ServingGenerationKey};
use nanosiem_core::{SearchRequest, SearchResponse};
use nanosiem_core::redis_transport::ReconnectingConnection as ConnectionManager;
use redis::AsyncCommands;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tracing::{debug, info, warn};

/// TTL for cached search results.
///
/// NAN-1027: shortened from 7 days. SIEM data is live — late-arriving events
/// change query results constantly. A multi-day cache risks serving "we're
/// clean" results long after a real detection lands in the data.
///
/// NAN-1596: 90s → 300s. 90s deduped same-session patterns (page refreshes,
/// dashboard panel re-renders, companion endpoints on one page load) but a
/// copy/pasted/shared link (Slack, ticket, case note) is clicked minutes
/// later, by which point the 90s entry has always expired — so the recipient
/// paid a full SQL re-run and the "instant shared view" never fired. 300s
/// keeps those links warm. Safe because (a) empty / "0 hits" results are
/// still never cached (`skip_cache_reason`), so the most dangerous stale
/// entry can't occur, and (b) the NAN-1595 "cached Ns ago · refresh" badge
/// discloses staleness and offers a one-click live re-run. 300s is the
/// guardrail ceiling — still far short of outliving a working session.
const CACHE_TTL_SECS: u64 = 300;

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
        return Some("empty result set");
    }
    if response.results.len() > MAX_CACHEABLE_ROWS {
        return Some("result row count exceeds MAX_CACHEABLE_ROWS");
    }
    None
}

/// NAN-4664: a conservative normal form of an nPL query for cache and
/// in-flight identity. Leading and trailing whitespace is trimmed, and runs
/// of spaces and tabs outside `"..."` / `'...'` strings collapse to one space.
/// It never changes meaning: newlines are kept (a `//` comment ends at one),
/// and a query containing `/` (regex literals, comments, division), `\` or
/// a backtick, or with an unbalanced quote, is only trimmed.
pub fn normalize_query(query: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = query.trim();
    if trimmed.contains(['/', '\\', '`']) {
        return std::borrow::Cow::Borrowed(trimmed);
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut quote: Option<char> = None;
    let mut pending_space = false;
    for c in trimmed.chars() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == q {
                    quote = None;
                }
            }
            None if c == ' ' || c == '\t' => pending_space = true,
            None => {
                if pending_space {
                    out.push(' ');
                    pending_space = false;
                }
                if c == '"' || c == '\'' {
                    quote = Some(c);
                }
                out.push(c);
            }
        }
    }
    if quote.is_some() || out == trimmed {
        return std::borrow::Cow::Borrowed(trimmed);
    }
    // The lexical pass above guesses where strings are. The parser is the
    // authority: collapse only when the collapsed text parses to exactly the
    // same query (an apostrophe or quote inside a bare word, or anything the
    // lexer misreads, keeps the trimmed text, which never merges meanings).
    if parses_identically(trimmed, &out) {
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

/// Whether two nPL texts parse to the same AST (both must parse).
fn parses_identically(a: &str, b: &str) -> bool {
    matches!(
        (nanosiem_core::query::parse_query(a), nanosiem_core::query::parse_query(b)),
        (Ok(left), Ok(right)) if left == right
    )
}

/// NAN-4664: whether this request may READ the Redis result cache.
/// `use_cache` is tri-state on the wire: absent keeps the historical
/// behavior (read, for API keys, agents and sessions alike), an explicit
/// `true` reads, an explicit `false` skips the read (a fresh run that still
/// writes the cache and still shares an identical in-flight run). The
/// `x-nano-cache-bypass` header (and the handler's other bypasses) always
/// skip the read.
pub fn reads_result_cache(bypass: bool, explicit_use_cache: Option<bool>) -> bool {
    !bypass && explicit_use_cache.unwrap_or(true)
}

/// Search result cache backed by Dragonfly/Redis
#[derive(Clone)]
pub struct SearchResultCache {
    conn: ConnectionManager,
}

impl SearchResultCache {
    const ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX: &'static str =
        "enterprise-shared-retention-cache-disabled:";
    /// Connect to Dragonfly/Redis. Returns None if connection fails (graceful degradation).
    pub async fn connect(redis_url: &str) -> Option<Self> {
        let client = match nanosiem_core::redis_transport::client_from_url(redis_url) {
            Ok(c) => c,
            Err(e) => {
                warn!("Search result cache: failed to create Redis client: {}", e);
                return None;
            }
        };

        match ConnectionManager::new(client).await {
            Ok(conn) => {
                info!("Search result cache connected");
                Some(Self { conn })
            }
            Err(e) => {
                warn!(
                    "Search result cache: failed to connect (caching disabled): {}",
                    e
                );
                None
            }
        }
    }

    /// Compute a deterministic cache key from the search request AND the
    /// caller's effective source-scope deny-set.
    /// Includes all query-affecting fields so that different source_type,
    /// table_view, or skip_histogram settings produce distinct cache entries.
    /// Uses SHA-256 for collision resistance.
    ///
    /// NAN-1799: `scope` is the EFFECTIVE deny-set (per-user source scope
    /// unioned with the audit gate, composed by the handler). The service
    /// injects the exclusion into the executed SQL, so the same request text
    /// produces DIFFERENT result sets for different scopes — the scope must
    /// be part of result identity or two users collide on one key and one is
    /// served the other's rows from cache (cross-user data leak).
    pub fn cache_key(request: &SearchRequest, scope: &ScopeSet) -> String {
        Self::cache_key_for(SearchTenantScope::dedicated(), request, scope, None)
    }

    /// Tenant-pinned cache identity for enterprise-shared search. Callers must
    /// already hold a server-resolved [`SearchTenantScope`]; a raw slug/header
    /// cannot reach this boundary. `generation` is the tenant's serving
    /// generation (NAN-2361 wave 6): folding it makes an erasure or retention
    /// swap — a new generation on a new Iceberg snapshot — miss every entry
    /// cached under the predecessor at once.
    pub fn cache_key_for(
        tenant: SearchTenantScope,
        request: &SearchRequest,
        scope: &ScopeSet,
        generation: Option<&ServingGenerationKey>,
    ) -> String {
        Self::search_identity_key(tenant, "search", request, scope, generation, &[])
    }

    /// NAN-4664: the identity of one in-flight search run, shared by every
    /// identical concurrent request: everything [`Self::cache_key_for`] folds
    /// (tenant, serving generation, effective source and artifact deny sets,
    /// perf overrides, normalized query, exact time bounds, limit, offset,
    /// result-shaping flags, dataset) plus `include_sql`, which shapes the
    /// response too.
    ///
    /// Also `use_cache` (an explicit `true` lets ClickHouse serve its own
    /// query cache, so a `false` caller never follows such a run) and
    /// `authority`: the caller's server-resolved authority fingerprint
    /// (plan/entitlement, prevalence and retention revisions, admission
    /// priority; see the search handler), so nothing that can shape a result
    /// differs between a leader and its followers.
    pub fn inflight_key_for(
        tenant: SearchTenantScope,
        request: &SearchRequest,
        scope: &ScopeSet,
        generation: Option<&ServingGenerationKey>,
        authority: &[u8],
    ) -> String {
        let include_sql: &[u8] = if request.include_sql.unwrap_or(false) { b"sql1" } else { b"sql0" };
        let use_cache: &[u8] = if request.use_cache { b"uc1" } else { b"uc0" };
        Self::search_identity_key(tenant, "inflight", request, scope, generation, &[include_sql, use_cache, authority])
    }

    fn search_identity_key(
        tenant: SearchTenantScope,
        prefix: &str,
        request: &SearchRequest,
        scope: &ScopeSet,
        generation: Option<&ServingGenerationKey>,
        extra: &[&[u8]],
    ) -> String {
        let mut generation_bytes = Vec::new();
        if let Some(generation) = generation {
            generation.fold_identity(&mut generation_bytes);
        }
        let query = normalize_query(&request.query);
        let start = request.time_range.start.timestamp_micros().to_string();
        let end = request.time_range.end.timestamp_micros().to_string();
        let limit = request.limit.unwrap_or(100).to_string();
        let offset = request.offset.unwrap_or(0).to_string();
        // Length-prefixed components (see `companion_key`): the query is
        // free-form and contains `|`, so a delimiter join is collision-prone.
        let mut components: Vec<&[u8]> = vec![
                generation_bytes.as_slice(),
                query.as_bytes(),
                start.as_bytes(),
                end.as_bytes(),
                limit.as_bytes(),
                offset.as_bytes(),
                if request.table_view { b"tv1" } else { b"tv0" },
                if request.skip_histogram { b"sh1" } else { b"sh0" },
                if request.skip_field_stats { b"sf1" } else { b"sf0" },
                // NAN-1569: the same nPL string runs against different physical
                // tables per dataset (logs / otel_spans / otel_metrics). Without
                // this, a query cached for one dataset is served for another →
                // cross-dataset cache poisoning.
                request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ];
        components.extend_from_slice(extra);
        Self::companion_key_with_generation(tenant, prefix, &components, scope, generation.is_some())
    }

    /// Try to get a cached search response for this request under the
    /// caller's effective scope (NAN-1799 — see [`Self::cache_key`]).
    pub async fn get(&self, request: &SearchRequest, scope: &ScopeSet) -> Option<SearchResponse> {
        self.get_for(SearchTenantScope::dedicated(), request, scope, None)
            .await
    }

    /// Whether a shared tenant's request may touch the result cache at all.
    /// NAN-2922: a query that reads tenant lookup tables, IOC sources or the
    /// tenant-billed `| ai` pipe is never cached, because the serving
    /// generation does not change when that state does, and a cached `| ai`
    /// answer would bypass per-member billing.
    ///
    /// NAN-2361 wave 6: the key must carry the serving generation (so a
    /// swap invalidates it) and the requested window must lie entirely
    /// inside retention at this instant (so a fixed-TTL entry can never
    /// cross the moving cutoff). Dedicated deployments are unconditional.
    fn shared_cache_admitted(
        tenant: SearchTenantScope,
        request: &SearchRequest,
        generation: Option<&ServingGenerationKey>,
    ) -> bool {
        if !crate::is_shared_scope(tenant) {
            return true;
        }
        generation.is_some()
            && tenant.cacheable_window(request.time_range.start, chrono::Utc::now())
            && !reads_state_outside_the_generation(&request.query)
    }

    pub async fn get_for(
        &self,
        tenant: SearchTenantScope,
        request: &SearchRequest,
        scope: &ScopeSet,
        generation: Option<&ServingGenerationKey>,
    ) -> Option<SearchResponse> {
        if !Self::shared_cache_admitted(tenant, request, generation) {
            return None;
        }
        let key = Self::cache_key_for(tenant, request, scope, generation);
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
        scope: &ScopeSet,
        run_search: F,
    ) -> Result<SearchResponse, E>
    where
        F: FnOnce(SearchRequest) -> Fut,
        Fut: std::future::Future<Output = Result<SearchResponse, E>>,
    {
        if let Some(cached) = self.get(request, scope).await {
            return Ok(cached);
        }
        let response = run_search(request.clone()).await?;
        let cache = self.clone();
        let req = request.clone();
        let scope = scope.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set(&req, &resp, &scope).await;
        });
        Ok(response)
    }

    /// Store a search response in the cache under the caller's effective
    /// scope (NAN-1799 — see [`Self::cache_key`]).
    pub async fn set(&self, request: &SearchRequest, response: &SearchResponse, scope: &ScopeSet) {
        self.set_for(SearchTenantScope::dedicated(), request, response, scope, None)
            .await;
    }

    pub async fn set_for(
        &self,
        tenant: SearchTenantScope,
        request: &SearchRequest,
        response: &SearchResponse,
        scope: &ScopeSet,
        generation: Option<&ServingGenerationKey>,
    ) {
        if !Self::shared_cache_admitted(tenant, request, generation) {
            return;
        }
        if let Some(reason) = skip_cache_reason(response) {
            debug!("Skipping cache: {}", reason);
            return;
        }

        let key = Self::cache_key_for(tenant, request, scope, generation);
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
    //
    // O42 exception: the trace-by-id companion opts OUT of caching an empty span
    // list at its call site. An empty trace is cheap to recompute and usually
    // means mid-ingest / unknown-id, so a cached empty would serve every later
    // viewer a stale "empty trace" — the trace analog of NAN-1027's rule. The
    // helpers below stay unconditional; the emptiness check lives in the handler.

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
    ///
    /// NAN-1799: `scope` is the caller's EFFECTIVE deny-set (per-user source
    /// scope unioned with the audit gate, composed by the handler). The
    /// service injects the exclusion into the executed SQL, so the same
    /// components produce DIFFERENT results per scope — the deny-set must be
    /// part of the key or two users with different scopes collide and one is
    /// served the other's rows from cache (cross-user data leak). The
    /// deny-set is folded as ONE final component whose bytes are the
    /// length-prefixed concatenation of the sorted deny values (`BTreeSet`
    /// iteration order): it can never be confused with a caller component
    /// regardless of component count, `{"ab"}` vs `{"a","b"}` stay distinct,
    /// and an empty deny-set folds an empty component — deterministic and
    /// identical across all unrestricted callers.
    ///
    /// NAN-2219: BOTH halves of the scope are folded, as two separate final
    /// components. The artifact half selects a different prevalence read path
    /// (source-attributed aggregates vs. the source-less dictionaries), so two
    /// callers can now share a row-filter deny-set yet execute different SQL:
    /// an ordinary analyst (`{audit}` row-filter, `{}` artifact) and a genuinely
    /// audit-restricted `audit:view` holder (`{audit}` row-filter, `{audit}`
    /// artifact) collide on the row-filter half alone, and the second would be
    /// served the first's unrestricted prevalence numbers. Folding both makes
    /// the key match result identity again; the added component rotates every
    /// existing key once on deploy (a cold cache, not a correctness event).
    pub fn companion_key(prefix: &str, components: &[&[u8]], scope: &ScopeSet) -> String {
        Self::companion_key_for(SearchTenantScope::dedicated(), prefix, components, scope)
    }

    pub fn companion_key_for(
        tenant: SearchTenantScope,
        prefix: &str,
        components: &[&[u8]],
        scope: &ScopeSet,
    ) -> String {
        Self::companion_key_with_generation(tenant, prefix, components, scope, false)
    }

    /// `generation_bound` is true only for the main search key, whose
    /// components carry the serving generation; companion keys stay
    /// release-closed for shared tenants (their payloads are not
    /// generation-keyed).
    fn companion_key_with_generation(
        tenant: SearchTenantScope,
        prefix: &str,
        components: &[&[u8]],
        scope: &ScopeSet,
        generation_bound: bool,
    ) -> String {
        fn fold(hasher: &mut Sha256, denied: &std::collections::BTreeSet<String>) {
            let mut bytes: Vec<u8> = Vec::new();
            for value in denied {
                bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
                bytes.extend_from_slice(value.as_bytes());
            }
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }

        let mut identity = Vec::new();
        tenant.fold_identity(&mut identity);
        let mut hasher = Sha256::new();
        hasher.update(identity);
        for c in components {
            hasher.update((c.len() as u64).to_le_bytes());
            hasher.update(c);
        }
        fold(&mut hasher, scope.deny_set());
        fold(&mut hasher, scope.artifact_deny_set());
        // NAN-3406: a request running with authorized per-request perf
        // overrides keys its entries apart, so an A/B mode's answer is never
        // served to an ordinary request (or to the other mode). Without
        // overrides the key is unchanged.
        if let Some(overrides) = nanosiem_core::search::lake_debug::perf_overrides() {
            hasher.update(b"nan3406-perf-overrides");
            hasher.update((overrides.len() as u64).to_le_bytes());
            hasher.update(overrides.as_bytes());
        }
        let key = format!("{}:{}", prefix, hex::encode(hasher.finalize()));
        if crate::is_shared_scope(tenant) && !generation_bound {
            format!("{}{}", Self::ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX, key)
        } else {
            key
        }
    }

    /// Fetch and decompress a cached companion response. Returns `None` on
    /// miss, connection error, or any decode failure (graceful degradation).
    pub async fn get_cached<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        if key.starts_with(Self::ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX) {
            return None;
        }
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
        if key.starts_with(Self::ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX) {
            return;
        }
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
        if key.starts_with(Self::ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX) {
            return None;
        }
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
        headers.insert(
            HeaderName::from_static(HEADER_CACHE_AGE),
            HeaderValue::from(age),
        );
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
            server_wall_ms: None,
            results,
            total_count: rows as u64,
            total_count_exact: true,
            execution_time_ms: 10,
            fields: Vec::new(),
            generated_sql: None,
            histogram: None,
            warnings: None,
            cost_score: None,
            display_type: None,
            column_order: None,
            completeness: None,
        }
    }

    #[test]
    fn empty_response_is_not_cached() {
        // NAN-1027: a stale "0 hits" cached for hours/days is the worst
        // possible cache entry for a SIEM — analysts get false-clear signal.
        let resp = make_response(0);
        assert_eq!(
            skip_cache_reason(&resp),
            Some("empty result set")
        );
    }

    #[test]
    fn non_empty_response_is_cached() {
        for n in [1, 2, 3, 5, 100, MAX_CACHEABLE_ROWS] {
            let resp = make_response(n);
            assert_eq!(skip_cache_reason(&resp), None, "n={n} should be cacheable");
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
        let scope = ScopeSet::unrestricted();
        assert_ne!(
            SearchResultCache::cache_key(&mk(1), &scope),
            SearchResultCache::cache_key(&mk(2), &scope)
        );
        assert_ne!(
            SearchResultCache::cache_key(&mk(2), &scope),
            SearchResultCache::cache_key(&mk(3), &scope)
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
        let scope = ScopeSet::unrestricted();
        assert_ne!(
            SearchResultCache::cache_key(&mk(None), &scope),
            SearchResultCache::cache_key(&mk(Some("spans")), &scope)
        );
        assert_ne!(
            SearchResultCache::cache_key(&mk(Some("spans")), &scope),
            SearchResultCache::cache_key(&mk(Some("metrics")), &scope)
        );
        // None and the explicit "logs" default collapse to the same key (byte-identical).
        assert_eq!(
            SearchResultCache::cache_key(&mk(None), &scope),
            SearchResultCache::cache_key(&mk(Some("logs")), &scope)
        );
    }

    /// NAN-3406: keys computed under per-request perf overrides are their
    /// own (per mode); a debug request without overrides keys as before.
    #[tokio::test]
    async fn perf_overrides_separate_cache_keys_per_mode() {
        use nanosiem_core::search::lake_debug::{collect, collect_with_perf_overrides};
        let scope = ScopeSet::unrestricted();
        let key = || SearchResultCache::companion_key("fstats", &[b"q", b"100"], &scope);
        let plain = key();
        let (debug, _) = collect(async { key() }).await;
        let (flat_on, _) = collect_with_perf_overrides(Some("flat_filter_leaves=1".into()), async { key() }).await;
        let (flat_off, _) = collect_with_perf_overrides(Some("flat_filter_leaves=0".into()), async { key() }).await;
        assert_eq!(plain, debug, "no overrides: the ordinary key");
        assert_ne!(plain, flat_on);
        assert_ne!(plain, flat_off);
        assert_ne!(flat_on, flat_off);
        assert!(flat_on.starts_with("fstats:"));
    }

    #[test]
    fn companion_key_is_deterministic_and_keyspace_isolated() {
        let scope = ScopeSet::unrestricted();

        // NAN-1593: same prefix + same components → identical key.
        let a =
            SearchResultCache::companion_key("retro", &[b"ioc=1.2.3.4", b"100", b"200"], &scope);
        let b =
            SearchResultCache::companion_key("retro", &[b"ioc=1.2.3.4", b"100", b"200"], &scope);
        assert_eq!(a, b);

        // A changed component → different key.
        let c =
            SearchResultCache::companion_key("retro", &[b"ioc=1.2.3.4", b"100", b"201"], &scope);
        assert_ne!(a, c);

        // Different keyspace prefixes never collide, even with identical
        // components — retro / field-stats / search stay disjoint.
        let retro = SearchResultCache::companion_key("retro", &[b"q", b"t"], &scope);
        let fstats = SearchResultCache::companion_key("fstats", &[b"q", b"t"], &scope);
        assert_ne!(retro, fstats);
        assert!(retro.starts_with("retro:"));
        assert!(fstats.starts_with("fstats:"));

        // Component boundaries are unambiguous: ["ab","c"] != ["a","bc"].
        assert_ne!(
            SearchResultCache::companion_key("x", &[b"ab", b"c"], &scope),
            SearchResultCache::companion_key("x", &[b"a", b"bc"], &scope),
        );

        // Poisoning regression: a `|` inside a component (nPL queries contain
        // pipes) must NOT shift the boundary. With a naive `|`-delimiter join
        // these two would hash identically — a different query served from the
        // wrong cache entry. Length-prefixing keeps them distinct.
        assert_ne!(
            SearchResultCache::companion_key("retro", &[b"ioc=x | retro", b"100"], &scope),
            SearchResultCache::companion_key("retro", &[b"ioc=x", b" retro|100"], &scope),
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_cache_identity_is_tenant_pinned() {
        let scope = ScopeSet::unrestricted();
        let tenant_a = SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(1));
        let tenant_b = SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(2));
        let components: &[&[u8]] = &[b"same-query", b"same-window"];

        let a = SearchResultCache::companion_key_for(tenant_a, "search", components, &scope);
        let b = SearchResultCache::companion_key_for(tenant_b, "search", components, &scope);
        assert_ne!(a, b, "identical queries must not collide across tenants");

        assert_eq!(
            SearchResultCache::companion_key("search", components, &scope),
            SearchResultCache::companion_key_for(
                SearchTenantScope::dedicated(),
                "search",
                components,
                &scope,
            ),
            "dedicated cache identity must remain byte-compatible"
        );
    }

    /// NAN-2711: `| risk` results are cached under the caller's tenant only.
    /// Tenant B issuing A's exact RBA query (same text, same window) can never
    /// be served A's scored rows from the result cache.
    #[cfg(feature = "enterprise")]
    #[test]
    fn risk_projection_results_are_cached_per_tenant() {
        let scope = ScopeSet::unrestricted();
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "metadata.log_source=windows_sysmon | risk score=80 entity=device.hostname",
            "time_range": {"start": "2026-09-23T00:00:00Z", "end": "2026-09-23T01:00:00Z"},
        }))
        .unwrap();
        let key = |tenant: u128| {
            SearchResultCache::cache_key_for(
                SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(tenant)),
                &request,
                &scope,
                None,
            )
        };
        assert_ne!(key(0xa), key(0xb));
        assert_eq!(key(0xa), key(0xa));
    }

    /// NAN-2361 wave 6: a shared tenant's result identity carries the serving
    /// generation, so an erasure / retention swap (new generation, new
    /// snapshot) misses every entry cached under the predecessor; and a
    /// shared tenant is admitted to the cache only when the requested window
    /// lies inside retention at delivery.
    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_cache_identity_is_generation_keyed_and_retention_fenced() {
        let scope = ScopeSet::unrestricted();
        let now = chrono::Utc::now();
        let tenant = SearchTenantScope::enterprise_shared_retained(
            uuid::Uuid::from_u128(7),
            3,
            30,
            0,
        )
        .unwrap();
        let request = SearchRequest {
            query: "error".into(),
            time_range: TimeRangeInput {
                start: now - chrono::Duration::hours(2),
                end: now,
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
            dataset: None,
        };
        let before = ServingGenerationKey {
            generation_id: "gen-1".into(),
            snapshot_id: 100,
        };
        let after = ServingGenerationKey {
            generation_id: "gen-2".into(),
            snapshot_id: 101,
        };
        let key_before = SearchResultCache::cache_key_for(tenant, &request, &scope, Some(&before));
        let key_after = SearchResultCache::cache_key_for(tenant, &request, &scope, Some(&after));
        assert_ne!(key_before, key_after, "a generation swap rotates the key");
        assert!(
            !key_before.starts_with(SearchResultCache::ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX),
            "a generation-bound shared key is live"
        );
        assert!(
            SearchResultCache::cache_key_for(tenant, &request, &scope, None)
                .starts_with(SearchResultCache::ENTERPRISE_SHARED_CACHE_DISABLED_PREFIX),
            "without a generation the shared key stays release-closed"
        );
        assert!(SearchResultCache::shared_cache_admitted(tenant, &request, Some(&before)));
        assert!(!SearchResultCache::shared_cache_admitted(tenant, &request, None));
        // A window that reaches past the 30-day cutoff is never cached for
        // a shared tenant, whatever the generation.
        let mut stale = request.clone();
        stale.time_range.start = now - chrono::Duration::days(31);
        assert!(!SearchResultCache::shared_cache_admitted(tenant, &stale, Some(&before)));
        // Dedicated identity is unchanged and unconditional.
        assert_eq!(
            SearchResultCache::cache_key(&request, &scope),
            SearchResultCache::cache_key_for(SearchTenantScope::dedicated(), &request, &scope, None)
        );
        assert!(SearchResultCache::shared_cache_admitted(SearchTenantScope::dedicated(), &stale, None));
    }

    fn scope_of(items: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(items.iter().map(|s| s.to_string()).collect())
    }

    /// NAN-1799: the effective deny-set is part of result identity. Two users
    /// whose scopes differ must NEVER share a cache entry — the service
    /// injects the exclusion into the executed SQL, so a shared key would
    /// serve one user the other's rows (cross-user data leak).
    #[test]
    fn cache_key_and_companion_key_distinguish_deny_sets() {
        // Fixed timestamps so the request is byte-identical across calls.
        let start = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mk = || SearchRequest {
            query: "error | stats count by src_ip".into(),
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
            dataset: None,
        };

        let unrestricted = ScopeSet::unrestricted();
        let audit_only = scope_of(&["audit"]);
        let audit_insider = scope_of(&["audit", "insider"]);

        // cache_key: all three scopes produce pairwise-distinct keys.
        let k_unrestricted = SearchResultCache::cache_key(&mk(), &unrestricted);
        let k_audit = SearchResultCache::cache_key(&mk(), &audit_only);
        let k_audit_insider = SearchResultCache::cache_key(&mk(), &audit_insider);
        assert_ne!(k_unrestricted, k_audit);
        assert_ne!(k_unrestricted, k_audit_insider);
        assert_ne!(k_audit, k_audit_insider);

        // companion_key: same pairwise distinction on identical components.
        let comps: &[&[u8]] = &[b"error", b"100", b"200"];
        let c_unrestricted = SearchResultCache::companion_key("fstats", comps, &unrestricted);
        let c_audit = SearchResultCache::companion_key("fstats", comps, &audit_only);
        let c_audit_insider = SearchResultCache::companion_key("fstats", comps, &audit_insider);
        assert_ne!(c_unrestricted, c_audit);
        assert_ne!(c_unrestricted, c_audit_insider);
        assert_ne!(c_audit, c_audit_insider);

        // Empty deny-set is stable: the same request + unrestricted scope is
        // unaffected relative to itself (deterministic key, so all
        // unrestricted callers — today's admin behavior — still share one
        // entry). `from_denied(∅)` and `unrestricted()` are the same scope.
        assert_eq!(
            k_unrestricted,
            SearchResultCache::cache_key(&mk(), &ScopeSet::unrestricted())
        );
        assert_eq!(
            k_unrestricted,
            SearchResultCache::cache_key(&mk(), &ScopeSet::from_denied(Default::default()))
        );
        assert_eq!(
            c_unrestricted,
            SearchResultCache::companion_key("fstats", comps, &ScopeSet::unrestricted())
        );

        // Deny-value boundaries are unambiguous inside the fold:
        // {"ab"} must not collide with {"a","b"}.
        assert_ne!(
            SearchResultCache::companion_key("x", &[b"q"], &scope_of(&["ab"])),
            SearchResultCache::companion_key("x", &[b"q"], &scope_of(&["a", "b"])),
        );
    }

    /// NAN-2219: two callers can now share a ROW-FILTER deny-set while
    /// differing in the artifact half, and the artifact half selects a
    /// different prevalence read path. They must not share a cache entry.
    ///
    /// * an ordinary analyst — no per-source grants restricting them, no
    ///   `audit:view` → row `{audit}`, artifact `{}`;
    /// * a principal whose tenant registered `audit` in
    ///   `restricted_source_types` and who holds `audit:view` → row `{audit}`,
    ///   artifact `{audit}`.
    #[test]
    fn cache_key_distinguishes_scopes_that_share_only_the_row_filter_half() {
        let start = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let request = SearchRequest {
            query: "* | prevalence enrich=true".into(),
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
            dataset: None,
        };

        let analyst = nanosiem_core::auth::compose_viewer_scope(&ScopeSet::unrestricted(), false);
        let audit_restricted =
            nanosiem_core::auth::compose_viewer_scope(&scope_of(&["audit"]), true);

        // Precondition: the row-filter halves really do collide.
        assert_eq!(analyst.deny_set(), audit_restricted.deny_set());
        assert_ne!(
            analyst.artifact_deny_set(),
            audit_restricted.artifact_deny_set()
        );

        assert_ne!(
            SearchResultCache::cache_key(&request, &analyst),
            SearchResultCache::cache_key(&request, &audit_restricted),
        );
        let comps: &[&[u8]] = &[b"error"];
        assert_ne!(
            SearchResultCache::companion_key("fstats", comps, &analyst),
            SearchResultCache::companion_key("fstats", comps, &audit_restricted),
        );
    }
}

/// Whether an nPL query reads tenant state that the serving generation does
/// not version: lookup tables, IOC lookup/feed sources, or `| ai` (NAN-2922).
/// An unparseable query is treated as uncacheable.
pub(crate) fn reads_state_outside_the_generation(query: &str) -> bool {
    use nanosiem_core::query::{Command, Query, SearchExpr};
    fn expr(e: &SearchExpr) -> bool {
        match e {
            SearchExpr::IocMatch { feed, lookup, .. } => feed.is_some() || lookup.is_some(),
            SearchExpr::And(l, r) | SearchExpr::Or(l, r) => expr(l) || expr(r),
            SearchExpr::Not(i) | SearchExpr::Group(i) => expr(i),
            SearchExpr::InSubsearch { subsearch, .. } => node(subsearch),
            _ => false,
        }
    }
    fn node(q: &Query) -> bool {
        match q {
            Query::Search(e) => expr(e),
            Query::Piped { source, command } => {
                node(source)
                    || matches!(
                        command,
                        Command::Lookup { .. } | Command::InputLookup { .. } | Command::Ai { .. }
                    )
                    || match command {
                        Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
                            node(subsearch)
                        }
                        Command::Where { condition } => expr(condition),
                        _ => false,
                    }
            }
        }
    }
    nanosiem_core::query::parse_query(query).map_or(true, |parsed| node(&parsed))
}

#[cfg(test)]
mod shared_state_cache_tests {
    use super::reads_state_outside_the_generation as uncacheable;

    #[test]
    fn tenant_state_reads_are_never_cached_on_shared() {
        for query in [
            "* | lookup assets user.name OUTPUT owner",
            "* | inputlookup assets",
            "* | ai prompt=\"x\"",
            "ioc in lookup(\"threats\")",
            "ioc in threatfox(\"apt29\")",
            "user.name=a | append [* | lookup assets user.name OUTPUT owner]",
        ] {
            assert!(uncacheable(query), "{query}");
        }
        for query in ["* | stats count() by user.name", "* | output x", "ioc=\"1.2.3.4\""] {
            assert!(!uncacheable(query), "{query}");
        }
    }
}

#[cfg(test)]
mod nan4664_cache_identity_tests {
    use super::*;

    #[test]
    fn normalization_trims_and_collapses_only_outside_strings() {
        assert_eq!(normalize_query("  class_uid=1007   |  stats count by  process.name \t"), "class_uid=1007 | stats count by process.name");
        // Inside quotes whitespace is data.
        assert_eq!(normalize_query(r#"message="a   b"  |  head 5"#), r#"message="a   b" | head 5"#);
        assert_eq!(normalize_query("user='x  y'   | head"), "user='x  y' | head");
        // Newlines are kept: a `//` comment ends at one.
        assert_eq!(normalize_query("a\n  | head 5"), "a\n | head 5");
    }

    #[test]
    fn normalization_is_conservative_where_meaning_could_change() {
        // Regex literals, comments, division: only trimmed.
        for query in ["user=/admin  .*/i", "a // note  x\n| head", "eval r=a/b  | head", r#"message="a\"  b""#, "x=`y  z`"] {
            assert_eq!(normalize_query(&format!("  {query}  ")), query);
        }
        // An unbalanced quote: only trimmed.
        assert_eq!(normalize_query(r#" message="a   b "#), r#"message="a   b"#);
        // Different meanings never collapse together.
        assert_ne!(normalize_query(r#"message="a b""#), normalize_query(r#"message="a  b""#));
    }

    /// Review (NAN-4664): whatever the lexer guesses, a normalized query is
    /// either the trimmed text or parses to exactly the original's AST, so
    /// two queries of different meaning can never share an identity.
    #[test]
    fn normalization_never_changes_the_parsed_query() {
        let corpus = [
            "class_uid=1007   |  stats count by  process.name",
            r#"x=a"b m="p   q" y=c"d"#,
            r#"user=O'Brien   m="x  ' y   z"   n='w'"#,
            r#"* | eval label="a   b"  |  table label"#,
            r#"* | rex field=message "(?<user>\w+)  logged"  | head 5"#,
            "* | where  count  >  10\n  | head  5",
            "process.name=cmd.exe\t\t| stats  count",
            r#"message="unterminated   | head"#,
        ];
        for query in corpus {
            let normalized = normalize_query(query);
            if normalized.as_ref() != query.trim() {
                assert!(
                    parses_identically(query.trim(), &normalized),
                    "{query:?} normalized to {normalized:?} with a different meaning"
                );
            }
        }
    }

    #[test]
    fn use_cache_tri_state_read_decision() {
        // Absent: today's behavior (read) for every caller.
        assert!(reads_result_cache(false, None));
        assert!(reads_result_cache(false, Some(true)));
        // Explicit false: a fresh run (it still writes and still shares).
        assert!(!reads_result_cache(false, Some(false)));
        // The bypass header always wins.
        assert!(!reads_result_cache(true, None));
        assert!(!reads_result_cache(true, Some(true)));
    }

    #[test]
    fn cache_key_uses_the_normalized_query() {
        let request = |query: &str| -> SearchRequest {
            serde_json::from_value(serde_json::json!({"query": query,
                "time_range": {"start": "2026-10-26T00:00:00Z", "end": "2026-10-27T00:00:00Z"}})).unwrap()
        };
        let scope = ScopeSet::default();
        assert_eq!(
            SearchResultCache::cache_key(&request(" class_uid=1007  | head 5 "), &scope),
            SearchResultCache::cache_key(&request("class_uid=1007 | head 5"), &scope),
        );
        assert_ne!(
            SearchResultCache::cache_key(&request(r#"m="a  b""#), &scope),
            SearchResultCache::cache_key(&request(r#"m="a b""#), &scope),
        );
    }
}
