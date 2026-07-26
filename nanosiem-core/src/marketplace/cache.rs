// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared Dragonfly/Redis-backed cache for the marketplace coverage hero
//! (NAN-609).
//!
//! ## Why
//!
//! The coverage SQL is a 12-`countIf` aggregate over the last 24h of `logs`.
//! On a medium-sized tenant it can run ~10s. Round 1 of NAN-609 made the FE
//! cache the result for 6h via React Query — but that's a per-browser-tab
//! memo, so every fresh tab on every replica still pays the full
//! recomputation cost. This module turns it into a *scope-partitioned shared*
//! cache: one slow recompute warms the hero for callers with the same effective
//! source visibility for the next 6 hours, without exposing an unrestricted
//! result to a restricted caller (NAN-2061).
//!
//! Mirrors the wiring pattern of `nanosiem_enterprise::cases::PresenceTracker`
//! (lifted in Phase 3.2 of NAN-744): an `Option<Arc<Mutex<ConnectionManager>>>`
//! so single-node dev (no Redis) short-circuits to a "cache miss every time"
//! path without any branches at the call site.
//!
//! ## Behavior
//!
//! - `get(scope)` — `GET marketplace:coverage:v2:<scope-hash>`, deserialize
//!   JSON. Any miss / error / decode failure returns `None` so the caller will
//!   recompute.
//! - `set(scope)` — `SETEX marketplace:coverage:v2:<scope-hash> 21600 <json>`.
//!   Best effort; Redis errors are logged and swallowed.
//! - `invalidate(scope)` — deletes only that caller scope's partition. Backs the
//!   manual refresh button without evicting other principals' scoped results.
//!
//! ### Concurrency
//!
//! Two parallel cache-miss requests will both recompute and both `SETEX` —
//! last write wins. We accept the duplicated work because the alternative
//! (a `SET NX` "computing" lock) is more state to manage and the recompute
//! is bounded by the 24h aggregation window. If the duplication ever
//! becomes a real cost, add a single-flight wrapper at the service layer.
//!
//! ### Versioning
//!
//! The cache key is suffixed with `:v2` for the NAN-2061 scope policy. If the
//! `MarketplaceCoverage` schema or authorization context ever changes shape,
//! bump to `:v3` rather than flushing — old replicas keep working until they
//! roll, and new replicas overlap cleanly.

use std::collections::BTreeSet;
use std::sync::Arc;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::coverage::MarketplaceCoverage;

/// 6 hours, in seconds. Matches the round-1 React Query `staleTime`; the
/// underlying SQL window is 24h, so re-running more often than this would
/// rarely show meaningfully different numbers.
const COVERAGE_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

/// Versioned key prefix — bump the suffix on schema or authorization-policy
/// changes (see module docs).
const COVERAGE_CACHE_KEY_PREFIX: &str = "marketplace:coverage:v2";

/// Authorization policy represented by this key version. Feeding the required
/// capability context into the digest makes the partition definition explicit:
/// a future endpoint policy change cannot accidentally reuse entries produced
/// under a weaker capability set without also changing this input or key
/// version.
const COVERAGE_CAPABILITY_CONTEXT: &str = "enrichments:view+search:execute";

/// Build a Redis-safe, stable partition key from the caller's canonical
/// effective source deny-set. `BTreeSet` iteration is stable, and each source is
/// length-prefixed before hashing so delimiter-bearing names cannot collide.
/// Raw source names never appear in Redis keys.
fn coverage_cache_key(denied_sources: &BTreeSet<String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(COVERAGE_CAPABILITY_CONTEXT.as_bytes());
    hasher.update([0]);
    for source in denied_sources {
        hasher.update((source.len() as u64).to_be_bytes());
        hasher.update(source.as_bytes());
    }
    format!(
        "{COVERAGE_CACHE_KEY_PREFIX}:{}",
        hex::encode(hasher.finalize())
    )
}

/// Shared cache for the marketplace coverage hero.
///
/// Cloneable + Send + Sync. When `redis` is `None`, every operation is a
/// no-op / cache miss — the caller falls through to a real recompute, same
/// as the in-memory presence-tracker fallback.
#[derive(Clone, Default)]
pub struct MarketplaceCoverageCache {
    redis: Option<Arc<Mutex<ConnectionManager>>>,
    #[cfg(test)]
    memory: Option<Arc<Mutex<std::collections::HashMap<String, MarketplaceCoverage>>>>,
}

impl MarketplaceCoverageCache {
    /// Disabled cache — every `get()` returns `None`, every `set()` is a
    /// no-op. This is the dev / single-node mode and what tests get by
    /// default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache backed by an existing Dragonfly/Redis `ConnectionManager`.
    pub fn with_redis(conn: ConnectionManager) -> Self {
        Self {
            redis: Some(Arc::new(Mutex::new(conn))),
            #[cfg(test)]
            memory: None,
        }
    }

    /// Try to build a Redis-backed cache from a connection URL. Falls back
    /// to a disabled cache (with a warning logged) if the connection can't
    /// be established. Mirrors `PresenceTracker::try_with_redis_url` so the
    /// `nanosiem-api` startup code stays out of the redis crate's surface.
    pub async fn try_with_redis_url(redis_url: &str) -> Self {
        match redis::Client::open(redis_url) {
            Ok(client) => match ConnectionManager::new(client).await {
                Ok(conn) => Self::with_redis(conn),
                Err(err) => {
                    warn!(redis_url, error = %err, "marketplace_coverage_cache: Redis ConnectionManager failed; cache disabled");
                    Self::new()
                }
            },
            Err(err) => {
                warn!(redis_url, error = %err, "marketplace_coverage_cache: invalid Redis URL; cache disabled");
                Self::new()
            }
        }
    }

    /// Look up the cached coverage payload. Returns `None` on miss, on any
    /// Redis error, or on JSON decode failure (the latter typically means a
    /// stale entry from a previous schema — recomputing + re-`set`-ing
    /// fixes it on the next call).
    pub async fn get(&self, denied_sources: &BTreeSet<String>) -> Option<MarketplaceCoverage> {
        let key = coverage_cache_key(denied_sources);
        #[cfg(test)]
        if let Some(memory) = &self.memory {
            return memory.lock().await.get(&key).cloned();
        }

        let redis = self.redis.as_ref()?;
        let mut conn = redis.lock().await;
        let payload: Option<String> = match conn.get(&key).await {
            Ok(p) => p,
            Err(err) => {
                debug!(error = %err, key, "marketplace_coverage_cache: GET failed");
                return None;
            }
        };
        drop(conn);
        let raw = payload?;
        match serde_json::from_str::<MarketplaceCoverage>(&raw) {
            Ok(cov) => Some(cov),
            Err(err) => {
                warn!(error = %err, key, "marketplace_coverage_cache: cached payload failed to deserialize; treating as miss");
                None
            }
        }
    }

    /// Store the freshly-computed coverage payload with a 6h TTL. Best
    /// effort — any Redis or serialization error is logged and swallowed.
    pub async fn set(&self, denied_sources: &BTreeSet<String>, value: &MarketplaceCoverage) {
        let key = coverage_cache_key(denied_sources);
        #[cfg(test)]
        if let Some(memory) = &self.memory {
            memory.lock().await.insert(key, value.clone());
            return;
        }

        let Some(redis) = self.redis.as_ref() else {
            return;
        };
        let json = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "marketplace_coverage_cache: serialization failed; not caching");
                return;
            }
        };
        let mut conn = redis.lock().await;
        let result: redis::RedisResult<()> = conn.set_ex(&key, json, COVERAGE_CACHE_TTL_SECS).await;
        drop(conn);
        if let Err(err) = result {
            warn!(error = %err, key, "marketplace_coverage_cache: SETEX failed");
        }
    }

    /// Drop only this effective-source-scope partition so the next `get()` for
    /// that scope is forced to miss. Used by the manual-refresh endpoint.
    pub async fn invalidate(&self, denied_sources: &BTreeSet<String>) {
        let key = coverage_cache_key(denied_sources);
        #[cfg(test)]
        if let Some(memory) = &self.memory {
            memory.lock().await.remove(&key);
            return;
        }

        let Some(redis) = self.redis.as_ref() else {
            return;
        };
        let mut conn = redis.lock().await;
        let result: redis::RedisResult<()> = conn.del(&key).await;
        drop(conn);
        if let Err(err) = result {
            warn!(error = %err, key, "marketplace_coverage_cache: DEL failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(sources: &[&str]) -> BTreeSet<String> {
        sources.iter().map(|source| (*source).to_string()).collect()
    }

    fn coverage(minute: i64) -> MarketplaceCoverage {
        MarketplaceCoverage {
            artifacts: vec![],
            computed_at: chrono::DateTime::from_timestamp(1_700_000_000 + minute * 60, 0).unwrap(),
        }
    }

    fn memory_cache() -> MarketplaceCoverageCache {
        MarketplaceCoverageCache {
            redis: None,
            memory: Some(Arc::new(Mutex::new(std::collections::HashMap::new()))),
        }
    }

    #[tokio::test]
    async fn disabled_cache_misses_silently() {
        // Without Redis the cache is a permanent miss — the caller will
        // always recompute. set/invalidate are no-ops and don't error.
        let cache = MarketplaceCoverageCache::new();
        let unrestricted = scope(&[]);
        assert!(cache.get(&unrestricted).await.is_none());
        cache.invalidate(&unrestricted).await;
        cache.set(&unrestricted, &coverage(0)).await;
        assert!(cache.get(&unrestricted).await.is_none());
    }

    #[test]
    fn cache_key_is_stable_and_scope_partitioned() {
        let unrestricted = coverage_cache_key(&scope(&[]));
        let restricted = coverage_cache_key(&scope(&["audit", "secret"]));
        assert_ne!(unrestricted, restricted);
        assert_eq!(
            restricted,
            coverage_cache_key(&scope(&["secret", "audit"])),
            "BTreeSet order must produce the same partition"
        );
        assert!(restricted.starts_with("marketplace:coverage:v2:"));
        assert!(
            !restricted.contains("secret"),
            "raw source names must not leak into Redis keys"
        );
    }

    #[tokio::test]
    async fn unrestricted_and_restricted_results_never_cross_partitions() {
        let cache = memory_cache();
        let unrestricted = scope(&[]);
        let restricted = scope(&["audit", "secret"]);
        cache.set(&unrestricted, &coverage(1)).await;

        assert!(
            cache.get(&restricted).await.is_none(),
            "restricted caller must miss an unrestricted caller's cached result"
        );

        cache.set(&restricted, &coverage(2)).await;
        assert_eq!(
            cache.get(&unrestricted).await.unwrap().computed_at,
            coverage(1).computed_at
        );
        assert_eq!(
            cache.get(&restricted).await.unwrap().computed_at,
            coverage(2).computed_at
        );
    }

    #[tokio::test]
    async fn refresh_invalidation_only_removes_callers_scope_partition() {
        let cache = memory_cache();
        let first = scope(&["audit"]);
        let second = scope(&["audit", "secret"]);
        cache.set(&first, &coverage(1)).await;
        cache.set(&second, &coverage(2)).await;

        cache.invalidate(&first).await;

        assert!(cache.get(&first).await.is_none());
        assert_eq!(
            cache.get(&second).await.unwrap().computed_at,
            coverage(2).computed_at,
            "refreshing one caller scope must not evict another scope"
        );
    }
}
