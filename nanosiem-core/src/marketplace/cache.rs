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
//! recomputation cost. This module turns it into a *shared* cache: one slow
//! recompute warms every user's hero for the next 6 hours.
//!
//! Mirrors the wiring pattern of `nanosiem_enterprise::cases::PresenceTracker`
//! (lifted in Phase 3.2 of NAN-744): an `Option<Arc<Mutex<ConnectionManager>>>`
//! so single-node dev (no Redis) short-circuits to a "cache miss every time"
//! path without any branches at the call site.
//!
//! ## Behavior
//!
//! - `get()` — `GET marketplace:coverage:v1`, deserialize JSON. Any miss /
//!   error / decode failure returns `None` so the caller will recompute.
//! - `set()` — `SETEX marketplace:coverage:v1 21600 <json>`. Best effort;
//!   Redis errors are logged and swallowed.
//! - `invalidate()` — `DEL marketplace:coverage:v1`. Backs the manual
//!   refresh button.
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
//! The cache key is suffixed with `:v1`. If the `MarketplaceCoverage`
//! schema ever changes shape (added/renamed fields), bump to `:v2` rather
//! than flushing — old replicas still reading `:v1` will keep working until
//! they roll, and new replicas writing `:v2` will overlap cleanly with no
//! cache stampede.

use std::sync::Arc;

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::coverage::MarketplaceCoverage;

/// 6 hours, in seconds. Matches the round-1 React Query `staleTime`; the
/// underlying SQL window is 24h, so re-running more often than this would
/// rarely show meaningfully different numbers.
const COVERAGE_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

/// Versioned key — bump the suffix on schema changes (see module docs).
const COVERAGE_CACHE_KEY: &str = "marketplace:coverage:v1";

/// Shared cache for the marketplace coverage hero.
///
/// Cloneable + Send + Sync. When `redis` is `None`, every operation is a
/// no-op / cache miss — the caller falls through to a real recompute, same
/// as the in-memory presence-tracker fallback.
#[derive(Clone, Default)]
pub struct MarketplaceCoverageCache {
    redis: Option<Arc<Mutex<ConnectionManager>>>,
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
    pub async fn get(&self) -> Option<MarketplaceCoverage> {
        let redis = self.redis.as_ref()?;
        let mut conn = redis.lock().await;
        let payload: Option<String> = match conn.get(COVERAGE_CACHE_KEY).await {
            Ok(p) => p,
            Err(err) => {
                debug!(error = %err, key = COVERAGE_CACHE_KEY, "marketplace_coverage_cache: GET failed");
                return None;
            }
        };
        drop(conn);
        let raw = payload?;
        match serde_json::from_str::<MarketplaceCoverage>(&raw) {
            Ok(cov) => Some(cov),
            Err(err) => {
                warn!(error = %err, key = COVERAGE_CACHE_KEY, "marketplace_coverage_cache: cached payload failed to deserialize; treating as miss");
                None
            }
        }
    }

    /// Store the freshly-computed coverage payload with a 6h TTL. Best
    /// effort — any Redis or serialization error is logged and swallowed.
    pub async fn set(&self, value: &MarketplaceCoverage) {
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
        let result: redis::RedisResult<()> = conn
            .set_ex(COVERAGE_CACHE_KEY, json, COVERAGE_CACHE_TTL_SECS)
            .await;
        drop(conn);
        if let Err(err) = result {
            warn!(error = %err, key = COVERAGE_CACHE_KEY, "marketplace_coverage_cache: SETEX failed");
        }
    }

    /// Drop the cached entry so the next `get()` is forced to miss. Used by
    /// the manual-refresh endpoint.
    pub async fn invalidate(&self) {
        let Some(redis) = self.redis.as_ref() else {
            return;
        };
        let mut conn = redis.lock().await;
        let result: redis::RedisResult<()> = conn.del(COVERAGE_CACHE_KEY).await;
        drop(conn);
        if let Err(err) = result {
            warn!(error = %err, key = COVERAGE_CACHE_KEY, "marketplace_coverage_cache: DEL failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_cache_misses_silently() {
        // Without Redis the cache is a permanent miss — the caller will
        // always recompute. set/invalidate are no-ops and don't error.
        let cache = MarketplaceCoverageCache::new();
        assert!(cache.get().await.is_none());
        cache.invalidate().await;
        cache
            .set(&MarketplaceCoverage {
                artifacts: vec![],
                computed_at: chrono::Utc::now(),
            })
            .await;
        assert!(cache.get().await.is_none());
    }
}
