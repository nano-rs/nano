// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cached per-request configuration provider for the nPL `dataset=risk`
//! derived base source (NAN-1798 P2).
//!
//! The risk dataset's decayed scores MUST equal the Risk page / leaderboard
//! numbers, so the generator has to inject the SAME two dynamic inputs the
//! enterprise `RiskRepository` binds on every read:
//!
//! - the TTL decay factors (`system_settings.decay_0_24h/1_3d/3_5d/5_7d`,
//!   mirrored from `RiskRepository::get_decay_config`), and
//! - the cleared-entity boundaries (`risk_clears`, 7-day lookback, mirrored
//!   from `RiskRepository::get_cleared_entities` — NAN-1810 moved the
//!   boundary off the retired `entity_risk_scores` rollup onto the slim
//!   `risk_clears` table).
//!
//! Both live behind enterprise-managed schema: the decay columns and the
//! `risk_clears` table are enterprise overlays absent from open-core
//! Postgres. Open-core still HAS a risk dataset (findings are written to
//! ClickHouse by every deployment), so missing schema degrades to the shipped
//! defaults (decay 1.0/0.7/0.4/0.2, nothing cleared) instead of erroring —
//! exactly the values the enterprise readers would COALESCE to on a fresh
//! install.
//!
//! Reads are cached for [`RISK_CONFIG_CACHE_TTL`] (design §4: "cached (60s)
//! read"), so per-search resolution is a lock read on the hot path. On a
//! transient Postgres error the provider serves the last cached snapshot
//! (stale-ok — clears and decay edits are rare) and only falls back to
//! defaults when it has never resolved successfully.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use tracing::{debug, warn};

use super::clickhouse_sql::{ClearedBoundaries, RiskQueryConfig};
use super::types::RiskDecayConfig;

/// How long a resolved decay/cleared snapshot is served before re-reading
/// Postgres (design §4). Clears/decay edits are rare.
pub const RISK_CONFIG_CACHE_TTL: Duration = Duration::from_secs(60);

/// Cleared-boundary lookback, mirroring the enterprise
/// `CLEAR_BOUNDARY_LOOKBACK_DAYS` (`repository.rs`): only the trailing 7 days
/// can affect a 7-day decay horizon.
const CLEAR_BOUNDARY_LOOKBACK_DAYS: i64 = 7;

#[derive(Clone)]
struct CachedSnapshot {
    fetched_at: Instant,
    decay: RiskDecayConfig,
    cleared: ClearedBoundaries,
}

/// Cached resolver for the risk dataset's decay factors + cleared boundaries.
/// One per `SearchService`; shared via `Arc`.
pub struct RiskQueryConfigProvider {
    pool: PgPool,
    cache: tokio::sync::RwLock<Option<CachedSnapshot>>,
    ttl: Duration,
}

impl RiskQueryConfigProvider {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: tokio::sync::RwLock::new(None),
            ttl: RISK_CONFIG_CACHE_TTL,
        }
    }

    /// Resolve the current [`RiskQueryConfig`], anchored at `Utc::now()`.
    /// Served from cache within the TTL; infallible by design (see module
    /// docs for the degradation ladder).
    pub async fn resolve(&self) -> RiskQueryConfig {
        if let Some(snap) = self.fresh_snapshot().await {
            return RiskQueryConfig {
                decay: snap.decay,
                cleared: snap.cleared,
                now: Utc::now(),
            };
        }

        let snapshot = self.fetch_snapshot().await;
        RiskQueryConfig {
            decay: snapshot.decay,
            cleared: snapshot.cleared,
            now: Utc::now(),
        }
    }

    /// The cached snapshot when it is still within the TTL.
    async fn fresh_snapshot(&self) -> Option<CachedSnapshot> {
        let guard = self.cache.read().await;
        guard
            .as_ref()
            .filter(|snap| snap.fetched_at.elapsed() < self.ttl)
            .cloned()
    }

    /// Re-read Postgres and refresh the cache. On error, serve the stale
    /// snapshot if one exists, else the shipped defaults.
    async fn fetch_snapshot(&self) -> CachedSnapshot {
        let decay = self.fetch_decay_config().await;
        let cleared = self.fetch_cleared_boundaries().await;

        let mut guard = self.cache.write().await;
        match (decay, cleared) {
            (Some(decay), Some(cleared)) => {
                let snap = CachedSnapshot {
                    fetched_at: Instant::now(),
                    decay,
                    cleared,
                };
                *guard = Some(snap.clone());
                snap
            }
            // Partial/failed read: keep serving the previous snapshot (stale-ok)
            // rather than mixing sources; defaults only when never resolved.
            // Deliberately NOT stored — the cache stays empty/stale so the next
            // request retries Postgres instead of pinning the fallback for a TTL.
            _ => guard.clone().unwrap_or_else(|| CachedSnapshot {
                fetched_at: Instant::now(),
                decay: RiskDecayConfig::default(),
                cleared: ClearedBoundaries::from_map(&HashMap::new()),
            }),
        }
    }

    /// Mirror of the enterprise `RiskRepository::get_decay_config`, tolerant of
    /// the open-core schema (no enterprise decay columns → defaults).
    async fn fetch_decay_config(&self) -> Option<RiskDecayConfig> {
        let result = sqlx::query(
            r#"
            SELECT
                COALESCE(decay_0_24h, 1.0)::float8 as decay_0_24h,
                COALESCE(decay_1_3d, 0.7)::float8 as decay_1_3d,
                COALESCE(decay_3_5d, 0.4)::float8 as decay_3_5d,
                COALESCE(decay_5_7d, 0.2)::float8 as decay_5_7d
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(row) => Some(
                row.map(|r| RiskDecayConfig {
                    decay_0_24h: r.get("decay_0_24h"),
                    decay_1_3d: r.get("decay_1_3d"),
                    decay_3_5d: r.get("decay_3_5d"),
                    decay_5_7d: r.get("decay_5_7d"),
                })
                .unwrap_or_default(),
            ),
            Err(e) if is_missing_schema(&e) => {
                debug!("risk decay columns absent (open-core schema); using defaults");
                Some(RiskDecayConfig::default())
            }
            Err(e) => {
                warn!("risk decay config read failed: {e}");
                None
            }
        }
    }

    /// Mirror of the enterprise `RiskRepository::get_cleared_entities`
    /// (7-day lookback, per-entity max `cleared_at` from the slim
    /// `risk_clears` table, NAN-1810), tolerant of the open-core schema
    /// (no `risk_clears` table → nothing cleared).
    async fn fetch_cleared_boundaries(&self) -> Option<ClearedBoundaries> {
        let cutoff = Utc::now() - chrono::Duration::days(CLEAR_BOUNDARY_LOOKBACK_DAYS);
        let result = sqlx::query(
            r#"
            SELECT entity, MAX(cleared_at) AS cleared_at
            FROM risk_clears
            WHERE cleared_at >= $1
            GROUP BY entity
            "#,
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await;

        match result {
            Ok(rows) => {
                let map: HashMap<String, DateTime<Utc>> = rows
                    .into_iter()
                    .map(|r| (r.get("entity"), r.get("cleared_at")))
                    .collect();
                Some(ClearedBoundaries::from_map(&map))
            }
            Err(e) if is_missing_schema(&e) => {
                debug!("risk_clears absent (open-core schema); no cleared boundaries");
                Some(ClearedBoundaries::from_map(&HashMap::new()))
            }
            Err(e) => {
                warn!("risk cleared-boundary read failed: {e}");
                None
            }
        }
    }
}

/// Whether a Postgres error is "this deployment doesn't have the enterprise
/// risk schema" — undefined table (42P01) or undefined column (42703) — as
/// opposed to a transient failure.
fn is_missing_schema(e: &sqlx::Error) -> bool {
    matches!(
        e.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("42P01") | Some("42703")
    )
}
