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
//! Reads are cached for [`RISK_CONFIG_CACHE_TTL`]. Lake clear deltas refresh on
//! the publisher's two-second cadence so a just-issued analyst clear is not
//! hidden behind the former 60-second configuration cache. On a
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
pub const RISK_CONFIG_CACHE_TTL: Duration = Duration::from_secs(2);

/// Cleared-boundary lookback, mirroring the enterprise
/// `CLEAR_BOUNDARY_LOOKBACK_DAYS` (`repository.rs`): only the trailing 7 days
/// can affect a 7-day decay horizon.
const CLEAR_BOUNDARY_LOOKBACK_DAYS: i64 = 7;
const GLOBAL_CLEAR_ENTITY: &str = "__nano_global_clear_boundary__";

#[derive(Clone)]
struct CachedSnapshot {
    fetched_at: Instant,
    decay: RiskDecayConfig,
    cleared: ClearedBoundaries,
    lake_cleared: Option<ClearedBoundaries>,
    lake_minimum_clear_revision: Option<i64>,
}

/// Where a provider's decay/cleared state comes from.
#[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
enum RiskConfigSource {
    /// Dedicated / open-core: the process's ambient Postgres pool.
    Pool(PgPool),
    /// Enterprise-shared tenant view with no request-bound tenant state: the
    /// shipped defaults only. The process pool is never tenant authority on
    /// the shared runtime, so a tenant view must not read it.
    Unbound,
    /// Enterprise-shared: one request's tenant decay + clear state, read in
    /// that tenant's signed transaction and pinned to the tenant UUID.
    Tenant {
        tenant_id: uuid::Uuid,
        snapshot: Box<CachedSnapshot>,
    },
}

/// Cached resolver for the risk dataset's decay factors + cleared boundaries.
/// One per `SearchService`; shared via `Arc`.
pub struct RiskQueryConfigProvider {
    source: RiskConfigSource,
    cache: tokio::sync::RwLock<Option<CachedSnapshot>>,
    ttl: Duration,
}

impl RiskQueryConfigProvider {
    pub fn new(pool: PgPool) -> Self {
        Self {
            source: RiskConfigSource::Pool(pool),
            cache: tokio::sync::RwLock::new(None),
            ttl: RISK_CONFIG_CACHE_TTL,
        }
    }

    /// A provider that never reads the process pool: shipped defaults, no
    /// clears. Installed on every enterprise-shared tenant view until a
    /// request binds its tenant's own state with [`Self::for_tenant`].
    pub fn unbound() -> Self {
        Self {
            source: RiskConfigSource::Unbound,
            cache: tokio::sync::RwLock::new(None),
            ttl: RISK_CONFIG_CACHE_TTL,
        }
    }

    /// A provider pinned to one enterprise-shared tenant's decay and clear
    /// state (`shared_risk::read_risk_configuration` /
    /// `read_clear_state`, read in the tenant's signed transaction). The
    /// boundaries are the exact set the tenant `/v1/risk` reads send, so
    /// `dataset=risk` scores match the Risk page.
    #[cfg(feature = "enterprise")]
    pub fn for_tenant(
        tenant_id: uuid::Uuid,
        decay: RiskDecayConfig,
        clear: &crate::enterprise_shared_risk::TenantRiskClearState,
    ) -> Result<Self, &'static str> {
        if tenant_id.is_nil() {
            return Err("tenant risk configuration requires a tenant identity");
        }
        let cleared = ClearedBoundaries::from_map(&clear.boundaries).with_watch(clear.watch.clone());
        Ok(Self {
            source: RiskConfigSource::Tenant {
                tenant_id,
                snapshot: Box::new(CachedSnapshot {
                    fetched_at: Instant::now(),
                    decay,
                    lake_cleared: Some(cleared.clone()),
                    cleared,
                    lake_minimum_clear_revision: clear.minimum_revision,
                }),
            },
            cache: tokio::sync::RwLock::new(None),
            ttl: RISK_CONFIG_CACHE_TTL,
        })
    }

    /// The tenant this provider's state belongs to, when it is a
    /// request-bound enterprise-shared provider.
    pub fn bound_tenant_id(&self) -> Option<uuid::Uuid> {
        match &self.source {
            RiskConfigSource::Tenant { tenant_id, .. } => Some(*tenant_id),
            _ => None,
        }
    }

    /// Resolve the current [`RiskQueryConfig`], anchored at `Utc::now()`.
    /// Served from cache within the TTL; infallible by design (see module
    /// docs for the degradation ladder).
    pub async fn resolve(&self) -> RiskQueryConfig {
        match &self.source {
            RiskConfigSource::Pool(_) => {}
            RiskConfigSource::Unbound => return RiskQueryConfig::default(),
            RiskConfigSource::Tenant { snapshot, .. } => {
                return RiskQueryConfig {
                    decay: snapshot.decay.clone(),
                    cleared: snapshot.cleared.clone(),
                    lake_cleared: snapshot.lake_cleared.clone(),
                    lake_minimum_clear_revision: snapshot.lake_minimum_clear_revision,
                    now: Utc::now(),
                };
            }
        }
        if let Some(snap) = self.fresh_snapshot().await {
            return RiskQueryConfig {
                decay: snap.decay,
                cleared: snap.cleared,
                lake_cleared: snap.lake_cleared,
                lake_minimum_clear_revision: snap.lake_minimum_clear_revision,
                now: Utc::now(),
            };
        }

        let snapshot = self.fetch_snapshot().await;
        RiskQueryConfig {
            decay: snapshot.decay,
            cleared: snapshot.cleared,
            lake_cleared: snapshot.lake_cleared,
            lake_minimum_clear_revision: snapshot.lake_minimum_clear_revision,
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
        let RiskConfigSource::Pool(pool) = &self.source else {
            // Unreachable: `resolve` answers non-pool sources itself.
            return CachedSnapshot {
                fetched_at: Instant::now(),
                decay: RiskDecayConfig::default(),
                cleared: ClearedBoundaries::from_map(&HashMap::new()),
                lake_cleared: None,
                lake_minimum_clear_revision: None,
            };
        };
        let decay = Self::fetch_decay_config(pool).await;
        let watch = Self::fetch_watch_weights(pool).await;
        let cleared = Self::fetch_cleared_boundaries(pool)
            .await
            .zip(watch)
            .map(|(cleared, watch)| cleared.with_watch(watch));
        let lake_clear = Self::fetch_lake_clear_delta(pool).await;

        let mut guard = self.cache.write().await;
        match (decay, cleared) {
            (Some(decay), Some(cleared)) => {
                let (lake_cleared, lake_minimum_clear_revision) = lake_clear
                    .flatten()
                    .map_or((None, None), |(revision, delta)| {
                        (Some(delta), Some(revision))
                    });
                let snap = CachedSnapshot {
                    fetched_at: Instant::now(),
                    decay,
                    cleared,
                    lake_cleared,
                    lake_minimum_clear_revision,
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
                lake_cleared: None,
                lake_minimum_clear_revision: None,
            }),
        }
    }

    /// Mirror of the enterprise `RiskRepository::get_decay_config`, tolerant of
    /// the open-core schema (no enterprise decay columns → defaults).
    async fn fetch_decay_config(pool: &PgPool) -> Option<RiskDecayConfig> {
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
        .fetch_optional(pool)
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

    /// The dedicated tenant's watchlist weights (NAN-3228). Tolerant of the
    /// open-core / pre-migration schema (no tables means no weights).
    async fn fetch_watch_weights(pool: &PgPool) -> Option<super::watchlist::RiskWatchWeights> {
        match super::watchlist::read_watch_weights(pool, super::watchlist::DEDICATED_TENANT_ID).await {
            Ok(weights) => Some(weights),
            Err(e) if super::watchlist::is_missing_watchlist_schema(&e) => {
                debug!("risk watchlist tables absent; no watchlist weights");
                Some(super::watchlist::RiskWatchWeights::default())
            }
            Err(e) => {
                warn!("risk watchlist weight read failed: {e}");
                None
            }
        }
    }

    /// Mirror of the enterprise `RiskRepository::get_cleared_entities`:
    /// one optional global clear watermark plus only the sparse per-entity
    /// boundaries newer than it. Tolerant of the open-core schema (no
    /// enterprise risk tables means nothing is cleared).
    async fn fetch_cleared_boundaries(pool: &PgPool) -> Option<ClearedBoundaries> {
        // NAN-3463: the clear tables exist only under the enterprise overlay.
        // The open edition never issues the read, rather than relying on the
        // 42P01 fallback below: that fallback still made PostgreSQL log an
        // error on every 2-second cache refresh.
        if !cfg!(feature = "enterprise") {
            return Some(ClearedBoundaries::from_map(&HashMap::new()));
        }
        let cutoff = Utc::now() - chrono::Duration::days(CLEAR_BOUNDARY_LOOKBACK_DAYS);
        let result = sqlx::query(
            r#"
            WITH global_boundary AS (
                SELECT MAX(cleared_at) AS cleared_at
                FROM risk_global_clear_boundary
                WHERE singleton = TRUE
            ), boundaries AS (
                SELECT entity, MAX(cleared_at) AS cleared_at
                FROM risk_clears
                WHERE cleared_at >= $1
                  AND cleared_at > COALESCE(
                      (SELECT cleared_at FROM global_boundary),
                      '-infinity'::timestamptz
                  )
                GROUP BY entity
                UNION ALL
                SELECT $2::text, cleared_at
                FROM global_boundary
                WHERE cleared_at >= $1
            )
            SELECT entity, cleared_at FROM boundaries
            "#,
        )
        .bind(cutoff)
        .bind(GLOBAL_CLEAR_ENTITY)
        .fetch_all(pool)
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

    /// Resolve only boundaries newer than the clear sidecar that the publisher
    /// has already activated. The outer `Option` distinguishes a transient
    /// database failure from a deployment without this lake metadata; either
    /// case safely falls back to sending the complete boundary map.
    async fn fetch_lake_clear_delta(pool: &PgPool) -> Option<Option<(i64, ClearedBoundaries)>> {
        // NAN-3463: enterprise-only tables; see `fetch_cleared_boundaries`.
        if !cfg!(feature = "enterprise") {
            return Some(None);
        }
        let published_revision = match sqlx::query_scalar::<_, i64>(
            "SELECT published_revision FROM risk_clear_lake_snapshot WHERE singleton = TRUE",
        )
        .fetch_optional(pool)
        .await
        {
            Ok(Some(revision)) if revision >= 0 => revision,
            Ok(_) => return Some(None),
            Err(error) if is_missing_schema(&error) => return Some(None),
            Err(error) => {
                warn!("risk clear lake-snapshot metadata read failed: {error}");
                return None;
            }
        };
        let cutoff = Utc::now() - chrono::Duration::days(CLEAR_BOUNDARY_LOOKBACK_DAYS);
        let rows = match sqlx::query(
            r#"
            WITH global_boundary AS (
                SELECT cleared_at, revision
                FROM risk_global_clear_boundary
                WHERE singleton = TRUE AND cleared_at >= $1
            ), boundaries AS (
                SELECT entity, MAX(cleared_at) AS cleared_at
                FROM risk_clears
                WHERE cleared_at >= $1
                  AND cleared_at > COALESCE(
                        (SELECT cleared_at FROM global_boundary),
                        '-infinity'::timestamptz
                  )
                  AND revision > $2
                GROUP BY entity
                UNION ALL
                SELECT $3::text, cleared_at
                FROM global_boundary
                WHERE revision > $2
            )
            SELECT entity, cleared_at FROM boundaries
            "#,
        )
        .bind(cutoff)
        .bind(published_revision)
        .bind(GLOBAL_CLEAR_ENTITY)
        .fetch_all(pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) if is_missing_schema(&error) => return Some(None),
            Err(error) => {
                warn!("risk clear lake delta read failed: {error}");
                return None;
            }
        };
        let map = rows
            .into_iter()
            .map(|row| (row.get("entity"), row.get("cleared_at")))
            .collect::<HashMap<String, DateTime<Utc>>>();
        Some(Some((
            published_revision,
            ClearedBoundaries::from_map(&map),
        )))
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

#[cfg(test)]
mod tenant_source_tests {
    use super::*;

    #[tokio::test]
    async fn unbound_provider_serves_defaults_without_a_pool() {
        let provider = RiskQueryConfigProvider::unbound();
        let config = provider.resolve().await;
        assert_eq!(config.decay, RiskDecayConfig::default());
        assert_eq!(config.cleared.entities(), &[String::new()]);
        assert!(config.lake_cleared.is_none());
        assert!(config.lake_minimum_clear_revision.is_none());
        assert_eq!(provider.bound_tenant_id(), None);
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn tenant_provider_carries_exactly_the_tenant_state() {
        let tenant = uuid::Uuid::from_u128(0xa);
        let boundary = DateTime::parse_from_rfc3339("2026-09-28T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let clear = crate::enterprise_shared_risk::TenantRiskClearState { watch: Default::default(),
            minimum_revision: Some(7),
            boundaries: HashMap::from([
                ("alice".to_string(), boundary),
                (GLOBAL_CLEAR_ENTITY.to_string(), boundary),
            ]),
        };
        let decay = RiskDecayConfig { decay_0_24h: 1.0, decay_1_3d: 0.5, decay_3_5d: 0.25, decay_5_7d: 0.1 };
        let provider = RiskQueryConfigProvider::for_tenant(tenant, decay.clone(), &clear).unwrap();
        assert_eq!(provider.bound_tenant_id(), Some(tenant));
        let config = provider.resolve().await;
        assert_eq!(config.decay, decay);
        assert_eq!(config.lake_minimum_clear_revision, Some(7));
        let lake = config.lake_cleared.expect("lake requests carry the tenant boundaries");
        let pairs: HashMap<&str, i64> = lake
            .entities()
            .iter()
            .map(String::as_str)
            .zip(lake.boundaries_micros().iter().copied())
            .filter(|(entity, _)| !entity.is_empty())
            .collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs["alice"], boundary.timestamp_micros());
        assert_eq!(pairs[GLOBAL_CLEAR_ENTITY], boundary.timestamp_micros());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_provider_refuses_a_nil_tenant() {
        let clear = crate::enterprise_shared_risk::TenantRiskClearState::default();
        assert!(RiskQueryConfigProvider::for_tenant(uuid::Uuid::nil(), RiskDecayConfig::default(), &clear).is_err());
    }
}
