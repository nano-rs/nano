// SPDX-License-Identifier: AGPL-3.0-or-later

//! Marketplace coverage hero — pct of events whose key artifacts are enriched.
//!
//! Drives the "Enrichment coverage · by artifact type" card on the redesigned
//! `/marketplace` page. For each of 6 artifact types we report:
//!
//! - `pct`: events with the artifact present that also got an enrichment field
//!   populated (in the last 24h)
//! - `state`: a 3-band classification (`good` ≥ 75 %, `partial` 30–74 %,
//!   `gap` < 30 %)
//! - `have`: installed providers from the recommended set for this artifact
//! - `missing`: recommended providers that are NOT installed
//!
//! Computed in a single ClickHouse round-trip via 12 `countIf` clauses (one
//! denominator + one numerator per artifact). Postgres is read for the
//! installed-providers set.

use chrono::{DateTime, Utc};
use clickhouse::Client as ChClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, instrument, warn};

use crate::marketplace::cache::MarketplaceCoverageCache;
use crate::marketplace::error::MarketplaceError;

// ============================================================================
// Recommended-provider map
// ============================================================================
//
// Conservative set of slugs that are recommended for each artifact type. The
// frontend hero shows installed providers from this list as `have` chips, and
// remaining ones as dashed `missing` chips that prefill the marketplace
// search when clicked. Add to (don't trim) this list as new integrations
// land — the catalog itself is the source of truth for what exists.

const ARTIFACTS: &[(&str, &str, &[&str])] = &[
    (
        "ip",
        "IP addresses",
        &[
            "abuseipdb",
            "greynoise",
            "virustotal",
            "ipinfo_lite",
            "tor-exit-nodes",
        ],
    ),
    (
        "domain",
        "Domains & URLs",
        &["virustotal", "urlhaus", "threatfox"],
    ),
    (
        "hash",
        "File hashes",
        &["virustotal", "malwarebazaar", "threatfox"],
    ),
    (
        "user",
        "Users & identity",
        &[
            "okta",
            "entra-id",
            "google-workspace",
            "active-directory",
            "workday",
        ],
    ),
    ("asset", "Assets & hosts", &["active-directory"]),
    ("asn", "ASN & geolocation", &["ipinfo_lite", "shodan"]),
];

// ============================================================================
// Public types
// ============================================================================

/// Coverage state band — drives the chip color in the hero card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CoverageState {
    Good,
    Partial,
    Gap,
}

impl CoverageState {
    fn from_pct(pct: u8) -> Self {
        if pct >= 75 {
            CoverageState::Good
        } else if pct >= 30 {
            CoverageState::Partial
        } else {
            CoverageState::Gap
        }
    }
}

/// Coverage row for one artifact type.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactCoverage {
    /// Stable id ("ip", "domain", "hash", "user", "asset", "asn")
    pub id: String,
    /// Display label ("IP addresses", "Domains & URLs", …)
    pub label: String,
    /// 0..=100 enrichment ratio over the last 24h
    pub pct: u8,
    pub state: CoverageState,
    /// Display labels of installed providers from the recommended set
    pub have: Vec<String>,
    /// Display labels of recommended providers that are NOT installed
    pub missing: Vec<String>,
}

/// Top-level response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MarketplaceCoverage {
    pub artifacts: Vec<ArtifactCoverage>,
    /// Wall-clock time the coverage SQL was last executed (UTC). Stamped
    /// on the hero so users can tell when the data was last refreshed —
    /// because the response is shared-cached for 6h, this is *not* the
    /// time the request was served. Use the manual-refresh button to
    /// force a recompute.
    pub computed_at: DateTime<Utc>,
}

// ============================================================================
// Single ClickHouse aggregate
// ============================================================================

/// Raw row returned by the coverage SQL — 12 fields (denominator + numerator
/// per artifact).
#[derive(Debug, Default, Deserialize, clickhouse::Row)]
struct CoverageCounts {
    ip_total: u64,
    ip_enriched: u64,
    domain_total: u64,
    domain_enriched: u64,
    hash_total: u64,
    hash_enriched: u64,
    user_total: u64,
    user_enriched: u64,
    asset_total: u64,
    asset_enriched: u64,
    asn_total: u64,
    asn_enriched: u64,
}

const COVERAGE_SQL: &str = r#"
SELECT
    countIf(src_ip != '' OR dest_ip != '')                                                        AS ip_total,
    countIf(
        (src_ip  != '' AND (enriched_src_country  != '' OR enriched_src_asn  != '' OR ioc_src_ip_threat_type  != ''))
     OR (dest_ip != '' AND (enriched_dest_country != '' OR enriched_dest_asn != '' OR ioc_dest_ip_threat_type != '' OR prevalence_dest_ip < 65535))
    )                                                                                              AS ip_enriched,

    countIf(url != '' OR (dest_host != '' AND NOT isIPv4String(dest_host)))
                                                                                                   AS domain_total,
    countIf(
        (dest_host != '' AND NOT isIPv4String(dest_host) AND prevalence_dest_domain < 65535)
    )                                                                                              AS domain_enriched,

    countIf(file_hash != '' OR process_hash != '')                                                AS hash_total,
    countIf(
        (file_hash    != '' AND prevalence_file_hash    < 65535)
     OR (process_hash != '' AND prevalence_process_hash < 65535)
    )                                                                                              AS hash_enriched,

    countIf(user != '' OR src_user != '' OR dest_user != '')                                      AS user_total,
    countIf(
        (src_user  != '' AND src_user_identity_display_name  != '')
     OR (dest_user != '' AND dest_user_identity_display_name != '')
    )                                                                                              AS user_enriched,

    countIf(src_host != '' OR dest_host != '')                                                    AS asset_total,
    countIf(
        (src_host  != '' AND prevalence_dest_domain < 65535)
     OR (dest_host != '' AND prevalence_dest_domain < 65535)
    )                                                                                              AS asset_enriched,

    countIf(src_ip != '' OR dest_ip != '')                                                        AS asn_total,
    countIf(
        (src_ip  != '' AND enriched_src_asn  != '')
     OR (dest_ip != '' AND enriched_dest_asn != '')
    )                                                                                              AS asn_enriched
FROM logs
PREWHERE timestamp >= now() - INTERVAL 24 HOUR
"#;

async fn fetch_counts(ch: &ChClient) -> CoverageCounts {
    match ch
        .query(COVERAGE_SQL)
        .fetch_one::<CoverageCounts>()
        .await
    {
        Ok(row) => row,
        Err(e) => {
            warn!(error = %e, "marketplace_coverage: ClickHouse aggregate failed; returning zeros");
            CoverageCounts::default()
        }
    }
}

// ============================================================================
// Service entry
// ============================================================================

#[derive(Clone)]
pub struct MarketplaceCoverageService {
    pool: PgPool,
    ch_client: ChClient,
    cache: MarketplaceCoverageCache,
}

impl MarketplaceCoverageService {
    /// Construct a service that consults `cache` before recomputing. In
    /// production the cache is Dragonfly-backed (see
    /// [`MarketplaceCoverageCache::with_redis`]), so a slow recompute on
    /// one replica warms every user's hero on every replica for the next
    /// 6 hours.
    pub fn new_with_cache(
        pool: PgPool,
        ch_client: ChClient,
        cache: MarketplaceCoverageCache,
    ) -> Self {
        Self {
            pool,
            ch_client,
            cache,
        }
    }

    /// Compute (or return cached) coverage. On a cache hit this is a single
    /// Redis round-trip + JSON decode — usually sub-millisecond. On a miss
    /// we run the full Postgres + 12-`countIf` ClickHouse aggregate, then
    /// `set()` the result so the next caller (and every other replica)
    /// hits the warm cache.
    #[instrument(skip(self))]
    pub async fn compute(&self) -> Result<MarketplaceCoverage, MarketplaceError> {
        if let Some(cached) = self.cache.get().await {
            info!(
                artifact_count = cached.artifacts.len(),
                computed_at = %cached.computed_at,
                "marketplace_coverage: cache HIT"
            );
            return Ok(cached);
        }

        let coverage = self.recompute().await?;
        // Best-effort: a Redis hiccup here just means the next caller also
        // recomputes. Don't fail the response over it.
        self.cache.set(&coverage).await;
        Ok(coverage)
    }

    /// Recompute coverage unconditionally, bypassing the cache. The
    /// refresh endpoint calls `cache.invalidate()` first and then `compute()`
    /// — keeping invalidate + compute as the public flow makes it obvious
    /// that the cache is also re-warmed (via `compute`'s `set`) on the
    /// next read.
    pub async fn recompute(&self) -> Result<MarketplaceCoverage, MarketplaceError> {
        // 1. Look up installed slug → name from Postgres so the hero chips can
        // render display labels rather than raw slugs. We pull both because
        // the recommended map is keyed by slug but the chips show the name.
        let installed: Vec<(String, String)> = sqlx::query_as(
            "SELECT slug, name FROM marketplace_catalog WHERE installed = true",
        )
        .fetch_all(&self.pool)
        .await?;

        // 2. Fan one query at ClickHouse.
        let counts = fetch_counts(&self.ch_client).await;

        // 3. Project each artifact row using the counts + installed set + the
        // recommended map.
        let artifacts = ARTIFACTS
            .iter()
            .map(|(id, label, recommended)| {
                let (total, enriched) = match *id {
                    "ip" => (counts.ip_total, counts.ip_enriched),
                    "domain" => (counts.domain_total, counts.domain_enriched),
                    "hash" => (counts.hash_total, counts.hash_enriched),
                    "user" => (counts.user_total, counts.user_enriched),
                    "asset" => (counts.asset_total, counts.asset_enriched),
                    "asn" => (counts.asn_total, counts.asn_enriched),
                    _ => (0, 0),
                };
                let pct = if total == 0 {
                    0
                } else {
                    ((enriched as f64 / total as f64) * 100.0).round().clamp(0.0, 100.0) as u8
                };

                let mut have = Vec::new();
                let mut missing = Vec::new();
                for slug in *recommended {
                    if let Some((_, name)) = installed.iter().find(|(s, _)| s == slug) {
                        have.push(name.clone());
                    } else {
                        missing.push(human_name_for(slug));
                    }
                }

                ArtifactCoverage {
                    id: (*id).to_string(),
                    label: (*label).to_string(),
                    pct,
                    state: CoverageState::from_pct(pct),
                    have,
                    missing,
                }
            })
            .collect();

        Ok(MarketplaceCoverage {
            artifacts,
            computed_at: Utc::now(),
        })
    }
}

/// Best-effort display name for a slug that isn't installed yet (so it has no
/// row in `marketplace_catalog`). Falls back to a Title-cased slug.
fn human_name_for(slug: &str) -> String {
    match slug {
        "abuseipdb" => "AbuseIPDB".to_string(),
        "greynoise" => "GreyNoise".to_string(),
        "virustotal" => "VirusTotal".to_string(),
        "ipinfo_lite" | "ipinfo-lite" => "IPinfo Lite".to_string(),
        "tor-exit-nodes" => "Tor Exit Nodes".to_string(),
        "urlhaus" => "URLhaus".to_string(),
        "threatfox" => "ThreatFox".to_string(),
        "malwarebazaar" => "MalwareBazaar".to_string(),
        "okta" => "Okta".to_string(),
        "entra-id" => "Microsoft Entra ID".to_string(),
        "google-workspace" => "Google Workspace".to_string(),
        "active-directory" => "Active Directory".to_string(),
        "workday" => "Workday".to_string(),
        "shodan" => "Shodan".to_string(),
        other => other
            .split('-')
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    Some(first) => first.to_ascii_uppercase().to_string() + c.as_str(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_state_bands() {
        assert_eq!(CoverageState::from_pct(0), CoverageState::Gap);
        assert_eq!(CoverageState::from_pct(29), CoverageState::Gap);
        assert_eq!(CoverageState::from_pct(30), CoverageState::Partial);
        assert_eq!(CoverageState::from_pct(74), CoverageState::Partial);
        assert_eq!(CoverageState::from_pct(75), CoverageState::Good);
        assert_eq!(CoverageState::from_pct(100), CoverageState::Good);
    }

    #[test]
    fn human_name_for_known_slug() {
        assert_eq!(human_name_for("threatfox"), "ThreatFox");
        assert_eq!(human_name_for("abuseipdb"), "AbuseIPDB");
    }

    #[test]
    fn human_name_for_unknown_slug() {
        assert_eq!(human_name_for("foo-bar"), "Foo Bar");
        assert_eq!(human_name_for("solo"), "Solo");
    }
}
