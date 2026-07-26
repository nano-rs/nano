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

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use clickhouse::Client as ChClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{info, instrument, warn};

use crate::marketplace::cache::MarketplaceCoverageCache;
use crate::marketplace::error::MarketplaceError;
use crate::schema::{SchemaId, SchemaProfile};
use crate::search::service::source_scope_sql_predicate;

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

/// The byte-for-byte UDM coverage aggregate. Kept verbatim (not synthesized
/// from the profile) so the long-lived UDM behavior is provably unchanged by
/// the profile-awareness work (NAN-1241): `udm_column_sql` would, for UDM,
/// re-escape the reserved word `user` to `"user"` and otherwise round-trip the
/// same column names — functionally identical, but this const removes any doubt.
/// OCSF builds its own SQL in [`build_ocsf_coverage_sql`].
const UDM_COVERAGE_SQL: &str = r#"
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

/// SQL access expression for a UDM-semantic column under `profile`, or `None`
/// when the active schema has no column for that concept (so the caller drops
/// the predicate rather than referencing a nonexistent column and 500-ing the
/// whole aggregate). UDM always returns the column itself; OCSF returns the
/// promoted dotted column (e.g. `enriched_src_asn` →
/// `` `src_endpoint.autonomous_system.number` ``) or `None` for unmapped
/// concepts (`enriched_*_country`, `dest_user`, `*_identity_display_name`).
fn col(profile: &dyn SchemaProfile, udm_field: &str) -> Option<String> {
    profile.udm_column_sql(udm_field)
}

/// `present` predicate for a STRING-typed coverage column: `<col> != ''`.
/// Resolves the column via [`col`]; returns `None` to drop the term when the
/// schema doesn't carry it.
fn str_present(profile: &dyn SchemaProfile, udm_field: &str) -> Option<String> {
    col(profile, udm_field).map(|c| format!("{c} != ''"))
}

/// `present` predicate for an ASN column. UDM stores ASN as a String
/// (`enriched_src_asn != ''`); OCSF promotes it to a numeric
/// `autonomous_system.number` (UInt32), where presence is `!= 0`. The
/// String-vs-numeric encoding difference is the OCSF value-encoding gate
/// (NAN-1241) — comparing the OCSF UInt32 column to `''` would be a type error.
fn asn_present(profile: &dyn SchemaProfile, udm_field: &str) -> Option<String> {
    let c = col(profile, udm_field)?;
    Some(match profile.id() {
        SchemaId::Ocsf => format!("{c} != 0"),
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => {
            format!("{c} != ''")
        }
    })
}

/// `present` predicate for a prevalence column (UInt16; `< 65535` means "we
/// have a host_count for this artifact"). Byte-identical semantics across UDM
/// and OCSF — OCSF promotes real `prevalence_*` UInt16 columns (NAN-1248).
fn prev_present(profile: &dyn SchemaProfile, udm_field: &str) -> Option<String> {
    col(profile, udm_field).map(|c| format!("{c} < 65535"))
}

/// Join a set of OR-able sub-predicates, dropping any that resolved to `None`
/// (unmapped in this schema). Returns `None` when nothing survives so the
/// caller can fall back to a literal `0`.
fn any_of(parts: Vec<Option<String>>) -> Option<String> {
    let kept: Vec<String> = parts.into_iter().flatten().collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join(" OR "))
    }
}

/// `countIf(<pred>)`, or `countIf(0)` (always zero, but keeps the SELECT shape /
/// column arity stable so the row decodes) when `pred` is `None`.
fn count_if(pred: Option<String>) -> String {
    match pred {
        Some(p) => format!("countIf({p})"),
        None => "countIf(0)".to_string(),
    }
}

/// Build the coverage aggregate for an arbitrary (non-UDM) profile by resolving
/// every UDM-semantic column through `udm_column_sql` and skipping/zeroing the
/// ones the schema doesn't map. Mirrors [`UDM_COVERAGE_SQL`]'s 12-column shape
/// exactly (denominator + numerator per artifact) so [`CoverageCounts`] decodes
/// unchanged. Drives the marketplace coverage hero under OCSF instead of the old
/// hardcoded `FROM logs` query (which would 500: `logs` doesn't exist under OCSF
/// and the bare UDM `enriched_*`/`ioc_*` columns aren't promoted there).
fn build_coverage_sql(profile: &dyn SchemaProfile, is_clustered: bool) -> String {
    // FROM the active schema's logs table (`nanosiem.ocsf_logs` for OCSF). The
    // PREWHERE timestamp column is the same in both schemas (`timestamp`).
    // NAN-1728 (H5/R11): on a cluster the read fans in across all shards via the
    // `_distributed` wrapper; single-node keeps the bare local name
    // (byte-identical). Both logs and ocsf_logs are in the distributed set.
    let table = profile.table_name();
    let table = if is_clustered {
        format!("{table}_distributed")
    } else {
        table.to_string()
    };

    // --- ip ---
    let src_ip = col(profile, "src_ip");
    let dest_ip = col(profile, "dest_ip");
    let ip_total = any_of(vec![
        src_ip.as_ref().map(|c| format!("{c} != ''")),
        dest_ip.as_ref().map(|c| format!("{c} != ''")),
    ]);
    let src_enriched = any_of(vec![
        str_present(profile, "enriched_src_country"),
        asn_present(profile, "enriched_src_asn"),
        str_present(profile, "ioc_src_ip_threat_type"),
    ]);
    let dest_enriched = any_of(vec![
        str_present(profile, "enriched_dest_country"),
        asn_present(profile, "enriched_dest_asn"),
        str_present(profile, "ioc_dest_ip_threat_type"),
        prev_present(profile, "prevalence_dest_ip"),
    ]);
    let ip_enriched = any_of(vec![
        match (src_ip.as_ref(), src_enriched) {
            (Some(c), Some(e)) => Some(format!("({c} != '' AND ({e}))")),
            _ => None,
        },
        match (dest_ip.as_ref(), dest_enriched) {
            (Some(c), Some(e)) => Some(format!("({c} != '' AND ({e}))")),
            _ => None,
        },
    ]);

    // --- domain ---
    let url = col(profile, "url");
    let dest_host = col(profile, "dest_host");
    let domain_total = any_of(vec![
        url.as_ref().map(|c| format!("{c} != ''")),
        dest_host
            .as_ref()
            .map(|c| format!("({c} != '' AND NOT isIPv4String({c}))")),
    ]);
    let domain_enriched = match (dest_host.as_ref(), prev_present(profile, "prevalence_dest_domain")) {
        (Some(c), Some(p)) => Some(format!("({c} != '' AND NOT isIPv4String({c}) AND {p})")),
        _ => None,
    };

    // --- hash ---
    let file_hash = col(profile, "file_hash");
    let process_hash = col(profile, "process_hash");
    let hash_total = any_of(vec![
        file_hash.as_ref().map(|c| format!("{c} != ''")),
        process_hash.as_ref().map(|c| format!("{c} != ''")),
    ]);
    let hash_enriched = any_of(vec![
        match (file_hash.as_ref(), prev_present(profile, "prevalence_file_hash")) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
        match (
            process_hash.as_ref(),
            prev_present(profile, "prevalence_process_hash"),
        ) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
    ]);

    // --- user ---
    let user = col(profile, "user");
    let src_user = col(profile, "src_user");
    let dest_user = col(profile, "dest_user");
    let user_total = any_of(vec![
        user.as_ref().map(|c| format!("{c} != ''")),
        src_user.as_ref().map(|c| format!("{c} != ''")),
        dest_user.as_ref().map(|c| format!("{c} != ''")),
    ]);
    // Identity-enrichment display names have no OCSF column today; both terms
    // drop and `user_enriched` falls back to 0 (gap) until OCSF identity
    // enrichment lands. TODO(OCSF): wire user-identity enrichment presence once
    // the OCSF identity-enrichment columns exist (NAN-1148 lane).
    let user_enriched = any_of(vec![
        match (src_user.as_ref(), str_present(profile, "src_user_identity_display_name")) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
        match (
            dest_user.as_ref(),
            str_present(profile, "dest_user_identity_display_name"),
        ) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
    ]);

    // --- asset ---
    let src_host = col(profile, "src_host");
    let asset_total = any_of(vec![
        src_host.as_ref().map(|c| format!("{c} != ''")),
        dest_host.as_ref().map(|c| format!("{c} != ''")),
    ]);
    // Asset enrichment reuses the destination-domain prevalence signal (matches
    // the UDM query's existing — admittedly approximate — heuristic).
    let asset_enriched = any_of(vec![
        match (src_host.as_ref(), prev_present(profile, "prevalence_dest_domain")) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
        match (dest_host.as_ref(), prev_present(profile, "prevalence_dest_domain")) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
    ]);

    // --- asn ---
    let asn_total = any_of(vec![
        src_ip.as_ref().map(|c| format!("{c} != ''")),
        dest_ip.as_ref().map(|c| format!("{c} != ''")),
    ]);
    let asn_enriched = any_of(vec![
        match (src_ip.as_ref(), asn_present(profile, "enriched_src_asn")) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
        match (dest_ip.as_ref(), asn_present(profile, "enriched_dest_asn")) {
            (Some(c), Some(p)) => Some(format!("({c} != '' AND {p})")),
            _ => None,
        },
    ]);

    format!(
        "SELECT\n    {} AS ip_total,\n    {} AS ip_enriched,\n    {} AS domain_total,\n    {} AS domain_enriched,\n    {} AS hash_total,\n    {} AS hash_enriched,\n    {} AS user_total,\n    {} AS user_enriched,\n    {} AS asset_total,\n    {} AS asset_enriched,\n    {} AS asn_total,\n    {} AS asn_enriched\nFROM {}\nPREWHERE timestamp >= now() - INTERVAL 24 HOUR\n",
        count_if(ip_total),
        count_if(ip_enriched),
        count_if(domain_total),
        count_if(domain_enriched),
        count_if(hash_total),
        count_if(hash_enriched),
        count_if(user_total),
        count_if(user_enriched),
        count_if(asset_total),
        count_if(asset_enriched),
        count_if(asn_total),
        count_if(asn_enriched),
        table,
    )
}

/// Resolve the coverage SQL for the active profile. UDM uses the verbatim
/// long-lived const (byte-identical, zero behavioral drift); every other schema
/// synthesizes a profile-aware query.
fn coverage_sql(
    profile: &dyn SchemaProfile,
    is_clustered: bool,
    denied_sources: &BTreeSet<String>,
) -> String {
    let base = match profile.id() {
        // NAN-1728 (H5/R11): route the verbatim UDM aggregate's `FROM logs` to
        // the `_distributed` wrapper on a cluster so the hero counts all shards;
        // single-node returns the const byte-for-byte.
        SchemaId::Udm if is_clustered => {
            UDM_COVERAGE_SQL.replace("\nFROM logs\n", "\nFROM logs_distributed\n")
        }
        SchemaId::Udm => UDM_COVERAGE_SQL.to_string(),
        _ => build_coverage_sql(profile, is_clustered),
    };

    // NAN-2061: this hand-built aggregate bypasses the normal search-service
    // planner, so inject the same canonical source-scope predicate explicitly.
    // `source_type` is the operational String column under both UDM and OCSF
    // (the OCSF taxonomy mapping of the UDM concept to `class_uid` is not the
    // authorization dimension). An empty effective deny-set preserves the
    // long-lived UDM query byte-for-byte.
    let Some(predicate) = source_scope_sql_predicate("source_type", denied_sources) else {
        return base;
    };
    let time_gate = "PREWHERE timestamp >= now() - INTERVAL 24 HOUR";
    debug_assert!(
        base.contains(time_gate),
        "coverage aggregate must retain its 24-hour PREWHERE"
    );
    base.replacen(time_gate, &format!("{time_gate} AND {predicate}"), 1)
}

async fn fetch_counts(
    ch: &ChClient,
    profile: &dyn SchemaProfile,
    denied_sources: &BTreeSet<String>,
) -> CoverageCounts {
    let sql = coverage_sql(profile, coverage_is_clustered(), denied_sources);
    match ch.query(&sql).fetch_one::<CoverageCounts>().await {
        Ok(row) => row,
        Err(e) => {
            warn!(error = %e, "marketplace_coverage: ClickHouse aggregate failed; returning zeros");
            CoverageCounts::default()
        }
    }
}

/// Whether this deployment is a multi-shard ClickHouse cluster, derived from the
/// `CLICKHOUSE_CLUSTER` env — `MarketplaceCoverageService` holds a bare `ChClient`
/// (no `DualPool`), so it uses the same env signal `on_cluster_clause` /
/// retention.rs use. Unset (single-node / open-core) → the coverage SQL is
/// byte-identical to the pre-cluster form (NAN-1728).
fn coverage_is_clustered() -> bool {
    std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .is_some_and(|c| !c.trim().is_empty())
}

// ============================================================================
// Service entry
// ============================================================================

#[derive(Clone)]
pub struct MarketplaceCoverageService {
    pool: PgPool,
    ch_client: ChClient,
    cache: MarketplaceCoverageCache,
    /// Active schema profile — the coverage aggregate is built against it so the
    /// hero is correct under OCSF (`nanosiem.ocsf_logs` + promoted dotted
    /// enrichment columns) as well as UDM (NAN-1241).
    profile: Arc<dyn SchemaProfile>,
    /// Canonical effective source deny-set supplied by the authenticated API
    /// context. It drives both the ClickHouse predicate and cache partition, so
    /// the two cannot drift apart.
    denied_sources: BTreeSet<String>,
}

impl MarketplaceCoverageService {
    /// Construct a service that consults `cache` before recomputing. In
    /// production the cache is Dragonfly-backed (see
    /// [`MarketplaceCoverageCache::with_redis`]), so a slow recompute on
    /// one replica warms the hero for callers with the same effective source
    /// visibility on every replica for the next 6 hours.
    ///
    /// `profile` is the active schema profile (`state.config.schema_profile()`
    /// at the API call site); it selects the logs table and resolves each
    /// enrichment column per schema.
    pub fn new_with_cache(
        pool: PgPool,
        ch_client: ChClient,
        cache: MarketplaceCoverageCache,
        profile: Arc<dyn SchemaProfile>,
        denied_sources: BTreeSet<String>,
    ) -> Self {
        Self {
            pool,
            ch_client,
            cache,
            profile,
            denied_sources,
        }
    }

    /// Compute (or return cached) coverage. On a cache hit this is a single
    /// Redis round-trip + JSON decode — usually sub-millisecond. On a miss
    /// we run the full Postgres + 12-`countIf` ClickHouse aggregate, then
    /// `set()` the result so the next caller (and every other replica)
    /// hits the warm cache.
    #[instrument(skip(self))]
    pub async fn compute(&self) -> Result<MarketplaceCoverage, MarketplaceError> {
        if let Some(cached) = self.cache.get(&self.denied_sources).await {
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
        self.cache.set(&self.denied_sources, &coverage).await;
        Ok(coverage)
    }

    /// Invalidate only this service's effective-source-scope partition, then
    /// recompute and re-warm it. Encapsulation keeps the refresh endpoint from
    /// accidentally evicting or populating a different caller's partition.
    pub async fn refresh(&self) -> Result<MarketplaceCoverage, MarketplaceError> {
        self.cache.invalidate(&self.denied_sources).await;
        self.compute().await
    }

    /// Recompute coverage unconditionally, bypassing the cache.
    pub async fn recompute(&self) -> Result<MarketplaceCoverage, MarketplaceError> {
        // 1. Look up installed slug → name from Postgres so the hero chips can
        // render display labels rather than raw slugs. We pull both because
        // the recommended map is keyed by slug but the chips show the name.
        let installed: Vec<(String, String)> = sqlx::query_as(
            "SELECT slug, name FROM marketplace_catalog WHERE installed = true",
        )
        .fetch_all(&self.pool)
        .await?;

        // 2. Fan one query at ClickHouse — built against the active schema.
        let counts =
            fetch_counts(&self.ch_client, self.profile.as_ref(), &self.denied_sources).await;

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

    #[test]
    fn udm_coverage_sql_is_byte_identical_to_const() {
        // The profile-aware resolver must reproduce the long-lived UDM query
        // verbatim — zero behavioral drift for the dominant deployment.
        let p = crate::schema::UdmProfile::new();
        assert_eq!(coverage_sql(&p, false, &BTreeSet::new()), UDM_COVERAGE_SQL);
    }

    #[test]
    fn clustered_coverage_sql_routes_to_distributed_wrappers() {
        // NAN-1728 (H5/R11): on a cluster the coverage hero must read the
        // `_distributed` wrapper so it counts all shards, not the LB-connected one.
        let udm = coverage_sql(&crate::schema::UdmProfile::new(), true, &BTreeSet::new());
        assert!(
            udm.contains("\nFROM logs_distributed\n"),
            "clustered UDM must read the distributed wrapper:\n{udm}"
        );
        assert!(
            !udm.contains("\nFROM logs\n"),
            "clustered UDM must not read the bare local table:\n{udm}"
        );

        let ocsf = coverage_sql(&crate::schema::OcsfProfile::new(), true, &BTreeSet::new());
        assert!(
            ocsf.contains("FROM nanosiem.ocsf_logs_distributed"),
            "clustered OCSF must read the distributed wrapper:\n{ocsf}"
        );
    }

    #[test]
    fn ocsf_coverage_sql_targets_ocsf_table_and_omits_unmapped_columns() {
        let p = crate::schema::OcsfProfile::new();
        let sql = coverage_sql(&p, false, &BTreeSet::new());

        // FROM the OCSF table, not the nonexistent `logs`.
        assert!(sql.contains("FROM nanosiem.ocsf_logs"), "sql:\n{sql}");
        assert!(!sql.contains("FROM logs\n"), "must not read UDM logs:\n{sql}");

        // Promoted dotted columns resolve (escaped) instead of bare UDM names.
        assert!(sql.contains("\"src_endpoint.ip\""), "sql:\n{sql}");
        assert!(
            sql.contains("\"src_endpoint.autonomous_system.number\""),
            "ASN should resolve to the promoted dotted column:\n{sql}"
        );

        // ASN presence is numeric (!= 0) under OCSF, never the String `!= ''`.
        assert!(
            sql.contains("\"src_endpoint.autonomous_system.number\" != 0"),
            "OCSF ASN presence must be numeric:\n{sql}"
        );

        // Unmapped UDM concepts are dropped, never emitted as dead columns.
        assert!(
            !sql.contains("enriched_src_country"),
            "enriched_src_country has no OCSF column:\n{sql}"
        );
        assert!(
            !sql.contains("identity_display_name"),
            "identity display-name has no OCSF column yet:\n{sql}"
        );

        // user_enriched has no OCSF signal today -> zeroed, but the SELECT shape
        // (12 aliases) is preserved so CoverageCounts still decodes.
        assert!(sql.contains("countIf(0) AS user_enriched"), "sql:\n{sql}");
        assert_eq!(sql.matches(" AS ").count(), 12, "12 aliases:\n{sql}");
    }

    #[test]
    fn restricted_coverage_sql_uses_canonical_source_scope_predicate() {
        let denied = ["windows_sysmon", "audit"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let sql = coverage_sql(&crate::schema::UdmProfile::new(), false, &denied);

        assert!(
            sql.contains(
                "PREWHERE timestamp >= now() - INTERVAL 24 HOUR \
                 AND lower(source_type) NOT IN ('audit', 'windows_sysmon')"
            ),
            "coverage aggregate must gate every counted row with the canonical predicate:\n{sql}"
        );
    }

    #[test]
    fn ocsf_scope_gate_uses_operational_source_type() {
        let denied = ["audit"].into_iter().map(str::to_string).collect();
        let sql = coverage_sql(&crate::schema::OcsfProfile::new(), false, &denied);

        assert!(
            sql.contains("AND lower(source_type) != 'audit'"),
            "OCSF coverage must scope on the operational source_type String:\n{sql}"
        );
        assert!(
            !sql.contains("lower(class_uid)"),
            "class_uid is taxonomy, not the source authorization dimension:\n{sql}"
        );
    }

    #[test]
    fn source_scope_values_are_escaped_by_canonical_builder() {
        let denied = ["audit", "weird'name"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let sql = coverage_sql(&crate::schema::UdmProfile::new(), false, &denied);
        assert!(
            sql.contains("NOT IN ('audit', 'weird''name')"),
            "scope values must be SQL-escaped:\n{sql}"
        );
    }
}
