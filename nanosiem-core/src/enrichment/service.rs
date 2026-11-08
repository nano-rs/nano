// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP enrichment service: lookups against the ingest-time IP dictionary,
//! source listing and stats.
//!
//! IPinfo Lite geo/ASN comes only from nano's signed platform feed bundle
//! (`platform_enrichment`, NAN-4948). NAN-4959 removed main's native
//! bring-your-own IPinfo download (configure URL, scheduled CSV sync) and the
//! legacy air-gap IP bundle import; the platform feed loader is the only
//! writer of `ip_enrichments` (plus this service's source tombstone).

use thiserror::Error;
use tracing::{info, instrument};

use super::repository::{EnrichmentRepository, EnrichmentRepositoryError};
use super::types::*;
use crate::db::dual_pool::{on_cluster_clause, TableNames};

#[derive(Error, Debug)]
pub enum EnrichmentError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] EnrichmentRepositoryError),
    #[error("ClickHouse error: {0}")]
    ClickHouseError(#[from] clickhouse::error::Error),
    #[error("ClickHouse client not configured")]
    ClickHouseNotConfigured,
}

/// IP enrichment service (lookups, source listing, stats)
pub struct EnrichmentService {
    repository: EnrichmentRepository,
    /// ClickHouse client. The IP enrichment payload + lookups live in CH as of
    /// NAN-1117 (ip_enrichment_dict was repointed off PostgreSQL — see CH
    /// migration 123). Optional so the service can still be constructed in
    /// contexts without a CH pool, but lookups error if it's absent rather
    /// than silently no-op'ing.
    clickhouse_client: Option<clickhouse::Client>,
}

impl EnrichmentService {
    /// Create the service
    pub fn with_defaults(repository: EnrichmentRepository) -> Self {
        Self {
            repository,
            clickhouse_client: None,
        }
    }

    /// Attach the ClickHouse client used for dictGet lookups, the source
    /// tombstone and the record-count stat (NAN-1117).
    pub fn with_clickhouse(mut self, client: clickhouse::Client) -> Self {
        self.clickhouse_client = Some(client);
        self
    }

    /// Get the ClickHouse client or a typed error if it was never configured.
    fn ch(&self) -> Result<&clickhouse::Client, EnrichmentError> {
        self.clickhouse_client
            .as_ref()
            .ok_or(EnrichmentError::ClickHouseNotConfigured)
    }

    /// Get the repository reference
    pub fn repository(&self) -> &EnrichmentRepository {
        &self.repository
    }

    /// Purge a source's CH IP enrichment rows by writing tombstones (deleted=1)
    /// for every CIDR it currently has. This preserves the legacy "disable the
    /// source -> dict blanks on next reload" UX (NAN-1117): the old PG dict
    /// source filtered `WHERE enabled = true`; CH can't join PG, so disabling a
    /// source instead tombstones its payload so the dict's `HAVING deleted = 0`
    /// drops it. Re-enabling repopulates on the next sync.
    ///
    /// Tombstones (rather than a hard ALTER DELETE) keep this cheap and
    /// merge-friendly: a new tombstone row per CIDR with a fresh `updated_at`
    /// wins the ReplacingMergeTree argMax against the prior live row.
    pub async fn clear_ip_enrichments_for_source(
        &self,
        source_id: &str,
    ) -> Result<(), EnrichmentError> {
        let ch = self.ch()?;
        let run_ms = chrono::Utc::now().timestamp_millis() as u64;
        // NAN-1728: ip_enrichments is a per-shard table with an additive
        // `_distributed` wrapper (in DISTRIBUTED_TABLES). The SELECT source must
        // read ALL shards so we re-stamp a tombstone for every live CIDR the
        // source owns cluster-wide, not just those on the connected shard — so it
        // routes through the wrapper (`.read()` returns the local name on
        // single-node → byte-identical). The INSERT TARGET stays the LOCAL name
        // (a Distributed table can't be an INSERT target here and the write path
        // is deliberately left per-shard, NAN-1728 M-6). `INSERT … SELECT` takes
        // no ON CLUSTER; the ALTER-DELETE purge path is what gets
        // `on_cluster_clause()`.
        let src = TableNames::new(!on_cluster_clause().is_empty()).read("ip_enrichments");
        ch.query(&format!(
            "INSERT INTO nanosiem.ip_enrichments \
             (network, source_id, country, country_code, continent, continent_code, \
              asn, as_name, as_domain, updated_at, deleted) \
             SELECT network, source_id, country, country_code, continent, continent_code, \
              asn, as_name, as_domain, fromUnixTimestamp64Milli(toInt64(?)), 1 \
             FROM {src} \
             WHERE source_id = ? AND deleted = 0",
        ))
        .bind(run_ms)
        .bind(source_id)
        .execute()
        .await?;
        info!(source_id, "Tombstoned IP enrichment rows for disabled source");
        Ok(())
    }

    // ========================================================================
    // Lookup Operations (for ingestion-time enrichment)
    // ========================================================================

    /// Lookup enrichment for a single IP via the ClickHouse dictionary.
    ///
    /// Uses the ip_geo dictionaries (`enrichment::ip_geo`, NAN-4957) so on-demand
    /// lookups resolve identically to ingest-time enrichment (same dicts, same IP_TRIE
    /// longest-prefix match, same toIPv4OrDefault/toIPv6OrDefault keying for
    /// v4 vs v6). NAN-1117 moved this off the PG `lookup_ip_enrichment`
    /// function.
    #[instrument(skip(self))]
    pub async fn lookup_ip(&self, ip: &str) -> Result<Option<IpEnrichmentResult>, EnrichmentError> {
        if ip.is_empty() {
            return Ok(None);
        }
        let mut map = self.lookup_ips_bulk(&[ip]).await?;
        Ok(map.remove(ip))
    }

    /// Bulk lookup enrichments for multiple IPs (optimized for batch ingestion).
    ///
    /// One ClickHouse round-trip: for each IP we evaluate the 8 dict attributes
    /// with `dictGetOrDefault`, branching on `isIPv4String` to key the IP_TRIE
    /// with `toIPv4OrDefault` / `toIPv6OrDefault` exactly as the nanosiem.logs
    /// enriched_* MATERIALIZED columns do (init.sql:557-570) — so v6 lookups
    /// don't silently miss. An all-empty result for an IP is treated as "no
    /// enrichment" and omitted from the map, matching the PG behavior.
    #[instrument(skip(self, ips))]
    pub async fn lookup_ips_bulk(
        &self,
        ips: &[&str],
    ) -> Result<std::collections::HashMap<String, IpEnrichmentResult>, EnrichmentError> {
        use std::collections::{HashMap, HashSet};

        let mut results: HashMap<String, IpEnrichmentResult> = HashMap::new();

        let unique_ips: Vec<String> = ips
            .iter()
            .filter(|ip| !ip.is_empty())
            .map(|ip| ip.to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if unique_ips.is_empty() {
            return Ok(results);
        }

        let ch = self.ch()?;

        // Build a SELECT over an injected array of IPs. The IP value is bound
        // as a parameter (no string splicing of user data into SQL). Each
        // attribute branches on isIPv4String to pick the right trie key type.
        // NAN-4957: the same two-step trie -> geo_id -> attribute lookup the
        // ingest columns use (migration 185); never the old single trie,
        // which would load 1.32 GiB back into ClickHouse.
        let attr = |name: &str| -> String { super::ip_geo::geo_attr_expr(name, "ip") };

        let sql = format!(
            "SELECT \
                ip, \
                {country}, {country_code}, {continent}, {continent_code}, \
                {asn}, {as_name}, {as_domain} \
             FROM (SELECT arrayJoin(?) AS ip)",
            country = attr("country"),
            country_code = attr("country_code"),
            continent = attr("continent"),
            continent_code = attr("continent_code"),
            asn = attr("asn"),
            as_name = attr("as_name"),
            as_domain = attr("as_domain"),
        );

        let rows: Vec<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )> = ch
            .query(&sql)
            .bind(&unique_ips)
            .fetch_all()
            .await?;

        for (ip, country, country_code, continent, continent_code, asn, as_name, as_domain) in rows
        {
            // Skip IPs the dict had no entry for (all attributes default to '').
            if country.is_empty() && asn.is_empty() {
                continue;
            }
            let to_opt = |s: String| if s.is_empty() { None } else { Some(s) };
            results.insert(
                ip,
                IpEnrichmentResult {
                    source_id: Some("ipinfo_lite".to_string()),
                    network: None,
                    country: to_opt(country),
                    country_code: to_opt(country_code),
                    continent: to_opt(continent),
                    continent_code: to_opt(continent_code),
                    asn: to_opt(asn),
                    as_name: to_opt(as_name),
                    as_domain: to_opt(as_domain),
                },
            );
        }

        Ok(results)
    }

    // ========================================================================
    // Source Management
    // ========================================================================

    /// List all enrichment sources
    pub async fn list_sources(&self) -> Result<Vec<EnrichmentSource>, EnrichmentError> {
        Ok(self.repository.list_sources().await?)
    }

    /// Get enrichment statistics.
    ///
    /// Hybrid since NAN-1117: `enabled_sources` is a PG count from
    /// enrichment_sources (config/metadata stays in PG); `total_ip_records` is
    /// a CH count of live (non-tombstoned) IP enrichment rows.
    pub async fn get_stats(&self) -> Result<super::repository::EnrichmentStats, EnrichmentError> {
        let enabled_sources = self.repository.count_enabled_sources().await?;

        let total_ip_records = match self.ch() {
            Ok(ch) => {
                // NAN-1728: ip_enrichments is per-shard with an additive
                // `_distributed` wrapper. Route the read through the wrapper so
                // the count spans all shards, not just the connected one;
                // `.read()` returns the local name on single-node → byte-identical.
                // `count(DISTINCT network)` collapses cross-shard duplicates of a
                // CIDR intrinsically, so no version-collapse is needed for this
                // display-only stat.
                let table =
                    TableNames::new(!on_cluster_clause().is_empty()).read("ip_enrichments");
                let count: u64 = ch
                    .query(&format!(
                        "SELECT count(DISTINCT network) FROM {table} WHERE deleted = 0"
                    ))
                    .fetch_one::<u64>()
                    .await?;
                count as i64
            }
            // No CH client (constructed without a pool): report 0 rather than
            // failing the whole stats endpoint.
            Err(_) => 0,
        };

        Ok(super::repository::EnrichmentStats {
            enabled_sources,
            total_ip_records,
        })
    }
}

/// Enrichment data for a log record
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LogEnrichment {
    pub src: Option<IpEnrichmentResult>,
    pub dest: Option<IpEnrichmentResult>,
}

impl LogEnrichment {
    /// Check if any enrichment data is present
    pub fn has_data(&self) -> bool {
        self.src.is_some() || self.dest.is_some()
    }
}
