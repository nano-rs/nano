// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Repository
//!
//! Database operations for prevalence tracking using ClickHouse.
//! Queries the hash_prevalence_agg, domain_prevalence_agg, and ip_prevalence_agg tables
//! which are populated by materialized views.

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client as ClickHouseClient;
use clickhouse::Row;
use serde::Deserialize;
use tracing::{debug, instrument};

use super::types::*;
use crate::sql_hygiene::escape_sql_string;
use crate::db::TableNames;

/// Chunk size for dict-based bulk lookups. Bounds the inlined
/// `arrayJoin([...])` literal so we stay well under CH's default
/// `max_query_size` (262KB) — 1000 sha256 hashes ≈ 67KB.
const DICT_QUERY_CHUNK: usize = 1000;

/// Memory-bound settings for the explorer's full-universe
/// `argMax(col, version) GROUP BY entity` reads over `*_prevalence_final`
/// (P2-B, NAN-1762). The rare/new explorer scans the whole retained entity
/// universe (up to ~119M IPs on Saturn) and aggregates per entity. An
/// unbounded `GROUP BY` grows the aggregation hash table to ~25 GiB at that
/// cardinality (local-measured ~208 bytes/entity marginal) and OOMs — exactly
/// the failure that gated rare/new IP to <=7d (NAN-1729). These settings spill
/// the aggregation to disk past 1 GiB and hard-cap the query at 2.5 GiB, so 30d
/// is viable and provably bounded regardless of cardinality. Byte-identical to
/// the deployed full-scan `argMax` dict source
/// (clickhouse/130 ip_enrichments: 1 GiB spill / 2.5 GiB cap / 2 threads).
const FINAL_AGG_SETTINGS: &str = "SETTINGS max_bytes_before_external_group_by = 1000000000, \
     max_memory_usage = 2500000000, max_threads = 2";

/// Internal row type for hash prevalence queries
#[derive(Debug, Row, Deserialize)]
pub struct HashPrevalenceRow {
    pub file_hash: String,
    pub hash_type: String,
    pub host_count: u64,
    pub first_seen: i64, // DateTime64(6) comes as microseconds
    pub last_seen: i64,
    pub total_count: u64,
}

/// Internal row type for hash daily breakdown queries
#[derive(Debug, Row, Deserialize)]
pub struct HashDailyRow {
    pub file_hash: String,
    pub day: String,
    pub daily_count: u64,
}

/// Internal row type for domain daily breakdown queries
#[derive(Debug, Row, Deserialize)]
pub struct DomainDailyRow {
    pub domain: String,
    pub day: String,
    pub daily_count: u64,
}

/// Internal row type for IP daily breakdown queries
#[derive(Debug, Row, Deserialize)]
pub struct IpDailyRow {
    pub ip: String,
    pub day: String,
    pub daily_count: u64,
}

/// Internal row type for domain prevalence queries
#[derive(Debug, Row, Deserialize)]
pub struct DomainPrevalenceRow {
    pub domain: String,
    pub is_subdomain: u8,
    pub source_host_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_count: u64,
}

/// Internal row type for IP prevalence queries
#[derive(Debug, Row, Deserialize)]
pub struct IpPrevalenceRow {
    pub ip: String,
    pub direction: String,
    pub is_private: u8,
    pub source_host_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_count: u64,
}

/// Artifact type selector for dict-based prevalence lookups.
///
/// Picks the right `nanosiem.{kind}_prevalence_dict` and the right key
/// transformation (lowercase for hash/domain, raw for IP) — mirroring the
/// JOIN path's lookup semantics in `prevalence_join.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DictArtifactKind {
    Hash,
    Domain,
    Ip,
}

impl DictArtifactKind {
    fn dict_name(self) -> &'static str {
        match self {
            Self::Hash => "nanosiem.hash_prevalence_dict",
            Self::Domain => "nanosiem.domain_prevalence_dict",
            Self::Ip => "nanosiem.ip_prevalence_dict",
        }
    }

    /// SQL expression that normalizes the input artifact to the dict's key form.
    /// Hash and domain dicts are populated via `lower(...)`; IP dicts use raw values.
    fn key_expr(self) -> &'static str {
        match self {
            Self::Hash | Self::Domain => "lower(artifact)",
            Self::Ip => "artifact",
        }
    }
}

/// Row returned by `get_bulk_prevalence_via_dict` — uniform shape regardless
/// of artifact kind (the kind-specific extras like `hash_type`, `is_subdomain`,
/// `is_private` are not stored in the dict; callers reconstruct them from the
/// artifact value via `ArtifactType::detect`).
#[derive(Debug, Row, Deserialize)]
pub struct DictPrevalenceRow {
    pub artifact: String,
    pub host_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_occurrences: u64,
}

/// Repository for prevalence data operations using ClickHouse
#[derive(Clone)]
pub struct PrevalenceRepository {
    client: ClickHouseClient,
    hash_prevalence_table: String,
    domain_prevalence_table: String,
    ip_prevalence_table: String,
    // Per-entity summary tables (migration 110). Keyed on entity only (no
    // time_bucket), so a `GROUP BY entity` read is bounded by N_entities rather
    // than N_entities × N_hours — the unbounded aggregation that OOM'd the
    // rare/new/explorer reads at scale (NAN-365 / prevalence-risk-audit P10).
    // They also carry the true GLOBAL first_seen (SimpleAggregateFunction(min)),
    // which is what makes the "new artifacts" query honest (audit P6).
    hash_prevalence_summary: String,
    domain_prevalence_summary: String,
    ip_prevalence_summary: String,
    // Pre-finalized per-entity tables (migration 160 / NAN-1732 P2-D). Hold the
    // MASKED UInt16 host_count already finalized (`if(uniqMerge>=1000, 9999,
    // least(9998, uniqMerge))`), read per entity via `argMax(col, version)` over
    // the ReplacingMergeTree(version). The rare/new explorer reads these instead
    // of re-running `uniqMerge(host_count)` over `*_prevalence_summary` on every
    // request (NAN-1762): no HLL merge, so 30d rare/new IP is viable (the
    // uniqMerge form OOM'd at 30d → NAN-1729 gated it to <=7d). Keep-local (not
    // distributed) and complete per node — read the bare local name, like the CH
    // dict source (migration 162).
    hash_prevalence_final: String,
    domain_prevalence_final: String,
    ip_prevalence_final: String,
}

impl PrevalenceRepository {
    /// Create a new PrevalenceRepository with a ClickHouse client
    pub fn new(client: ClickHouseClient, table_names: TableNames) -> Self {
        Self {
            client,
            hash_prevalence_table: table_names.read("hash_prevalence_agg"),
            domain_prevalence_table: table_names.read("domain_prevalence_agg"),
            ip_prevalence_table: table_names.read("ip_prevalence_agg"),
            // NOTE(P11): `*_prevalence_summary` are NOT in `DISTRIBUTED_TABLE_SET`,
            // so in cluster mode `table_names.read()` returns the node-local name
            // — the same node-local read the CH dict sources already do. Routing
            // through `read()` here means these queries pick up the distributed
            // wrapper automatically once Lane L4 adds
            // `*_prevalence_summary_distributed` + registers them in the set.
            hash_prevalence_summary: table_names.read("hash_prevalence_summary"),
            domain_prevalence_summary: table_names.read("domain_prevalence_summary"),
            ip_prevalence_summary: table_names.read("ip_prevalence_summary"),
            // `*_prevalence_final` are keep-local (not in DISTRIBUTED_TABLE_SET),
            // so `read()` returns the node-local name — the LOCAL point-read the
            // dict source uses (migration 162). The refresh MV keeps each node's
            // copy globally-complete, so no distributed wrapper is needed.
            hash_prevalence_final: table_names.read("hash_prevalence_final"),
            domain_prevalence_final: table_names.read("domain_prevalence_final"),
            ip_prevalence_final: table_names.read("ip_prevalence_final"),
        }
    }

    /// Convert microseconds timestamp to DateTime<Utc>
    pub(crate) fn micros_to_datetime(micros: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_micros(micros).unwrap_or_else(Utc::now)
    }

    /// Get the cutoff time for a time window
    fn get_cutoff_time(time_window: TimeWindow) -> DateTime<Utc> {
        Utc::now() - Duration::hours(time_window.hours())
    }

    /// Index-eligible recency predicate (NAN-1729, P2-B): compare the RAW
    /// `DateTime64(6)` column against a constant so the `idx_last_seen` /
    /// `idx_first_seen` minmax skip indexes (migration 155) and part-level
    /// min/max metadata can prune. The prior `reinterpretAsInt64(col) >= micros`
    /// form wrapped the column in a function, which is opaque to the skip index —
    /// forcing a full column scan of the `*_prevalence_summary` table on every
    /// rare/new lookup. `micros` is epoch-microseconds (the DateTime64(6) tick
    /// scale), so `fromUnixTimestamp64Micro` reconstructs the identical instant:
    /// same rows, prunable predicate (verified byte-identical vs the reinterpret
    /// form on local CH).
    fn recency_at_least(col: &str, micros: i64) -> String {
        format!("{col} >= fromUnixTimestamp64Micro(toInt64({micros}))")
    }

    /// Query hash prevalence for a single hash
    #[instrument(skip(self))]
    pub async fn get_hash_prevalence(
        &self,
        hash: &str,
        time_window: TimeWindow,
    ) -> Result<Option<HashPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        // MV already stores file_hash as lower() — no need to lower() in query
        let hash_lower = escape_sql_string(hash.to_lowercase());

        let query = format!(
            r#"
            SELECT
                file_hash,
                hash_type,
                host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    file_hash,
                    hash_type,
                    uniqMerge(host_count) AS host_count,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_count) AS total_count
                FROM {hash_prevalence_table}
                PREWHERE time_bucket >= toDateTime('{cutoff_str}')
                WHERE file_hash = '{hash_lower}'
                GROUP BY file_hash, hash_type
            )
            "#,
            hash_prevalence_table = self.hash_prevalence_table,
            hash_lower = hash_lower,
            cutoff_str = cutoff_str
        );

        debug!("Executing hash prevalence query for hash: {}", hash);

        let rows: Vec<HashPrevalenceRow> = self.client.query(&query).fetch_all().await?;

        Ok(rows.into_iter().next())
    }

    /// Query domain prevalence for a single domain
    #[instrument(skip(self))]
    pub async fn get_domain_prevalence(
        &self,
        domain: &str,
        time_window: TimeWindow,
    ) -> Result<Option<DomainPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        let query = format!(
            r#"
            SELECT
                domain,
                is_subdomain,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    domain,
                    max(is_subdomain) AS is_subdomain,
                    uniqMerge(source_host_count) AS source_host_count,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_count) AS total_count
                FROM {domain_prevalence_table}
                PREWHERE time_bucket >= toDateTime('{cutoff_str}')
                WHERE domain = '{domain}'
                GROUP BY domain
            )
            "#,
            domain_prevalence_table = self.domain_prevalence_table,
            // Storage is MV-lowercased (`lower(dest_host) AS domain`); compare the
            // input lowercased so `Accounts.Google.com` matches (audit P9).
            domain = escape_sql_string(domain.to_lowercase()),
            cutoff_str = cutoff_str
        );

        debug!("Executing domain prevalence query for domain: {}", domain);

        let rows: Vec<DomainPrevalenceRow> = self.client.query(&query).fetch_all().await?;

        Ok(rows.into_iter().next())
    }

    /// Query hash prevalence for multiple hashes in a single query
    #[instrument(skip(self, hashes))]
    pub async fn get_bulk_hash_prevalence(
        &self,
        hashes: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<HashPrevalenceRow>, clickhouse::error::Error> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        // Build the IN clause with escaped values (lowercase for case-insensitive matching)
        let hash_list: String = hashes
            .iter()
            .map(|h| format!("'{}'", escape_sql_string(h.to_lowercase())))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            r#"
            SELECT
                file_hash,
                hash_type,
                host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    file_hash,
                    hash_type,
                    uniqMerge(host_count) AS host_count,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_count) AS total_count
                FROM {hash_prevalence_table}
                PREWHERE time_bucket >= toDateTime('{cutoff_str}')
                WHERE file_hash IN ({hash_list})
                GROUP BY file_hash, hash_type
            )
            "#,
            hash_prevalence_table = self.hash_prevalence_table,
            hash_list = hash_list,
            cutoff_str = cutoff_str
        );

        debug!(
            "Executing bulk hash prevalence query for {} hashes",
            hashes.len()
        );

        self.client.query(&query).fetch_all().await
    }

    /// Query domain prevalence for multiple domains in a single query
    #[instrument(skip(self, domains))]
    pub async fn get_bulk_domain_prevalence(
        &self,
        domains: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<DomainPrevalenceRow>, clickhouse::error::Error> {
        if domains.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        // Build the IN clause with escaped values. Storage is MV-lowercased
        // (`lower(dest_host) AS domain`); lowercase the input so mixed-case
        // domains like `Accounts.Google.com` match (audit P9).
        let domain_list: String = domains
            .iter()
            .map(|d| format!("'{}'", escape_sql_string(d.to_lowercase())))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            r#"
            SELECT
                domain,
                is_subdomain,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    domain,
                    max(is_subdomain) AS is_subdomain,
                    uniqMerge(source_host_count) AS source_host_count,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_count) AS total_count
                FROM {domain_prevalence_table}
                PREWHERE time_bucket >= toDateTime('{cutoff_str}')
                WHERE domain IN ({domain_list})
                GROUP BY domain
            )
            "#,
            domain_prevalence_table = self.domain_prevalence_table,
            domain_list = domain_list,
            cutoff_str = cutoff_str
        );

        debug!(
            "Executing bulk domain prevalence query for {} domains",
            domains.len()
        );

        self.client.query(&query).fetch_all().await
    }

    /// Query IP prevalence for a single IP address
    #[instrument(skip(self))]
    pub async fn get_ip_prevalence(
        &self,
        ip: &str,
        time_window: TimeWindow,
    ) -> Result<Option<IpPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        let query = format!(
            r#"
            SELECT
                ip,
                direction,
                is_private,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    ip,
                    'dest' AS direction,
                    max(is_private) AS is_private,
                    uniqMerge(source_host_count) AS source_host_count,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_count) AS total_count
                FROM {ip_prevalence_table}
                PREWHERE time_bucket >= toDateTime('{cutoff_str}')
                WHERE ip = '{ip}'
                GROUP BY ip
            )
            "#,
            ip_prevalence_table = self.ip_prevalence_table,
            ip = escape_sql_string(ip),
            cutoff_str = cutoff_str
        );

        debug!("Executing IP prevalence query for IP: {}", ip);

        let rows: Vec<IpPrevalenceRow> = self.client.query(&query).fetch_all().await?;

        Ok(rows.into_iter().next())
    }

    /// Query IP prevalence for multiple IPs in a single query
    #[instrument(skip(self, ips))]
    pub async fn get_bulk_ip_prevalence(
        &self,
        ips: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<IpPrevalenceRow>, clickhouse::error::Error> {
        if ips.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        // Build the IN clause with escaped values
        let ip_list: String = ips
            .iter()
            .map(|ip| format!("'{}'", escape_sql_string(ip)))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            r#"
            SELECT
                ip,
                direction,
                is_private,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    ip,
                    'dest' AS direction,
                    max(is_private) AS is_private,
                    uniqMerge(source_host_count) AS source_host_count,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_count) AS total_count
                FROM {ip_prevalence_table}
                PREWHERE time_bucket >= toDateTime('{cutoff_str}')
                WHERE ip IN ({ip_list})
                GROUP BY ip
            )
            "#,
            ip_prevalence_table = self.ip_prevalence_table,
            ip_list = ip_list,
            cutoff_str = cutoff_str
        );

        debug!("Executing bulk IP prevalence query for {} IPs", ips.len());

        self.client.query(&query).fetch_all().await
    }

    /// Query prevalence for multiple artifacts of a single kind via the
    /// loaded ClickHouse dictionary instead of the `*_prevalence_agg`
    /// MergeTree tables.
    ///
    /// Mirrors `prevalence_join.rs:457-505` so the post-processing path
    /// gets the same dict-based lookups the JOIN path already uses. The
    /// 30d dict serves sub-30d windows by masking `host_count` to the
    /// 9999 sentinel when `last_seen` is older than the requested window.
    ///
    /// Returns rows only for artifacts found in the dict (sentinel rows
    /// are filtered server-side via `WHERE host_count_masked < 9999`).
    /// Hash and domain artifacts are returned in lowercase; IPs preserve
    /// the input value.
    ///
    /// Internally chunks at `DICT_QUERY_CHUNK` artifacts per query so
    /// inlined `arrayJoin([...])` literals stay well under CH's
    /// `max_query_size` default (262KB). Worst case for 1000 sha256
    /// hashes is ~67KB of literal — comfortably below the limit while
    /// still issuing far fewer queries than the agg-based fan-out.
    #[instrument(skip(self, artifacts))]
    pub async fn get_bulk_prevalence_via_dict(
        &self,
        artifacts: &[String],
        kind: DictArtifactKind,
        time_window: TimeWindow,
    ) -> Result<Vec<DictPrevalenceRow>, clickhouse::error::Error> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_rows = Vec::with_capacity(artifacts.len());
        for chunk in artifacts.chunks(DICT_QUERY_CHUNK) {
            let mut rows = self
                .get_bulk_prevalence_via_dict_chunk(chunk, kind, time_window)
                .await?;
            all_rows.append(&mut rows);
        }
        Ok(all_rows)
    }

    /// Single-shot dict query for a bounded chunk. Caller must ensure
    /// `chunk.len() <= DICT_QUERY_CHUNK`.
    async fn get_bulk_prevalence_via_dict_chunk(
        &self,
        artifacts: &[String],
        kind: DictArtifactKind,
        time_window: TimeWindow,
    ) -> Result<Vec<DictPrevalenceRow>, clickhouse::error::Error> {
        let dict_name = kind.dict_name();
        let key_expr = kind.key_expr();
        // `output_artifact_expr` decides what we return for the `artifact`
        // column. Lowercased for hash/domain (so callers' lowercase lookups
        // match), raw for IP (no case ambiguity).
        let output_artifact_expr = key_expr;

        // Window cutoff masking — see prevalence_join.rs:323-333. The SEARCH
        // prevalence command now rejects `window=1h` up front for every command
        // (core_search.rs, audit P2), so this fallback never receives 1h from
        // search. The `OneHour` arm remains only as defense-in-depth for any
        // non-search caller that constructs `TimeWindow::OneHour`: treat it as
        // 24h rather than erroring (this returns `clickhouse::error::Error`, the
        // wrong type for a validation failure).
        let cutoff_sql = match time_window {
            TimeWindow::OneHour | TimeWindow::TwentyFourHours => "now() - INTERVAL 1 DAY",
            TimeWindow::SevenDays => "now() - INTERVAL 7 DAY",
            TimeWindow::ThirtyDays => "toDateTime64(0, 6)",
        };

        let artifact_list: String = artifacts
            .iter()
            .map(|a| format!("'{}'", escape_sql_string(a)))
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r#"
            WITH base AS (
                SELECT
                    artifact,
                    if(dictGetOrDefault('{dict_name}', 'last_seen', {key_expr}, toDateTime64(0, 6)) >= {cutoff_sql},
                       dictGetOrDefault('{dict_name}', 'host_count', {key_expr}, toUInt16(9999)),
                       toUInt16(9999)) AS host_count_masked,
                    dictGetOrDefault('{dict_name}', 'first_seen', {key_expr}, toDateTime64(0, 6)) AS first_seen_dt,
                    dictGetOrDefault('{dict_name}', 'last_seen', {key_expr}, toDateTime64(0, 6)) AS last_seen_dt,
                    dictGetOrDefault('{dict_name}', 'total_occurrences', {key_expr}, toUInt64(0)) AS total_occurrences
                FROM (SELECT arrayJoin([{artifact_list}]) AS artifact)
            )
            SELECT
                {output_artifact_expr} AS artifact,
                toUInt64(host_count_masked) AS host_count,
                reinterpretAsInt64(first_seen_dt) AS first_seen,
                reinterpretAsInt64(last_seen_dt) AS last_seen,
                total_occurrences
            FROM base
            WHERE host_count_masked < 9999
            "#,
            dict_name = dict_name,
            key_expr = key_expr,
            cutoff_sql = cutoff_sql,
            artifact_list = artifact_list,
            output_artifact_expr = output_artifact_expr,
        );

        debug!(
            "Executing dict-based prevalence query for {} {:?} artifacts",
            artifacts.len(),
            kind
        );

        self.client.query(&query).fetch_all().await
    }

    /// NAN-1705 (D4b): fresh bulk prevalence straight from the per-entity
    /// `*_prevalence_summary` tables — the CACHE dicts' OWN source data, read
    /// directly so the dicts' negative caching (LIFETIME 900–1800s) cannot mask
    /// a brand-new artifact. A brand-new artifact's absence is negative-cached
    /// at ingest (the `logs.prevalence_*` MATERIALIZED-column lookups run before
    /// the same insert block's summary-MV rows land), so `dictGetOrDefault`
    /// returns the 9999 sentinel for 15–30 minutes after first sighting; the
    /// summary itself is populated by insert-time MV chains and already carries
    /// the artifact at its real host_count.
    ///
    /// Applies the dict source's exact contract (keep in lock-step with
    /// clickhouse/130_memory_bound_dict_source_queries.sql):
    ///   - entities with `host_count >= 1000` are excluded (the HAVING mirror) —
    ///     a masked-common artifact can never be "rescued" into a rarity filter;
    ///   - entities whose fresh `last_seen` falls outside the window cutoff are
    ///     excluded (the NAN-364 mask the dict path applies at lookup time);
    ///   - private IPs are excluded for [`DictArtifactKind::Ip`] (the source's
    ///     `WHERE is_private = 0`).
    ///
    /// Bounded: the `GROUP BY` aggregates only the `IN (...)` artifacts (chunked
    /// at [`DICT_QUERY_CHUNK`]), never the summary universe.
    pub async fn get_bulk_summary_prevalence(
        &self,
        artifacts: &[String],
        kind: DictArtifactKind,
        time_window: TimeWindow,
    ) -> Result<Vec<DictPrevalenceRow>, clickhouse::error::Error> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_rows = Vec::with_capacity(artifacts.len().min(DICT_QUERY_CHUNK));
        for chunk in artifacts.chunks(DICT_QUERY_CHUNK) {
            let mut rows = self
                .get_bulk_summary_prevalence_chunk(chunk, kind, time_window)
                .await?;
            all_rows.append(&mut rows);
        }
        Ok(all_rows)
    }

    /// Single-shot summary query for a bounded chunk. Caller must ensure
    /// `chunk.len() <= DICT_QUERY_CHUNK`.
    async fn get_bulk_summary_prevalence_chunk(
        &self,
        artifacts: &[String],
        kind: DictArtifactKind,
        time_window: TimeWindow,
    ) -> Result<Vec<DictPrevalenceRow>, clickhouse::error::Error> {
        // Same window-cutoff mapping as `get_bulk_prevalence_via_dict_chunk`
        // (1h is defense-in-depth-coerced to 24h; search rejects it upstream).
        let cutoff_sql = match time_window {
            TimeWindow::OneHour | TimeWindow::TwentyFourHours => "now() - INTERVAL 1 DAY",
            TimeWindow::SevenDays => "now() - INTERVAL 7 DAY",
            TimeWindow::ThirtyDays => "toDateTime64(0, 6)",
        };

        // Summary storage is MV-lowercased for hash/domain; raw for IP —
        // mirrors `DictArtifactKind::key_expr`.
        let normalize = |a: &String| match kind {
            DictArtifactKind::Hash | DictArtifactKind::Domain => a.to_lowercase(),
            DictArtifactKind::Ip => a.clone(),
        };
        let artifact_list: String = artifacts
            .iter()
            .map(|a| format!("'{}'", escape_sql_string(normalize(a))))
            .collect::<Vec<_>>()
            .join(",");

        let (table, key_col, state_col, extra_where) = match kind {
            DictArtifactKind::Hash => (
                self.hash_prevalence_summary.as_str(),
                "file_hash",
                "host_count",
                "",
            ),
            DictArtifactKind::Domain => (
                self.domain_prevalence_summary.as_str(),
                "domain",
                "source_host_count",
                "",
            ),
            DictArtifactKind::Ip => (
                self.ip_prevalence_summary.as_str(),
                "ip",
                "source_host_count",
                "is_private = 0 AND ",
            ),
        };

        let query = format!(
            r#"
            SELECT
                artifact,
                toUInt64(hc) AS host_count,
                reinterpretAsInt64(fs) AS first_seen,
                reinterpretAsInt64(ls) AS last_seen,
                occ AS total_occurrences
            FROM (
                SELECT
                    {key_col} AS artifact,
                    toUInt16(least(9998, uniqMerge({state_col}))) AS hc,
                    min(first_seen) AS fs,
                    max(last_seen) AS ls,
                    toUInt64(sum(total_count)) AS occ
                FROM {table}
                WHERE {extra_where}{key_col} IN ({artifact_list})
                GROUP BY {key_col}
            )
            WHERE hc < 1000 AND ls >= {cutoff_sql}
            "#,
            key_col = key_col,
            state_col = state_col,
            table = table,
            extra_where = extra_where,
            artifact_list = artifact_list,
            cutoff_sql = cutoff_sql,
        );

        debug!(
            "Executing summary-based prevalence rescue query for {} {:?} artifacts",
            artifacts.len(),
            kind
        );

        self.client.query(&query).fetch_all().await
    }

    /// Get rare artifacts (below threshold) that were active within the window.
    ///
    /// Reads the pre-finalized per-entity `hash_prevalence_final` table
    /// (NAN-1762, P2-B): `host_count` is ALREADY the finalized, masked prevalence
    /// (`if(uniqMerge>=1000, 9999, least(9998, uniqMerge))` — byte-identical to
    /// the CH dict source), so the read is `argMax(host_count, version)` per
    /// entity over the ReplacingMergeTree(version) — NO `uniqMerge` HLL. That
    /// removal is what makes 30d rare IP viable (the old summary `uniqMerge` at
    /// 30d OOM'd, so NAN-1729 gated IP windows to <=7d). `host_count` is the
    /// GLOBAL (30d-TTL-bounded) prevalence; `time_window` scopes *recency* via
    /// `last_seen >= cutoff`. Rarity boundary is `<` (strictly below threshold):
    /// threshold N means "seen on fewer than N hosts" (audit P10 — Lane L2
    /// search-side must match this `<`, not `<=`). `hash_type` is synthesized
    /// from the hash length (final does not store it), mirroring the summary MV
    /// (`multiIf(length…)`).
    #[instrument(skip(self))]
    // Recency filter pushdown (audit NAN-1664): the recency predicate is applied
    // in a nested `SELECT * … WHERE …` BEFORE the GROUP BY, so ClickHouse only
    // aggregates in-window entities (fewer distinct keys → smaller aggregation
    // hash table). It MUST live in the nested subquery, not the aggregating
    // SELECT's WHERE, because that SELECT aliases `argMax(last_seen, version) AS
    // last_seen` which would shadow the raw column (ILLEGAL_AGGREGATION — the R2
    // alias-shadow class). Pushdown is exact: `last_seen` is monotonically
    // non-decreasing across an entity's finalization versions, so any surviving
    // row's `last_seen >= cutoff` implies the argMax-latest is too, and an entity
    // whose latest `last_seen < cutoff` has ALL rows dropped (correctly excluded).
    //
    // MEMORY (NAN-1762): 30d admits the whole entity universe (up to ~119M IPs on
    // Saturn; TTL bounds all rows to 30d so recency does not prune at 30d). The
    // full `GROUP BY entity` is bounded by FINAL_AGG_SETTINGS — the aggregation
    // spills to disk past 1 GiB and the query hard-caps at 2.5 GiB (the deployed
    // full-scan argMax dict-source budget), so it stays bounded instead of the
    // ~25 GiB unbounded footprint. Sub-30d additionally prunes via the recency
    // pushdown + the `idx_last_seen` minmax skip index (migration 163).
    //
    // CORRECTNESS CAVEAT (carried from the summary path): `argMax(…, version)` is
    // exact in the merged steady state. `*_prevalence_final` is a
    // ReplacingMergeTree; between merges an entity can transiently hold multiple
    // finalization rows. argMax over ALL of them still picks the latest version,
    // so the read is robust to unmerged duplicates — but the recency pushdown
    // drops rows below the cutoff first, which is exact only under the monotonic
    // `last_seen` argument above. The 30d TTL bounds duplication.
    pub async fn get_rare_hashes(
        &self,
        threshold: u64,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<HashPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_micros = cutoff.timestamp_micros();
        let recency = Self::recency_at_least("last_seen", cutoff_micros);

        let query = format!(
            r#"
            SELECT
                file_hash,
                hash_type,
                host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    file_hash,
                    multiIf(length(file_hash) = 32, 'md5', length(file_hash) = 40, 'sha1', length(file_hash) = 64, 'sha256', 'unknown') AS hash_type,
                    toUInt64(argMax(host_count, version)) AS host_count,
                    argMax(first_seen, version) AS first_seen,
                    argMax(last_seen, version) AS last_seen,
                    argMax(total_occurrences, version) AS total_count
                FROM (
                    SELECT * FROM {hash_prevalence_final}
                    WHERE {recency}
                )
                GROUP BY file_hash
            )
            WHERE host_count < {threshold}
            ORDER BY last_seen DESC
            LIMIT {limit}
            {settings}
            "#,
            hash_prevalence_final = self.hash_prevalence_final,
            threshold = threshold,
            recency = recency,
            limit = limit,
            settings = FINAL_AGG_SETTINGS,
        );

        debug!("Executing rare hashes query with threshold {}", threshold);

        self.client.query(&query).fetch_all().await
    }

    /// Get rare domains (below threshold) active within the window.
    ///
    /// Reads `domain_prevalence_final` (finalized per-entity, `argMax` read) —
    /// see `get_rare_hashes` for the rationale, memory bound, and recency/rarity
    /// semantics (NAN-1762). `is_subdomain` is synthesized from the label count
    /// (final does not store it), mirroring the summary MV
    /// (`if(length(splitByChar('.', domain)) > 2, 1, 0)`).
    #[instrument(skip(self))]
    pub async fn get_rare_domains(
        &self,
        threshold: u64,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<DomainPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_micros = cutoff.timestamp_micros();
        let recency = Self::recency_at_least("last_seen", cutoff_micros);

        let query = format!(
            r#"
            SELECT
                domain,
                is_subdomain,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    domain,
                    if(length(splitByChar('.', domain)) > 2, 1, 0) AS is_subdomain,
                    toUInt64(argMax(host_count, version)) AS source_host_count,
                    argMax(first_seen, version) AS first_seen,
                    argMax(last_seen, version) AS last_seen,
                    argMax(total_occurrences, version) AS total_count
                FROM (
                    SELECT * FROM {domain_prevalence_final}
                    WHERE {recency}
                )
                GROUP BY domain
            )
            WHERE source_host_count < {threshold}
            ORDER BY last_seen DESC
            LIMIT {limit}
            {settings}
            "#,
            domain_prevalence_final = self.domain_prevalence_final,
            recency = recency,
            threshold = threshold,
            limit = limit,
            settings = FINAL_AGG_SETTINGS,
        );

        debug!("Executing rare domains query with threshold {}", threshold);

        self.client.query(&query).fetch_all().await
    }

    /// Get genuinely new hashes — those whose GLOBAL first_seen falls inside
    /// the requested window (audit P6).
    ///
    /// Reads `hash_prevalence_final`, whose `first_seen` is the finalized true
    /// earliest-ever sighting (`argMax(first_seen, version)`). Filtering that
    /// global minimum against `since` is meaningful: an artifact first observed
    /// months ago but seen again today has a `first_seen` far below `since` and
    /// is correctly excluded. Reads the finalized value via `argMax` (no HLL
    /// `uniqMerge`) so the read is memory-bounded at 30d (NAN-1762); see
    /// `get_rare_hashes` for the pushdown/memory/correctness notes.
    #[instrument(skip(self))]
    pub async fn get_new_hashes(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<HashPrevalenceRow>, clickhouse::error::Error> {
        // The recency predicate compares the raw `first_seen` column so the
        // idx_first_seen minmax index (migration 163) can prune; `since_micros`
        // feeds fromUnixTimestamp64Micro in recency_at_least (same instant).
        let since_micros = since.timestamp_micros();
        let recency = Self::recency_at_least("first_seen", since_micros);

        let query = format!(
            r#"
            SELECT
                file_hash,
                hash_type,
                host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    file_hash,
                    multiIf(length(file_hash) = 32, 'md5', length(file_hash) = 40, 'sha1', length(file_hash) = 64, 'sha256', 'unknown') AS hash_type,
                    toUInt64(argMax(host_count, version)) AS host_count,
                    argMax(first_seen, version) AS first_seen,
                    argMax(last_seen, version) AS last_seen,
                    argMax(total_occurrences, version) AS total_count
                FROM (
                    SELECT * FROM {hash_prevalence_final}
                    WHERE {recency}
                )
                GROUP BY file_hash
            )
            ORDER BY first_seen DESC
            LIMIT {limit}
            {settings}
            "#,
            hash_prevalence_final = self.hash_prevalence_final,
            recency = recency,
            limit = limit,
            settings = FINAL_AGG_SETTINGS,
        );

        debug!("Executing new hashes query since {}", since);

        self.client.query(&query).fetch_all().await
    }

    /// Get genuinely new domains — global first_seen inside the window.
    /// Reads `domain_prevalence_final` for the finalized true earliest-ever
    /// sighting (`argMax(first_seen, version)`); see `get_new_hashes` for the
    /// semantics and `get_rare_domains` for the `is_subdomain` synthesis
    /// (NAN-1762).
    #[instrument(skip(self))]
    pub async fn get_new_domains(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<DomainPrevalenceRow>, clickhouse::error::Error> {
        // Raw `first_seen` predicate (idx_first_seen-eligible) — see get_new_hashes.
        let since_micros = since.timestamp_micros();
        let recency = Self::recency_at_least("first_seen", since_micros);

        let query = format!(
            r#"
            SELECT
                domain,
                is_subdomain,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    domain,
                    if(length(splitByChar('.', domain)) > 2, 1, 0) AS is_subdomain,
                    toUInt64(argMax(host_count, version)) AS source_host_count,
                    argMax(first_seen, version) AS first_seen,
                    argMax(last_seen, version) AS last_seen,
                    argMax(total_occurrences, version) AS total_count
                FROM (
                    SELECT * FROM {domain_prevalence_final}
                    WHERE {recency}
                )
                GROUP BY domain
            )
            ORDER BY first_seen DESC
            LIMIT {limit}
            {settings}
            "#,
            domain_prevalence_final = self.domain_prevalence_final,
            recency = recency,
            limit = limit,
            settings = FINAL_AGG_SETTINGS,
        );

        debug!("Executing new domains query since {}", since);

        self.client.query(&query).fetch_all().await
    }

    /// Get rare IPs (below threshold) active within the window.
    /// Reads `ip_prevalence_final` (finalized per-entity, `argMax` read) — see
    /// `get_rare_hashes` for the rationale and memory bound (NAN-1762).
    /// `ip_prevalence_final` already holds only public IPs (its refresh MV
    /// filters `is_private = 0`), so the private-IP exclusion is structural and
    /// `is_private`/`direction` are hardcoded (0 / 'dest'). Reading `final`
    /// removes the summary `uniqMerge`, which is what lifts the NAN-1729 <=7d IP
    /// window gate: 30d rare IP is now viable.
    #[instrument(skip(self))]
    pub async fn get_rare_ips(
        &self,
        threshold: u64,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<IpPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_micros = cutoff.timestamp_micros();
        let recency = Self::recency_at_least("last_seen", cutoff_micros);

        let query = format!(
            r#"
            SELECT
                ip,
                direction,
                is_private,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    ip,
                    'dest' AS direction,
                    toUInt8(0) AS is_private,
                    toUInt64(argMax(host_count, version)) AS source_host_count,
                    argMax(first_seen, version) AS first_seen,
                    argMax(last_seen, version) AS last_seen,
                    argMax(total_occurrences, version) AS total_count
                FROM (
                    SELECT * FROM {ip_prevalence_final}
                    WHERE {recency}
                )
                GROUP BY ip
            )
            WHERE source_host_count < {threshold}
            ORDER BY last_seen DESC
            LIMIT {limit}
            {settings}
            "#,
            ip_prevalence_final = self.ip_prevalence_final,
            recency = recency,
            threshold = threshold,
            limit = limit,
            settings = FINAL_AGG_SETTINGS,
        );

        debug!("Executing rare IPs query with threshold {}", threshold);

        self.client.query(&query).fetch_all().await
    }

    /// Get genuinely new IPs — global first_seen inside the window.
    /// Reads `ip_prevalence_final` (finalized per-entity, `argMax` read); see
    /// `get_new_hashes` for the semantics and `get_rare_ips` for the structural
    /// public-IP-only / hardcoded `is_private`/`direction` note (NAN-1762).
    #[instrument(skip(self))]
    pub async fn get_new_ips(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<IpPrevalenceRow>, clickhouse::error::Error> {
        // Raw `first_seen` predicate (idx_first_seen-eligible) — see get_new_hashes.
        let since_micros = since.timestamp_micros();
        let recency = Self::recency_at_least("first_seen", since_micros);

        let query = format!(
            r#"
            SELECT
                ip,
                direction,
                is_private,
                source_host_count,
                reinterpretAsInt64(first_seen) AS first_seen,
                reinterpretAsInt64(last_seen) AS last_seen,
                total_count
            FROM (
                SELECT
                    ip,
                    'dest' AS direction,
                    toUInt8(0) AS is_private,
                    toUInt64(argMax(host_count, version)) AS source_host_count,
                    argMax(first_seen, version) AS first_seen,
                    argMax(last_seen, version) AS last_seen,
                    argMax(total_occurrences, version) AS total_count
                FROM (
                    SELECT * FROM {ip_prevalence_final}
                    WHERE {recency}
                )
                GROUP BY ip
            )
            ORDER BY first_seen DESC
            LIMIT {limit}
            {settings}
            "#,
            ip_prevalence_final = self.ip_prevalence_final,
            recency = recency,
            limit = limit,
            settings = FINAL_AGG_SETTINGS,
        );

        debug!("Executing new IPs query since {}", since);

        self.client.query(&query).fetch_all().await
    }

    /// Convert a hash prevalence row to PrevalenceData
    pub fn hash_row_to_prevalence_data(
        row: HashPrevalenceRow,
        rarity_threshold: u64,
    ) -> PrevalenceData {
        let artifact_type = match row.hash_type.as_str() {
            "md5" => ArtifactType::HashMd5,
            "sha256" => ArtifactType::HashSha256,
            _ => ArtifactType::HashUnknown,
        };

        let is_rare = row.host_count < rarity_threshold;
        let prevalence_score = Self::calculate_prevalence_score(row.host_count, rarity_threshold);

        PrevalenceData {
            artifact: row.file_hash,
            artifact_type,
            host_count: row.host_count,
            total_occurrences: row.total_count,
            first_seen: Self::micros_to_datetime(row.first_seen),
            last_seen: Self::micros_to_datetime(row.last_seen),
            is_rare,
            prevalence_score,
        }
    }

    /// Convert a domain prevalence row to PrevalenceData
    pub fn domain_row_to_prevalence_data(
        row: DomainPrevalenceRow,
        rarity_threshold: u64,
    ) -> PrevalenceData {
        let artifact_type = if row.is_subdomain == 1 {
            ArtifactType::Subdomain
        } else {
            ArtifactType::Domain
        };

        let is_rare = row.source_host_count < rarity_threshold;
        let prevalence_score =
            Self::calculate_prevalence_score(row.source_host_count, rarity_threshold);

        PrevalenceData {
            artifact: row.domain,
            artifact_type,
            host_count: row.source_host_count,
            total_occurrences: row.total_count,
            first_seen: Self::micros_to_datetime(row.first_seen),
            last_seen: Self::micros_to_datetime(row.last_seen),
            is_rare,
            prevalence_score,
        }
    }

    /// Convert an IP prevalence row to PrevalenceData
    pub fn ip_row_to_prevalence_data(
        row: IpPrevalenceRow,
        rarity_threshold: u64,
    ) -> PrevalenceData {
        let artifact_type = if row.is_private == 1 {
            ArtifactType::IpAddressPrivate
        } else {
            ArtifactType::IpAddress
        };

        let is_rare = row.source_host_count < rarity_threshold;
        let prevalence_score =
            Self::calculate_prevalence_score(row.source_host_count, rarity_threshold);

        PrevalenceData {
            artifact: row.ip,
            artifact_type,
            host_count: row.source_host_count,
            total_occurrences: row.total_count,
            first_seen: Self::micros_to_datetime(row.first_seen),
            last_seen: Self::micros_to_datetime(row.last_seen),
            is_rare,
            prevalence_score,
        }
    }

    /// Get daily breakdown for a set of hashes
    #[instrument(skip(self, hashes))]
    pub async fn get_hash_daily_counts(
        &self,
        hashes: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<HashDailyRow>, clickhouse::error::Error> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        let hash_list: String = hashes
            .iter()
            .map(|h| format!("'{}'", escape_sql_string(h.to_lowercase())))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            r#"
            SELECT
                file_hash,
                toString(toDate(time_bucket)) AS day,
                sum(total_count) AS daily_count
            FROM {hash_prevalence_table}
            PREWHERE time_bucket >= toDateTime('{cutoff_str}')
            WHERE file_hash IN ({hash_list})
            GROUP BY file_hash, day
            ORDER BY file_hash, day
            "#,
            hash_prevalence_table = self.hash_prevalence_table,
            cutoff_str = cutoff_str,
            hash_list = hash_list
        );

        debug!(
            "Executing hash daily counts query for {} hashes",
            hashes.len()
        );
        self.client.query(&query).fetch_all().await
    }

    /// Get daily breakdown for a set of domains
    #[instrument(skip(self, domains))]
    pub async fn get_domain_daily_counts(
        &self,
        domains: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<DomainDailyRow>, clickhouse::error::Error> {
        if domains.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        // Storage is MV-lowercased; lowercase the input so mixed-case domains
        // still match their daily buckets (audit P9).
        let domain_list: String = domains
            .iter()
            .map(|d| format!("'{}'", escape_sql_string(d.to_lowercase())))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            r#"
            SELECT
                domain,
                toString(toDate(time_bucket)) AS day,
                sum(total_count) AS daily_count
            FROM {domain_prevalence_table}
            PREWHERE time_bucket >= toDateTime('{cutoff_str}')
            WHERE domain IN ({domain_list})
            GROUP BY domain, day
            ORDER BY domain, day
            "#,
            domain_prevalence_table = self.domain_prevalence_table,
            cutoff_str = cutoff_str,
            domain_list = domain_list
        );

        debug!(
            "Executing domain daily counts query for {} domains",
            domains.len()
        );
        self.client.query(&query).fetch_all().await
    }

    /// Get daily breakdown for a set of IPs
    #[instrument(skip(self, ips))]
    pub async fn get_ip_daily_counts(
        &self,
        ips: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<IpDailyRow>, clickhouse::error::Error> {
        if ips.is_empty() {
            return Ok(Vec::new());
        }

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();

        let ip_list: String = ips
            .iter()
            .map(|ip| format!("'{}'", escape_sql_string(ip)))
            .collect::<Vec<_>>()
            .join(", ");

        let query = format!(
            r#"
            SELECT
                ip,
                toString(toDate(time_bucket)) AS day,
                sum(total_count) AS daily_count
            FROM {ip_prevalence_table}
            PREWHERE time_bucket >= toDateTime('{cutoff_str}')
            WHERE ip IN ({ip_list})
            GROUP BY ip, day
            ORDER BY ip, day
            "#,
            ip_prevalence_table = self.ip_prevalence_table,
            cutoff_str = cutoff_str,
            ip_list = ip_list
        );

        debug!("Executing IP daily counts query for {} IPs", ips.len());
        self.client.query(&query).fetch_all().await
    }

    /// Empty artifact-detail response — returned when the active schema has no
    /// column for the artifact's own pivot field (NAN-1241), so the detail
    /// cannot be selected at all. UDM always has these columns, so this is only
    /// reachable under a schema profile that drops the pivot concept.
    fn empty_artifact_detail(
        artifact: &str,
        artifact_type: &ArtifactType,
    ) -> ArtifactDetailResponse {
        ArtifactDetailResponse {
            artifact: artifact.to_string(),
            artifact_type: *artifact_type,
            top_hosts: Vec::new(),
            top_users: Vec::new(),
            source_types: Vec::new(),
            processes: Vec::new(),
            top_file_names: Vec::new(),
            network: Vec::new(),
            geo: Vec::new(),
            threat_intel: Vec::new(),
        }
    }

    /// Get artifact detail from the logs table — top hosts, users, source types, and contextual data
    ///
    /// `scope` is the caller's source-scope (NAN-1801): its deny set is AND-ed
    /// into the shared WHERE clause so every sub-query — including the
    /// `source_type` GROUP BY, a direct existence leak — only sees rows from
    /// sources the caller may read. Unrestricted (empty) scope emits
    /// byte-identical SQL to the pre-scoping form.
    #[instrument(skip(self, profile, scope))]
    pub async fn get_artifact_detail(
        &self,
        artifact: &str,
        artifact_type: &ArtifactType,
        logs_table: &str,
        profile: &dyn crate::schema::SchemaProfile,
        scope: &crate::auth::ScopeSet,
        time_window: TimeWindow,
    ) -> Result<ArtifactDetailResponse, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();
        let escaped = escape_sql_string(artifact);

        // Resolve UDM-semantic column names to the active schema's physical
        // columns (NAN-1241). Under UDM these return the same name (byte-identical
        // SQL); under OCSF they return the promoted OCSF column expression. A
        // `None` means the schema has no column for that concept — the dependent
        // sub-query is skipped rather than emitting an unknown-column 500.
        let col_file_hash = profile.udm_column_sql("file_hash");
        let col_dest_ip = profile.udm_column_sql("dest_ip");
        let col_dest_host = profile.udm_column_sql("dest_host");
        let col_src_host = profile.udm_column_sql("src_host");
        let col_user = profile.udm_column_sql("user");
        let col_process_name = profile.udm_column_sql("process_name");
        let col_command_line = profile.udm_column_sql("command_line");
        let col_file_name = profile.udm_column_sql("file_name");
        let col_dest_port = profile.udm_column_sql("dest_port");
        let col_protocol = profile.udm_column_sql("protocol");

        // Determine WHERE clause based on artifact type. If the schema lacks a
        // column for the artifact's own pivot field, we cannot select this
        // artifact at all — return an empty detail rather than a broken query.
        let where_clause = if artifact_type.is_hash() {
            // Logs table stores mixed-case hashes; use lower() on column but not the
            // parameter (artifacts from the agg table are already lowercase).
            match &col_file_hash {
                Some(c) => format!("lower({}) = '{}'", c, escaped.to_lowercase()),
                None => {
                    return Ok(Self::empty_artifact_detail(artifact, artifact_type));
                }
            }
        } else if artifact_type.is_ip() {
            match &col_dest_ip {
                Some(c) => format!("{} = '{}'", c, escaped),
                None => {
                    return Ok(Self::empty_artifact_detail(artifact, artifact_type));
                }
            }
        } else {
            match &col_dest_host {
                Some(c) => format!("{} = '{}'", c, escaped),
                None => {
                    return Ok(Self::empty_artifact_detail(artifact, artifact_type));
                }
            }
        };

        // NAN-1801 (P3 side-doors): AND the caller's source-scope predicate
        // into the SHARED artifact where_clause so all seven tokio::join!
        // sub-queries below inherit it — these are raw-logs drilldowns that
        // bypass the nPL search-path scope injector. The handler composes the
        // deny set via `effective_source_deny_set()` (per-source RBAC ∪ audit
        // unless `audit:view`), so audit rows are covered too. Empty deny set
        // appends nothing — byte-identical SQL for unrestricted callers.
        let where_clause = match crate::search::service::source_scope_sql_predicate(
            "source_type",
            scope.deny_set(),
        ) {
            Some(pred) => format!("{where_clause} AND ({pred})"),
            None => where_clause,
        };

        let time_filter = format!("timestamp >= toDateTime('{}')", cutoff_str);

        // Run all detail queries concurrently
        let (hosts_r, users_r, sources_r, processes_r, file_names_r, network_r, geo_r) = tokio::join!(
            // Top hosts
            async {
                let Some(src_host) = &col_src_host else {
                    return Ok(Vec::new());
                };
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    host: String,
                    cnt: u64,
                    last_ts: i64,
                }
                let q = format!(
                    "SELECT {sh} AS host, count() AS cnt, reinterpretAsInt64(max(timestamp)) AS last_ts \
                     FROM {} WHERE {} AND {} AND {sh} != '' \
                     GROUP BY {sh} ORDER BY cnt DESC LIMIT 10",
                    logs_table, time_filter, where_clause, sh = src_host
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactHostEntry {
                            host: r.host,
                            count: r.cnt,
                            last_seen: Self::micros_to_datetime(r.last_ts),
                        })
                        .collect::<Vec<_>>()
                })
            },
            // Top users
            async {
                let Some(user) = &col_user else {
                    return Ok(Vec::new());
                };
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    user: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT {u} AS user, count() AS cnt \
                     FROM {} WHERE {} AND {} AND {u} != '' \
                     GROUP BY {u} ORDER BY cnt DESC LIMIT 10",
                    logs_table, time_filter, where_clause, u = user
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactUserEntry {
                            user: r.user,
                            count: r.cnt,
                        })
                        .collect::<Vec<_>>()
                })
            },
            // Source types
            async {
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    source_type: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT source_type, count() AS cnt \
                     FROM {} WHERE {} AND {} AND source_type != '' \
                     GROUP BY source_type ORDER BY cnt DESC LIMIT 10",
                    logs_table, time_filter, where_clause
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactSourceEntry {
                            source_type: r.source_type,
                            count: r.cnt,
                        })
                        .collect::<Vec<_>>()
                })
            },
            // Process context (hashes only). The `is_wrapper` flag lets the
            // UI collapse consecutive svchost/rundll32/powershell rows into
            // a single group so a hash like svchost reads as "one host, many
            // command lines" instead of 10 near-identical rows.
            async {
                if !artifact_type.is_hash() {
                    return Ok(Vec::new());
                }
                let (Some(process_name), Some(command_line)) =
                    (&col_process_name, &col_command_line)
                else {
                    return Ok(Vec::new());
                };
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    process_name: String,
                    command_line: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT {pn} AS process_name, {cl} AS command_line, count() AS cnt \
                     FROM {} WHERE {} AND {} AND {pn} != '' \
                     GROUP BY {pn}, {cl} ORDER BY cnt DESC LIMIT 5",
                    logs_table, time_filter, where_clause, pn = process_name, cl = command_line
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| {
                            let is_wrapper = is_wrapper_process(&r.process_name);
                            ArtifactProcessEntry {
                                process_name: r.process_name,
                                command_line: r.command_line,
                                count: r.cnt,
                                is_wrapper,
                            }
                        })
                        .collect::<Vec<_>>()
                })
            },
            // Top on-disk file names (hashes only). Aggregated from the same
            // events as `processes`, but pivoted on `file_name` instead of
            // `process_name`. For svchost-style hashes, file_name is the
            // truer identity (`tiledatamodelsvc.dll`) — the running image is
            // always svchost.exe.
            async {
                if !artifact_type.is_hash() {
                    return Ok(Vec::new());
                }
                let Some(file_name) = &col_file_name else {
                    return Ok(Vec::new());
                };
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    file_name: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT {fn_} AS file_name, count() AS cnt \
                     FROM {} WHERE {} AND {} AND {fn_} != '' \
                     GROUP BY {fn_} ORDER BY cnt DESC LIMIT 5",
                    logs_table, time_filter, where_clause, fn_ = file_name
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactFileNameEntry {
                            file_name: r.file_name,
                            count: r.cnt,
                        })
                        .collect::<Vec<_>>()
                })
            },
            // Network context (IPs and domains only)
            async {
                if artifact_type.is_hash() {
                    return Ok(Vec::new());
                }
                let (Some(dest_port), Some(protocol)) = (&col_dest_port, &col_protocol) else {
                    return Ok(Vec::new());
                };
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    dest_port: u16,
                    protocol: String,
                    cnt: u64,
                }
                // NOTE(OCSF/NAN-1241): under OCSF `protocol` resolves to
                // `connection_info.protocol_num` (Int32), not a String. This
                // query deserializes `protocol` as a String, so under OCSF the
                // fetch will error and the network sub-context degrades to empty
                // (caught by `unwrap_or_default` below). Acceptable best-effort
                // degradation; a String protocol name has no promoted OCSF column.
                let q = format!(
                    "SELECT {dp} AS dest_port, {proto} AS protocol, count() AS cnt \
                     FROM {} WHERE {} AND {} AND {dp} > 0 \
                     GROUP BY {dp}, {proto} ORDER BY cnt DESC LIMIT 10",
                    logs_table, time_filter, where_clause, dp = dest_port, proto = protocol
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactNetworkEntry {
                            dest_port: r.dest_port,
                            protocol: r.protocol,
                            count: r.cnt,
                        })
                        .collect::<Vec<_>>()
                })
            },
            // Geo/ASN context (IPs only)
            async {
                if !artifact_type.is_ip() {
                    return Ok(Vec::new());
                }
                // NOTE(OCSF/NAN-1241): the UDM geo columns resolve via their UDM
                // semantic names. `enriched_dest_country` has NO OCSF `udm_field`
                // mapping (OCSF promotes `enriched_dest_country_code` →
                // `dst_endpoint.location.country` instead), so under OCSF this
                // returns None and the geo sub-context is skipped (empty). Under
                // UDM both resolve to their own column names (byte-identical).
                let (Some(country_col), Some(asn_col)) = (
                    profile.udm_column_sql("enriched_dest_country"),
                    profile.udm_column_sql("enriched_dest_asn"),
                ) else {
                    return Ok(Vec::new());
                };
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    country: String,
                    asn: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT {cc} AS country, {asn} AS asn, count() AS cnt \
                     FROM {} WHERE {} AND {} AND {cc} != '' \
                     GROUP BY country, asn ORDER BY cnt DESC LIMIT 5",
                    logs_table, time_filter, where_clause, cc = country_col, asn = asn_col
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactGeoEntry {
                            country: r.country,
                            asn: r.asn,
                            count: r.cnt,
                        })
                        .collect::<Vec<_>>()
                })
            },
        );

        Ok(ArtifactDetailResponse {
            artifact: artifact.to_string(),
            artifact_type: *artifact_type,
            top_hosts: hosts_r.unwrap_or_default(),
            top_users: users_r.unwrap_or_default(),
            source_types: sources_r.unwrap_or_default(),
            processes: processes_r.unwrap_or_default(),
            top_file_names: file_names_r.unwrap_or_default(),
            network: network_r.unwrap_or_default(),
            geo: geo_r.unwrap_or_default(),
            // Populated at the service layer where the EnrichmentService
            // handle is available — the repository only knows about CH.
            threat_intel: Vec::new(),
        })
    }

    /// Bulk fetch inline-subtitle context for a batch of artifacts.
    ///
    /// Returns a `(value, ArtifactInlineContext)` map. For each artifact this
    /// pulls in *one* row's worth of summary data — top file_name (hashes),
    /// top process_name + command_line + is_wrapper (hashes), user_count,
    /// top source_type. Geo/ASN for IPs comes from the PG enrichment table
    /// and is layered on at the service level.
    ///
    /// Each call issues two CH queries that group by (artifact, …) so the
    /// scan cost is one pass per call regardless of artifact count, bounded
    /// by `time_filter` (which is the same time window as the list).
    ///
    /// Per-bucket size is capped at `MAX_BULK_INLINE_CONTEXT` to keep the
    /// inlined `IN (...)` list well under ClickHouse's 262 KB `max_query_size`
    /// — see the constant for the rationale. Today the handler caps `limit`
    /// at 200, so this is belt-and-suspenders for a future caller that
    /// raises or skips that cap.
    /// `scope` (NAN-1801): the caller's source-scope deny set is AND-ed into
    /// the shared time filter so every bucket query — each of which carries an
    /// `argMax(source_type, …) AS top_source_type` leg — only aggregates rows
    /// from sources the caller may read. Unrestricted scope is byte-identical.
    #[instrument(skip(self, profile, scope, hash_artifacts, ip_artifacts, domain_artifacts))]
    #[allow(clippy::too_many_arguments)]
    pub async fn bulk_artifact_inline_context(
        &self,
        hash_artifacts: &[String],
        ip_artifacts: &[String],
        domain_artifacts: &[String],
        logs_table: &str,
        profile: &dyn crate::schema::SchemaProfile,
        scope: &crate::auth::ScopeSet,
        time_window: TimeWindow,
    ) -> std::collections::HashMap<String, ArtifactInlineContext> {
        use std::collections::HashMap;
        let mut out: HashMap<String, ArtifactInlineContext> = HashMap::new();

        // Resolve UDM-semantic columns to the active schema's physical columns
        // (NAN-1241). Under UDM these return the same name (byte-identical SQL);
        // under OCSF they return the promoted OCSF column. `source_type` is a real
        // column on both tables and is left literal. A `None` resolution skips the
        // dependent bucket rather than emitting an unknown-column query.
        let col_file_hash = profile.udm_column_sql("file_hash");
        let col_file_name = profile.udm_column_sql("file_name");
        let col_user = profile.udm_column_sql("user");
        let col_process_name = profile.udm_column_sql("process_name");
        let col_command_line = profile.udm_column_sql("command_line");
        let col_dest_ip = profile.udm_column_sql("dest_ip");
        let col_dest_host = profile.udm_column_sql("dest_host");

        // Defensive cap on the inlined IN-list size. Each artifact value is
        // ~70 bytes worst case (SHA-256 hex + quoting + comma); 1000 entries
        // is ~70 KB, still well under CH's default `max_query_size = 262144`.
        // Truncate-with-warn rather than panic so a future caller that
        // accidentally passes more doesn't break the page.
        fn cap<'a>(slice: &'a [String], bucket: &'static str) -> &'a [String] {
            const MAX_BULK_INLINE_CONTEXT: usize = 1000;
            if slice.len() > MAX_BULK_INLINE_CONTEXT {
                tracing::warn!(
                    bucket,
                    requested = slice.len(),
                    cap = MAX_BULK_INLINE_CONTEXT,
                    "bulk_artifact_inline_context: truncating IN-list",
                );
                &slice[..MAX_BULK_INLINE_CONTEXT]
            } else {
                slice
            }
        }
        let hash_artifacts = cap(hash_artifacts, "hash");
        let ip_artifacts = cap(ip_artifacts, "ip");
        let domain_artifacts = cap(domain_artifacts, "domain");

        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = crate::sql_hygiene::format_ch_bound(&cutoff).to_string();
        let time_filter = format!("timestamp >= toDateTime('{}')", cutoff_str);

        // NAN-1801 (P3 side-doors): AND the caller's source-scope predicate
        // into the shared `{pre}` fragment so all bucket queries (hash file/
        // process, IP, domain) inherit it — each has a `top_source_type` leg
        // that would otherwise leak denied-source names, and the counts would
        // include denied-source rows. Empty deny set appends nothing —
        // byte-identical SQL for unrestricted callers.
        let time_filter = match crate::search::service::source_scope_sql_predicate(
            "source_type",
            scope.deny_set(),
        ) {
            Some(pred) => format!("{time_filter} AND ({pred})"),
            None => time_filter,
        };

        // --- Hashes: top file_name, top process_name+command_line, user_count, top source_type ---
        // Requires file_hash + file_name + user columns; skip the whole bucket if
        // the schema lacks any of them (NAN-1241).
        if !hash_artifacts.is_empty()
            && col_file_hash.is_some()
            && col_file_name.is_some()
            && col_user.is_some()
        {
            let file_hash = col_file_hash.as_deref().expect("checked is_some");
            let file_name = col_file_name.as_deref().expect("checked is_some");
            let user = col_user.as_deref().expect("checked is_some");
            let escaped: Vec<String> = hash_artifacts
                .iter()
                .map(|h| format!("'{}'", escape_sql_string(h).to_lowercase()))
                .collect();
            let hash_list = escaped.join(",");

            // Top file_name per hash (argMax on count). Single pass.
            #[derive(Debug, Row, Deserialize)]
            struct FRow {
                hash: String,
                top_file_name: String,
                user_count: u64,
                top_source_type: String,
            }
            let q_files = format!(
                // user_count is a TRUE distinct across the whole hash, not `any()`
                // of one (file_name, source_type) group's count (audit P10): the
                // inner emits a per-group `uniqExactState`, the outer merges those
                // states so partial per-group counts don't undercount the hash.
                "SELECT lower({fh}) AS hash, \
                        argMax({fn_}, file_name_cnt) AS top_file_name, \
                        uniqExactMerge(distinct_users) AS user_count, \
                        argMax(source_type, src_cnt) AS top_source_type \
                 FROM ( \
                    SELECT lower({fh}) AS hash_lc, {fn_} AS file_name, count() AS file_name_cnt, \
                           uniqExactState({u}) AS distinct_users, source_type, count() AS src_cnt \
                    FROM {logs} \
                    WHERE {pre} AND lower({fh}) IN ({hashes}) \
                    GROUP BY hash_lc, file_name, source_type \
                 ) \
                 GROUP BY lower({fh})",
                logs = logs_table,
                pre = time_filter,
                hashes = hash_list,
                fh = file_hash,
                fn_ = file_name,
                u = user,
            );
            if let Ok(rows) = self.client.query(&q_files).fetch_all::<FRow>().await {
                for r in rows {
                    let entry = out.entry(r.hash.clone()).or_default();
                    if !r.top_file_name.is_empty() {
                        entry.top_file_name = Some(r.top_file_name);
                    }
                    entry.user_count = Some(r.user_count);
                    if !r.top_source_type.is_empty() {
                        entry.top_source_type = Some(r.top_source_type);
                    }
                }
            }

            // Top (process_name, command_line) per hash. Separate query so the
            // file_name aggregation above stays a single group-by per hash.
            // Skipped if the schema lacks either process column (NAN-1241).
            if let (Some(process_name), Some(command_line)) =
                (col_process_name.as_deref(), col_command_line.as_deref())
            {
                #[derive(Debug, Row, Deserialize)]
                struct PRow {
                    hash: String,
                    top_process_name: String,
                    top_command_line: String,
                }
                let q_procs = format!(
                    "SELECT lower({fh}) AS hash, \
                            argMax({pn}, cnt) AS top_process_name, \
                            argMax({cl}, cnt) AS top_command_line \
                     FROM ( \
                        SELECT lower({fh}) AS hash_lc, {pn} AS process_name, {cl} AS command_line, count() AS cnt \
                        FROM {logs} \
                        WHERE {pre} AND lower({fh}) IN ({hashes}) AND {pn} != '' \
                        GROUP BY hash_lc, process_name, command_line \
                     ) \
                     GROUP BY lower({fh})",
                    logs = logs_table,
                    pre = time_filter,
                    hashes = hash_list,
                    fh = file_hash,
                    pn = process_name,
                    cl = command_line,
                );
                if let Ok(rows) = self.client.query(&q_procs).fetch_all::<PRow>().await {
                    for r in rows {
                        let is_wrapper = is_wrapper_process(&r.top_process_name);
                        let entry = out.entry(r.hash.clone()).or_default();
                        if !r.top_process_name.is_empty() {
                            entry.top_process_is_wrapper = is_wrapper;
                            entry.top_process_name = Some(r.top_process_name);
                        }
                        if !r.top_command_line.is_empty() {
                            entry.top_command_line = Some(r.top_command_line);
                        }
                    }
                }
            }
        }

        // --- IPs: user_count + top source_type (geo/ASN comes from PG later) ---
        // Requires dest_ip + user columns; skip if the schema lacks either (NAN-1241).
        if !ip_artifacts.is_empty() && col_dest_ip.is_some() && col_user.is_some() {
            let dest_ip = col_dest_ip.as_deref().expect("checked is_some");
            let user = col_user.as_deref().expect("checked is_some");
            let escaped: Vec<String> = ip_artifacts
                .iter()
                .map(|v| format!("'{}'", escape_sql_string(v)))
                .collect();
            let ip_list = escaped.join(",");

            #[derive(Debug, Row, Deserialize)]
            struct IRow {
                ip: String,
                user_count: u64,
                top_source_type: String,
            }
            let q = format!(
                "SELECT {di} AS ip, \
                        uniqExact({u}) AS user_count, \
                        argMax(source_type, src_cnt) AS top_source_type \
                 FROM ( \
                    SELECT {di} AS dest_ip, {u} AS user, source_type, count() AS src_cnt \
                    FROM {logs} \
                    WHERE {pre} AND {di} IN ({ips}) \
                    GROUP BY dest_ip, user, source_type \
                 ) \
                 GROUP BY {di}",
                logs = logs_table,
                pre = time_filter,
                ips = ip_list,
                di = dest_ip,
                u = user,
            );
            if let Ok(rows) = self.client.query(&q).fetch_all::<IRow>().await {
                for r in rows {
                    let entry = out.entry(r.ip.clone()).or_default();
                    entry.user_count = Some(r.user_count);
                    if !r.top_source_type.is_empty() {
                        entry.top_source_type = Some(r.top_source_type);
                    }
                }
            }
        }

        // --- Domains: user_count + top source_type ---
        // Requires dest_host + user columns; skip if the schema lacks either (NAN-1241).
        if !domain_artifacts.is_empty() && col_dest_host.is_some() && col_user.is_some() {
            let dest_host = col_dest_host.as_deref().expect("checked is_some");
            let user = col_user.as_deref().expect("checked is_some");
            let escaped: Vec<String> = domain_artifacts
                .iter()
                .map(|v| format!("'{}'", escape_sql_string(v)))
                .collect();
            let dom_list = escaped.join(",");

            #[derive(Debug, Row, Deserialize)]
            struct DRow {
                domain: String,
                user_count: u64,
                top_source_type: String,
            }
            let q = format!(
                "SELECT {dh} AS domain, \
                        uniqExact({u}) AS user_count, \
                        argMax(source_type, src_cnt) AS top_source_type \
                 FROM ( \
                    SELECT {dh} AS dest_host, {u} AS user, source_type, count() AS src_cnt \
                    FROM {logs} \
                    WHERE {pre} AND {dh} IN ({doms}) \
                    GROUP BY dest_host, user, source_type \
                 ) \
                 GROUP BY {dh}",
                logs = logs_table,
                pre = time_filter,
                doms = dom_list,
                dh = dest_host,
                u = user,
            );
            if let Ok(rows) = self.client.query(&q).fetch_all::<DRow>().await {
                for r in rows {
                    let entry = out.entry(r.domain.clone()).or_default();
                    entry.user_count = Some(r.user_count);
                    if !r.top_source_type.is_empty() {
                        entry.top_source_type = Some(r.top_source_type);
                    }
                }
            }
        }

        out
    }

    /// Calculate prevalence score (0-100, lower = rarer)
    ///
    /// Score calculation:
    /// - 0: Never seen (0 hosts)
    /// - 1-20: Very rare (1 to threshold hosts)
    /// - 21-50: Rare (threshold to 2x threshold)
    /// - 51-80: Uncommon (2x to 10x threshold)
    /// - 81-100: Common (>10x threshold)
    pub(crate) fn calculate_prevalence_score(host_count: u64, rarity_threshold: u64) -> u8 {
        if host_count == 0 {
            return 0;
        }

        let threshold = rarity_threshold.max(1) as f64;
        let count = host_count as f64;

        let score = if count < threshold {
            // Very rare: 1-20
            (count / threshold * 20.0).min(20.0)
        } else if count < threshold * 2.0 {
            // Rare: 21-50
            20.0 + ((count - threshold) / threshold * 30.0)
        } else if count < threshold * 10.0 {
            // Uncommon: 51-80
            50.0 + ((count - threshold * 2.0) / (threshold * 8.0) * 30.0)
        } else {
            // Common: 81-100
            80.0 + ((count - threshold * 10.0) / (threshold * 90.0) * 20.0).min(20.0)
        };

        score.round() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-1729 (P2-B): the recency predicate must compare the RAW DateTime64
    /// column so the idx_last_seen / idx_first_seen minmax indexes (migration
    /// 155) can prune. The old `reinterpretAsInt64(col) >= micros` form wrapped
    /// the column and was opaque to the skip index — a full summary-column scan
    /// on every rare/new lookup (Saturn: 30d rare-IP OOM'd at 1.86 GiB).
    #[test]
    fn recency_predicate_is_index_eligible() {
        let p = PrevalenceRepository::recency_at_least("last_seen", 1_700_000_000_000_000);
        assert_eq!(
            p,
            "last_seen >= fromUnixTimestamp64Micro(toInt64(1700000000000000))"
        );
        // Must NOT wrap the column in a function — that defeats the skip index.
        assert!(
            !p.contains("reinterpretAsInt64"),
            "recency predicate must compare the raw column, got: {p}"
        );
        // first_seen (newness) variant compares the raw first_seen column too.
        let f = PrevalenceRepository::recency_at_least("first_seen", 42);
        assert_eq!(f, "first_seen >= fromUnixTimestamp64Micro(toInt64(42))");
    }

    #[test]
    fn dict_artifact_kind_picks_correct_dict_and_key_expr() {
        // Mirrors the dict-name expectations encoded in prevalence_join.rs:334-336.
        // If these strings drift, the JOIN path and the post-processing path
        // would silently target different dicts.
        assert_eq!(
            DictArtifactKind::Hash.dict_name(),
            "nanosiem.hash_prevalence_dict"
        );
        assert_eq!(
            DictArtifactKind::Domain.dict_name(),
            "nanosiem.domain_prevalence_dict"
        );
        assert_eq!(
            DictArtifactKind::Ip.dict_name(),
            "nanosiem.ip_prevalence_dict"
        );

        // Hash and domain dicts are populated in lowercase; IP dicts use raw values.
        assert_eq!(DictArtifactKind::Hash.key_expr(), "lower(artifact)");
        assert_eq!(DictArtifactKind::Domain.key_expr(), "lower(artifact)");
        assert_eq!(DictArtifactKind::Ip.key_expr(), "artifact");
    }

    #[test]
    fn calculate_prevalence_score_clamps_at_boundaries() {
        // Spot-check the regions documented above the function (very rare,
        // rare, uncommon, common). These are unchanged by NAN-701 but the
        // function is now `pub(crate)`, so locking the contract here keeps
        // future refactors honest.
        assert_eq!(PrevalenceRepository::calculate_prevalence_score(0, 3), 0);
        assert!(PrevalenceRepository::calculate_prevalence_score(1, 3) <= 20);
        assert!(PrevalenceRepository::calculate_prevalence_score(5, 3) <= 50);
        assert!(PrevalenceRepository::calculate_prevalence_score(9999, 3) >= 80);
    }
}
