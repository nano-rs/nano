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
use crate::db::TableNames;

/// Chunk size for dict-based bulk lookups. Bounds the inlined
/// `arrayJoin([...])` literal so we stay well under CH's default
/// `max_query_size` (262KB) — 1000 sha256 hashes ≈ 67KB.
const DICT_QUERY_CHUNK: usize = 1000;

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
}

impl PrevalenceRepository {
    /// Create a new PrevalenceRepository with a ClickHouse client
    pub fn new(client: ClickHouseClient, table_names: TableNames) -> Self {
        Self {
            client,
            hash_prevalence_table: table_names.read("hash_prevalence_agg"),
            domain_prevalence_table: table_names.read("domain_prevalence_agg"),
            ip_prevalence_table: table_names.read("ip_prevalence_agg"),
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

    /// Query hash prevalence for a single hash
    #[instrument(skip(self))]
    pub async fn get_hash_prevalence(
        &self,
        hash: &str,
        time_window: TimeWindow,
    ) -> Result<Option<HashPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        // MV already stores file_hash as lower() — no need to lower() in query
        let hash_lower = hash.to_lowercase().replace('\'', "''");

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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

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
            domain = domain.replace('\'', "''"),
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        // Build the IN clause with escaped values (lowercase for case-insensitive matching)
        let hash_list: String = hashes
            .iter()
            .map(|h| format!("'{}'", h.to_lowercase().replace('\'', "''")))
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        // Build the IN clause with escaped values
        let domain_list: String = domains
            .iter()
            .map(|d| format!("'{}'", d.replace('\'', "''")))
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

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
            ip = ip.replace('\'', "''"),
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        // Build the IN clause with escaped values
        let ip_list: String = ips
            .iter()
            .map(|ip| format!("'{}'", ip.replace('\'', "''")))
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

        // Window cutoff masking — see prevalence_join.rs:323-333. 1h is
        // rejected upstream there; we accept it here and treat it as 24h
        // (post-processing fallback is rare; not worth a separate error).
        let cutoff_sql = match time_window {
            TimeWindow::OneHour | TimeWindow::TwentyFourHours => "now() - INTERVAL 1 DAY",
            TimeWindow::SevenDays => "now() - INTERVAL 7 DAY",
            TimeWindow::ThirtyDays => "toDateTime64(0, 6)",
        };

        let artifact_list: String = artifacts
            .iter()
            .map(|a| format!("'{}'", a.replace('\'', "''")))
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

    /// Get rare artifacts (below threshold) for a given time window
    #[instrument(skip(self))]
    pub async fn get_rare_hashes(
        &self,
        threshold: u64,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<HashPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

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
                GROUP BY file_hash, hash_type
            )
            WHERE host_count < {threshold}
            ORDER BY last_seen DESC
            LIMIT {limit}
            "#,
            hash_prevalence_table = self.hash_prevalence_table,
            cutoff_str = cutoff_str,
            threshold = threshold,
            limit = limit
        );

        debug!("Executing rare hashes query with threshold {}", threshold);

        self.client.query(&query).fetch_all().await
    }

    /// Get rare domains (below threshold) for a given time window
    #[instrument(skip(self))]
    pub async fn get_rare_domains(
        &self,
        threshold: u64,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<DomainPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

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
                GROUP BY domain
            )
            WHERE source_host_count < {threshold}
            ORDER BY last_seen DESC
            LIMIT {limit}
            "#,
            domain_prevalence_table = self.domain_prevalence_table,
            cutoff_str = cutoff_str,
            threshold = threshold,
            limit = limit
        );

        debug!("Executing rare domains query with threshold {}", threshold);

        self.client.query(&query).fetch_all().await
    }

    /// Get newly seen hashes (first_seen after specified time)
    #[instrument(skip(self))]
    pub async fn get_new_hashes(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<HashPrevalenceRow>, clickhouse::error::Error> {
        // Convert since to microseconds for comparison with reinterpretAsInt64
        let since_micros = since.timestamp_micros();
        let since_str = since.format("%Y-%m-%d %H:%M:%S").to_string();

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
                PREWHERE time_bucket >= toDateTime('{since_str}')
                GROUP BY file_hash, hash_type
            )
            WHERE reinterpretAsInt64(first_seen) >= {since_micros}
            ORDER BY first_seen DESC
            LIMIT {limit}
            "#,
            hash_prevalence_table = self.hash_prevalence_table,
            since_str = since_str,
            since_micros = since_micros,
            limit = limit
        );

        debug!("Executing new hashes query since {}", since);

        self.client.query(&query).fetch_all().await
    }

    /// Get newly seen domains (first_seen after specified time)
    #[instrument(skip(self))]
    pub async fn get_new_domains(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<DomainPrevalenceRow>, clickhouse::error::Error> {
        // Convert since to microseconds for comparison with reinterpretAsInt64
        let since_micros = since.timestamp_micros();
        let since_str = since.format("%Y-%m-%d %H:%M:%S").to_string();

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
                PREWHERE time_bucket >= toDateTime('{since_str}')
                GROUP BY domain
            )
            WHERE reinterpretAsInt64(first_seen) >= {since_micros}
            ORDER BY first_seen DESC
            LIMIT {limit}
            "#,
            domain_prevalence_table = self.domain_prevalence_table,
            since_str = since_str,
            since_micros = since_micros,
            limit = limit
        );

        debug!("Executing new domains query since {}", since);

        self.client.query(&query).fetch_all().await
    }

    /// Get rare IPs (below threshold) for a given time window
    /// Note: Excludes private/RFC1918 IPs by default to reduce noise
    #[instrument(skip(self))]
    pub async fn get_rare_ips(
        &self,
        threshold: u64,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<IpPrevalenceRow>, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

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
                GROUP BY ip
            )
            WHERE source_host_count < {threshold}
              AND is_private = 0
            ORDER BY last_seen DESC
            LIMIT {limit}
            "#,
            ip_prevalence_table = self.ip_prevalence_table,
            cutoff_str = cutoff_str,
            threshold = threshold,
            limit = limit
        );

        debug!("Executing rare IPs query with threshold {}", threshold);

        self.client.query(&query).fetch_all().await
    }

    /// Get newly seen IPs (first_seen after specified time)
    /// Note: Excludes private/RFC1918 IPs by default to reduce noise
    #[instrument(skip(self))]
    pub async fn get_new_ips(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<IpPrevalenceRow>, clickhouse::error::Error> {
        // Convert since to microseconds for comparison with reinterpretAsInt64
        let since_micros = since.timestamp_micros();
        let since_str = since.format("%Y-%m-%d %H:%M:%S").to_string();

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
                PREWHERE time_bucket >= toDateTime('{since_str}')
                GROUP BY ip
            )
            WHERE reinterpretAsInt64(first_seen) >= {since_micros}
              AND is_private = 0
            ORDER BY first_seen DESC
            LIMIT {limit}
            "#,
            ip_prevalence_table = self.ip_prevalence_table,
            since_str = since_str,
            since_micros = since_micros,
            limit = limit
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        let hash_list: String = hashes
            .iter()
            .map(|h| format!("'{}'", h.to_lowercase().replace('\'', "''")))
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        let domain_list: String = domains
            .iter()
            .map(|d| format!("'{}'", d.replace('\'', "''")))
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
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();

        let ip_list: String = ips
            .iter()
            .map(|ip| format!("'{}'", ip.replace('\'', "''")))
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

    /// Get artifact detail from the logs table — top hosts, users, source types, and contextual data
    #[instrument(skip(self))]
    pub async fn get_artifact_detail(
        &self,
        artifact: &str,
        artifact_type: &ArtifactType,
        logs_table: &str,
        time_window: TimeWindow,
    ) -> Result<ArtifactDetailResponse, clickhouse::error::Error> {
        let cutoff = Self::get_cutoff_time(time_window);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        let escaped = artifact.replace('\'', "''");

        // Determine WHERE clause based on artifact type
        let (where_field, where_clause) = if artifact_type.is_hash() {
            // Logs table stores mixed-case hashes; use lower() on column but not the
            // parameter (artifacts from the agg table are already lowercase).
            (
                "file_hash",
                format!("lower(file_hash) = '{}'", escaped.to_lowercase()),
            )
        } else if artifact_type.is_ip() {
            ("dest_ip", format!("dest_ip = '{}'", escaped))
        } else {
            ("dest_host", format!("dest_host = '{}'", escaped))
        };

        let prewhere_filter = format!("timestamp >= toDateTime('{}')", cutoff_str);

        // Run all detail queries concurrently
        let (hosts_r, users_r, sources_r, processes_r, network_r, geo_r) = tokio::join!(
            // Top hosts
            async {
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    host: String,
                    cnt: u64,
                    last_ts: i64,
                }
                let q = format!(
                    "SELECT src_host AS host, count() AS cnt, reinterpretAsInt64(max(timestamp)) AS last_ts \
                     FROM {} PREWHERE {} WHERE {} AND src_host != '' \
                     GROUP BY src_host ORDER BY cnt DESC LIMIT 10",
                    logs_table, prewhere_filter, where_clause
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
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    user: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT user, count() AS cnt \
                     FROM {} PREWHERE {} WHERE {} AND user != '' \
                     GROUP BY user ORDER BY cnt DESC LIMIT 10",
                    logs_table, prewhere_filter, where_clause
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
                     FROM {} PREWHERE {} WHERE {} AND source_type != '' \
                     GROUP BY source_type ORDER BY cnt DESC LIMIT 10",
                    logs_table, prewhere_filter, where_clause
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
            // Process context (hashes only)
            async {
                if !artifact_type.is_hash() {
                    return Ok(Vec::new());
                }
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    process_name: String,
                    command_line: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT process_name, command_line, count() AS cnt \
                     FROM {} PREWHERE {} WHERE {} AND process_name != '' \
                     GROUP BY process_name, command_line ORDER BY cnt DESC LIMIT 5",
                    logs_table, prewhere_filter, where_clause
                );
                self.client.query(&q).fetch_all::<R>().await.map(|rows| {
                    rows.into_iter()
                        .map(|r| ArtifactProcessEntry {
                            process_name: r.process_name,
                            command_line: r.command_line,
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
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    dest_port: u16,
                    protocol: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT dest_port, protocol, count() AS cnt \
                     FROM {} PREWHERE {} WHERE {} AND dest_port > 0 \
                     GROUP BY dest_port, protocol ORDER BY cnt DESC LIMIT 10",
                    logs_table, prewhere_filter, where_clause
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
                #[derive(Debug, Row, Deserialize)]
                struct R {
                    country: String,
                    asn: String,
                    cnt: u64,
                }
                let q = format!(
                    "SELECT enriched_dest_country AS country, enriched_dest_asn AS asn, count() AS cnt \
                     FROM {} PREWHERE {} WHERE {} AND enriched_dest_country != '' \
                     GROUP BY country, asn ORDER BY cnt DESC LIMIT 5",
                    logs_table, prewhere_filter, where_clause
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

        let _ = where_field; // used in where_clause construction

        Ok(ArtifactDetailResponse {
            artifact: artifact.to_string(),
            artifact_type: *artifact_type,
            top_hosts: hosts_r.unwrap_or_default(),
            top_users: users_r.unwrap_or_default(),
            source_types: sources_r.unwrap_or_default(),
            processes: processes_r.unwrap_or_default(),
            network: network_r.unwrap_or_default(),
            geo: geo_r.unwrap_or_default(),
        })
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
