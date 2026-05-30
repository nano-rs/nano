// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment sync service for downloading and loading enrichment data
//!
//! Handles:
//! - Downloading IPinfo Lite CSV data (with streaming for large files)
//! - Parsing and loading into database
//! - Scheduled daily syncs
//! - IP enrichment lookups for ingestion

use async_compression::tokio::bufread::GzipDecoder;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::RwLock;
use tokio_util::io::StreamReader;
use tracing::{info, instrument, warn};

use super::repository::{EnrichmentRepository, EnrichmentRepositoryError};
use super::types::*;
use crate::inputlookup::{SsrfConfig, SsrfValidator};

#[derive(Error, Debug)]
pub enum EnrichmentError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] EnrichmentRepositoryError),
    #[error("Download error: {0}")]
    DownloadError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Source not configured: {0}")]
    SourceNotConfigured(String),
    #[error("ClickHouse error: {0}")]
    ClickHouseError(#[from] clickhouse::error::Error),
    #[error("ClickHouse client not configured")]
    ClickHouseNotConfigured,
}

/// Result of an enrichment sync operation
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnrichmentSyncResult {
    pub source_id: String,
    pub success: bool,
    pub records_loaded: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Configuration for the enrichment service
#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    /// IPinfo Lite download URL override (with token) - if not set, reads from database
    pub ipinfo_lite_url: Option<String>,
    /// Whether to enable automatic daily sync
    pub auto_sync_enabled: bool,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            ipinfo_lite_url: None,
            auto_sync_enabled: false,
        }
    }
}

/// HTTP download configuration - extracted from enrichment source's config JSONB
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    /// HTTP timeout for downloads (seconds) - should be long enough for large files through CDNs
    pub download_timeout_secs: u64,
    /// TCP keepalive interval (seconds) - helps prevent CDN/proxy timeouts
    pub tcp_keepalive_secs: u64,
    /// HTTP connection timeout (seconds)
    pub connect_timeout_secs: u64,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            download_timeout_secs: 1800, // 30 minutes - IPinfo lite is ~400MB compressed
            tcp_keepalive_secs: 30,      // Keep connection alive through Cloudflare
            connect_timeout_secs: 30,    // Initial connection timeout
        }
    }
}

impl DownloadConfig {
    /// Extract download config from a source's JSONB config field
    pub fn from_source_config(config: &serde_json::Value) -> Self {
        Self {
            download_timeout_secs: config
                .get("download_timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(1800),
            tcp_keepalive_secs: config
                .get("tcp_keepalive_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30),
            connect_timeout_secs: config
                .get("connect_timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30),
        }
    }
}

/// Enrichment service for managing and applying IP enrichments
pub struct EnrichmentService {
    repository: EnrichmentRepository,
    config: EnrichmentConfig,
    /// In-memory cache for fast lookups during ingestion
    cache: Arc<RwLock<IpEnrichmentCache>>,
    /// ClickHouse client. The IP enrichment payload + lookups live in CH as of
    /// NAN-1117 (ip_enrichment_dict was repointed off PostgreSQL — see CH
    /// migration 123). Optional so the service can still be constructed in
    /// contexts without a CH pool, but the sync writer / lookups error if it's
    /// absent rather than silently no-op'ing.
    clickhouse_client: Option<clickhouse::Client>,
}

/// Simple in-memory cache for IP enrichments
struct IpEnrichmentCache {
    /// Whether cache is loaded
    loaded: bool,
}

impl Default for IpEnrichmentCache {
    fn default() -> Self {
        Self { loaded: false }
    }
}

/// SSRF-validate an IPinfo download URL and resolve it to socket addresses
/// safe to pin into a reqwest client.
///
/// Two-step resolution: `SsrfValidator::validate_with_dns` runs first to
/// catch syntax / scheme / blocked-domain / metadata-hostname violations
/// and reject the URL early if its hostname currently resolves to a
/// forbidden IP. We then re-resolve so we have addresses to feed
/// `ClientBuilder::resolve_to_addrs`, validating every address from the
/// second lookup the same way (catches the case where DNS flipped between
/// the two calls). Pinning closes the rebinding window between our final
/// resolution and reqwest's connect-time resolution — the connector dials
/// these exact addresses, not whatever the resolver returns later.
///
/// IP-literal hosts return an empty `Vec`; reqwest dials the literal
/// directly and no override is needed.
///
/// Mirrors the pattern in `nanosiem-core/src/settings/tiering/validation.rs`
/// (`validate_and_resolve_s3_endpoint`) so the two SSRF-sensitive download
/// paths in the codebase share the same shape.
async fn validate_and_resolve_ipinfo_url(
    url_str: &str,
) -> Result<(url::Url, Vec<std::net::SocketAddr>), EnrichmentError> {
    let validator = SsrfValidator::new(SsrfConfig {
        allow_http: true,
        ..Default::default()
    });

    let parsed_url = validator.validate_with_dns(url_str).await.map_err(|e| {
        EnrichmentError::DownloadError(format!(
            "URL rejected by SSRF check before fetch: {}",
            e
        ))
    })?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| EnrichmentError::DownloadError("URL missing host".to_string()))?;

    // IP-literal hosts: validate_with_dns already validated the IP; reqwest
    // dials it directly, no override needed. (`url::Url::host_str` returns
    // IPv6 literals without brackets — `::1`, not `[::1]` — so this catches
    // both forms.)
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok((parsed_url, Vec::new()));
    }

    let port = parsed_url.port_or_known_default().unwrap_or(443);
    let resolve_target = format!("{}:{}", host, port);

    // Bound DNS resolution so a slow / poisoned resolver can't pin a runtime
    // worker indefinitely. Five seconds matches the default in SsrfValidator.
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(resolve_target),
    )
    .await
    .map_err(|_| {
        EnrichmentError::DownloadError(format!("DNS resolution timed out for {}", host))
    })?
    .map_err(|e| {
        EnrichmentError::DownloadError(format!("DNS resolution failed for {}: {}", host, e))
    })?
    .collect();

    if addrs.is_empty() {
        return Err(EnrichmentError::DownloadError(format!(
            "DNS resolution returned no addresses for {}",
            host
        )));
    }

    for addr in &addrs {
        validator.validate_ip_address(addr.ip()).map_err(|e| {
            EnrichmentError::DownloadError(format!(
                "URL rejected by SSRF check: resolved IP blocked: {}",
                e
            ))
        })?;
    }

    Ok((parsed_url, addrs))
}

impl EnrichmentService {
    /// Create a new enrichment service
    pub fn new(repository: EnrichmentRepository, config: EnrichmentConfig) -> Self {
        Self {
            repository,
            config,
            cache: Arc::new(RwLock::new(IpEnrichmentCache::default())),
            clickhouse_client: None,
        }
    }

    /// Create with default configuration
    pub fn with_defaults(repository: EnrichmentRepository) -> Self {
        Self::new(repository, EnrichmentConfig::default())
    }

    /// Attach the ClickHouse client used for the IP enrichment payload table,
    /// dictGet lookups, and the record-count stat (NAN-1117). This MUST be set
    /// before the service is wrapped in the shared `Arc<RwLock<>>`, because the
    /// auto-sync scheduler runs `sync_ipinfo_lite` against that same Arc — if
    /// the client is absent the sync writer errors instead of writing PG.
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

    /// Configure IPinfo Lite URL
    pub fn set_ipinfo_url(&mut self, url: String) {
        self.config.ipinfo_lite_url = Some(url);
    }

    /// Get the repository reference
    pub fn repository(&self) -> &EnrichmentRepository {
        &self.repository
    }

    // ========================================================================
    // Sync Operations
    // ========================================================================

    /// Sync IPinfo Lite data from the configured URL
    ///
    /// Uses a true streaming pipeline: HTTP stream → gzip decode → CSV parse → batched DB insert.
    /// Peak memory stays flat (~10k records per batch) regardless of dataset size.
    #[instrument(skip(self))]
    pub async fn sync_ipinfo_lite(&self) -> Result<EnrichmentSyncResult, EnrichmentError> {
        let start = std::time::Instant::now();
        let source_id = "ipinfo_lite";

        // Load source from database to get URL and download config
        let source = self.repository.get_source(source_id).await?;

        // Get URL from service config override or database
        let url = match &self.config.ipinfo_lite_url {
            Some(url) => url.clone(),
            None => source.download_url.ok_or_else(|| {
                EnrichmentError::SourceNotConfigured("IPinfo Lite URL not configured".to_string())
            })?,
        };

        // Extract download config from source's JSONB config
        let download_config = DownloadConfig::from_source_config(&source.config);

        info!(
            url = %url,
            keepalive_secs = download_config.tcp_keepalive_secs,
            "Starting IPinfo Lite streaming sync"
        );

        // Update status to in_progress
        self.repository
            .update_sync_status(source_id, SyncStatus::InProgress, None, None, None)
            .await?;

        match self
            .stream_and_insert_ipinfo(&url, &download_config, source_id)
            .await
        {
            Ok(record_count) => {
                self.repository
                    .update_sync_status(
                        source_id,
                        SyncStatus::Success,
                        None,
                        Some(record_count as i64),
                        None,
                    )
                    .await?;

                self.repository.set_source_enabled(source_id, true).await?;

                // Invalidate cache
                {
                    let mut cache = self.cache.write().await;
                    cache.loaded = false;
                }

                let duration_ms = start.elapsed().as_millis() as u64;
                info!(
                    record_count,
                    duration_ms, "IPinfo Lite streaming sync completed"
                );

                Ok(EnrichmentSyncResult {
                    source_id: source_id.to_string(),
                    success: true,
                    records_loaded: record_count,
                    duration_ms,
                    error: None,
                })
            }
            Err(e) => {
                let error_msg = e.to_string();
                warn!("IPinfo Lite sync failed: {}", error_msg);

                self.repository
                    .update_sync_status(source_id, SyncStatus::Failed, Some(&error_msg), None, None)
                    .await?;

                Ok(EnrichmentSyncResult {
                    source_id: source_id.to_string(),
                    success: false,
                    records_loaded: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    error: Some(error_msg),
                })
            }
        }
    }

    /// Build a configured HTTP client with keepalive for CDN compatibility.
    ///
    /// `pin_host` + `pinned_addrs` come from `validate_and_resolve_ipinfo_url`.
    /// When non-empty, `resolve_to_addrs` overrides reqwest's connect-time DNS
    /// lookup so the connector dials those exact pre-validated addresses.
    /// Without this, an attacker controlling authoritative DNS could flip the
    /// A record between our SSRF validation and reqwest's resolution and
    /// re-introduce the rebinding bypass closed by `validate_with_dns`.
    fn build_http_client(
        config: &DownloadConfig,
        pin_host: &str,
        pinned_addrs: &[std::net::SocketAddr],
    ) -> Result<reqwest::Client, EnrichmentError> {
        let mut builder = reqwest::Client::builder()
            // No overall timeout — we stream for as long as it takes.
            // The per-chunk read timeout is handled by tcp_keepalive + CDN behavior.
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .tcp_keepalive(Duration::from_secs(config.tcp_keepalive_secs))
            .read_timeout(Duration::from_secs(300)) // 5 min per chunk — safety net
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(1)
            // Don't let reqwest auto-decompress — we stream through our own gzip decoder
            .no_gzip()
            // SSRF: a public download URL that 302-redirects to 127.0.0.1 or
            // 169.254.169.254 would bypass our pre-fetch DNS check, since the
            // check only inspects the saved URL. We refuse reqwest-driven
            // redirects entirely; `fetch_with_validated_redirects` follows
            // 3xx responses manually so each hop re-runs the SSRF check and
            // gets a freshly pinned client for the new host.
            .redirect(reqwest::redirect::Policy::none());

        // SSRF: pin to the validated SocketAddrs. Empty slice means the URL
        // host is an IP literal — reqwest dials it directly, no override
        // needed. `resolve_to_addrs` pins the entire list at once; the
        // single-arg `resolve` would only retain the last addr per domain.
        if !pinned_addrs.is_empty() {
            builder = builder.resolve_to_addrs(pin_host, pinned_addrs);
        }

        builder.build().map_err(|e| {
            EnrichmentError::DownloadError(format!("Failed to build HTTP client: {}", e))
        })
    }

    /// GET `initial_url`, manually following up to `MAX_REDIRECTS` 3xx hops
    /// with full SSRF re-validation on every hop.
    ///
    /// reqwest's built-in redirect policy can't be used here: it would do a
    /// fresh DNS lookup for the redirect target without our rebinding-safe
    /// validation + `resolve_to_addrs` pin, re-introducing the bypass that
    /// `validate_with_dns` closes. So each hop re-runs the validator and
    /// builds a brand-new client pinned to the new host's resolved addrs.
    ///
    /// Background: IPinfo started returning 302s in May 2026 —
    /// `ipinfo.io/data/ipinfo_lite.csv.gz?token=...` redirects to a
    /// per-request signed URL on `dl.assets.ipinfo.io`.
    async fn fetch_with_validated_redirects(
        &self,
        initial_url: &str,
        config: &DownloadConfig,
    ) -> Result<reqwest::Response, EnrichmentError> {
        const MAX_REDIRECTS: usize = 5;
        let mut current_url = initial_url.to_string();
        let mut redirects_followed = 0usize;

        loop {
            let (parsed_url, pinned_addrs) =
                validate_and_resolve_ipinfo_url(&current_url).await?;
            let pin_host = parsed_url
                .host_str()
                .ok_or_else(|| EnrichmentError::DownloadError("URL missing host".to_string()))?
                .to_string();

            let client = Self::build_http_client(config, &pin_host, &pinned_addrs)?;

            let response = client
                .get(parsed_url.as_str())
                .send()
                .await
                .map_err(|e| EnrichmentError::DownloadError(format!("Request failed: {}", e)))?;

            let status = response.status();

            if status.is_redirection() {
                if redirects_followed >= MAX_REDIRECTS {
                    return Err(EnrichmentError::DownloadError(format!(
                        "Exceeded {} redirect hops while fetching enrichment data",
                        MAX_REDIRECTS
                    )));
                }

                let location_header = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| {
                        EnrichmentError::DownloadError(format!(
                            "HTTP {} redirect missing Location header",
                            status
                        ))
                    })?
                    .to_str()
                    .map_err(|e| {
                        EnrichmentError::DownloadError(format!(
                            "Location header not valid UTF-8: {}",
                            e
                        ))
                    })?
                    .to_string();

                // `Url::join` handles both absolute and relative Location
                // values per RFC 3986; the result is SSRF-validated at the
                // top of the next iteration.
                let next_url = parsed_url.join(&location_header).map_err(|e| {
                    EnrichmentError::DownloadError(format!(
                        "Could not resolve redirect target: {}",
                        e
                    ))
                })?;

                // Log hosts only — the original URL carries the IPinfo API
                // token in the query string and the redirect target carries
                // a signed `verify=` token. Hosts are enough for diagnostics.
                info!(
                    from_host = parsed_url.host_str().unwrap_or(""),
                    to_host = next_url.host_str().unwrap_or(""),
                    hop = redirects_followed + 1,
                    "Following enrichment download redirect with SSRF re-validation"
                );

                current_url = next_url.to_string();
                redirects_followed += 1;
                continue;
            }

            if !status.is_success() {
                return Err(EnrichmentError::DownloadError(format!(
                    "HTTP {}: {}",
                    status,
                    status.canonical_reason().unwrap_or("Unknown")
                )));
            }

            return Ok(response);
        }
    }

    /// Stream HTTP → gzip decode → CSV parse → batched DB insert
    ///
    /// Memory stays bounded: only one batch of records (~10k) is in memory at a time.
    /// The HTTP response, gzip decompression, and CSV parsing all happen as a single
    /// streaming pipeline — nothing is buffered to completion.
    async fn stream_and_insert_ipinfo(
        &self,
        url: &str,
        config: &DownloadConfig,
        source_id: &str,
    ) -> Result<u64, EnrichmentError> {
        const BATCH_SIZE: usize = 10_000;

        let ch = self.ch()?;

        // One run timestamp stamps every row inserted by this sync as a single
        // ReplacingMergeTree generation. After the stream completes we
        // lightweight-DELETE any CIDR for this source whose `updated_at` is
        // older than `run_ms` — i.e. CIDRs the new feed dropped. The dict's
        // argMax(updated_at) resolves a CIDR present in both generations to the
        // newest row, so correctness holds even before the async DELETE mutation
        // lands. Scoping the DELETE by source_id avoids clobbering other sources.
        let run_ms = chrono::Utc::now().timestamp_millis() as u64;

        // SSRF defense-in-depth: every hop (initial + each redirect) is
        // re-validated with DNS resolution and dialed against a freshly
        // pinned client. See `fetch_with_validated_redirects` for the
        // rebinding-bypass we're closing.
        let response = self.fetch_with_validated_redirects(url, config).await?;

        let content_length = response.content_length();
        info!(content_length = ?content_length, "Response received, starting streaming pipeline");

        // Build the streaming pipeline:
        // reqwest byte stream → StreamReader (AsyncRead) → GzipDecoder → BufReader → lines
        let byte_stream = response
            .bytes_stream()
            .map(|result| result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
        let stream_reader = StreamReader::new(byte_stream);
        let gzip_decoder = GzipDecoder::new(BufReader::new(stream_reader));
        let mut lines = BufReader::new(gzip_decoder).lines();

        let mut total_inserted = 0u64;
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let mut header_skipped = false;
        let mut line_count = 0u64;

        while let Some(line_result) = lines
            .next_line()
            .await
            .map_err(|e| EnrichmentError::ParseError(format!("Stream read error: {}", e)))?
        {
            // Skip CSV header row
            if !header_skipped {
                header_skipped = true;
                continue;
            }

            line_count += 1;

            // Parse CSV line using the csv crate to handle quoted fields correctly
            // (as_name can contain commas, e.g. "Amazon.com, Inc.")
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader(line_result.as_bytes());

            if let Some(result) = reader.deserialize::<IpInfoLiteRecord>().next() {
                let record = result.map_err(|e| {
                    EnrichmentError::ParseError(format!(
                        "CSV parse error at line {}: {}",
                        line_count, e
                    ))
                })?;
                batch.push(record);
            }

            // Flush batch when full
            if batch.len() >= BATCH_SIZE {
                let inserted =
                    Self::insert_ch_batch(ch, source_id, run_ms, &batch).await?;
                total_inserted += inserted;
                batch.clear();

                if total_inserted % 100_000 == 0 {
                    info!(total_inserted, "Streaming insert progress");
                }
            }
        }

        // Flush remaining records
        if !batch.is_empty() {
            let inserted = Self::insert_ch_batch(ch, source_id, run_ms, &batch).await?;
            total_inserted += inserted;
        }

        info!(
            total_inserted,
            "Streaming insert into ClickHouse complete"
        );

        // Empty-feed footgun: a sync that yields zero rows must NOT delete the
        // prior generation, or the dict reloads empty and all enrichment goes
        // blank. This mirrors the old PG behavior, where swap_enrichment_staging
        // only ran after a successful, non-empty stream.
        if total_inserted > 0 {
            // Lightweight delete of CIDRs the new feed dropped. Async mutation;
            // the dict's argMax keeps correctness during the brief window where
            // both generations coexist.
            // NAN-1123: `updated_at` is DateTime64(3); a raw integer in a
            // `updated_at < ?` comparison is coerced by ClickHouse as SECONDS
            // (far-future), so `< run_ms` matched every row just inserted and
            // the purge wiped the whole generation. fromUnixTimestamp64Milli
            // makes the ms scale explicit (matches the INSERT below).
            ch.query(
                "ALTER TABLE nanosiem.ip_enrichments \
                 DELETE WHERE source_id = ? AND updated_at < fromUnixTimestamp64Milli(toInt64(?))",
            )
            .bind(source_id)
            .bind(run_ms)
            .execute()
            .await?;
            info!(source_id, "Stale IP enrichment CIDRs removed (lightweight delete)");
        } else {
            warn!(
                source_id,
                "IPinfo Lite sync produced zero rows; keeping prior generation"
            );
        }

        Ok(total_inserted)
    }

    /// Insert one batch of IPinfo records into the CH payload table.
    ///
    /// Mirrors the batched multi-row INSERT pattern in
    /// `nanosiem-enterprise/src/custom_enrichment/results_store.rs`: build one
    /// `INSERT ... VALUES (?),(?),...` per chunk, falling back to per-row
    /// inserts if a chunk fails so one malformed CIDR can't sink the whole
    /// batch. `network` is inserted verbatim as a CIDR String (IP_TRIE keys on
    /// the CIDR text — do NOT convert to a CH IP type).
    async fn insert_ch_batch(
        ch: &clickhouse::Client,
        source_id: &str,
        run_ms: u64,
        records: &[IpInfoLiteRecord],
    ) -> Result<u64, EnrichmentError> {
        const CHUNK_SIZE: usize = 5000;
        // (network, source_id, country, country_code, continent, continent_code,
        //  asn, as_name, as_domain, updated_at, deleted)
        const COLUMNS: &str = "(network, source_id, country, country_code, continent, \
             continent_code, asn, as_name, as_domain, updated_at, deleted)";
        // updated_at (10th col) is DateTime64(3); wrap the bound ms value in
        // fromUnixTimestamp64Milli so storage uses the explicit ms scale that
        // the purge DELETE compares against (NAN-1123).
        const VALUE_TUPLE: &str =
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, fromUnixTimestamp64Milli(toInt64(?)), ?)";

        if records.is_empty() {
            return Ok(0);
        }

        let mut inserted = 0u64;
        for chunk in records.chunks(CHUNK_SIZE) {
            match Self::insert_ch_rows(ch, source_id, run_ms, COLUMNS, VALUE_TUPLE, chunk).await {
                Ok(()) => inserted += chunk.len() as u64,
                Err(e) => {
                    warn!(
                        chunk_size = chunk.len(),
                        error = %e,
                        "CH IP enrichment batch insert failed; retrying records individually"
                    );
                    for record in chunk {
                        match Self::insert_ch_rows(
                            ch,
                            source_id,
                            run_ms,
                            COLUMNS,
                            VALUE_TUPLE,
                            std::slice::from_ref(record),
                        )
                        .await
                        {
                            Ok(()) => inserted += 1,
                            Err(e) => {
                                warn!(network = %record.network, error = %e, "Failed to store IP enrichment record");
                            }
                        }
                    }
                }
            }
        }
        Ok(inserted)
    }

    /// Build + execute a single multi-row INSERT for `rows` (length >= 1).
    async fn insert_ch_rows(
        ch: &clickhouse::Client,
        source_id: &str,
        run_ms: u64,
        columns: &str,
        value_tuple: &str,
        rows: &[IpInfoLiteRecord],
    ) -> Result<(), clickhouse::error::Error> {
        let tuples = vec![value_tuple; rows.len()].join(", ");
        let sql = format!("INSERT INTO nanosiem.ip_enrichments {columns} VALUES {tuples}");

        let mut q = ch.query(&sql);
        for record in rows {
            q = q
                .bind(&record.network)
                .bind(source_id)
                .bind(&record.country)
                .bind(&record.country_code)
                .bind(&record.continent)
                .bind(&record.continent_code)
                .bind(&record.asn)
                .bind(&record.as_name)
                .bind(&record.as_domain)
                .bind(run_ms)
                .bind(0u8);
        }
        q.execute().await
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
        ch.query(
            "INSERT INTO nanosiem.ip_enrichments \
             (network, source_id, country, country_code, continent, continent_code, \
              asn, as_name, as_domain, updated_at, deleted) \
             SELECT network, source_id, country, country_code, continent, continent_code, \
              asn, as_name, as_domain, ?, 1 \
             FROM nanosiem.ip_enrichments \
             WHERE source_id = ? AND deleted = 0",
        )
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
    /// Uses `dictGetOrDefault` against `ip_enrichment_dict` so on-demand lookups
    /// resolve identically to ingest-time enrichment (same dict, same IP_TRIE
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
        const DICT: &str = "nanosiem.ip_enrichment_dict";
        let attr = |name: &str| -> String {
            format!(
                "if(isIPv4String(ip), \
                   dictGetOrDefault('{DICT}', '{name}', toIPv4OrDefault(ip), ''), \
                   dictGetOrDefault('{DICT}', '{name}', toIPv6OrDefault(ip), ''))"
            )
        };

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

    /// Enrich a log record with IP geolocation data
    /// Returns enrichment data for src_ip and dest_ip
    pub async fn enrich_log_ips(
        &self,
        src_ip: Option<&str>,
        dest_ip: Option<&str>,
    ) -> Result<LogEnrichment, EnrichmentError> {
        let mut enrichment = LogEnrichment::default();

        // Collect IPs to lookup
        let mut ips_to_lookup = Vec::new();
        if let Some(ip) = src_ip {
            if !ip.is_empty() {
                ips_to_lookup.push(ip);
            }
        }
        if let Some(ip) = dest_ip {
            if !ip.is_empty() && Some(ip) != src_ip {
                ips_to_lookup.push(ip);
            }
        }

        if ips_to_lookup.is_empty() {
            return Ok(enrichment);
        }

        // Bulk lookup (CH dictGet path — NAN-1117)
        let results = self.lookup_ips_bulk(&ips_to_lookup).await?;

        // Apply results
        if let Some(ip) = src_ip {
            if let Some(result) = results.get(ip) {
                enrichment.src = Some(result.clone());
            }
        }
        if let Some(ip) = dest_ip {
            if let Some(result) = results.get(ip) {
                enrichment.dest = Some(result.clone());
            }
        }

        Ok(enrichment)
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
                let count: u64 = ch
                    .query("SELECT count(DISTINCT network) FROM nanosiem.ip_enrichments WHERE deleted = 0")
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

#[cfg(test)]
mod ssrf_tests {
    //! NAN-696 regression coverage for `validate_and_resolve_ipinfo_url`.
    //!
    //! Literal-IP cases run offline; the public-hostname and DNS-rebinding
    //! reproducer cases require outbound DNS and are gated `#[ignore]` so CI
    //! on offline build hosts stays green.
    use super::*;

    #[tokio::test]
    async fn rejects_loopback_ipv4_literal() {
        let res = validate_and_resolve_ipinfo_url("http://127.0.0.1/data.csv.gz").await;
        assert!(
            matches!(res, Err(EnrichmentError::DownloadError(_))),
            "expected loopback rejection, got {res:?}"
        );
    }

    #[tokio::test]
    async fn rejects_loopback_ipv6_literal() {
        let res = validate_and_resolve_ipinfo_url("http://[::1]/data.csv.gz").await;
        assert!(matches!(res, Err(EnrichmentError::DownloadError(_))));
    }

    #[tokio::test]
    async fn rejects_aws_metadata_endpoint() {
        let res =
            validate_and_resolve_ipinfo_url("http://169.254.169.254/latest/meta-data/").await;
        assert!(matches!(res, Err(EnrichmentError::DownloadError(_))));
    }

    #[tokio::test]
    async fn rejects_metadata_hostname() {
        let res = validate_and_resolve_ipinfo_url(
            "http://metadata.google.internal/computeMetadata/v1/",
        )
        .await;
        assert!(matches!(res, Err(EnrichmentError::DownloadError(_))));
    }

    #[tokio::test]
    async fn rejects_rfc1918_literal() {
        for url in [
            "http://10.0.0.1/",
            "http://172.20.5.5/",
            "http://192.168.1.1/",
        ] {
            let res = validate_and_resolve_ipinfo_url(url).await;
            assert!(
                matches!(res, Err(EnrichmentError::DownloadError(_))),
                "{url} should be rejected; got {res:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let res = validate_and_resolve_ipinfo_url("file:///etc/passwd").await;
        assert!(matches!(res, Err(EnrichmentError::DownloadError(_))));
    }

    #[tokio::test]
    async fn returns_empty_addrs_for_public_ip_literal() {
        // Public IP literal: no DNS override needed; reqwest dials the literal
        // directly. An empty Vec signals "skip resolve_to_addrs".
        let (url, addrs) = validate_and_resolve_ipinfo_url("https://1.1.1.1/data.csv.gz")
            .await
            .expect("public IP literal should be accepted");
        assert_eq!(url.host_str(), Some("1.1.1.1"));
        assert!(
            addrs.is_empty(),
            "expected empty addrs for IP literal, got {addrs:?}"
        );
    }

    // Public DNS gate. Validates that the helper returns at least one safe
    // SocketAddr that the caller can pin via `resolve_to_addrs`. Skipped in
    // sandboxed CI without outbound DNS.
    #[tokio::test]
    #[ignore = "requires outbound DNS"]
    async fn returns_addrs_for_public_hostname() {
        let (url, addrs) = validate_and_resolve_ipinfo_url("https://ipinfo.io/data.csv.gz")
            .await
            .expect("public hostname should resolve");
        assert_eq!(url.host_str(), Some("ipinfo.io"));
        assert!(!addrs.is_empty(), "expected at least one resolved addr");
    }

    // The exact attack from the Caido session: a hostname that resolves to
    // 127.0.0.1 must be rejected, not pinned. Gated because `localtest.me`
    // resolution requires outbound DNS.
    #[tokio::test]
    #[ignore = "requires outbound DNS for localtest.me"]
    async fn rejects_hostname_resolving_to_loopback() {
        let res = validate_and_resolve_ipinfo_url("http://localtest.me/data.csv.gz").await;
        assert!(
            matches!(res, Err(EnrichmentError::DownloadError(_))),
            "expected loopback hostname rejection, got {res:?}"
        );
    }
}
