// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment sync service for downloading and loading enrichment data
//!
//! Handles:
//! - Downloading IPinfo Lite CSV data (with streaming for large files)
//! - Parsing and loading into database
//! - Scheduled daily syncs
//! - IP enrichment lookups for ingestion

use async_compression::tokio::bufread::GzipDecoder;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::RwLock;
use tracing::{info, instrument, warn};

use super::repository::{EnrichmentRepository, EnrichmentRepositoryError};
use super::types::*;
use crate::db::dual_pool::{on_cluster_clause, TableNames};
use crate::inputlookup::{SsrfError, SsrfValidator};

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

/// Row written to `nanosiem.ip_enrichments` by the IPinfo bulk loader
/// (NAN-1286). `source_id`, `updated_at`, and `deleted` are stamped
/// EXPLICITLY — never left to the table DEFAULTs (NAN-1441). Relying on
/// DEFAULTs made every retry's RowBinary blocks byte-identical to the
/// previous (failed) attempt's, so ClickHouse's Replicated insert
/// deduplication silently skipped them: the rows kept the FAILED attempt's
/// `now64()` stamp, and the post-success purge (`updated_at < run_ms`) then
/// deleted the generation the sync had just "inserted" — Saturn's
/// ip_enrichments sat at 0 rows for 15 days. Stamping `updated_at = run_ms`
/// makes each attempt's blocks content-distinct (dedup can't resurrect
/// stale stamps) and makes the purge cutoff exact by construction: this
/// generation `= run_ms`, prior generations `< run_ms` — no server-clock or
/// DEFAULT-evaluation assumptions.
///
/// `updated_at` is `i64` epoch-MILLISECONDS: the RowBinary wire format of
/// the column's `DateTime64(3)` is exactly Int64 ticks at scale 3 (the
/// crate's validation is off for this writer, so the bytes must match).
/// Owned `String`s so rows can be moved straight out of the parsed CSV
/// record.
#[derive(clickhouse::Row, serde::Serialize)]
struct IpEnrichRow {
    network: String,
    country: String,
    country_code: String,
    continent: String,
    continent_code: String,
    asn: String,
    as_name: String,
    as_domain: String,
    source_id: String,
    updated_at: i64,
    deleted: u8,
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
/// Delegates to the shared `SsrfValidator::validate_and_resolve` helper
/// (NAN-1617), which performs the validate-then-pin sequence in one place:
/// pre-flight validation, IP-literal short-circuit (returns an empty `Vec`,
/// reqwest dials the literal directly), then a re-resolve whose every address
/// is re-validated and returned for `ClientBuilder::resolve_to_addrs`. Pinning
/// closes the DNS-rebinding window between resolution and reqwest's
/// connect-time lookup.
///
/// NAN-2343: a malformed URL and a policy rejection are reported differently.
/// `SsrfError::InvalidUrl` means `Url::parse` failed — the string is not a URL
/// at all — which happens *before* any scheme, blocked-domain, IP-class or DNS
/// check runs. Attributing that to "the SSRF check" sent a customer (and us)
/// hunting a security regression over what was a malformed saved value, so the
/// configuration case gets a message that names the real problem and the
/// action. Every other variant is a genuine policy rejection and keeps the
/// SSRF wording.
async fn validate_and_resolve_ipinfo_url(
    url_str: &str,
) -> Result<(url::Url, Vec<std::net::SocketAddr>), EnrichmentError> {
    SsrfValidator::http_allowed_validator()
        .validate_and_resolve(url_str)
        .await
        .map_err(|e| match e {
            SsrfError::InvalidUrl(reason) => EnrichmentError::DownloadError(format!(
                "configured download URL is not a valid URL ({reason}) — \
                 re-enter it, including the https:// prefix"
            )),
            other => EnrichmentError::DownloadError(format!(
                "URL rejected by SSRF check before fetch: {other}"
            )),
        })
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

        // The stored URL wins; the in-process override is only a fallback for
        // deployments that configure the service directly without a row.
        //
        // NAN-2343: this precedence used to be reversed, and the override is
        // written by exactly one code path — the native configure handler —
        // and never invalidated. So once an operator had configured IPinfo on
        // that page, every later change made through the marketplace updated
        // the database and was then ignored for the rest of the process
        // lifetime, silently reappearing on the next restart. The database is
        // the surface both write paths agree on, so it is the source of truth.
        let url = match source.download_url {
            Some(url) => url,
            None => self.config.ipinfo_lite_url.clone().ok_or_else(|| {
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

            // NAN-2027: surface upstream rate-limiting distinctly (with any
            // Retry-After) instead of a generic download failure, so a genuinely
            // throttled feed reads as intentional backoff in the logs. The main
            // 429 driver — a per-cycle re-download storm from the ON CLUSTER purge
            // failing every run — is fixed by making that purge non-fatal above;
            // this keeps a rate-limited upstream legible on the hourly retry.
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
            {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .map(|r| format!(" (Retry-After: {r})"))
                    .unwrap_or_default();
                return Err(EnrichmentError::DownloadError(format!(
                    "HTTP {}: upstream throttled/unavailable{}",
                    status.as_u16(),
                    retry_after
                )));
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

    /// Download the IPinfo Lite gzip fully, then bulk-load it into ClickHouse.
    ///
    /// NAN-1286: the previous version streamed download → gzip → CSV →
    /// per-5k-row `INSERT … VALUES` (~800 round-trips). Backpressure from the
    /// insert loop held the HTTP download connection open for the whole
    /// ~59-minute load, so the CDN dropped it near the tail (`error decoding
    /// response body`) and the run raced the 60-minute stale timeout. We now
    /// (1) drain the ~24 MB gzip to memory so the connection lives only for the
    /// transfer, then (2) bulk-insert via native RowBinary in a single request.
    ///
    /// This function is IPinfo-specific: every row is stamped explicitly with
    /// `source_id`, `updated_at = run_ms`, and `deleted = 0` (NAN-1441 — see
    /// `IpEnrichRow`); the trailing purge is scoped to the same `source_id`.
    async fn stream_and_insert_ipinfo(
        &self,
        url: &str,
        config: &DownloadConfig,
        source_id: &str,
    ) -> Result<u64, EnrichmentError> {
        let ch = self.ch()?;

        // One run timestamp marks this ReplacingMergeTree generation: every
        // row of this attempt is stamped `updated_at = run_ms` EXPLICITLY.
        // Because run_ms differs per attempt, a retry's insert blocks are
        // content-distinct from a previous failed attempt's — ClickHouse's
        // Replicated insert deduplication can no longer silently keep the old
        // attempt's rows (with their OLDER stamp) in place of ours (NAN-1441:
        // that was how the sync wiped itself — the post-success purge below
        // deleted the dedup-resurrected generation it thought it had just
        // written). After a successful, non-empty load we lightweight-DELETE
        // this source's rows STRICTLY older than `run_ms` — prior
        // generations, including partial rows persisted by failed attempts.
        // The dict's argMax(updated_at) resolves a CIDR present in both
        // generations to the newest row until the purge mutation lands.
        let run_ms = chrono::Utc::now().timestamp_millis() as u64;

        // SSRF defense-in-depth: every hop (initial + each redirect) is
        // re-validated with DNS resolution and dialed against a freshly pinned
        // client. See `fetch_with_validated_redirects`.
        let response = self.fetch_with_validated_redirects(url, config).await?;
        let content_length = response.content_length();

        // Drain the whole compressed payload first so the download connection is
        // held open only for the (seconds-long) ~24 MB transfer, not the load.
        let compressed = response.bytes().await.map_err(|e| {
            EnrichmentError::DownloadError(format!("reading response body: {}", e))
        })?;
        info!(
            content_length = ?content_length,
            compressed_bytes = compressed.len(),
            "Downloaded IPinfo Lite payload; connection closed, starting bulk load"
        );

        // Bulk insert via native RowBinary in a single request. Validation off
        // so the client emits exactly IpEnrichRow's column list (with the
        // explicit source_id / updated_at / deleted stamps — NAN-1441);
        // async_insert off + wait_end_of_query so the rows are durable and
        // queryable by the time we return (the caller reloads the dict on
        // success).
        let writer = ch
            .clone()
            .with_validation(false)
            .with_option("async_insert", "0")
            .with_option("wait_end_of_query", "1");
        // Writes the LOCAL name (a Distributed table can't be a native-insert
        // target). NAN-1728: ip_enrichments is a per-shard table with an additive
        // `_distributed` wrapper; the bulk load lands on whichever shard the LB
        // pinned this connection to. The write path is deliberately left
        // per-shard (NAN-1728 M-6 / dict-source completeness is handled on the
        // foundation side); reads route through the wrapper. Single-node: the one
        // shard holds everything.
        let mut insert = writer
            .insert::<IpEnrichRow>("nanosiem.ip_enrichments")
            .await?;

        // Decompress + CSV-parse from the in-memory buffer (bounded: the native
        // insert streams its body out as we write, so we don't hold all rows).
        let decoder = GzipDecoder::new(BufReader::new(std::io::Cursor::new(compressed)));
        let mut lines = BufReader::new(decoder).lines();

        let mut total_inserted = 0u64;
        let mut skipped = 0u64;
        let mut header_skipped = false;
        let mut line_count = 0u64;

        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| EnrichmentError::ParseError(format!("gzip/CSV read error: {}", e)))?
        {
            // Skip CSV header row
            if !header_skipped {
                header_skipped = true;
                continue;
            }
            line_count += 1;

            // The csv crate handles quoted fields (as_name can contain commas,
            // e.g. "Amazon.com, Inc.").
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(false)
                .from_reader(line.as_bytes());
            match reader.deserialize::<IpInfoLiteRecord>().next() {
                Some(Ok(rec)) => {
                    // Move the parsed Strings into the row — no extra
                    // allocation for the feed fields; source_id is one small
                    // clone per row.
                    insert
                        .write(&IpEnrichRow {
                            network: rec.network,
                            country: rec.country,
                            country_code: rec.country_code,
                            continent: rec.continent,
                            continent_code: rec.continent_code,
                            asn: rec.asn,
                            as_name: rec.as_name,
                            as_domain: rec.as_domain,
                            source_id: source_id.to_string(),
                            updated_at: run_ms as i64,
                            deleted: 0,
                        })
                        .await?;
                    total_inserted += 1;
                    if total_inserted.is_multiple_of(500_000) {
                        info!(total_inserted, "Bulk insert progress");
                    }
                    // NAN-1511: cooperatively yield so this CPU-bound parse+write
                    // loop doesn't monopolize the runtime under the 1-CPU quota.
                    // Without this, the jobs liveness probe (GET /health) can't be
                    // scheduled within its timeout and kubelet kills the pod
                    // (exit 137), which re-runs the sync → crash loop.
                    if total_inserted.is_multiple_of(10_000) {
                        tokio::task::yield_now().await;
                    }
                }
                // A single malformed line shouldn't sink a multi-million-row feed.
                Some(Err(e)) => {
                    skipped += 1;
                    if skipped <= 20 {
                        warn!(line = line_count, error = %e, "Skipping malformed IPinfo row");
                    }
                }
                None => {}
            }
        }

        // Finalize the single insert request.
        insert.end().await?;

        if skipped > 0 {
            warn!(skipped, "Skipped malformed IPinfo rows during bulk load");
        }
        info!(total_inserted, "Bulk insert into ClickHouse complete");

        // Empty-feed footgun: a sync that yields zero rows must NOT delete the
        // prior generation, or the dict reloads empty and all enrichment goes
        // blank. This mirrors the old PG behavior, where swap_enrichment_staging
        // only ran after a successful, non-empty stream.
        if total_inserted > 0 {
            // Lightweight delete of the prior generation (CIDRs older than this
            // run). The cutoff is exact by construction: this attempt's rows
            // carry `updated_at = run_ms` verbatim (NAN-1441), so STRICTLY-less
            // keeps them and removes everything older — prior generations and
            // partial rows from failed attempts. Two self-wipe bugs live here;
            // both have regression coverage:
            //   * NAN-1123: `updated_at` is DateTime64(3); a RAW integer in a
            //     `updated_at < ?` comparison is coerced by ClickHouse as
            //     SECONDS (far-future), matching every row just inserted —
            //     fromUnixTimestamp64Milli keeps the ms scale explicit.
            //   * NAN-1441: when rows relied on the `now64(3)` DEFAULT, a
            //     retry's blocks were byte-identical to a failed attempt's, so
            //     Replicated insert dedup kept the OLD (pre-run_ms-stamped)
            //     rows — which this delete then removed. Explicit stamps make
            //     retry blocks distinct; dedup can't resurrect stale stamps.
            // ON CLUSTER so the stale-generation purge runs on every shard
            // (ip_enrichments is a per-shard table, NAN-1728; a bare mutation only
            // lands on the connected shard, leaving prior generations live on the
            // other shards). Empty clause on single-node → identical DDL.
            let purge_sql = format!(
                "ALTER TABLE nanosiem.ip_enrichments{on_cluster} \
                 DELETE WHERE source_id = ? AND updated_at < fromUnixTimestamp64Milli(toInt64(?))",
                on_cluster = on_cluster_clause()
            );
            // NAN-2027: the fresh generation is already inserted and the dict
            // resolves the newest row via argMax(updated_at), so a failed
            // stale-generation purge is a cosmetic bloat issue — NOT a reason to
            // fail the whole sync. Propagating this error marked the source
            // `failed` every cycle, which re-queued a full ~24 MB re-download
            // (hourly + on every restart) and eventually earned an upstream 429.
            // The `ON CLUSTER` mutation needs the CLUSTER grant on this user; where
            // that grant is missing the sync now still succeeds with fresh data,
            // and the next successful purge (once the grant lands) reclaims the
            // accumulated generations.
            match ch
                .query(&purge_sql)
                .bind(source_id)
                .bind(run_ms)
                .execute()
                .await
            {
                Ok(()) => {
                    info!(source_id, "Stale IP enrichment CIDRs removed (lightweight delete)")
                }
                Err(e) => warn!(
                    source_id,
                    error = %e,
                    "IP enrichment stale-generation purge failed; fresh data is live \
                     (dict reads newest via argMax), leaving prior generations in place (non-fatal)"
                ),
            }
        } else {
            warn!(
                source_id,
                "IPinfo Lite sync produced zero rows; keeping prior generation"
            );
        }

        Ok(total_inserted)
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
              asn, as_name, as_domain, ?, 1 \
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

#[cfg(test)]
mod ipinfo_row_shape_tests {
    //! NAN-1441 regression coverage: the IPinfo bulk loader must stamp
    //! `source_id` / `updated_at` / `deleted` EXPLICITLY in its insert column
    //! list. If any of them ever falls back to a table DEFAULT again, a
    //! retry's RowBinary blocks become byte-identical to a previous failed
    //! attempt's, Replicated insert dedup silently keeps the old
    //! (stale-stamped) rows, and the post-success purge deletes the
    //! generation the sync just "inserted" (Saturn sat at 0 enrichment rows
    //! for 15 days). The end-to-end property is exercised against a real
    //! ClickHouse in tests/ipinfo_generation_purge.rs; this guard pins the
    //! struct shape so the property can't silently regress at the source.
    use super::IpEnrichRow;
    use clickhouse::Row;

    #[test]
    fn loader_row_stamps_generation_columns_explicitly() {
        for required in ["source_id", "updated_at", "deleted"] {
            assert!(
                IpEnrichRow::COLUMN_NAMES.contains(&required),
                "IpEnrichRow no longer writes `{required}` explicitly — reverting to the \
                 table DEFAULT re-opens the NAN-1441 dedup self-wipe"
            );
        }
    }
}
