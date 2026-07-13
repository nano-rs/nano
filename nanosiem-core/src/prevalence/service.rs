// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Service
//!
//! Business logic for prevalence tracking operations including:
//! - Hash and domain prevalence queries
//! - Bulk prevalence lookups
//! - Rare artifact detection
//! - In-memory LRU caching with TTL

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client as ClickHouseClient;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use super::repository::{DictArtifactKind, PrevalenceRepository};
use super::types::*;
use crate::db::TableNames;

/// Maximum number of entries in the prevalence cache
const DEFAULT_CACHE_SIZE: usize = 10_000;

/// Maximum artifacts per bulk query
pub const MAX_BULK_ARTIFACTS: usize = 100;

/// Backend for the bounded bulk prevalence lookups (NAN-1705, D4b): the CACHE
/// dicts (fast, but negative-cache brand-new artifacts for their LIFETIME) or
/// the real-time `*_prevalence_summary` tables the dicts source from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BulkPrevalenceSource {
    Dict,
    Summary,
}

/// Cache entry with TTL
#[derive(Debug, Clone)]
struct CacheEntry {
    data: PrevalenceData,
    expires_at: DateTime<Utc>,
}

impl CacheEntry {
    fn new(data: PrevalenceData, ttl_seconds: u64) -> Self {
        Self {
            data,
            expires_at: Utc::now() + Duration::seconds(ttl_seconds as i64),
        }
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Simple LRU cache with TTL support
struct PrevalenceCache {
    entries: HashMap<String, CacheEntry>,
    max_size: usize,
    ttl_seconds: u64,
}

impl PrevalenceCache {
    fn new(max_size: usize, ttl_seconds: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            max_size,
            ttl_seconds,
        }
    }

    fn cache_key(artifact: &str, time_window: TimeWindow) -> String {
        format!("{}:{}", artifact, time_window)
    }

    fn get(&mut self, artifact: &str, time_window: TimeWindow) -> Option<PrevalenceData> {
        let key = Self::cache_key(artifact, time_window);
        if let Some(entry) = self.entries.get(&key) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
            // Remove expired entry
            self.entries.remove(&key);
        }
        None
    }

    fn insert(&mut self, artifact: &str, time_window: TimeWindow, data: PrevalenceData) {
        // Evict oldest entries if at capacity
        if self.entries.len() >= self.max_size {
            // Simple eviction: remove expired entries first
            self.entries.retain(|_, v| !v.is_expired());

            // If still at capacity, remove some entries
            if self.entries.len() >= self.max_size {
                let keys_to_remove: Vec<String> = self
                    .entries
                    .keys()
                    .take(self.max_size / 10)
                    .cloned()
                    .collect();
                for key in keys_to_remove {
                    self.entries.remove(&key);
                }
            }
        }

        let key = Self::cache_key(artifact, time_window);
        self.entries
            .insert(key, CacheEntry::new(data, self.ttl_seconds));
    }

    fn invalidate_all(&mut self) {
        self.entries.clear();
    }

    fn update_ttl(&mut self, ttl_seconds: u64) {
        self.ttl_seconds = ttl_seconds;
        // Invalidate all entries when TTL changes
        self.invalidate_all();
    }
}

/// Service for prevalence tracking operations
#[derive(Clone)]
pub struct PrevalenceService {
    repository: PrevalenceRepository,
    config: Arc<RwLock<PrevalenceConfig>>,
    cache: Arc<RwLock<PrevalenceCache>>,
}

impl PrevalenceService {
    /// Create a new PrevalenceService with a ClickHouse client
    pub fn new(client: ClickHouseClient, table_names: TableNames) -> Self {
        let config = PrevalenceConfig::default();
        Self {
            repository: PrevalenceRepository::new(client, table_names),
            cache: Arc::new(RwLock::new(PrevalenceCache::new(
                DEFAULT_CACHE_SIZE,
                config.cache_ttl_seconds,
            ))),
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Create a new PrevalenceService with custom configuration
    pub fn with_config(
        client: ClickHouseClient,
        table_names: TableNames,
        config: PrevalenceConfig,
    ) -> Self {
        Self {
            repository: PrevalenceRepository::new(client, table_names),
            cache: Arc::new(RwLock::new(PrevalenceCache::new(
                DEFAULT_CACHE_SIZE,
                config.cache_ttl_seconds,
            ))),
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Create a new PrevalenceService that loads config from PostgreSQL
    ///
    /// This constructor loads the prevalence configuration from the system_settings
    /// table in PostgreSQL, enabling hot-reload of settings.
    ///
    /// Requirement: 8.5
    pub async fn with_database_config(
        clickhouse_client: ClickHouseClient,
        table_names: TableNames,
        pg_pool: &sqlx::PgPool,
    ) -> Self {
        use super::settings::PrevalenceSettings;

        let settings = PrevalenceSettings::new(pg_pool.clone());
        let config = settings.get_config().await.unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to load prevalence config from database: {}, using defaults",
                e
            );
            PrevalenceConfig::default()
        });

        Self::with_config(clickhouse_client, table_names, config)
    }

    /// Get the current configuration
    pub async fn get_config(&self) -> PrevalenceConfig {
        self.config.read().await.clone()
    }

    /// Update the configuration (invalidates cache)
    ///
    /// This method is called when settings are changed via the API.
    /// Requirement: 8.5
    pub async fn update_config(&self, new_config: PrevalenceConfig) {
        let mut cache = self.cache.write().await;
        cache.update_ttl(new_config.cache_ttl_seconds);

        let mut config = self.config.write().await;
        *config = new_config;

        debug!("Prevalence config updated, cache invalidated");
    }

    /// Get the current rarity threshold value
    pub async fn rarity_threshold(&self) -> u64 {
        self.config.read().await.rarity_threshold
    }

    /// Query prevalence for a single hash
    #[instrument(skip(self))]
    pub async fn get_hash_prevalence(
        &self,
        hash: &str,
        time_window: TimeWindow,
    ) -> Result<PrevalenceData, PrevalenceError> {
        let config = self.config.read().await;

        if !config.enable_hash_tracking {
            return Err(PrevalenceError::TrackingDisabled("hash".to_string()));
        }

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(data) = cache.get(hash, time_window) {
                debug!("Cache hit for hash: {}", hash);
                return Ok(data);
            }
        }

        // Query ClickHouse
        let row = self
            .repository
            .get_hash_prevalence(hash, time_window)
            .await
            .map_err(PrevalenceError::ClickHouse)?;

        let data = match row {
            Some(row) => {
                PrevalenceRepository::hash_row_to_prevalence_data(row, config.rarity_threshold)
            }
            None => {
                // Return empty data for missing hash
                let artifact_type = ArtifactType::detect(hash);
                PrevalenceData::empty(hash.to_string(), artifact_type)
            }
        };

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(hash, time_window, data.clone());
        }

        Ok(data)
    }

    /// Query prevalence for a single domain
    #[instrument(skip(self))]
    pub async fn get_domain_prevalence(
        &self,
        domain: &str,
        time_window: TimeWindow,
    ) -> Result<PrevalenceData, PrevalenceError> {
        let config = self.config.read().await;

        if !config.enable_domain_tracking {
            return Err(PrevalenceError::TrackingDisabled("domain".to_string()));
        }

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(data) = cache.get(domain, time_window) {
                debug!("Cache hit for domain: {}", domain);
                return Ok(data);
            }
        }

        // Query ClickHouse
        let row = self
            .repository
            .get_domain_prevalence(domain, time_window)
            .await
            .map_err(PrevalenceError::ClickHouse)?;

        let data = match row {
            Some(row) => {
                PrevalenceRepository::domain_row_to_prevalence_data(row, config.rarity_threshold)
            }
            None => {
                // Return empty data for missing domain
                let artifact_type = ArtifactType::detect(domain);
                PrevalenceData::empty(domain.to_string(), artifact_type)
            }
        };

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(domain, time_window, data.clone());
        }

        Ok(data)
    }

    /// Query prevalence for a single IP address
    #[instrument(skip(self))]
    pub async fn get_ip_prevalence(
        &self,
        ip: &str,
        time_window: TimeWindow,
    ) -> Result<PrevalenceData, PrevalenceError> {
        let config = self.config.read().await;

        if !config.enable_ip_tracking {
            return Err(PrevalenceError::TrackingDisabled("ip".to_string()));
        }

        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(data) = cache.get(ip, time_window) {
                debug!("Cache hit for IP: {}", ip);
                return Ok(data);
            }
        }

        // Query ClickHouse
        let row = self
            .repository
            .get_ip_prevalence(ip, time_window)
            .await
            .map_err(PrevalenceError::ClickHouse)?;

        let data = match row {
            Some(row) => {
                PrevalenceRepository::ip_row_to_prevalence_data(row, config.rarity_threshold)
            }
            None => {
                // Return empty data for missing IP
                let artifact_type = ArtifactType::detect(ip);
                PrevalenceData::empty(ip.to_string(), artifact_type)
            }
        };

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(ip, time_window, data.clone());
        }

        Ok(data)
    }

    /// Bulk query prevalence for multiple artifacts
    ///
    /// Returns results for all requested artifacts (zero counts for missing).
    /// Limited to MAX_BULK_ARTIFACTS per request.
    #[instrument(skip(self, artifacts))]
    pub async fn get_bulk_prevalence(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        if artifacts.len() > MAX_BULK_ARTIFACTS {
            return Err(PrevalenceError::TooManyArtifacts {
                requested: artifacts.len(),
                max: MAX_BULK_ARTIFACTS,
            });
        }

        if artifacts.is_empty() {
            return Ok(Vec::new());
        }

        let config = self.config.read().await;
        let rarity_threshold = config.rarity_threshold;

        // Separate hashes, domains, and IPs
        let mut hashes: Vec<String> = Vec::new();
        let mut domains: Vec<String> = Vec::new();
        let mut ips: Vec<String> = Vec::new();
        let mut results: HashMap<String, PrevalenceData> = HashMap::new();

        // Check cache and categorize artifacts
        {
            let mut cache = self.cache.write().await;
            for artifact in artifacts {
                if let Some(data) = cache.get(artifact, time_window) {
                    results.insert(artifact.clone(), data);
                } else {
                    let artifact_type = ArtifactType::detect(artifact);
                    if artifact_type.is_hash() {
                        hashes.push(artifact.clone());
                    } else if artifact_type.is_domain() {
                        domains.push(artifact.clone());
                    } else if artifact_type.is_ip() {
                        ips.push(artifact.clone());
                    }
                }
            }
        }

        // Query hashes if enabled
        if config.enable_hash_tracking && !hashes.is_empty() {
            let hash_rows = self
                .repository
                .get_bulk_hash_prevalence(&hashes, time_window)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            // Track found hashes (lowercase for case-insensitive comparison)
            let found_hashes: std::collections::HashSet<String> = hash_rows
                .iter()
                .map(|r| r.file_hash.to_lowercase())
                .collect();

            // Add found hashes to results (use lowercase key for matching)
            for row in hash_rows {
                let hash_lower = row.file_hash.to_lowercase();
                let data = PrevalenceRepository::hash_row_to_prevalence_data(row, rarity_threshold);
                results.insert(hash_lower, data);
            }

            // Add empty data for missing hashes
            for hash in &hashes {
                let hash_lower = hash.to_lowercase();
                if !found_hashes.contains(&hash_lower) {
                    let artifact_type = ArtifactType::detect(hash);
                    results.insert(
                        hash_lower,
                        PrevalenceData::empty(hash.clone(), artifact_type),
                    );
                }
            }
        }

        // Query domains if enabled
        if config.enable_domain_tracking && !domains.is_empty() {
            let domain_rows = self
                .repository
                .get_bulk_domain_prevalence(&domains, time_window)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            // Domain storage is MV-lowercased, so `row.domain` is already
            // lowercase; key everything lowercase so mixed-case inputs like
            // `Accounts.Google.com` both MATCH a found row and get a correctly
            // keyed empty fallback (audit P9). The final result lookup lowercases
            // the input, so an empty keyed on the verbatim case would be lost.
            let found_domains: std::collections::HashSet<String> =
                domain_rows.iter().map(|r| r.domain.to_lowercase()).collect();

            // Add found domains to results
            for row in domain_rows {
                let domain = row.domain.to_lowercase();
                let data =
                    PrevalenceRepository::domain_row_to_prevalence_data(row, rarity_threshold);
                results.insert(domain, data);
            }

            // Add empty data for missing domains
            for domain in &domains {
                let domain_lower = domain.to_lowercase();
                if !found_domains.contains(&domain_lower) {
                    let artifact_type = ArtifactType::detect(domain);
                    results.insert(
                        domain_lower,
                        PrevalenceData::empty(domain.clone(), artifact_type),
                    );
                }
            }
        }

        // Query IPs if enabled
        if config.enable_ip_tracking && !ips.is_empty() {
            let ip_rows = self
                .repository
                .get_bulk_ip_prevalence(&ips, time_window)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            let found_ips: std::collections::HashSet<String> =
                ip_rows.iter().map(|r| r.ip.clone()).collect();

            // Add found IPs to results
            for row in ip_rows {
                let ip = row.ip.clone();
                let data = PrevalenceRepository::ip_row_to_prevalence_data(row, rarity_threshold);
                results.insert(ip, data);
            }

            // Add empty data for missing IPs
            for ip in &ips {
                if !found_ips.contains(ip) {
                    let artifact_type = ArtifactType::detect(ip);
                    results.insert(ip.clone(), PrevalenceData::empty(ip.clone(), artifact_type));
                }
            }
        }

        // Update cache with new results
        {
            let mut cache = self.cache.write().await;
            for (artifact, data) in &results {
                cache.insert(artifact, time_window, data.clone());
            }
        }

        // Return results in the same order as input (use lowercase for matching)
        Ok(artifacts
            .iter()
            .filter_map(|a| results.remove(&a.to_lowercase()))
            .collect())
    }

    /// Bulk prevalence lookup via the loaded ClickHouse dictionaries — same
    /// dict pattern the JOIN path uses (`prevalence_join.rs:457-505`).
    ///
    /// Faster than `get_bulk_prevalence`: dict lookups against in-RAM data
    /// instead of `uniqMerge` aggregations against `*_prevalence_agg`. No
    /// chunking is required at the SQL level (single `arrayJoin([...])`
    /// per artifact kind handles any reasonable size).
    ///
    /// Returned `PrevalenceData.artifact` is lowercase for hash/domain and
    /// raw for IP — callers should lowercase hash/domain values when
    /// looking up in the resulting map. Tracking-disabled artifact kinds
    /// are silently skipped (no entries returned for that kind).
    #[instrument(skip(self, artifacts))]
    pub async fn get_bulk_prevalence_via_dict(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        self.get_bulk_prevalence_bounded(artifacts, time_window, BulkPrevalenceSource::Dict)
            .await
    }

    /// NAN-1705 (D4b): bulk prevalence lookup straight from the real-time
    /// `*_prevalence_summary` tables — the dicts' own source data, bypassing the
    /// CACHE dicts' negative caching. Used by the in-memory prevalence filter to
    /// rescue dict-missed artifacts (a brand-new artifact is negative-cached for
    /// the dict LIFETIME — 15–30 min — while the summary already carries it at
    /// its real host_count). Same contract as the dict source: common
    /// (`host_count >= 1000`) and out-of-window entities return no row.
    ///
    /// Same result shape and cache behavior as [`Self::get_bulk_prevalence_via_dict`].
    #[instrument(skip(self, artifacts))]
    pub async fn get_bulk_summary_prevalence(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        self.get_bulk_prevalence_bounded(artifacts, time_window, BulkPrevalenceSource::Summary)
            .await
    }

    /// Shared body for the two bounded bulk lookups above — identical cache
    /// handling, kind detection, tracking gates, and result shaping; only the
    /// repository call differs (dict vs summary).
    async fn get_bulk_prevalence_bounded(
        &self,
        artifacts: &[String],
        time_window: TimeWindow,
        source: BulkPrevalenceSource,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }

        let config = self.config.read().await;
        let rarity_threshold = config.rarity_threshold;

        let mut hashes: Vec<String> = Vec::new();
        let mut domains: Vec<String> = Vec::new();
        let mut ips: Vec<String> = Vec::new();
        let mut results: Vec<PrevalenceData> = Vec::new();

        // Cache check + categorize misses by kind. We use the cache key as-is
        // (caller's input case) so subsequent lookups by the same value hit.
        {
            let mut cache = self.cache.write().await;
            for artifact in artifacts {
                if let Some(data) = cache.get(artifact, time_window) {
                    results.push(data);
                    continue;
                }
                match ArtifactType::detect(artifact) {
                    t if t.is_hash() => hashes.push(artifact.clone()),
                    t if t.is_domain() => domains.push(artifact.clone()),
                    t if t.is_ip() => ips.push(artifact.clone()),
                    _ => {}
                }
            }
        }

        // Helper to lift a DictPrevalenceRow into a PrevalenceData. The
        // artifact_type is recovered from the artifact value — the dict
        // doesn't store it.
        let to_data = |row: super::repository::DictPrevalenceRow| PrevalenceData {
            artifact_type: ArtifactType::detect(&row.artifact),
            host_count: row.host_count,
            total_occurrences: row.total_occurrences,
            first_seen: PrevalenceRepository::micros_to_datetime(row.first_seen),
            last_seen: PrevalenceRepository::micros_to_datetime(row.last_seen),
            is_rare: row.host_count < rarity_threshold,
            prevalence_score: PrevalenceRepository::calculate_prevalence_score(
                row.host_count,
                rarity_threshold,
            ),
            artifact: row.artifact,
        };

        let fetch = |kind_artifacts: Vec<String>, kind: DictArtifactKind| async move {
            match source {
                BulkPrevalenceSource::Dict => {
                    self.repository
                        .get_bulk_prevalence_via_dict(&kind_artifacts, kind, time_window)
                        .await
                }
                BulkPrevalenceSource::Summary => {
                    self.repository
                        .get_bulk_summary_prevalence(&kind_artifacts, kind, time_window)
                        .await
                }
            }
        };

        if config.enable_hash_tracking && !hashes.is_empty() {
            let rows = fetch(hashes, DictArtifactKind::Hash)
                .await
                .map_err(PrevalenceError::ClickHouse)?;
            for row in rows {
                results.push(to_data(row));
            }
        }

        if config.enable_domain_tracking && !domains.is_empty() {
            let rows = fetch(domains, DictArtifactKind::Domain)
                .await
                .map_err(PrevalenceError::ClickHouse)?;
            for row in rows {
                results.push(to_data(row));
            }
        }

        if config.enable_ip_tracking && !ips.is_empty() {
            let rows = fetch(ips, DictArtifactKind::Ip)
                .await
                .map_err(PrevalenceError::ClickHouse)?;
            for row in rows {
                results.push(to_data(row));
            }
        }

        // Populate cache with newly fetched entries.
        {
            let mut cache = self.cache.write().await;
            for data in &results {
                cache.insert(&data.artifact, time_window, data.clone());
            }
        }

        Ok(results)
    }

    /// Get list of rare artifacts (below threshold)
    #[instrument(skip(self))]
    pub async fn get_rare_artifacts(
        &self,
        artifact_type: Option<ArtifactType>,
        time_window: TimeWindow,
        limit: i64,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        let config = self.config.read().await;
        let rarity_threshold = config.rarity_threshold;
        let mut results = Vec::new();

        // Get rare hashes if requested or no filter
        let include_hashes = artifact_type.map_or(true, |t| t.is_hash());
        if include_hashes && config.enable_hash_tracking {
            let hash_rows = self
                .repository
                .get_rare_hashes(rarity_threshold, time_window, limit)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            for row in hash_rows {
                results.push(PrevalenceRepository::hash_row_to_prevalence_data(
                    row,
                    rarity_threshold,
                ));
            }
        }

        // Get rare domains if requested or no filter
        let include_domains = artifact_type.map_or(true, |t| t.is_domain());
        if include_domains && config.enable_domain_tracking {
            let domain_rows = self
                .repository
                .get_rare_domains(rarity_threshold, time_window, limit)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            for row in domain_rows {
                results.push(PrevalenceRepository::domain_row_to_prevalence_data(
                    row,
                    rarity_threshold,
                ));
            }
        }

        // Get rare IPs if requested or no filter. NAN-1762 lifted the NAN-1729
        // <=7d IP window gate: `get_rare_ips` now reads the pre-finalized
        // `ip_prevalence_final` via `argMax` (no `uniqMerge`) under a
        // memory-bounded GROUP BY, so 30d is viable without the shared-CH OOM
        // the gate guarded against.
        let include_ips = artifact_type.map_or(true, |t| t.is_ip());
        if include_ips && config.enable_ip_tracking {
            let ip_rows = self
                .repository
                .get_rare_ips(rarity_threshold, time_window, limit)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            for row in ip_rows {
                results.push(PrevalenceRepository::ip_row_to_prevalence_data(
                    row,
                    rarity_threshold,
                ));
            }
        }

        // Sort by last_seen descending and limit
        results.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        results.truncate(limit as usize);

        Ok(results)
    }

    /// Get newly seen artifacts (first_seen within time range)
    #[instrument(skip(self))]
    pub async fn get_new_artifacts(
        &self,
        artifact_type: Option<ArtifactType>,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<PrevalenceData>, PrevalenceError> {
        let config = self.config.read().await;
        let rarity_threshold = config.rarity_threshold;
        let mut results = Vec::new();

        // Get new hashes if requested or no filter
        let include_hashes = artifact_type.map_or(true, |t| t.is_hash());
        if include_hashes && config.enable_hash_tracking {
            let hash_rows = self
                .repository
                .get_new_hashes(since, limit)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            for row in hash_rows {
                results.push(PrevalenceRepository::hash_row_to_prevalence_data(
                    row,
                    rarity_threshold,
                ));
            }
        }

        // Get new domains if requested or no filter
        let include_domains = artifact_type.map_or(true, |t| t.is_domain());
        if include_domains && config.enable_domain_tracking {
            let domain_rows = self
                .repository
                .get_new_domains(since, limit)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            for row in domain_rows {
                results.push(PrevalenceRepository::domain_row_to_prevalence_data(
                    row,
                    rarity_threshold,
                ));
            }
        }

        // Get new IPs if requested or no filter. NAN-1762 lifted the NAN-1729
        // <=7d IP window gate — `get_new_ips` reads the pre-finalized
        // `ip_prevalence_final` via `argMax` under a memory-bounded GROUP BY, so
        // an arbitrarily-old `since` (up to the 30d TTL horizon) is viable.
        let include_ips = artifact_type.map_or(true, |t| t.is_ip());
        if include_ips && config.enable_ip_tracking {
            let ip_rows = self
                .repository
                .get_new_ips(since, limit)
                .await
                .map_err(PrevalenceError::ClickHouse)?;

            for row in ip_rows {
                results.push(PrevalenceRepository::ip_row_to_prevalence_data(
                    row,
                    rarity_threshold,
                ));
            }
        }

        // Sort by first_seen descending and limit
        results.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));
        results.truncate(limit as usize);

        Ok(results)
    }

    /// Get artifact explorer data with daily breakdowns
    #[instrument(skip(self))]
    pub async fn get_artifact_explorer(
        &self,
        artifact_type: Option<ArtifactType>,
        time_window: TimeWindow,
        risk_filter: Option<&str>,
        search: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<ArtifactExplorerResponse, PrevalenceError> {
        let config = self.config.read().await;
        let rarity_threshold = config.rarity_threshold;

        // Determine which artifact types to query
        let include_hashes = artifact_type.map_or(true, |t| t.is_hash());
        let include_domains = artifact_type.map_or(true, |t| t.is_domain());
        let include_ips = artifact_type.map_or(true, |t| t.is_ip());

        // Search filtering and cross-type merging still happen in memory after fetch.
        // Keep a larger buffer in those cases so pagination doesn't hide valid results.
        let base_fetch = limit + offset + 1;
        let fetch_limit = if search.is_some_and(|s| !s.is_empty()) || artifact_type.is_none() {
            base_fetch * 2
        } else {
            ((base_fetch as f64) * 1.2).ceil() as i64 + 10
        };

        // Fetch aggregate data for all types concurrently
        let (hash_results, domain_results, ip_results) = tokio::join!(
            async {
                if include_hashes && config.enable_hash_tracking {
                    match risk_filter {
                        Some("rare") => self
                            .repository
                            .get_rare_hashes(rarity_threshold, time_window, fetch_limit)
                            .await
                            .map(|rows| {
                                rows.into_iter()
                                    .map(|r| {
                                        PrevalenceRepository::hash_row_to_prevalence_data(
                                            r,
                                            rarity_threshold,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        Some("new") => {
                            let since = Utc::now() - Duration::hours(24);
                            self.repository
                                .get_new_hashes(since, fetch_limit)
                                .await
                                .map(|rows| {
                                    rows.into_iter()
                                        .map(|r| {
                                            PrevalenceRepository::hash_row_to_prevalence_data(
                                                r,
                                                rarity_threshold,
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                })
                        }
                        _ => self
                            .repository
                            // Default lane = "all artifacts active in the window",
                            // NOT "rare-ish". `rarity_threshold * 1000` silently
                            // dropped any artifact seen on ≥ threshold×1000 hosts
                            // (the most common ones) and made the headline totals
                            // undercount them (audit P10). `u64::MAX` keeps the
                            // get_rare code path (host_count < threshold + recency)
                            // while admitting every host_count.
                            .get_rare_hashes(u64::MAX, time_window, fetch_limit)
                            .await
                            .map(|rows| {
                                rows.into_iter()
                                    .map(|r| {
                                        PrevalenceRepository::hash_row_to_prevalence_data(
                                            r,
                                            rarity_threshold,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                    }
                } else {
                    Ok(Vec::new())
                }
            },
            async {
                if include_domains && config.enable_domain_tracking {
                    match risk_filter {
                        Some("rare") => self
                            .repository
                            .get_rare_domains(rarity_threshold, time_window, fetch_limit)
                            .await
                            .map(|rows| {
                                rows.into_iter()
                                    .map(|r| {
                                        PrevalenceRepository::domain_row_to_prevalence_data(
                                            r,
                                            rarity_threshold,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        Some("new") => {
                            let since = Utc::now() - Duration::hours(24);
                            self.repository
                                .get_new_domains(since, fetch_limit)
                                .await
                                .map(|rows| {
                                    rows.into_iter()
                                        .map(|r| {
                                            PrevalenceRepository::domain_row_to_prevalence_data(
                                                r,
                                                rarity_threshold,
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                })
                        }
                        _ => self
                            .repository
                            // See hash lane above — admit every host_count (P10).
                            .get_rare_domains(u64::MAX, time_window, fetch_limit)
                            .await
                            .map(|rows| {
                                rows.into_iter()
                                    .map(|r| {
                                        PrevalenceRepository::domain_row_to_prevalence_data(
                                            r,
                                            rarity_threshold,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                    }
                } else {
                    Ok(Vec::new())
                }
            },
            async {
                if include_ips && config.enable_ip_tracking {
                    match risk_filter {
                        Some("rare") => self
                            .repository
                            .get_rare_ips(rarity_threshold, time_window, fetch_limit)
                            .await
                            .map(|rows| {
                                rows.into_iter()
                                    .map(|r| {
                                        PrevalenceRepository::ip_row_to_prevalence_data(
                                            r,
                                            rarity_threshold,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        Some("new") => {
                            let since = Utc::now() - Duration::hours(24);
                            self.repository
                                .get_new_ips(since, fetch_limit)
                                .await
                                .map(|rows| {
                                    rows.into_iter()
                                        .map(|r| {
                                            PrevalenceRepository::ip_row_to_prevalence_data(
                                                r,
                                                rarity_threshold,
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                })
                        }
                        _ => self
                            .repository
                            // See hash lane above — admit every host_count (P10).
                            .get_rare_ips(u64::MAX, time_window, fetch_limit)
                            .await
                            .map(|rows| {
                                rows.into_iter()
                                    .map(|r| {
                                        PrevalenceRepository::ip_row_to_prevalence_data(
                                            r,
                                            rarity_threshold,
                                        )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                    }
                } else {
                    Ok(Vec::new())
                }
            }
        );

        let hash_vec = hash_results.map_err(PrevalenceError::ClickHouse)?;
        let domain_vec = domain_results.map_err(PrevalenceError::ClickHouse)?;
        let ip_vec = ip_results.map_err(PrevalenceError::ClickHouse)?;

        // P6: each per-type fetch is bounded by `fetch_limit`. If any of them
        // came back full, that type was truncated, so the headline counts below
        // (total/rare/new/high_risk) are FLOORS, not true totals — flag them so
        // the UI renders `N+` instead of a confident under-count. A true
        // count(distinct) would re-pay the expensive uniqMerge aggregation
        // (NAN-1664), and analysts don't need exactness here — only honesty.
        let counts_approximate = (hash_vec.len() as i64) >= fetch_limit
            || (domain_vec.len() as i64) >= fetch_limit
            || (ip_vec.len() as i64) >= fetch_limit;

        let mut all_artifacts: Vec<PrevalenceData> = Vec::new();
        all_artifacts.extend(hash_vec);
        all_artifacts.extend(domain_vec);
        all_artifacts.extend(ip_vec);

        // Apply search filter
        if let Some(search_term) = search {
            if !search_term.is_empty() {
                let term = search_term.to_lowercase();
                all_artifacts.retain(|a| a.artifact.to_lowercase().contains(&term));
            }
        }

        // Sort by last_seen descending
        all_artifacts.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        // Calculate counts from the full result set (before pagination)
        let now = Utc::now();
        let twenty_four_hours_ago = now - Duration::hours(24);
        let rare_count = all_artifacts.iter().filter(|a| a.is_rare).count();
        let new_count = all_artifacts
            .iter()
            .filter(|a| a.first_seen >= twenty_four_hours_ago)
            .count();
        let high_risk_asset_count = all_artifacts
            .iter()
            .filter(|a| a.is_rare && a.last_seen >= twenty_four_hours_ago)
            .count();

        let total = all_artifacts.len();
        let has_more = total > (offset + limit) as usize;

        // Apply pagination
        let paginated: Vec<PrevalenceData> = all_artifacts
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        // Fetch daily breakdowns for the paginated artifacts
        let mut hash_artifacts: Vec<String> = Vec::new();
        let mut domain_artifacts: Vec<String> = Vec::new();
        let mut ip_artifacts: Vec<String> = Vec::new();

        for a in &paginated {
            if a.artifact_type.is_hash() {
                hash_artifacts.push(a.artifact.clone());
            } else if a.artifact_type.is_domain() {
                domain_artifacts.push(a.artifact.clone());
            } else if a.artifact_type.is_ip() {
                ip_artifacts.push(a.artifact.clone());
            }
        }

        // The prevalence heatmap renders a fixed 30-day historical view, so
        // we always fetch 30 days of daily counts regardless of the requested
        // `time_window` for the artifact aggregation above. The wire saving
        // comes from the packed-array shape, not from narrowing the window.
        let daily_window = TimeWindow::ThirtyDays;
        let n_days: usize = 30;

        let (hash_daily, domain_daily, ip_daily) = tokio::join!(
            self.repository
                .get_hash_daily_counts(&hash_artifacts, daily_window),
            self.repository
                .get_domain_daily_counts(&domain_artifacts, daily_window),
            self.repository
                .get_ip_daily_counts(&ip_artifacts, daily_window),
        );

        // Build a sparse {artifact → {day → count}} map from the daily rows,
        // then expand into dense `Vec<u64>` of length `n_days` keyed by the
        // span [daily_start, today]. Zero-filling lives server-side so the
        // frontend can read the array by index without date arithmetic per
        // cell.
        let mut daily_map: HashMap<String, HashMap<String, u64>> = HashMap::new();

        if let Ok(rows) = hash_daily {
            for row in rows {
                daily_map
                    .entry(row.file_hash.to_lowercase())
                    .or_default()
                    .insert(row.day, row.daily_count);
            }
        }
        if let Ok(rows) = domain_daily {
            for row in rows {
                daily_map
                    .entry(row.domain.clone())
                    .or_default()
                    .insert(row.day, row.daily_count);
            }
        }
        if let Ok(rows) = ip_daily {
            for row in rows {
                daily_map
                    .entry(row.ip.clone())
                    .or_default()
                    .insert(row.day, row.daily_count);
            }
        }

        // Precompute the span of `n_days` ending today (in YYYY-MM-DD).
        let today = Utc::now().date_naive();
        let span_start = today - chrono::Duration::days((n_days as i64) - 1);
        let day_keys: Vec<String> = (0..n_days)
            .map(|i| {
                (span_start + chrono::Duration::days(i as i64))
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .collect();
        let daily_start = day_keys.first().cloned().unwrap_or_default();

        // Convert to explorer items, expanding each artifact's sparse map into
        // a dense Vec aligned to `day_keys`.
        let artifacts: Vec<ArtifactExplorerItem> = paginated
            .into_iter()
            .map(|data| {
                let key = if data.artifact_type.is_hash() {
                    data.artifact.to_lowercase()
                } else {
                    data.artifact.clone()
                };
                let sparse = daily_map.remove(&key).unwrap_or_default();
                let packed: Vec<u64> = day_keys
                    .iter()
                    .map(|d| sparse.get(d).copied().unwrap_or(0))
                    .collect();
                ArtifactExplorerItem::from_prevalence_data(data, packed, daily_start.clone())
            })
            .collect();

        Ok(ArtifactExplorerResponse {
            artifacts,
            total,
            limit,
            offset,
            has_more,
            rarity_threshold,
            rare_count,
            new_count,
            high_risk_asset_count,
            counts_approximate,
        })
    }

    /// Get detailed context for a single artifact from the logs table
    ///
    /// `scope` is the caller's source-scope (NAN-1801) — the handler composes
    /// it from `effective_source_deny_set()` (per-source RBAC ∪ audit unless
    /// `audit:view`) and the repository ANDs it into every raw-logs sub-query.
    #[instrument(skip(self, scope))]
    pub async fn get_artifact_detail(
        &self,
        artifact: &str,
        artifact_type: &ArtifactType,
        logs_table: &str,
        scope: &crate::auth::ScopeSet,
        time_window: TimeWindow,
    ) -> Result<ArtifactDetailResponse, PrevalenceError> {
        // Resolve the active schema profile so the repository's raw-SQL detail
        // queries target the right physical columns (UDM byte-identical; OCSF
        // promoted columns). The service struct holds no profile, so read the
        // env-configured one here (NAN-1241).
        let profile = crate::schema::active_profile_from_env()
            .map_err(|e| PrevalenceError::Config(format!("schema profile: {e}")))?;
        self.repository
            .get_artifact_detail(
                artifact,
                artifact_type,
                logs_table,
                profile.as_ref(),
                scope,
                time_window,
            )
            .await
            .map_err(PrevalenceError::ClickHouse)
    }

    /// Enrich a batch of explorer items with inline-subtitle context
    /// (top file_name, top process_name + is_wrapper, user_count, top
    /// source_type). Mutates the `context` field on each item in-place.
    ///
    /// Single-batch design: one CH pass per artifact-type bucket, so cost
    /// is bounded regardless of page size. Empty input is a no-op.
    ///
    /// `scope` is the caller's source-scope (NAN-1801) — AND-ed into every
    /// bucket query so `top_source_type` / counts never reflect denied sources.
    pub async fn enrich_explorer_items(
        &self,
        items: &mut [ArtifactExplorerItem],
        logs_table: &str,
        scope: &crate::auth::ScopeSet,
        time_window: TimeWindow,
    ) {
        if items.is_empty() {
            return;
        }

        let mut hash_artifacts = Vec::new();
        let mut ip_artifacts = Vec::new();
        let mut domain_artifacts = Vec::new();
        for item in items.iter() {
            if item.artifact_type.is_hash() {
                hash_artifacts.push(item.artifact.to_lowercase());
            } else if item.artifact_type.is_ip() {
                ip_artifacts.push(item.artifact.clone());
            } else if item.artifact_type.is_domain() {
                domain_artifacts.push(item.artifact.clone());
            }
        }

        // Active schema profile for column resolution (NAN-1241). This is a
        // best-effort enrichment path with no Result channel; a malformed
        // profile env already fails fast at boot, so fall back to the UDM
        // profile (byte-identical default) on the unreachable error case.
        let profile = crate::schema::active_profile_from_env().unwrap_or_else(|_| {
            crate::schema::profile_for_id(crate::schema::SchemaId::Udm)
        });

        let ctx_map = self
            .repository
            .bulk_artifact_inline_context(
                &hash_artifacts,
                &ip_artifacts,
                &domain_artifacts,
                logs_table,
                profile.as_ref(),
                scope,
                time_window,
            )
            .await;

        for item in items.iter_mut() {
            let key = if item.artifact_type.is_hash() {
                item.artifact.to_lowercase()
            } else {
                item.artifact.clone()
            };
            if let Some(ctx) = ctx_map.get(&key) {
                item.context = Some(ctx.clone());
            }
        }
    }

    /// Get scatter plot data for a set of artifacts
    #[instrument(skip(self, hashes, domains, ips))]
    pub async fn get_scatter_data(
        &self,
        hashes: &[String],
        domains: &[String],
        ips: &[String],
        time_window: TimeWindow,
    ) -> Result<PrevalenceScatterData, PrevalenceError> {
        // Snapshot the config values we need and release the guard *before*
        // the concurrent fetches — get_bulk_prevalence re-acquires config.read()
        // internally, and holding an outer read guard across a queued writer
        // would deadlock tokio's write-preferring RwLock.
        let (enable_hash, enable_domain, enable_ip, rarity_threshold) = {
            let config = self.config.read().await;
            (
                config.enable_hash_tracking,
                config.enable_domain_tracking,
                config.enable_ip_tracking,
                config.rarity_threshold,
            )
        };

        // NAN-1699: the scatter looks up prevalence for a BOUNDED set of specific
        // artifacts pulled from the search results, and must return ALL of them —
        // including common ones — so the chart can render them (faded) and the
        // host-count slider can filter on real counts. The dict path
        // (`get_bulk_prevalence_via_dict`, NAN-1691 P2-C) ends with
        // `WHERE host_count_masked < 9999`, which silently DROPS every
        // masked-common artifact: a 2000-host binary came back empty, so the
        // frontend fabricated a rare-on-0-hosts "new to env" dot. Use the
        // agg-based bulk lookup instead — bounded `file_hash IN (…)`, so it's
        // fast — which returns real host_count + real env-first-seen for every
        // requested artifact. (The `| prevalence` command keeps the dict path.)
        // Still fetch the three kinds concurrently so tab-open latency is
        // max(kind), not sum(kind).
        let (hash_res, domain_res, ip_res) = tokio::join!(
            async {
                if !hashes.is_empty() && enable_hash {
                    self.get_bulk_prevalence(hashes, time_window).await
                } else {
                    Ok(Vec::new())
                }
            },
            async {
                if !domains.is_empty() && enable_domain {
                    self.get_bulk_prevalence(domains, time_window).await
                } else {
                    Ok(Vec::new())
                }
            },
            async {
                if !ips.is_empty() && enable_ip {
                    self.get_bulk_prevalence(ips, time_window).await
                } else {
                    Ok(Vec::new())
                }
            },
        );

        let hash_points: Vec<PrevalenceScatterPoint> = hash_res?
            .into_iter()
            .map(PrevalenceScatterPoint::from)
            .collect();
        let domain_points: Vec<PrevalenceScatterPoint> = domain_res?
            .into_iter()
            .map(PrevalenceScatterPoint::from)
            .collect();
        let ip_points: Vec<PrevalenceScatterPoint> = ip_res?
            .into_iter()
            .map(PrevalenceScatterPoint::from)
            .collect();

        Ok(PrevalenceScatterData {
            hash_points,
            domain_points,
            ip_points,
            rarity_threshold,
        })
    }
}

/// Errors that can occur in prevalence operations
#[derive(Debug, thiserror::Error)]
pub enum PrevalenceError {
    #[error("ClickHouse error: {0}")]
    ClickHouse(#[from] clickhouse::error::Error),

    #[error("Prevalence tracking for {0} is disabled")]
    TrackingDisabled(String),

    #[error("Too many artifacts requested: {requested} (max: {max})")]
    TooManyArtifacts { requested: usize, max: usize },

    #[error("Invalid artifact: {0}")]
    InvalidArtifact(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_expiration() {
        let data = PrevalenceData::empty("test".to_string(), ArtifactType::HashMd5);
        let entry = CacheEntry::new(data, 0); // 0 second TTL
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_entry_not_expired() {
        let data = PrevalenceData::empty("test".to_string(), ArtifactType::HashMd5);
        let entry = CacheEntry::new(data, 3600); // 1 hour TTL
        assert!(!entry.is_expired());
    }
}
