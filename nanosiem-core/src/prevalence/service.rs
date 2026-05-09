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

    /// Reload configuration from the database
    ///
    /// This method reloads the configuration from PostgreSQL, enabling
    /// hot-reload of settings without service restart.
    ///
    /// Requirement: 8.5
    pub async fn reload_config(&self, pg_pool: &sqlx::PgPool) -> Result<(), PrevalenceError> {
        use super::settings::PrevalenceSettings;

        let settings = PrevalenceSettings::new(pg_pool.clone());
        let new_config = settings.get_config().await.map_err(|e| {
            PrevalenceError::InvalidArtifact(format!("Failed to load config: {}", e))
        })?;

        self.update_config(new_config).await;
        debug!("Prevalence config reloaded from database");
        Ok(())
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

            let found_domains: std::collections::HashSet<String> =
                domain_rows.iter().map(|r| r.domain.clone()).collect();

            // Add found domains to results
            for row in domain_rows {
                let domain = row.domain.clone();
                let data =
                    PrevalenceRepository::domain_row_to_prevalence_data(row, rarity_threshold);
                results.insert(domain, data);
            }

            // Add empty data for missing domains
            for domain in &domains {
                if !found_domains.contains(domain) {
                    let artifact_type = ArtifactType::detect(domain);
                    results.insert(
                        domain.clone(),
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

        if config.enable_hash_tracking && !hashes.is_empty() {
            let rows = self
                .repository
                .get_bulk_prevalence_via_dict(&hashes, DictArtifactKind::Hash, time_window)
                .await
                .map_err(PrevalenceError::ClickHouse)?;
            for row in rows {
                results.push(to_data(row));
            }
        }

        if config.enable_domain_tracking && !domains.is_empty() {
            let rows = self
                .repository
                .get_bulk_prevalence_via_dict(&domains, DictArtifactKind::Domain, time_window)
                .await
                .map_err(PrevalenceError::ClickHouse)?;
            for row in rows {
                results.push(to_data(row));
            }
        }

        if config.enable_ip_tracking && !ips.is_empty() {
            let rows = self
                .repository
                .get_bulk_prevalence_via_dict(&ips, DictArtifactKind::Ip, time_window)
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

        // Get rare IPs if requested or no filter
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

        // Get new IPs if requested or no filter
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
                            .get_rare_hashes(rarity_threshold * 1000, time_window, fetch_limit) // High threshold = get all
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
                            .get_rare_domains(rarity_threshold * 1000, time_window, fetch_limit)
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
                            .get_rare_ips(rarity_threshold * 1000, time_window, fetch_limit)
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

        let mut all_artifacts: Vec<PrevalenceData> = Vec::new();
        all_artifacts.extend(hash_results.map_err(PrevalenceError::ClickHouse)?);
        all_artifacts.extend(domain_results.map_err(PrevalenceError::ClickHouse)?);
        all_artifacts.extend(ip_results.map_err(PrevalenceError::ClickHouse)?);

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

        // The prevalence UI renders a fixed historical heatmap/sparkline window.
        // Keep daily counts at 30 days until the frontend is made window-aware.
        let daily_window = TimeWindow::ThirtyDays;
        let (hash_daily, domain_daily, ip_daily) = tokio::join!(
            self.repository
                .get_hash_daily_counts(&hash_artifacts, daily_window),
            self.repository
                .get_domain_daily_counts(&domain_artifacts, daily_window),
            self.repository
                .get_ip_daily_counts(&ip_artifacts, daily_window),
        );

        // Build daily counts lookup maps
        let mut daily_map: HashMap<String, Vec<ArtifactDailyCount>> = HashMap::new();

        if let Ok(rows) = hash_daily {
            for row in rows {
                daily_map
                    .entry(row.file_hash.to_lowercase())
                    .or_default()
                    .push(ArtifactDailyCount {
                        date: row.day,
                        count: row.daily_count,
                    });
            }
        }
        if let Ok(rows) = domain_daily {
            for row in rows {
                daily_map
                    .entry(row.domain.clone())
                    .or_default()
                    .push(ArtifactDailyCount {
                        date: row.day,
                        count: row.daily_count,
                    });
            }
        }
        if let Ok(rows) = ip_daily {
            for row in rows {
                daily_map
                    .entry(row.ip.clone())
                    .or_default()
                    .push(ArtifactDailyCount {
                        date: row.day,
                        count: row.daily_count,
                    });
            }
        }

        // Convert to explorer items
        let artifacts: Vec<ArtifactExplorerItem> = paginated
            .into_iter()
            .map(|data| {
                let key = if data.artifact_type.is_hash() {
                    data.artifact.to_lowercase()
                } else {
                    data.artifact.clone()
                };
                let daily_counts = daily_map.remove(&key).unwrap_or_default();
                ArtifactExplorerItem::from_prevalence_data(data, daily_counts)
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
        })
    }

    /// Get detailed context for a single artifact from the logs table
    #[instrument(skip(self))]
    pub async fn get_artifact_detail(
        &self,
        artifact: &str,
        artifact_type: &ArtifactType,
        logs_table: &str,
        time_window: TimeWindow,
    ) -> Result<ArtifactDetailResponse, PrevalenceError> {
        self.repository
            .get_artifact_detail(artifact, artifact_type, logs_table, time_window)
            .await
            .map_err(PrevalenceError::ClickHouse)
    }

    /// Extract parent domain from a subdomain
    ///
    /// Examples:
    /// - "evil.example.com" → Some("example.com")
    /// - "sub.evil.example.com" → Some("example.com")
    /// - "example.com" → None (already a root domain)
    /// - "192.168.1.1" → None (IP address)
    /// - "localhost" → None (single label)
    pub fn extract_parent_domain(domain: &str) -> Option<String> {
        // Check if it's an IP address
        if domain.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        let parts: Vec<&str> = domain.split('.').collect();

        // Need at least 3 parts for a subdomain (sub.example.com)
        if parts.len() < 3 {
            return None;
        }

        // Handle common TLDs (simplified - a full implementation would use a TLD list)
        let tld_count = if parts.len() >= 2 {
            let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            // Common two-part TLDs
            if matches!(
                last_two.as_str(),
                "co.uk"
                    | "co.jp"
                    | "co.nz"
                    | "co.za"
                    | "com.au"
                    | "com.br"
                    | "org.uk"
                    | "net.au"
                    | "gov.uk"
                    | "ac.uk"
                    | "edu.au"
            ) {
                2
            } else {
                1
            }
        } else {
            1
        };

        // Calculate how many parts make up the parent domain
        let parent_parts = tld_count + 1;

        if parts.len() <= parent_parts {
            return None;
        }

        // Extract parent domain
        let parent = parts[parts.len() - parent_parts..].join(".");
        Some(parent)
    }

    /// Get prevalence for both a domain and its parent domain
    #[instrument(skip(self))]
    pub async fn get_domain_with_parent_prevalence(
        &self,
        domain: &str,
        time_window: TimeWindow,
    ) -> Result<(PrevalenceData, Option<PrevalenceData>), PrevalenceError> {
        let domain_data = self.get_domain_prevalence(domain, time_window).await?;

        let parent_data = if let Some(parent) = Self::extract_parent_domain(domain) {
            Some(self.get_domain_prevalence(&parent, time_window).await?)
        } else {
            None
        };

        Ok((domain_data, parent_data))
    }

    /// Invalidate all cached prevalence data
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.invalidate_all();
        debug!("Prevalence cache invalidated");
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
        let config = self.config.read().await;

        // Get hash prevalence data
        let hash_points: Vec<PrevalenceScatterPoint> =
            if !hashes.is_empty() && config.enable_hash_tracking {
                self.get_bulk_prevalence(hashes, time_window)
                    .await?
                    .into_iter()
                    .map(PrevalenceScatterPoint::from)
                    .collect()
            } else {
                Vec::new()
            };

        // Get domain prevalence data
        let domain_points: Vec<PrevalenceScatterPoint> =
            if !domains.is_empty() && config.enable_domain_tracking {
                self.get_bulk_prevalence(domains, time_window)
                    .await?
                    .into_iter()
                    .map(PrevalenceScatterPoint::from)
                    .collect()
            } else {
                Vec::new()
            };

        // Get IP prevalence data
        let ip_points: Vec<PrevalenceScatterPoint> = if !ips.is_empty() && config.enable_ip_tracking
        {
            self.get_bulk_prevalence(ips, time_window)
                .await?
                .into_iter()
                .map(PrevalenceScatterPoint::from)
                .collect()
        } else {
            Vec::new()
        };

        Ok(PrevalenceScatterData {
            hash_points,
            domain_points,
            ip_points,
            rarity_threshold: config.rarity_threshold,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_parent_domain_subdomain() {
        assert_eq!(
            PrevalenceService::extract_parent_domain("evil.example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_parent_domain_deep_subdomain() {
        assert_eq!(
            PrevalenceService::extract_parent_domain("sub.evil.example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_parent_domain_root() {
        assert_eq!(
            PrevalenceService::extract_parent_domain("example.com"),
            None
        );
    }

    #[test]
    fn test_extract_parent_domain_ip() {
        assert_eq!(
            PrevalenceService::extract_parent_domain("192.168.1.1"),
            None
        );
    }

    #[test]
    fn test_extract_parent_domain_single_label() {
        assert_eq!(PrevalenceService::extract_parent_domain("localhost"), None);
    }

    #[test]
    fn test_extract_parent_domain_two_part_tld() {
        assert_eq!(
            PrevalenceService::extract_parent_domain("evil.example.co.uk"),
            Some("example.co.uk".to_string())
        );
    }

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
