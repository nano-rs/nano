// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment auto-sync scheduler
//!
//! Runs background tasks to automatically sync enrichment sources
//! based on their configured schedules.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use super::repository::EnrichmentRepository;
use super::service::EnrichmentService;
use super::types::SyncStatus;
use crate::settings::DeveloperSettingsRepository;

/// Configuration for the enrichment scheduler
#[derive(Debug, Clone)]
pub struct EnrichmentSchedulerConfig {
    /// How often to check for sources that need syncing (seconds)
    pub check_interval_secs: u64,
    /// Default sync interval for sources without explicit config (hours)
    pub default_sync_interval_hours: u64,
    /// How long a sync can be "in_progress" before we consider it stale (minutes)
    pub stale_sync_timeout_minutes: i64,
    /// Minimum time between sync attempts after a failure (minutes)
    pub failure_cooldown_minutes: i64,
    /// How often to run IOC cleanup (hours)
    pub ioc_cleanup_interval_hours: u64,
}

impl Default for EnrichmentSchedulerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 300,        // Check every 5 minutes
            default_sync_interval_hours: 24, // Daily sync by default
            stale_sync_timeout_minutes: 60, // Consider in_progress stale after 60 min (IPinfo can take 45+ min)
            failure_cooldown_minutes: 60,   // Wait 1 hour after failure before retry
            ioc_cleanup_interval_hours: 1,  // Cleanup expired IOCs every hour
        }
    }
}

/// Enrichment scheduler for automatic syncing
pub struct EnrichmentScheduler {
    service: Arc<RwLock<EnrichmentService>>,
    repository: EnrichmentRepository,
    config: EnrichmentSchedulerConfig,
    developer_settings: Option<DeveloperSettingsRepository>,
    clickhouse_client: Option<clickhouse::Client>,
    /// Track which sources are currently syncing to prevent overlapping syncs
    running: RwLock<HashMap<String, DateTime<Utc>>>,
}

impl EnrichmentScheduler {
    /// Create a new enrichment scheduler
    pub fn new(
        service: Arc<RwLock<EnrichmentService>>,
        repository: EnrichmentRepository,
        config: EnrichmentSchedulerConfig,
    ) -> Self {
        Self {
            service,
            repository,
            config,
            developer_settings: None,
            clickhouse_client: None,
            running: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults(
        service: Arc<RwLock<EnrichmentService>>,
        repository: EnrichmentRepository,
    ) -> Self {
        Self::new(service, repository, EnrichmentSchedulerConfig::default())
    }

    /// Set the PostgreSQL pool for developer settings (optional)
    pub fn with_pg_pool(mut self, pool: PgPool) -> Self {
        self.developer_settings = Some(DeveloperSettingsRepository::new(pool));
        self
    }

    /// Set the ClickHouse client for dictionary reloads after sync
    pub fn with_clickhouse(mut self, client: clickhouse::Client) -> Self {
        self.clickhouse_client = Some(client);
        self
    }

    /// Check if a source needs syncing based on its configuration
    fn needs_sync(&self, source: &super::types::EnrichmentSource) -> bool {
        // Skip disabled sources
        if !source.enabled {
            return false;
        }

        // Check if sync is already in progress
        if source.last_sync_status == Some("in_progress".to_string()) {
            // Check if it's been in_progress for too long (stale)
            if let Some(updated_at) = Some(source.updated_at) {
                let minutes_since_update = (Utc::now() - updated_at).num_minutes();
                if minutes_since_update < self.config.stale_sync_timeout_minutes {
                    info!(
                        source_id = %source.id,
                        minutes_in_progress = minutes_since_update,
                        "Sync already in progress, skipping"
                    );
                    return false;
                } else {
                    warn!(
                        source_id = %source.id,
                        minutes_in_progress = minutes_since_update,
                        "Sync has been in_progress for too long, will reset and retry"
                    );
                    // Fall through to allow sync - the sync function will reset the status
                }
            } else {
                return false;
            }
        }

        // Check if last sync failed - apply cooldown
        if source.last_sync_status == Some("failed".to_string()) {
            if let Some(updated_at) = Some(source.updated_at) {
                let minutes_since_failure = (Utc::now() - updated_at).num_minutes();
                if minutes_since_failure < self.config.failure_cooldown_minutes {
                    info!(
                        source_id = %source.id,
                        minutes_since_failure = minutes_since_failure,
                        cooldown_minutes = self.config.failure_cooldown_minutes,
                        "In failure cooldown period, skipping"
                    );
                    return false;
                }
            }
        }

        // Get sync interval from config, or use default
        let sync_interval_hours = source
            .config
            .get("sync_interval_hours")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.config.default_sync_interval_hours);

        // 'pending' status means a manual sync was requested — always honor it
        if source.last_sync_status == Some("pending".to_string()) {
            info!(source_id = %source.id, "Manual sync requested (pending status)");
            return true;
        }

        // Check if auto-sync is explicitly disabled
        let auto_sync_enabled = source
            .config
            .get("auto_sync_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false); // Default to disabled for safety

        if !auto_sync_enabled {
            return false;
        }

        // For IPinfo, check if we have a download URL configured
        // For IOC feeds, we use API endpoints from config
        if source.source_type == "ipinfo_lite" && source.download_url.is_none() {
            return false;
        }

        // Check last sync time
        match source.last_sync_at {
            None => true, // Never synced, needs sync
            Some(last_sync) => {
                let hours_since_sync = (Utc::now() - last_sync).num_hours();
                hours_since_sync >= sync_interval_hours as i64
            }
        }
    }

    /// Reset a stale in_progress status to failed
    async fn reset_stale_sync(
        &self,
        source_id: &str,
    ) -> Result<(), super::service::EnrichmentError> {
        warn!(source_id = %source_id, "Resetting stale in_progress sync to failed");
        self.repository
            .update_sync_status(
                source_id,
                SyncStatus::Failed,
                Some("Sync was interrupted or timed out"),
                None,
                None,
            )
            .await?;
        Ok(())
    }

    /// Run a single check iteration
    #[instrument(skip(self))]
    pub async fn check_and_sync(&self) -> Result<Vec<String>, super::service::EnrichmentError> {
        // Check if enrichment sync scheduler is enabled
        if let Some(ref settings_repo) = self.developer_settings {
            match settings_repo.is_enrichment_sync_scheduler_enabled().await {
                Ok(false) => {
                    debug!("Enrichment sync scheduler disabled, skipping sync check");
                    return Ok(Vec::new());
                }
                Err(e) => {
                    warn!(
                        "Failed to check enrichment sync scheduler enabled status: {}",
                        e
                    );
                    // Continue on error (fail-open)
                }
                Ok(true) => {}
            }
        }

        info!("Checking enrichment sources for sync...");
        let sources = self.repository.list_sources().await?;
        info!(source_count = sources.len(), "Found enrichment sources");
        let mut synced = Vec::new();

        for source in sources {
            info!(
                source_id = %source.id,
                enabled = source.enabled,
                has_url = source.download_url.is_some(),
                last_sync = ?source.last_sync_at,
                last_status = ?source.last_sync_status,
                "Checking source"
            );

            // Check for stale in_progress and reset if needed
            if source.last_sync_status == Some("in_progress".to_string()) {
                let minutes_since_update = (Utc::now() - source.updated_at).num_minutes();
                if minutes_since_update >= self.config.stale_sync_timeout_minutes {
                    if let Err(e) = self.reset_stale_sync(&source.id).await {
                        warn!(source_id = %source.id, error = %e, "Failed to reset stale sync");
                    }
                    // Skip this iteration, will retry on next check
                    continue;
                }
            }

            if self.needs_sync(&source) {
                // Atomically check-and-insert into running guard to prevent overlapping syncs
                {
                    use std::collections::hash_map::Entry;
                    let mut running = self.running.write().await;
                    match running.entry(source.id.clone()) {
                        Entry::Occupied(_) => {
                            info!(
                                source_id = %source.id,
                                "Sync already running in this process, skipping"
                            );
                            continue;
                        }
                        Entry::Vacant(e) => {
                            e.insert(Utc::now());
                        }
                    }
                }

                info!(source_id = %source.id, source_type = %source.source_type, "Source needs sync, starting...");

                let service = self.service.read().await;
                let result = match source.source_type.as_str() {
                    "ipinfo_lite" => service.sync_ipinfo_lite().await,
                    "ioc_feed" => {
                        // Route to appropriate IOC feed based on source ID
                        match source.id.as_str() {
                            "threatfox" => service.sync_threatfox().await,
                            "tor_exit_nodes" => service.sync_tor_exit_nodes().await,
                            _ => {
                                info!(source_id = %source.id, "Unknown IOC feed source, skipping");
                                self.running.write().await.remove(&source.id);
                                continue;
                            }
                        }
                    }
                    _ => {
                        info!(source_id = %source.id, source_type = %source.source_type, "Unknown source type, skipping");
                        self.running.write().await.remove(&source.id);
                        continue;
                    }
                };

                match result {
                    Ok(sync_result) => {
                        if sync_result.success {
                            info!(
                                source_id = %source.id,
                                records = sync_result.records_loaded,
                                duration_ms = sync_result.duration_ms,
                                "Auto-sync completed successfully"
                            );
                            // Reload the relevant ClickHouse dictionary
                            if let Some(ref ch) = self.clickhouse_client {
                                let dict_name = match source.source_type.as_str() {
                                    "ipinfo_lite" => Some("nanosiem.ip_enrichment_dict"),
                                    "ioc_feed" => Some("nanosiem.ioc_enrichment_dict"),
                                    _ => None,
                                };
                                if let Some(dict) = dict_name {
                                    match ch
                                        .query(&format!("SYSTEM RELOAD DICTIONARY {}", dict))
                                        .execute()
                                        .await
                                    {
                                        Ok(_) => info!(
                                            dictionary = dict,
                                            "Reloaded dictionary after auto-sync"
                                        ),
                                        Err(e) => {
                                            warn!(dictionary = dict, error = %e, "Failed to reload dictionary after auto-sync")
                                        }
                                    }
                                }
                            }
                            synced.push(source.id.clone());
                        } else {
                            warn!(
                                source_id = %source.id,
                                error = ?sync_result.error,
                                "Auto-sync failed"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            source_id = %source.id,
                            error = %e,
                            "Auto-sync error"
                        );
                        // Make sure we mark it as failed so cooldown applies
                        let _ = self
                            .repository
                            .update_sync_status(
                                &source.id,
                                SyncStatus::Failed,
                                Some(&e.to_string()),
                                None,
                                None,
                            )
                            .await;
                    }
                }

                // Remove from running guard
                {
                    let mut running = self.running.write().await;
                    running.remove(&source.id);
                }
            } else {
                info!(source_id = %source.id, "Source does not need sync");
            }
        }

        // Run IOC cleanup
        let service = self.service.read().await;
        match service.cleanup_expired_iocs().await {
            Ok(deleted) if deleted > 0 => {
                info!(deleted_count = deleted, "Cleaned up expired IOCs");
            }
            Err(e) => {
                warn!(error = %e, "Failed to cleanup expired IOCs");
            }
            _ => {}
        }

        Ok(synced)
    }

    /// Run the scheduler loop
    pub async fn run_loop(&self) {
        info!(
            check_interval_secs = self.config.check_interval_secs,
            default_sync_hours = self.config.default_sync_interval_hours,
            stale_timeout_mins = self.config.stale_sync_timeout_minutes,
            failure_cooldown_mins = self.config.failure_cooldown_minutes,
            "Starting enrichment auto-sync scheduler"
        );

        // Skip initial sync on startup - let the scheduler handle it on the regular interval
        // This prevents blocking startup with a potentially long sync operation
        info!(
            "Enrichment scheduler started, first check in {} seconds",
            self.config.check_interval_secs
        );

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            self.config.check_interval_secs,
        ));
        interval.tick().await; // First tick is immediate, skip it

        let mut consecutive_errors: u32 = 0;
        const MAX_BACKOFF_SECS: u64 = 900; // 15 minutes max backoff

        loop {
            interval.tick().await;

            match self.check_and_sync().await {
                Ok(synced) => {
                    consecutive_errors = 0;
                    if !synced.is_empty() {
                        info!(synced_sources = ?synced, "Auto-sync check completed");
                    }
                }
                Err(e) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    let backoff_secs = std::cmp::min(
                        (2_u64)
                            .saturating_pow(consecutive_errors)
                            .saturating_mul(self.config.check_interval_secs),
                        MAX_BACKOFF_SECS,
                    );
                    warn!(
                        error = %e,
                        attempt = consecutive_errors,
                        backoff_secs = backoff_secs,
                        "Auto-sync check failed, backing off"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                }
            }
        }
    }

    /// Start the scheduler as a background task
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run_loop().await;
        })
    }
}

/// Get the next scheduled sync time for a source
pub fn get_next_sync_time(
    source: &super::types::EnrichmentSource,
    default_hours: u64,
) -> Option<DateTime<Utc>> {
    if !source.enabled {
        return None;
    }

    let auto_sync_enabled = source
        .config
        .get("auto_sync_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if !auto_sync_enabled {
        return None;
    }

    let sync_interval_hours = source
        .config
        .get("sync_interval_hours")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_hours);

    match source.last_sync_at {
        None => Some(Utc::now()), // Needs sync now
        Some(last_sync) => {
            let next = last_sync + chrono::Duration::hours(sync_interval_hours as i64);
            // If next sync time is in the past, it means we're overdue - return now
            if next < Utc::now() {
                Some(Utc::now())
            } else {
                Some(next)
            }
        }
    }
}
