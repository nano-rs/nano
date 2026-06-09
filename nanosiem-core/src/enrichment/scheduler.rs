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

    /// Check if a source needs syncing based on its configuration.
    ///
    /// Thin wrapper over the pure [`source_needs_sync`] so the decision logic can
    /// be unit-tested without a DB-backed scheduler.
    fn needs_sync(&self, source: &super::types::EnrichmentSource) -> bool {
        source_needs_sync(source, &self.config, Utc::now())
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
                    // NAN-1112: the `ioc_feed` source_type (ThreatFox + Tor
                    // exit nodes) was sunset entirely. The legacy engine
                    // methods + PG `ioc_enrichments` table + the orphan
                    // `enrichment_sources` rows are gone. IOC enrichment
                    // is now Deno-only via the marketplace path; reads
                    // are served by `enrichment::ioc::lookup_ioc_all_sources`
                    // against CH `custom_enrichment_results`.
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

        // NAN-1112: legacy IOC cleanup was a PG `DELETE FROM ioc_enrichments
        // WHERE expires_at < now()` against the now-deleted table. The
        // marketplace path stores IOCs in CH `custom_enrichment_results`
        // with a 30-day TTL enforced by the table's own TTL clause —
        // no application-side cleanup needed. The `cleanup_expired_iocs`
        // service method was deleted with the rest of the engine.

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

        // NAN-1280: reconcile syncs orphaned by a restart before the loop. A
        // sync that was interrupted (e.g. a deploy aborted the fire-and-forget
        // task) leaves `last_sync_status = 'in_progress'` in Postgres forever;
        // re-queue those to `pending` so the first check below picks them up
        // immediately instead of waiting out the ~2h stale + cooldown windows.
        match self.repository.reset_interrupted_syncs().await {
            Ok(ids) if !ids.is_empty() => {
                warn!(
                    reset_sources = ?ids,
                    "Re-queued enrichment syncs orphaned by a previous restart"
                );
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Failed to reconcile interrupted enrichment syncs"),
        }

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

/// Pure decision logic behind [`EnrichmentScheduler::needs_sync`].
///
/// Factored out (DB-free, `now` injected) so it can be unit-tested without a
/// scheduler instance. Mirrors the free-function style of [`get_next_sync_time`].
fn source_needs_sync(
    source: &super::types::EnrichmentSource,
    config: &EnrichmentSchedulerConfig,
    now: DateTime<Utc>,
) -> bool {
    // Skip disabled sources
    if !source.enabled {
        return false;
    }

    // Check if sync is already in progress
    if source.last_sync_status == Some("in_progress".to_string()) {
        // Check if it's been in_progress for too long (stale)
        let minutes_since_update = (now - source.updated_at).num_minutes();
        if minutes_since_update < config.stale_sync_timeout_minutes {
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
    }

    // Check if last sync failed - apply cooldown
    if source.last_sync_status == Some("failed".to_string()) {
        let minutes_since_failure = (now - source.updated_at).num_minutes();
        if minutes_since_failure < config.failure_cooldown_minutes {
            info!(
                source_id = %source.id,
                minutes_since_failure = minutes_since_failure,
                cooldown_minutes = config.failure_cooldown_minutes,
                "In failure cooldown period, skipping"
            );
            return false;
        }
    }

    // Get sync interval from config, or use default
    let sync_interval_hours = source
        .config
        .get("sync_interval_hours")
        .and_then(|v| v.as_u64())
        .unwrap_or(config.default_sync_interval_hours);

    // 'pending' status means a manual sync was requested — always honor it
    if source.last_sync_status == Some("pending".to_string()) {
        info!(source_id = %source.id, "Manual sync requested (pending status)");
        return true;
    }

    // Check if auto-sync is explicitly disabled.
    // NAN-1279: default to ENABLED for an unset flag, matching the two read
    // paths the UI relies on (`get_auto_sync_config` and `get_next_sync_time`,
    // both `unwrap_or(true)`). When this defaulted to false, a source with the
    // empty `{}` config (the default state) showed "auto-sync on / next sync
    // at…" in the UI while the scheduler silently never ran it — so an
    // interrupted sync (deploy aborts the fire-and-forget task → stuck
    // `in_progress`) would stale-reset to `failed` and then never retry,
    // stalling permanently. The global developer-settings scheduler gate and
    // the per-source `enabled` column remain the real master switches.
    let auto_sync_enabled = source
        .config
        .get("auto_sync_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

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
            let hours_since_sync = (now - last_sync).num_hours();
            hours_since_sync >= sync_interval_hours as i64
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `now` reference for deterministic timing in tests.
    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    /// Build an enrichment source fixture. `last_sync_at`/`updated_at` are given
    /// as offsets in hours/minutes from `now`.
    #[allow(clippy::too_many_arguments)]
    fn source(
        config: serde_json::Value,
        enabled: bool,
        last_sync_status: Option<&str>,
        last_sync_at_hours_ago: Option<i64>,
        updated_at_minutes_ago: i64,
    ) -> super::super::types::EnrichmentSource {
        let n = now();
        super::super::types::EnrichmentSource {
            id: "ipinfo_lite".to_string(),
            name: "IPinfo Lite".to_string(),
            source_type: "ipinfo_lite".to_string(),
            description: None,
            download_url: Some("https://ipinfo.io/data/ipinfo_lite.csv.gz?token=x".to_string()),
            last_sync_at: last_sync_at_hours_ago.map(|h| n - chrono::Duration::hours(h)),
            last_sync_status: last_sync_status.map(|s| s.to_string()),
            last_sync_error: None,
            record_count: 0,
            deprovisioned_count: 0,
            file_hash: None,
            config,
            enabled,
            created_at: n,
            updated_at: n - chrono::Duration::minutes(updated_at_minutes_ago),
        }
    }

    // NAN-1279: the core regression. An enabled source with the default empty
    // `{}` config that is overdue MUST be picked up by the scheduler. Before the
    // fix `needs_sync` defaulted auto-sync to false here, so it silently never
    // ran while the UI showed it enabled.
    #[test]
    fn empty_config_overdue_source_needs_sync() {
        let cfg = EnrichmentSchedulerConfig::default();
        let s = source(json!({}), true, Some("success"), Some(48), 60 * 48);
        assert!(source_needs_sync(&s, &cfg, now()));
    }

    // The three default sites must agree: get_next_sync_time (read path) returns
    // Some for the same empty-config source it would for needs_sync == true.
    #[test]
    fn empty_config_defaults_match_read_path() {
        let cfg = EnrichmentSchedulerConfig::default();
        let s = source(json!({}), true, Some("success"), Some(48), 60 * 48);
        assert!(source_needs_sync(&s, &cfg, now()));
        assert!(get_next_sync_time(&s, cfg.default_sync_interval_hours).is_some());
    }

    #[test]
    fn never_synced_empty_config_needs_sync() {
        let cfg = EnrichmentSchedulerConfig::default();
        let s = source(json!({}), true, None, None, 0);
        assert!(source_needs_sync(&s, &cfg, now()));
    }

    #[test]
    fn explicit_disable_is_respected() {
        let cfg = EnrichmentSchedulerConfig::default();
        let s = source(json!({"auto_sync_enabled": false}), true, Some("success"), Some(48), 60 * 48);
        assert!(!source_needs_sync(&s, &cfg, now()));
    }

    #[test]
    fn disabled_source_never_syncs() {
        let cfg = EnrichmentSchedulerConfig::default();
        let s = source(json!({"auto_sync_enabled": true}), false, Some("success"), Some(48), 60 * 48);
        assert!(!source_needs_sync(&s, &cfg, now()));
    }

    #[test]
    fn recently_synced_source_is_not_due() {
        let cfg = EnrichmentSchedulerConfig::default();
        // Synced 1h ago, 24h interval → not due yet.
        let s = source(json!({}), true, Some("success"), Some(1), 60);
        assert!(!source_needs_sync(&s, &cfg, now()));
    }

    #[test]
    fn in_progress_within_timeout_is_skipped_but_stale_falls_through() {
        let cfg = EnrichmentSchedulerConfig::default();
        // Fresh in_progress (10 min) → skip.
        let fresh = source(json!({}), true, Some("in_progress"), Some(48), 10);
        assert!(!source_needs_sync(&fresh, &cfg, now()));
        // Stale in_progress (well past stale timeout) + overdue → eligible again.
        let stale = source(json!({}), true, Some("in_progress"), Some(48), 60 * 48);
        assert!(source_needs_sync(&stale, &cfg, now()));
    }

    #[test]
    fn failed_source_respects_then_clears_cooldown() {
        let cfg = EnrichmentSchedulerConfig::default();
        // Failed 10 min ago, cooldown 60 min → still cooling down.
        let cooling = source(json!({}), true, Some("failed"), Some(48), 10);
        assert!(!source_needs_sync(&cooling, &cfg, now()));
        // Failed well past cooldown + overdue → retry.
        let cooled = source(json!({}), true, Some("failed"), Some(48), 60 * 48);
        assert!(source_needs_sync(&cooled, &cfg, now()));
    }

    #[test]
    fn ipinfo_without_download_url_is_skipped() {
        let cfg = EnrichmentSchedulerConfig::default();
        let mut s = source(json!({}), true, Some("success"), Some(48), 60 * 48);
        s.download_url = None;
        assert!(!source_needs_sync(&s, &cfg, now()));
    }
}
