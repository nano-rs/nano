// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity sync scheduler
//!
//! Background task that periodically checks identity providers
//! and triggers syncs based on their configured intervals.

use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

use super::service::IdentitySyncService;
use super::types::IdentityProvider;

/// Configuration for the identity sync scheduler
#[derive(Debug, Clone)]
pub struct IdentitySyncSchedulerConfig {
    /// How often to check for providers that need syncing (seconds)
    pub check_interval_secs: u64,
    /// Default sync interval for providers without explicit config (hours)
    pub default_sync_interval_hours: u64,
    /// How long a sync can be "in_progress" before we consider it stale (minutes)
    pub stale_sync_timeout_minutes: i64,
    /// Minimum time between sync attempts after a failure (minutes)
    pub failure_cooldown_minutes: i64,
    /// NAN-1151: how many sync intervals an account may go unseen before the
    /// staleness reconciler tombstones it. Must be ≥2 so a still-active account
    /// (whose latest landed sync is ≤1 interval old) is never false-deleted
    /// while an in-flight async-lane emit is still settling.
    pub staleness_multiplier: u64,
}

impl Default for IdentitySyncSchedulerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 60,
            default_sync_interval_hours: 6,
            stale_sync_timeout_minutes: 30,
            failure_cooldown_minutes: 30,
            staleness_multiplier: 3,
        }
    }
}

/// Staleness cutoff: accounts whose latest `last_synced_at` is older than this
/// are considered deprovisioned. Pure (testable) — `multiplier` is clamped to
/// ≥2 so a misconfigured `1` can't collapse the safety margin and false-delete
/// active accounts whose async-lane emit hasn't landed yet.
fn staleness_cutoff(
    now: chrono::DateTime<Utc>,
    sync_interval_hours: u64,
    multiplier: u64,
) -> chrono::DateTime<Utc> {
    let mult = multiplier.max(2);
    now - chrono::Duration::hours((sync_interval_hours.max(1) * mult) as i64)
}

pub struct IdentitySyncScheduler {
    service: Arc<IdentitySyncService>,
    config: IdentitySyncSchedulerConfig,
}

impl IdentitySyncScheduler {
    pub fn new(service: Arc<IdentitySyncService>, config: IdentitySyncSchedulerConfig) -> Self {
        Self { service, config }
    }

    pub fn with_defaults(service: Arc<IdentitySyncService>) -> Self {
        Self::new(service, IdentitySyncSchedulerConfig::default())
    }

    /// Run the scheduler loop. Should be spawned as a background task.
    pub async fn run(&self) {
        info!(
            check_interval_secs = self.config.check_interval_secs,
            "Identity sync scheduler started"
        );

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(
                self.config.check_interval_secs,
            ))
            .await;

            if let Err(e) = self.check_and_sync().await {
                warn!(error = %e, "Identity sync scheduler error");
            }
        }
    }

    #[instrument(skip(self))]
    async fn check_and_sync(&self) -> Result<(), super::service::IdentityServiceError> {
        let providers = self.service.list_providers().await?;
        debug!(
            provider_count = providers.len(),
            "Checking identity providers for sync"
        );

        for provider in providers {
            if self.needs_sync(&provider) {
                info!(provider_id = %provider.id, "Triggering scheduled sync");
                match self.service.sync_provider(&provider.id).await {
                    Ok(result) => {
                        info!(
                            provider_id = %provider.id,
                            users_synced = result.users_synced,
                            duration_ms = result.duration_ms,
                            "Scheduled sync completed"
                        );
                    }
                    Err(e) => {
                        warn!(
                            provider_id = %provider.id,
                            error = %e,
                            "Scheduled sync failed"
                        );
                    }
                }
            }
            // NAN-1151: staleness reconciliation runs independently of the sync
            // trigger above — deprovisioning is now "not seen in N intervals",
            // not "not in this sync", so it must not be gated on needs_sync.
            self.reconcile_provider(&provider).await;
        }
        Ok(())
    }

    /// Age out directory accounts a pull provider hasn't re-synced within its
    /// staleness window. No-op for AD (push-based, external cadence), disabled/
    /// credential-less providers, and providers that have never synced.
    async fn reconcile_provider(&self, provider: &IdentityProvider) {
        if !provider.enabled
            || !provider.has_credentials()
            || provider.provider_type == "active_directory"
            || provider.last_sync_at.is_none()
        {
            return;
        }
        let cutoff = staleness_cutoff(
            Utc::now(),
            self.sync_interval_hours(provider),
            self.config.staleness_multiplier,
        );
        if let Err(e) = self.service.reconcile_stale_users(&provider.id, cutoff).await {
            warn!(provider_id = %provider.id, error = %e, "Staleness reconciliation failed");
        }
    }

    /// Per-provider sync interval (hours), falling back to the scheduler default.
    fn sync_interval_hours(&self, provider: &IdentityProvider) -> u64 {
        provider
            .config
            .as_ref()
            .and_then(|c| c.get("sync_interval_hours"))
            .and_then(|v| v.as_u64())
            .unwrap_or(self.config.default_sync_interval_hours)
    }

    fn needs_sync(&self, provider: &IdentityProvider) -> bool {
        // Skip disabled providers
        if !provider.enabled {
            return false;
        }

        // Skip providers without credentials
        if !provider.has_credentials() {
            return false;
        }

        // Skip AD providers (push-based, not pull)
        if provider.provider_type == "active_directory" {
            return false;
        }

        // Check if sync is already in progress
        if provider.sync_status.as_deref() == Some("in_progress") {
            if let Some(updated_at) = Some(provider.updated_at) {
                let minutes = (Utc::now() - updated_at).num_minutes();
                if minutes < self.config.stale_sync_timeout_minutes {
                    return false;
                }
                // Stale sync — allow retry
                warn!(
                    provider_id = %provider.id,
                    minutes_in_progress = minutes,
                    "Sync appears stale, will allow retry"
                );
            } else {
                return false;
            }
        }

        // Failure cooldown
        if provider.sync_status.as_deref() == Some("failed") {
            let minutes = (Utc::now() - provider.updated_at).num_minutes();
            if minutes < self.config.failure_cooldown_minutes {
                return false;
            }
        }

        // Get sync interval from config
        let sync_interval_hours = self.sync_interval_hours(provider);

        // Check last sync time
        match provider.last_sync_at {
            None => true,
            Some(last_sync) => {
                let hours_since = (Utc::now() - last_sync).num_hours();
                hours_since >= sync_interval_hours as i64
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::staleness_cutoff;
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn staleness_cutoff_is_interval_times_multiplier() {
        let now = Utc.timestamp_opt(1_717_000_000, 0).unwrap();
        // 6h interval × 3 = 18h window.
        assert_eq!(staleness_cutoff(now, 6, 3), now - Duration::hours(18));
    }

    #[test]
    fn staleness_cutoff_clamps_multiplier_to_two() {
        // A misconfigured multiplier of 1 (or 0) would collapse the safety
        // margin and risk false-deleting active accounts mid-emit; clamp to 2.
        let now = Utc.timestamp_opt(1_717_000_000, 0).unwrap();
        assert_eq!(staleness_cutoff(now, 6, 1), now - Duration::hours(12));
        assert_eq!(staleness_cutoff(now, 6, 0), now - Duration::hours(12));
    }

    #[test]
    fn staleness_cutoff_clamps_zero_interval() {
        let now = Utc.timestamp_opt(1_717_000_000, 0).unwrap();
        // interval 0 → treated as 1h; ×2 (clamped mult) = 2h.
        assert_eq!(staleness_cutoff(now, 0, 2), now - Duration::hours(2));
    }
}
