// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tuning Scheduler
//!
//! Provides scheduled execution of tuning tasks including:
//! - Metrics collection (every 5 minutes)
//! - Baseline updates (every 1 hour)
//! - Threshold detection (every 15 minutes)
//! - Notification batching (every 5 minutes)
//!
//! Requirements: 1.1, 1.6, 2.1, 7.1

use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, instrument, warn};

use super::{
    BaselineMonitor, MetricsCollector, NotificationService, ThresholdDetector, TuningCache,
};
use crate::extensions::TuningProposalGenerator;
use crate::settings::DeveloperSettingsRepository;

/// Configuration for the tuning scheduler
#[derive(Debug, Clone)]
pub struct TuningSchedulerConfig {
    /// How often to collect metrics (in seconds)
    pub metrics_collection_interval_secs: u64,
    /// How often to update baselines (in seconds)
    pub baseline_update_interval_secs: u64,
    /// How often to check thresholds (in seconds)
    pub threshold_check_interval_secs: u64,
    /// How often to batch notifications (in seconds)
    pub notification_batch_interval_secs: u64,
    /// How often to cleanup expired cache entries (in seconds)
    pub cache_cleanup_interval_secs: u64,
}

impl Default for TuningSchedulerConfig {
    fn default() -> Self {
        Self {
            metrics_collection_interval_secs: 300, // 5 minutes
            baseline_update_interval_secs: 3600,   // 1 hour
            threshold_check_interval_secs: 900,    // 15 minutes
            notification_batch_interval_secs: 300, // 5 minutes
            cache_cleanup_interval_secs: 3600,     // 1 hour
        }
    }
}

/// Tuning scheduler for managing auto-tuning background tasks
pub struct TuningScheduler {
    metrics_collector: Arc<MetricsCollector>,
    baseline_monitor: Arc<BaselineMonitor>,
    threshold_detector: Arc<ThresholdDetector>,
    notification_service: Arc<NotificationService>,
    cache: Arc<TuningCache>,
    orchestrator: Option<Arc<dyn TuningProposalGenerator>>,
    config: TuningSchedulerConfig,
    developer_settings: Option<Arc<DeveloperSettingsRepository>>,
}

impl TuningScheduler {
    /// Create a new tuning scheduler
    pub fn new(
        metrics_collector: MetricsCollector,
        baseline_monitor: BaselineMonitor,
        threshold_detector: ThresholdDetector,
        notification_service: NotificationService,
        cache: TuningCache,
    ) -> Self {
        Self {
            metrics_collector: Arc::new(metrics_collector),
            baseline_monitor: Arc::new(baseline_monitor),
            threshold_detector: Arc::new(threshold_detector),
            notification_service: Arc::new(notification_service),
            cache: Arc::new(cache),
            orchestrator: None,
            config: TuningSchedulerConfig::default(),
            developer_settings: None,
        }
    }

    /// Create a new tuning scheduler with custom configuration
    pub fn with_config(
        metrics_collector: MetricsCollector,
        baseline_monitor: BaselineMonitor,
        threshold_detector: ThresholdDetector,
        notification_service: NotificationService,
        cache: TuningCache,
        config: TuningSchedulerConfig,
    ) -> Self {
        Self {
            metrics_collector: Arc::new(metrics_collector),
            baseline_monitor: Arc::new(baseline_monitor),
            threshold_detector: Arc::new(threshold_detector),
            notification_service: Arc::new(notification_service),
            cache: Arc::new(cache),
            orchestrator: None,
            config,
            developer_settings: None,
        }
    }

    /// Set the orchestrator (optional — only if AI is configured). Takes any
    /// `TuningProposalGenerator` so the open-core scheduler stays decoupled
    /// from the enterprise `TuningOrchestrator` concrete type.
    pub fn with_orchestrator(mut self, orchestrator: Arc<dyn TuningProposalGenerator>) -> Self {
        self.orchestrator = Some(orchestrator);
        self
    }

    /// Set the PostgreSQL pool for developer settings (optional)
    pub fn with_pg_pool(mut self, pool: PgPool) -> Self {
        self.developer_settings = Some(Arc::new(DeveloperSettingsRepository::new(pool)));
        self
    }

    /// Start all tuning scheduler tasks
    ///
    /// Returns a vector of JoinHandles for all spawned tasks
    #[instrument(skip(self))]
    pub fn start(&self) -> Vec<tokio::task::JoinHandle<()>> {
        info!("Starting tuning scheduler tasks");

        let mut handles = Vec::new();

        // Start metrics collection task
        handles.push(self.start_metrics_collection_task());

        // Start baseline update task
        handles.push(self.start_baseline_update_task());

        // Start threshold detection task
        handles.push(self.start_threshold_detection_task());

        // Start notification batching task
        handles.push(self.start_notification_batch_task());

        // Start cache cleanup task
        handles.push(self.start_cache_cleanup_task());

        info!("All tuning scheduler tasks started");
        handles
    }

    /// Start the metrics collection task (every 5 minutes)
    ///
    /// Collects metrics for all enabled detection rules
    /// Requirements: 1.1
    fn start_metrics_collection_task(&self) -> tokio::task::JoinHandle<()> {
        let metrics_collector = self.metrics_collector.clone();
        let interval_secs = self.config.metrics_collection_interval_secs;
        let developer_settings = self.developer_settings.clone();

        info!(interval_secs, "Starting metrics collection task");

        tokio::spawn(async move {
            let mut check_interval = interval(TokioDuration::from_secs(interval_secs));
            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_SECS: u64 = 900; // 15 minutes max backoff

            loop {
                check_interval.tick().await;

                // Check if tuning scheduler is enabled
                if let Some(ref settings_repo) = developer_settings {
                    match settings_repo.is_tuning_scheduler_enabled().await {
                        Ok(false) => {
                            debug!("Tuning scheduler disabled, skipping metrics collection");
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to check tuning scheduler enabled status: {}", e);
                        }
                        Ok(true) => {}
                    }
                }

                debug!("Running metrics collection");

                match metrics_collector.collect_all_metrics().await {
                    Ok(count) => {
                        consecutive_errors = 0;
                        debug!("Collected metrics for {} rules", count);
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(interval_secs),
                            MAX_BACKOFF_SECS,
                        );
                        error!(
                            "Error collecting metrics (attempt {}, backoff {}s): {}",
                            consecutive_errors, backoff_secs, e
                        );
                        tokio::time::sleep(TokioDuration::from_secs(backoff_secs)).await;
                    }
                }
            }
        })
    }

    /// Start the baseline update task (every 1 hour)
    ///
    /// Updates baselines for all rules with established baselines
    /// Requirements: 1.6
    fn start_baseline_update_task(&self) -> tokio::task::JoinHandle<()> {
        let baseline_monitor = self.baseline_monitor.clone();
        let interval_secs = self.config.baseline_update_interval_secs;
        let developer_settings = self.developer_settings.clone();

        info!(interval_secs, "Starting baseline update task");

        tokio::spawn(async move {
            let mut check_interval = interval(TokioDuration::from_secs(interval_secs));
            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_SECS: u64 = 1800; // 30 minutes max backoff

            loop {
                check_interval.tick().await;

                // Check if tuning scheduler is enabled
                if let Some(ref settings_repo) = developer_settings {
                    match settings_repo.is_tuning_scheduler_enabled().await {
                        Ok(false) => {
                            debug!("Tuning scheduler disabled, skipping baseline updates");
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to check tuning scheduler enabled status: {}", e);
                        }
                        Ok(true) => {}
                    }
                }

                debug!("Running baseline updates");

                match baseline_monitor.update_all_baselines().await {
                    Ok(count) => {
                        debug!("Updated baselines for {} rules", count);
                    }
                    Err(e) => {
                        warn!("Error updating baselines: {}", e);
                    }
                }

                // Try to establish baselines for new rules that don't have one yet
                match baseline_monitor.try_establish_new_baselines().await {
                    Ok(count) => {
                        consecutive_errors = 0;
                        if count > 0 {
                            info!("Established {} new baselines", count);
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(interval_secs / 60), // Scale down since interval is 1 hour
                            MAX_BACKOFF_SECS,
                        );
                        error!(
                            "Error updating baselines (attempt {}, backoff {}s): {}",
                            consecutive_errors, backoff_secs, e
                        );
                        tokio::time::sleep(TokioDuration::from_secs(backoff_secs)).await;
                    }
                }
            }
        })
    }

    /// Start the threshold detection task (every 15 minutes)
    ///
    /// Checks for threshold breaches and triggers auto-tuning via orchestrator if available
    /// Requirements: 2.1
    fn start_threshold_detection_task(&self) -> tokio::task::JoinHandle<()> {
        let orchestrator = self.orchestrator.clone();
        let threshold_detector = self.threshold_detector.clone();
        let interval_secs = self.config.threshold_check_interval_secs;
        let developer_settings = self.developer_settings.clone();

        info!(interval_secs, "Starting threshold detection task");

        tokio::spawn(async move {
            let mut check_interval = interval(TokioDuration::from_secs(interval_secs));
            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_SECS: u64 = 900; // 15 minutes max backoff

            loop {
                check_interval.tick().await;

                // Check if tuning scheduler is enabled
                if let Some(ref settings_repo) = developer_settings {
                    match settings_repo.is_tuning_scheduler_enabled().await {
                        Ok(false) => {
                            debug!("Tuning scheduler disabled, skipping threshold detection");
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to check tuning scheduler enabled status: {}", e);
                        }
                        Ok(true) => {}
                    }
                }

                debug!("Running threshold detection");

                // If orchestrator is available, use it to process breaches and generate proposals
                let result: Result<(), String> = if let Some(orch) = &orchestrator {
                    match orch.process_breaches().await {
                        Ok(count) => {
                            if count > 0 {
                                info!(
                                    "Generated {} tuning proposals from threshold breaches",
                                    count
                                );
                            } else {
                                debug!("No threshold breaches requiring tuning");
                            }
                            Ok(())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                } else {
                    // No orchestrator (AI not configured) - just detect breaches for monitoring
                    match threshold_detector.check_all_thresholds().await {
                        Ok(breaches) => {
                            if !breaches.is_empty() {
                                warn!(
                                    "Detected {} threshold breaches but AI tuning is not configured. \
                                    Configure AI credentials in Settings > meloD to enable auto-tuning.",
                                    breaches.len()
                                );
                            } else {
                                debug!("No threshold breaches detected");
                            }
                            Ok(())
                        }
                        Err(e) => Err(e.to_string()),
                    }
                };

                match result {
                    Ok(()) => {
                        consecutive_errors = 0;
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(interval_secs / 60),
                            MAX_BACKOFF_SECS,
                        );
                        error!(
                            "Error in threshold detection (attempt {}, backoff {}s): {}",
                            consecutive_errors, backoff_secs, e
                        );
                        tokio::time::sleep(TokioDuration::from_secs(backoff_secs)).await;
                    }
                }
            }
        })
    }

    /// Start the notification batching task (every 5 minutes)
    ///
    /// Batches and sends pending notifications
    /// Requirements: 7.1
    fn start_notification_batch_task(&self) -> tokio::task::JoinHandle<()> {
        let notification_service = self.notification_service.clone();
        let interval_secs = self.config.notification_batch_interval_secs;
        let developer_settings = self.developer_settings.clone();

        info!(interval_secs, "Starting notification batching task");

        tokio::spawn(async move {
            let mut check_interval = interval(TokioDuration::from_secs(interval_secs));
            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_SECS: u64 = 600; // 10 minutes max backoff

            loop {
                check_interval.tick().await;

                // Check if tuning scheduler is enabled
                if let Some(ref settings_repo) = developer_settings {
                    match settings_repo.is_tuning_scheduler_enabled().await {
                        Ok(false) => {
                            debug!("Tuning scheduler disabled, skipping notification batching");
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to check tuning scheduler enabled status: {}", e);
                        }
                        Ok(true) => {}
                    }
                }

                debug!("Running notification batching");

                match notification_service.process_pending_notifications().await {
                    Ok(count) => {
                        consecutive_errors = 0;
                        if count > 0 {
                            debug!("Processed {} pending notifications", count);
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(interval_secs / 60),
                            MAX_BACKOFF_SECS,
                        );
                        error!(
                            "Error processing notifications (attempt {}, backoff {}s): {}",
                            consecutive_errors, backoff_secs, e
                        );
                        tokio::time::sleep(TokioDuration::from_secs(backoff_secs)).await;
                    }
                }
            }
        })
    }

    /// Start the cache cleanup task (every 1 hour by default)
    ///
    /// Periodically removes expired entries from tuning caches to prevent memory growth
    fn start_cache_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let cache = self.cache.clone();
        let interval_secs = self.config.cache_cleanup_interval_secs;
        let developer_settings = self.developer_settings.clone();

        info!(interval_secs, "Starting cache cleanup task");

        tokio::spawn(async move {
            let mut check_interval = interval(TokioDuration::from_secs(interval_secs));

            loop {
                check_interval.tick().await;

                // Check if tuning scheduler is enabled
                if let Some(ref settings_repo) = developer_settings {
                    match settings_repo.is_tuning_scheduler_enabled().await {
                        Ok(false) => {
                            debug!("Tuning scheduler disabled, skipping cache cleanup");
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to check tuning scheduler enabled status: {}", e);
                        }
                        Ok(true) => {}
                    }
                }

                debug!("Running cache cleanup");

                cache.cleanup_expired().await;

                let stats = cache.get_stats().await;
                debug!(
                    "Cache cleanup complete - baselines: {}, metrics: {}, rule_configs: {}",
                    stats.baselines_count, stats.metrics_count, stats.rule_configs_count
                );
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TuningSchedulerConfig::default();
        assert_eq!(config.metrics_collection_interval_secs, 300); // 5 minutes
        assert_eq!(config.baseline_update_interval_secs, 3600); // 1 hour
        assert_eq!(config.threshold_check_interval_secs, 900); // 15 minutes
        assert_eq!(config.notification_batch_interval_secs, 300); // 5 minutes
    }

    #[test]
    fn test_custom_config() {
        let config = TuningSchedulerConfig {
            metrics_collection_interval_secs: 60,
            baseline_update_interval_secs: 1800,
            threshold_check_interval_secs: 300,
            notification_batch_interval_secs: 120,
            cache_cleanup_interval_secs: 1800,
        };
        assert_eq!(config.metrics_collection_interval_secs, 60);
        assert_eq!(config.baseline_update_interval_secs, 1800);
        assert_eq!(config.threshold_check_interval_secs, 300);
        assert_eq!(config.notification_batch_interval_secs, 120);
        assert_eq!(config.cache_cleanup_interval_secs, 1800);
    }
}
