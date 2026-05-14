// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;

#[cfg(feature = "enterprise")]
use nanosiem_core::crypto::EncryptionService;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::custom_enrichment::scheduler::CustomEnrichmentScheduler;
use nanosiem_core::enrichment::{EnrichmentRepository, EnrichmentScheduler};
use nanosiem_core::identity::IdentitySyncScheduler;
use nanosiem_core::marketplace::MarketplaceSyncService;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::ModelCatalogScheduler;
use nanosiem_core::parser_repository::ParserRepositoryService;
use nanosiem_core::rule_repository::RuleRepositoryService;
use nanosiem_core::{DistributedDetectionScheduler, DistributedSchedulerConfig};
use std::sync::Arc;

impl AppState {
    /// Start distributed schedulers (detection rules + scheduled jobs via SKIP LOCKED).
    ///
    /// These run on ALL nodes, not just the leader. Each node competes for work
    /// via `SELECT FOR UPDATE SKIP LOCKED`, providing automatic load balancing.
    pub async fn start_distributed_schedulers(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        // --- Distributed detection scheduler ---
        let config = DistributedSchedulerConfig::from_env();
        tracing::info!(
            node_id = %self.node_id,
            poll_interval = config.poll_interval_secs,
            batch_size = config.batch_size,
            max_concurrent = config.max_concurrent_executions,
            stale_timeout = config.stale_claim_timeout_secs,
            "Starting distributed detection scheduler"
        );

        let scheduler = Arc::new(
            DistributedDetectionScheduler::new(
                self.detection_service.clone(),
                self.pool.clone(),
                config,
                self.node_id.clone(),
            )
            .with_developer_settings(self.pool.clone()),
        );

        // Backfill next_run_at for any rules missing it
        if let Err(e) = scheduler.backfill_next_run_at().await {
            tracing::warn!("Failed to backfill next_run_at: {}", e);
        }

        // Store reference for graceful shutdown
        {
            let mut guard = self.distributed_scheduler.write().await;
            *guard = Some(scheduler.clone());
        }

        handles.push(scheduler.start());
        tracing::info!("Distributed detection scheduler started");

        // --- Distributed scheduled jobs ---
        let scheduler_service =
            nanosiem_core::SchedulerService::with_node_id(self.pool.clone(), self.node_id.clone());
        let poll_interval: u64 = std::env::var("SCHEDULER_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        handles.push(scheduler_service.start_scheduler(poll_interval));
        tracing::info!(
            "Distributed scheduled jobs loop started ({}s poll)",
            poll_interval
        );

        handles
    }

    /// Start the enrichment auto-sync scheduler
    ///
    /// This spawns a background task that periodically checks enrichment sources
    /// and syncs them if they're due for an update.
    pub fn start_enrichment_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let enrichment_repo = EnrichmentRepository::new(self.pool.clone());
        let scheduler = EnrichmentScheduler::with_defaults(self.enrichment.clone(), enrichment_repo)
            .with_clickhouse(self.dual_pool.clickhouse().clone());
        let scheduler = Arc::new(scheduler);
        scheduler.start()
    }

    /// Start the custom enrichment scheduler (Deno data enrichments on cron
    /// schedules) — enterprise only after Phase 3.3 of NAN-744.
    #[cfg(feature = "enterprise")]
    pub fn start_custom_enrichment_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let encryption = Some(Arc::new(EncryptionService::from_env()));
        let scheduler = Arc::new(CustomEnrichmentScheduler::new(
            self.pool.clone(),
            self.dual_pool.clickhouse().clone(),
            encryption,
        ));
        let poll_interval: u64 = std::env::var("CUSTOM_ENRICHMENT_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60); // Check every 60 seconds
        scheduler.start_scheduler(poll_interval)
    }

    /// Start the identity sync scheduler
    pub fn start_identity_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let scheduler = IdentitySyncScheduler::with_defaults(self.identity_service.clone());
        tokio::spawn(async move {
            scheduler.run().await;
        })
    }

    /// Start the marketplace repo auto-sync scheduler
    ///
    /// Initial delay: 30 minutes, then polls every 12 hours (configurable via MARKETPLACE_SYNC_INTERVAL_SECS).
    /// Syncs any repos that have auto_sync_enabled and are past their sync_interval_hours.
    /// Runs last among repo schedulers (after parsers at 10m, rules at 20m).
    pub fn start_marketplace_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let poll_secs: u64 = std::env::var("MARKETPLACE_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(43200); // 12 hours

        tokio::spawn(async move {
            // Initial delay: 30 minutes — after parsers (10m) and rules (20m)
            tokio::time::sleep(std::time::Duration::from_secs(1800)).await;

            // Create sync service once so the syncing_repos guard persists across ticks
            let sync_service = MarketplaceSyncService::new(pool.clone());

            let interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));
            tokio::pin!(interval);

            loop {
                match sync_service.repository().list_repos_for_auto_sync().await {
                    Ok(repos) if repos.is_empty() => {}
                    Ok(repos) => {
                        tracing::info!(count = repos.len(), "Auto-syncing marketplace repos");
                        for r in &repos {
                            if let Err(e) = sync_service.start_sync(r.id).await {
                                tracing::warn!(repo = %r.name, error = %e, "Failed to auto-sync marketplace repo");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to list marketplace repos for auto-sync");
                    }
                }
                interval.tick().await;
            }
        })
    }

    /// Start the parser repo auto-sync scheduler
    ///
    /// Initial delay: 10 minutes, then polls every 12 hours (configurable via PARSER_REPO_SYNC_INTERVAL_SECS).
    /// Syncs any repos that have auto_sync_enabled and are past their sync_interval_hours.
    /// Runs first among repo schedulers so parsers are available for rule evaluation.
    pub fn start_parser_repo_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::parser_repository::ParserRepositoryRepository;

        let pool = self.pool.clone();
        let poll_secs: u64 = std::env::var("PARSER_REPO_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(43200); // 12 hours

        tokio::spawn(async move {
            // Initial delay: 10 minutes — let the system stabilise, then sync promptly
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;

            let repo_repository = ParserRepositoryRepository::new(pool.clone());
            let service = ParserRepositoryService::new(pool.clone());

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));

            loop {
                match repo_repository.list_for_auto_sync().await {
                    Ok(repos) if repos.is_empty() => {}
                    Ok(repos) => {
                        tracing::info!(count = repos.len(), "Auto-syncing parser repos");
                        for r in &repos {
                            if let Err(e) = service.start_sync(r.id).await {
                                tracing::warn!(repo = %r.name, error = %e, "Failed to auto-sync parser repo");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to list parser repos for auto-sync");
                    }
                }
                interval.tick().await;
            }
        })
    }

    /// Start the rule repo auto-sync scheduler
    ///
    /// Initial delay: 20 minutes, then polls every 12 hours (configurable via RULE_REPO_SYNC_INTERVAL_SECS).
    /// Syncs any repos that have auto_sync_enabled and are past their sync_interval_hours.
    pub fn start_rule_repo_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::rule_repository::RuleRepositoryRepository;

        let pool = self.pool.clone();
        let dual_pool = self.dual_pool.clone();
        let poll_secs: u64 = std::env::var("RULE_REPO_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(43200); // 12 hours

        tokio::spawn(async move {
            // Initial delay: 20 minutes — after parsers, before marketplace
            tokio::time::sleep(std::time::Duration::from_secs(1200)).await;

            let repo_repository = RuleRepositoryRepository::new(pool.clone());
            let service = RuleRepositoryService::with_dual_pool(&dual_pool);

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));

            loop {
                match repo_repository.list_for_auto_sync().await {
                    Ok(repos) if repos.is_empty() => {}
                    Ok(repos) => {
                        tracing::info!(count = repos.len(), "Auto-syncing rule repos");
                        for r in &repos {
                            if let Err(e) = service.start_sync(r.id).await {
                                tracing::warn!(repo = %r.name, error = %e, "Failed to auto-sync rule repo");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to list rule repos for auto-sync");
                    }
                }
                interval.tick().await;
            }
        })
    }

    /// Start the model catalog auto-sync scheduler
    ///
    /// Runs daily (configurable via MODEL_CATALOG_SYNC_INTERVAL_SECS).
    /// Syncs model catalog from GitHub and notifies admins about deprecated agent models.
    #[cfg(feature = "enterprise")]
    pub fn start_model_catalog_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let interval_secs: u64 = std::env::var("MODEL_CATALOG_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400); // 24 hours

        ModelCatalogScheduler::new(pool, interval_secs).start()
    }

    /// Start the tuning scheduler
    ///
    /// This spawns background tasks for:
    /// - Metrics collection (every 5 minutes)
    /// - Baseline updates (every 1 hour)
    /// - Threshold detection (every 15 minutes)
    /// - Notification batching (every 5 minutes)
    ///
    /// Returns a vector of JoinHandles for all spawned tasks
    pub fn start_tuning_scheduler(&self) -> Vec<tokio::task::JoinHandle<()>> {
        use nanosiem_core::tuning::{
            BaselineMonitor, MetricsCollector, NotificationService, ThresholdDetector, TuningCache,
            TuningScheduler,
        };
        // Repository stays in core (data access only). The orchestrator
        // moved to nanosiem-enterprise in Phase 3.5; only enterprise builds
        // import it. Keep both imports gated so the open build doesn't trip
        // the unused-import lint.
        #[cfg(feature = "enterprise")]
        use nanosiem_core::tuning::TuningRepository;
        #[cfg(feature = "enterprise")]
        use nanosiem_enterprise::tuning::orchestrator::TuningOrchestrator;

        // The pool is only used by the enterprise AI orchestrator path; in
        // open mode we just bind it for symmetry and drop it.
        #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
        let dual_pool = self.dual_pool.clone();

        // Create tuning services
        let metrics_collector = MetricsCollector::new(self.pool.clone());
        let baseline_monitor = BaselineMonitor::new(self.pool.clone());
        let threshold_detector =
            ThresholdDetector::new(self.pool.clone(), Arc::new(baseline_monitor.clone()));
        let notification_service = NotificationService::new(self.pool.clone());

        // Create tuning cache for performance optimization and memory management
        let tuning_cache = TuningCache::new();

        // Create the scheduler. `mut` is only required by the enterprise AI
        // proposal-generation path that reassigns `scheduler` after wiring the
        // orchestrator; open builds don't reassign.
        #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
        let mut scheduler = TuningScheduler::new(
            metrics_collector,
            baseline_monitor,
            threshold_detector,
            notification_service,
            tuning_cache,
        );

        // If AI is configured, create and add the orchestrator. Open-core
        // builds skip this entirely — tuning still detects threshold breaches
        // but never generates proposals.
        #[cfg(feature = "enterprise")]
        if let Ok(melod_guard) = self.melod_service.try_read() {
            if melod_guard.is_some() {
                drop(melod_guard);
                tracing::info!("AI is configured - enabling auto-tuning proposal generation");

                let tuning_repository = TuningRepository::new(self.pool.clone());
                let threshold_detector_arc = Arc::new(ThresholdDetector::new(
                    self.pool.clone(),
                    Arc::new(BaselineMonitor::new(self.pool.clone())),
                ));
                let notification_service_arc =
                    Arc::new(NotificationService::new(self.pool.clone()));

                // Wrap the reloadable meloD handles in a `MelodAiClientBridge::live`
                // so the tuning agents see only the open-core `AiClient` trait.
                // Per-agent routing (`tuning_auto`, `tuning_hint`) is handled
                // inside the bridge.
                let ai_client: Arc<dyn nanosiem_core::extensions::AiClient> = Arc::new(
                    nanosiem_enterprise::melod::MelodAiClientBridge::live(
                        self.melod_service.clone(),
                        self.agent_config_registry.clone(),
                    ),
                );

                let orchestrator = TuningOrchestrator::new(
                    threshold_detector_arc,
                    Arc::new(tuning_repository),
                    notification_service_arc,
                    Arc::new(dual_pool),
                    Some(ai_client),
                );

                scheduler = scheduler.with_orchestrator(Arc::new(orchestrator));
            } else {
                tracing::warn!(
                    "AI is not configured - tuning scheduler will monitor metrics and detect breaches, \
                    but will not generate tuning proposals. Configure AI credentials in Settings > meloD to enable auto-tuning."
                );
            }
        } else {
            tracing::warn!(
                "Could not read meloD service state - tuning scheduler will monitor metrics and detect breaches, \
                but will not generate tuning proposals."
            );
        }

        tracing::info!("Starting tuning scheduler tasks");
        scheduler.start()
    }

    /// Start the SIEM health check scheduler (leader-only, every 12 hours)
    pub fn start_siem_health_check_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use std::sync::Arc;
        use nanosiem_core::extensions::SiemHealthAiAnalyzer;
        #[cfg(not(feature = "enterprise"))]
        use nanosiem_core::extensions::NoopSiemHealthAiAnalyzer;

        let ch_client = self.dual_pool.clickhouse().clone();
        let is_clustered = self.dual_pool.table_names().is_clustered();

        // Enterprise builds wrap the live meloD AI client in
        // `AiPoweredSiemHealthAnalyzer`; open-core builds use the noop
        // analyzer, which returns `Unavailable` and lets the scheduler fall
        // through to the rules-based `analyzer::fallback_report`.
        #[cfg(feature = "enterprise")]
        let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = {
            use nanosiem_core::extensions::AiClient;
            let ai_client: Arc<dyn AiClient> = self
                .melod_service
                .try_read()
                .ok()
                .and_then(|guard| guard.as_ref().map(|s| s.ai_client_arc()))
                .map(|shared| {
                    Arc::new(nanosiem_enterprise::melod::MelodAiClientBridge::new(shared))
                        as Arc<dyn AiClient>
                })
                .unwrap_or_else(|| Arc::new(nanosiem_core::extensions::NoopAiClient));
            Arc::new(nanosiem_enterprise::siem_health::AiPoweredSiemHealthAnalyzer::new(ai_client))
        };
        #[cfg(not(feature = "enterprise"))]
        let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = Arc::new(NoopSiemHealthAiAnalyzer);

        nanosiem_core::siem_health::scheduler::start(
            self.pool.clone(),
            ch_client,
            is_clustered,
            ai_analyzer,
        )
    }
}
