// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;

#[cfg(feature = "enterprise")]
use nanosiem_core::crypto::EncryptionService;
use nanosiem_core::enrichment::{EnrichmentRepository, EnrichmentScheduler};
use nanosiem_core::identity::IdentitySyncScheduler;
use nanosiem_core::marketplace::MarketplaceSyncService;
use nanosiem_core::mitre::{MitreRepository, MitreSync, MitreSyncOutcome};
use nanosiem_core::models::detection_rule::DetectionMode;
use nanosiem_core::parser_repository::ParserRepositoryService;
use nanosiem_core::rule_repository::RuleRepositoryService;
use nanosiem_core::tuning::versions::{PendingRuntimeSync, RuleVersionManager};
use nanosiem_core::{DistributedDetectionScheduler, DistributedSchedulerConfig};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::custom_enrichment::scheduler::CustomEnrichmentScheduler;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::integrations::CollectorScheduler;
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::ModelCatalogScheduler;
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

        handles.push(scheduler.start_with_shutdown(self.shutdown_token()));
        tracing::info!("Distributed detection scheduler started");

        // Query changes and rollbacks commit a durable reconciliation job with
        // PostgreSQL state. Every API node competes for these jobs so a crash
        // between commit and ClickHouse DDL is recoverable.
        handles.push(self.start_rule_runtime_sync_reconciler());
        tracing::info!("Distributed rule runtime reconciliation started");

        // --- Distributed scheduled jobs ---
        // These are inputlookup ingestion jobs that fetch remote feed URLs over
        // the network (see SchedulerService::fetch_and_process). That's an egress
        // path, so the loop must NOT run in air-gap mode. The detection scheduler
        // above is internal (ClickHouse/PG only) and keeps running regardless.
        if !self.config.egress_jobs_enabled() {
            tracing::info!(
                "AIRGAP_MODE: skipping distributed scheduled jobs loop (remote inputlookup feed ingestion)"
            );
        } else {
            let scheduler_service = nanosiem_core::SchedulerService::with_node_id(
                self.pool.clone(),
                self.node_id.clone(),
            );
            let poll_interval: u64 = std::env::var("SCHEDULER_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30);
            handles.push(
                scheduler_service
                    .start_scheduler_with_shutdown(poll_interval, self.shutdown_token()),
            );
            tracing::info!(
                "Distributed scheduled jobs loop started ({}s poll)",
                poll_interval
            );
        }

        // --- Distributed scheduled reports (NAN-1793) ---
        // Runs on ALL nodes via SKIP LOCKED (same pattern as scheduled jobs).
        // Report execution is internal (ClickHouse + PostgreSQL only); the
        // completion `report_ready` webhook is best-effort and SSRF-guarded, so
        // unlike the feed-fetch jobs loop this is NOT egress-gated — reports
        // still generate (and notify in-app) in air-gap mode.
        {
            let report_service = nanosiem_core::ReportService::with_node_id(
                self.pool.clone(),
                self.search_service.clone(),
                self.node_id.clone(),
            );
            let poll_interval: u64 = std::env::var("REPORT_SCHEDULER_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30);
            handles.push(
                report_service.start_scheduler_with_shutdown(poll_interval, self.shutdown_token()),
            );
            tracing::info!(
                "Distributed report scheduler started ({}s poll)",
                poll_interval
            );
        }

        handles
    }

    fn start_rule_runtime_sync_reconciler(&self) -> tokio::task::JoinHandle<()> {
        let state = self.clone();
        tokio::spawn(async move {
            let manager = RuleVersionManager::new(state.pool.clone());
            loop {
                let owner = format!("{}:{}", state.node_id, uuid::Uuid::now_v7());
                match manager.claim_pending_runtime_sync(&owner).await {
                    Ok(Some(pending)) => {
                        match state.reconcile_rule_runtime_sync(&pending, &owner).await {
                            Ok(()) => tracing::info!(
                                rule_id = %pending.rule_id,
                                version_id = pending.desired_version_id,
                                "Reconciled rule runtime after PostgreSQL change"
                            ),
                            Err(error) => tracing::warn!(
                                rule_id = %pending.rule_id,
                                %error,
                                "Rule runtime reconciliation will retry"
                            ),
                        }
                    }
                    Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
                    Err(error) => {
                        tracing::warn!(%error, "Failed to claim runtime reconciliation job");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        })
    }

    /// Render and acknowledge a runtime sync only for the exact PostgreSQL
    /// revision loaded under the shared per-rule writer lock. If the rule is
    /// revised during DDL, the CAS fails and the loop renders the newer state.
    pub(crate) async fn reconcile_rule_runtime_sync(
        &self,
        pending: &PendingRuntimeSync,
        owner: &str,
    ) -> Result<(), String> {
        const MAX_REVISION_RETRIES: usize = 3;
        const DDL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

        let _runtime_lock = self
            .detection_service
            .acquire_rule_runtime_lock(pending.rule_id)
            .await
            .map_err(|error| error.to_string())?;
        let manager = RuleVersionManager::new(self.pool.clone());
        for _ in 0..MAX_REVISION_RETRIES {
            let renewed = manager
                .renew_runtime_sync_lease(pending, owner)
                .await
                .map_err(|error| error.to_string())?;
            if !renewed {
                if matches!(
                    self.detection_service.get_rule(pending.rule_id).await,
                    Err(nanosiem_core::detection::DetectionError::RuleNotFound(_))
                ) {
                    return self
                        .cleanup_deleted_rule_runtime(pending, owner, &manager)
                        .await;
                }
                return Err("runtime reconciliation lease is no longer owned".to_string());
            }

            let rule = match self.detection_service.get_rule(pending.rule_id).await {
                Ok(rule) => rule,
                Err(nanosiem_core::detection::DetectionError::RuleNotFound(_)) => {
                    return self
                        .cleanup_deleted_rule_runtime(pending, owner, &manager)
                        .await;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = manager.fail_runtime_sync(pending, owner, &message).await;
                    return Err(message);
                }
            };
            let mut rendered_revision = rule.updated_at;
            if rule.detection_mode == DetectionMode::RealTime {
                match tokio::time::timeout(
                    DDL_TIMEOUT,
                    self.materialized_view_generator.recreate_view(&rule),
                )
                .await
                {
                    Ok(Ok(view_name)) => {
                        if rule.materialized_view_name.as_deref() != Some(&view_name) {
                            let revision: Option<chrono::DateTime<chrono::Utc>> =
                                sqlx::query_scalar(
                                    "UPDATE detection_rules
                                     SET materialized_view_name = $1, updated_at = NOW()
                                     WHERE id = $2 AND updated_at = $3
                                     RETURNING updated_at",
                                )
                                .bind(&view_name)
                                .bind(rule.id)
                                .bind(rule.updated_at)
                                .fetch_optional(&self.pool)
                                .await
                                .map_err(|error| error.to_string())?;
                            let Some(revision) = revision else {
                                continue;
                            };
                            rendered_revision = revision;
                        }
                    }
                    Ok(Err(error)) => {
                        let message = error.to_string();
                        let _ = manager.fail_runtime_sync(pending, owner, &message).await;
                        return Err(message);
                    }
                    Err(_) => {
                        let message = "materialized-view reconciliation timed out".to_string();
                        let _ = manager.fail_runtime_sync(pending, owner, &message).await;
                        return Err(message);
                    }
                }
            } else {
                if let Err(message) = self.drop_rule_runtime_view(rule.id).await {
                    let _ = manager.fail_runtime_sync(pending, owner, &message).await;
                    return Err(message);
                }
            }

            match manager
                .complete_runtime_sync(pending, owner, rendered_revision)
                .await
            {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    if matches!(
                        self.detection_service.get_rule(pending.rule_id).await,
                        Err(nanosiem_core::detection::DetectionError::RuleNotFound(_))
                    ) {
                        return self
                            .cleanup_deleted_rule_runtime(pending, owner, &manager)
                            .await;
                    }
                    continue;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = manager.fail_runtime_sync(pending, owner, &message).await;
                    return Err(message);
                }
            }
        }

        let message = "rule changed repeatedly during runtime reconciliation".to_string();
        let _ = manager.fail_runtime_sync(pending, owner, &message).await;
        Err(message)
    }

    async fn drop_rule_runtime_view(&self, rule_id: uuid::Uuid) -> Result<(), String> {
        let view_name =
            nanosiem_core::detection::MaterializedViewGenerator::view_name_for_rule_id(rule_id);
        match tokio::time::timeout(
            std::time::Duration::from_secs(120),
            self.materialized_view_generator.drop_view(&view_name),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err("materialized-view cleanup timed out".to_string()),
        }
    }

    async fn cleanup_deleted_rule_runtime(
        &self,
        pending: &PendingRuntimeSync,
        owner: &str,
        manager: &RuleVersionManager,
    ) -> Result<(), String> {
        if let Err(message) = self.drop_rule_runtime_view(pending.rule_id).await {
            let _ = manager.fail_runtime_sync(pending, owner, &message).await;
            return Err(message);
        }
        match manager.complete_deleted_runtime_sync(pending, owner).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                Err("deleted-rule runtime cleanup lost its reconciliation lease".to_string())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    /// Start the enrichment auto-sync scheduler
    ///
    /// This spawns a background task that periodically checks enrichment sources
    /// and syncs them if they're due for an update.
    pub fn start_enrichment_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let enrichment_repo = EnrichmentRepository::new(self.pool.clone());
        let scheduler =
            EnrichmentScheduler::with_defaults(self.enrichment.clone(), enrichment_repo)
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

    /// Start the collector scheduler (NAN-2189) — pulls events from SaaS APIs
    /// on their cron schedules. Enterprise only, and egress-gated by the caller
    /// since collectors are unsupported in air-gapped deployments.
    ///
    /// Leadership keeps replicas from stampeding, but the real single-flight
    /// guard is the per-instance database lease: iterator APIs lose events when
    /// the same cursor is consumed twice, and a leader handover mid-run would
    /// otherwise do exactly that.
    #[cfg(feature = "enterprise")]
    pub fn start_collector_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let scheduler = Arc::new(CollectorScheduler::new(
            self.pool.clone(),
            Arc::new(EncryptionService::from_env()),
        ));
        let poll_interval: u64 = std::env::var("COLLECTOR_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        scheduler.start(poll_interval)
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
                            if let Err(e) = sync_service.sync_repository(r.id).await {
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
                            if let Err(e) = service.sync_repository(r.id).await {
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
                            if let Err(e) = service.sync_repository(r.id).await {
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

    /// Start the pinned MITRE ATT&CK catalog synchronizer.
    ///
    /// The first tick runs immediately. Until the catalog is first populated the
    /// loop ticks on a short boot cadence (MITRE_SYNC_BOOT_INTERVAL_SECS, default
    /// 60s) so a transient first-boot failure re-exposes an empty catalog
    /// (NAN-1103) for at most that long rather than for a full long-interval
    /// period — the persisted 300s·2ⁿ retry backoff otherwise sits well under
    /// the 6h interval and never gets a chance to fire (NAN-1766 / D4). Once the
    /// catalog is current the loop falls back to the long interval
    /// (MITRE_SYNC_INTERVAL_SECS, default 6h). `sync_if_due` dedupes every tick
    /// via the durable release/digest check and the persisted retry window, so
    /// fast ticking never triggers redundant fetches. PostgreSQL advisory
    /// locking fences manual sync and leader-failover overlap across nodes.
    pub fn start_mitre_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let interval_secs: u64 = std::env::var("MITRE_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(21_600); // 6 hours
        let boot_interval_secs: u64 = std::env::var("MITRE_SYNC_BOOT_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(60);

        tokio::spawn(async move {
            let sync = MitreSync::new(MitreRepository::new(pool));
            let long_interval = std::time::Duration::from_secs(interval_secs.max(60));
            // Never let the boot cadence exceed the steady-state interval, and
            // keep a small floor so a misconfiguration can't hot-loop.
            let boot_interval = std::time::Duration::from_secs(
                boot_interval_secs.clamp(15, interval_secs.max(60)),
            );
            let mut catalog_ready = false;
            let mut interval = tokio::time::interval(boot_interval);
            loop {
                interval.tick().await;
                let mut newly_ready = false;
                match sync.sync_if_due().await {
                    Ok(MitreSyncOutcome::Synced(result)) => {
                        tracing::info!(
                            release = %result.release,
                            tactics = result.tactic_count,
                            techniques = result.technique_count,
                            "Scheduled MITRE catalog sync completed"
                        );
                        newly_ready = true;
                    }
                    Ok(MitreSyncOutcome::AlreadyCurrent) => {
                        tracing::debug!("MITRE catalog is already current");
                        newly_ready = true;
                    }
                    Ok(MitreSyncOutcome::RetryBackoff) => {
                        tracing::debug!("MITRE catalog sync remains in retry backoff")
                    }
                    Ok(MitreSyncOutcome::AlreadyRunning) => {
                        tracing::debug!("MITRE catalog sync is already running on another node")
                    }
                    Err(error) => tracing::warn!(%error, "Scheduled MITRE catalog sync failed"),
                }

                // Once the catalog is confirmed current, drop to the long steady
                // -state cadence. `interval_at` schedules the next tick a full
                // long interval out instead of firing immediately.
                if newly_ready && !catalog_ready {
                    catalog_ready = true;
                    interval = tokio::time::interval_at(
                        tokio::time::Instant::now() + long_interval,
                        long_interval,
                    );
                }
            }
        })
    }

    // NAN-1810: the RiskDecayScheduler (NAN-1675) is retired along with the
    // `entity_risk_scores` rollup it maintained — every risk read computes the
    // decayed score live from the ClickHouse findings stream (NAN-1806), so
    // there is no persisted snapshot left to sweep.

    // NAN-1805: the RiskNotableScheduler (NAN-1792) is retired. Risk notables
    // are now an ordinary detection rule over `dataset=risk` (the seeded
    // "Accumulated risk threshold exceeded" rule, enterprise migration
    // 9000033) — grouping/cases/webhooks/cooldown ride the standard detection
    // engine, with the per-(rule, entity) alert_cooldown_minutes throttle
    // carrying the scheduler's durable hysteresis. Historical
    // kind="risk_notable" alerts remain valid (migration 237's CHECK is
    // append-only).

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
        use nanosiem_core::tuning::{TestEngine, TuningRepository};
        #[cfg(feature = "enterprise")]
        use nanosiem_enterprise::tuning::orchestrator::TuningOrchestrator;

        // The pool is only used by the enterprise AI orchestrator path; in
        // open mode we just bind it for symmetry and drop it.
        #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
        let dual_pool = self.dual_pool.clone();

        // Create tuning services. Metrics collector reads findings from
        // ClickHouse (`logs WHERE source_type='findings'`) — not the legacy
        // PG `alerts` table — so it sees scheduled-mode detection output
        // (NAN-866).
        let metrics_collector = MetricsCollector::new(
            self.pool.clone(),
            self.dual_pool.clickhouse().clone(),
            self.dual_pool.table_names(),
        );
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

        // Enterprise always wires the orchestrator: durable PR recovery must
        // run after leader failover even when AI is unavailable and there are
        // no fresh breaches. The optional AI client gates only new generation.
        #[cfg(feature = "enterprise")]
        {
            let ai_client: Option<Arc<dyn nanosiem_core::extensions::AiClient>> = match self
                .melod_service
                .try_read()
            {
                Ok(melod_guard) if melod_guard.is_some() => {
                    drop(melod_guard);
                    tracing::info!("AI is configured - enabling auto-tuning proposal generation");
                    Some(Arc::new(
                        nanosiem_enterprise::melod::MelodAiClientBridge::live(
                            self.melod_service.clone(),
                            self.agent_config_registry.clone(),
                        ),
                    ))
                }
                Ok(_) => {
                    tracing::warn!(
                            "AI is not configured - new tuning proposals are disabled; durable PR recovery remains enabled"
                        );
                    None
                }
                Err(_) => {
                    tracing::warn!(
                            "Could not read meloD service state - new tuning proposals are disabled; durable PR recovery remains enabled"
                        );
                    None
                }
            };

            let tuning_repository = TuningRepository::new(self.pool.clone());
            let threshold_detector_arc = Arc::new(ThresholdDetector::new(
                self.pool.clone(),
                Arc::new(BaselineMonitor::new(self.pool.clone())),
            ));
            let notification_service_arc = Arc::new(NotificationService::new(self.pool.clone()));
            let test_engine = Arc::new(TestEngine::new(
                Arc::new(self.detection_service.clone()),
                self.pool.clone(),
            ));

            let orchestrator = TuningOrchestrator::new(
                threshold_detector_arc,
                Arc::new(tuning_repository),
                notification_service_arc,
                test_engine,
                Arc::new(dual_pool),
                ai_client,
                self.config.schema_profile(),
            );

            scheduler = scheduler.with_orchestrator(Arc::new(orchestrator));
        }

        tracing::info!("Starting tuning scheduler tasks");
        scheduler.start()
    }

    /// Start the synthetic-check runner (NAN-1538).
    ///
    /// Leader-only + egress-gated: probes hit arbitrary remote URLs (outbound),
    /// so this must not start in air-gap mode, and only one node should probe.
    /// The runner is panic-safe — a single failing check never aborts the loop
    /// (NAN-1102). Reads check definitions from PG, writes probe results to the
    /// ClickHouse `synthetic_check_results` table (migration 142).
    pub fn start_synthetics_runner(&self) -> tokio::task::JoinHandle<()> {
        let runner = nanosiem_core::observability::SyntheticRunner::new(
            self.pool.clone(),
            self.dual_pool.clickhouse().clone(),
            // NAN-1721 O1: route the `due_for` read to the `_distributed` wrapper
            // on a cluster so it sees every shard's results (INSERT stays local).
            self.dual_pool.table_names().is_clustered(),
        )
        // NAN-1546: forward synthetic-failure alerts to observability-subscribed
        // webhooks (same wiring pattern as the detection service).
        .with_webhook_service(nanosiem_core::webhooks::WebhookService::new(
            nanosiem_core::webhooks::WebhookRepository::new(self.pool.clone()),
        ));
        runner.start()
    }

    /// Start the SIEM health check scheduler (leader-only, every 12 hours)
    pub fn start_siem_health_check_scheduler(&self) -> tokio::task::JoinHandle<()> {
        #[cfg(not(feature = "enterprise"))]
        use nanosiem_core::extensions::NoopSiemHealthAiAnalyzer;
        use nanosiem_core::extensions::SiemHealthAiAnalyzer;
        use std::sync::Arc;

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

    /// Start the metric-monitor evaluator (NAN-1540).
    ///
    /// Ticks every 30s (the minimum `eval_interval_secs`). On each tick it
    /// loads the enabled monitors and, for each whose `eval_interval_secs` has
    /// elapsed since its last evaluation, runs the monitor's metrics-v2
    /// aggregate over the trailing `window_secs` window (one scalar per series),
    /// compares each series value to `threshold` via the comparator, and raises
    /// an alert on breach via [`super::AppState`]'s shared alert store.
    ///
    /// Panic-safe (NAN-1102): each monitor's evaluation is isolated with
    /// `catch_unwind`, so a panic in one monitor cannot abort the evaluator task
    /// (and therefore cannot take down the other background schedulers sharing
    /// the jobs process). Last-evaluation times are tracked in-memory and reset
    /// on process restart — a restart simply re-evaluates everything on the next
    /// tick, which is harmless for a threshold check.
    pub fn start_metric_monitor_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use futures::FutureExt;
        use std::collections::HashMap;
        use std::time::Instant;
        use uuid::Uuid;

        let pool = self.pool.clone();
        let search_service = self.search_service.clone();
        // NAN-1741 A1: forward metric-monitor breach alerts to
        // observability-subscribed webhooks (kind "metric_monitor" → obs_alert
        // stream, migration 217). Same wiring pattern as the synthetics runner.
        let webhook_service = nanosiem_core::webhooks::WebhookService::new(
            nanosiem_core::webhooks::WebhookRepository::new(self.pool.clone()),
        );

        // Per-(monitor, series) durable re-arm window: a persistent breach raises
        // at most one alert per this window (O14; mirrors the SLO scheduler's
        // durable re-arm). Defaults to 1h.
        let rearm_secs: u64 = std::env::var("METRIC_MONITOR_REARM_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        tokio::spawn(async move {
            let repo = nanosiem_core::observability::MetricMonitorRepository::new(pool.clone());
            // Last-evaluation instant per monitor id (in-memory due-time gate).
            let mut last_eval: HashMap<Uuid, Instant> = HashMap::new();

            let interval = tokio::time::interval(std::time::Duration::from_secs(30));
            tokio::pin!(interval);

            tracing::info!("Metric-monitor evaluator started (30s tick)");

            loop {
                interval.tick().await;

                let monitors = match repo.list_enabled().await {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "Metric-monitor: failed to list enabled monitors");
                        continue;
                    }
                };

                // Drop due-gate entries for monitors that no longer exist so the
                // map doesn't grow unbounded across deletes (O46; mirrors the SLO
                // loop's retain at start_slo_scheduler).
                let live: std::collections::HashSet<Uuid> = monitors.iter().map(|m| m.id).collect();
                last_eval.retain(|id, _| live.contains(id));

                let now = Instant::now();
                for monitor in monitors {
                    // Per-monitor due gate: skip until eval_interval_secs elapsed.
                    let interval_secs = monitor.eval_interval_secs.max(1) as u64;
                    if let Some(last) = last_eval.get(&monitor.id) {
                        if now.duration_since(*last).as_secs() < interval_secs {
                            continue;
                        }
                    }

                    // Isolate each monitor's evaluation so a panic cannot abort
                    // the evaluator (NAN-1102).
                    let fut = super::AppState::evaluate_one_metric_monitor(
                        &search_service,
                        &pool,
                        &monitor,
                        rearm_secs,
                        &webhook_service,
                    );
                    match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
                        // O4: advance the due gate ONLY on success. On error or
                        // panic we deliberately do NOT advance `last_eval`, so the
                        // failed window is re-evaluated on the next tick instead of
                        // being marked evaluated and silently skipped (mirrors the
                        // SLO scheduler's skip-tick-on-failure behavior).
                        Ok(Ok(())) => {
                            last_eval.insert(monitor.id, now);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                monitor = %monitor.name,
                                error = %e,
                                "Metric-monitor evaluation failed"
                            );
                        }
                        Err(_) => {
                            tracing::error!(
                                monitor = %monitor.name,
                                "Metric-monitor evaluation PANICKED (isolated)"
                            );
                        }
                    }
                }
            }
        })
    }

    /// Evaluate a single metric monitor: run the aggregate over the trailing
    /// `window_secs`, compare each series to the threshold, and insert a
    /// high-severity alert per breaching series. Errors are returned (logged by
    /// the caller); a per-series alert-insert failure is logged but does not
    /// abort the remaining series.
    ///
    /// No-data (O13 / Contract #1): each series value arrives as `Option<f64>`
    /// (`None` when the window had no data — never a fabricated 0.0). A `None`
    /// series is skipped: no comparison, no alert.
    ///
    /// Re-arm (O14): each breaching series is gated by the durable
    /// [`AlertRepository::latest_alert_at_for_source`] check keyed by
    /// `(monitor, series)` with a `rearm_secs` window, so a persistent breach
    /// raises at most one alert per series per window instead of one per eval
    /// interval (mirrors the SLO scheduler's durable re-arm).
    async fn evaluate_one_metric_monitor(
        search_service: &nanosiem_core::SearchService,
        pool: &sqlx::PgPool,
        monitor: &nanosiem_core::observability::MetricMonitor,
        rearm_secs: u64,
        webhook_service: &nanosiem_core::webhooks::WebhookService,
    ) -> anyhow::Result<()> {
        use nanosiem_core::query::{MetricAgg, MetricQuery, MetricTagFilter, TimeRange};

        // Re-parse the stored (already-validated) aggregate.
        let agg = MetricAgg::from_str(&monitor.agg)
            .ok_or_else(|| anyhow::anyhow!("monitor has unknown agg '{}'", monitor.agg))?;

        // Bridge the owned monitor filters into the query-layer borrow form.
        let filters: Vec<MetricTagFilter> = monitor
            .filters
            .iter()
            .map(|f| MetricTagFilter {
                key: f.key.clone(),
                value: f.value.clone(),
            })
            .collect();

        let now = chrono::Utc::now();
        let begin = now - chrono::Duration::seconds(monitor.window_secs.max(1) as i64);
        let time_range = TimeRange::new(begin, now);

        let query = MetricQuery {
            metric_name: &monitor.metric_name,
            // O31 (NAN-1721): scope the aggregate to the monitor's stored service
            // (the promoted `service_name` column). None = fleet-wide. Applied by
            // `metric_scalar_sql` to both the group_by and no-group_by paths.
            service_name: monitor.service_name.as_deref(),
            agg,
            group_by: monitor.group_by.as_deref(),
            filters: &filters,
            step_secs: monitor.window_secs.max(1) as u64,
        };

        // One (series_key, value) per series over the window. `value` is
        // `Option<f64>` (Contract #1): `None` = no data in the window
        // (row_count == 0 or a JSON-null aggregate) — never coerced to 0.0. An
        // empty vec (no rows at all) is likewise no breach.
        let results = search_service
            .evaluate_metric_monitor(&query, &time_range)
            .await
            .map_err(|e| anyhow::anyhow!("metric query failed: {e}"))?;

        // NAN-1541: raise through the UNIFIED alert spine.
        let alert_repo = nanosiem_core::db::repository::AlertRepository::new(pool.clone());

        for (series_key, value) in results {
            // O13: a `None` scalar is no-data — neither a breach nor a
            // comparison. Skip it rather than fabricate a 0.0 that would
            // false-fire `lt`/`lte` monitors when the metric stops reporting.
            let value = match value {
                Some(v) => v,
                None => continue,
            };

            if !monitor.comparator.breached(value, monitor.threshold) {
                continue;
            }

            // Durable, time-based re-arm keyed by (monitor, series) — O14.
            // Without this a persistent breach raises one High alert per series
            // every eval interval (an alert storm). The authority is the
            // persisted `alerts` table (survives jobs restart / leader
            // failover), keyed via the per-series `source_id`; mirrors the SLO
            // scheduler's re-arm gate.
            let source_id = metric_monitor_source_id(monitor.id, &series_key);
            match alert_repo
                .latest_alert_at_for_source("metric_monitor", &source_id)
                .await
            {
                Ok(Some(last_created)) => {
                    if slo_alert_within_rearm(last_created, chrono::Utc::now(), rearm_secs) {
                        // Within the re-arm window — this series already alerted
                        // recently; skip to avoid a storm.
                        continue;
                    }
                }
                Ok(None) => {
                    // No prior alert for this (monitor, series) — proceed to raise.
                }
                Err(e) => {
                    // Re-arm lookup failed: skip raising this series rather than
                    // risk a storm without the durable guard (mirrors the SLO
                    // scheduler). The evaluation itself still succeeded, so the
                    // due gate advances and the next due tick re-checks.
                    tracing::warn!(
                        monitor = %monitor.name,
                        series = %series_key,
                        error = %e,
                        "Metric-monitor: re-arm lookup failed; skipping series this tick"
                    );
                    continue;
                }
            }

            // Entity for webhook context (NAN-1741 A1): which series breached.
            // Un-grouped monitors have an empty series key, so fall back to the
            // monitor's service scope. Computed before `payload` so the move of
            // `series_key` into the JSON below can't race it.
            let webhook_entity = if series_key.is_empty() {
                monitor.service_name.clone()
            } else {
                Some(series_key.clone())
            };

            // Breach payload — captured in the alert's matched_events so the
            // console can render which monitor/series/value tripped.
            let payload = serde_json::json!([{
                "monitor_id": monitor.id.to_string(),
                "monitor_name": monitor.name,
                "metric_name": monitor.metric_name,
                "agg": monitor.agg,
                "service_name": monitor.service_name,
                "group_by": monitor.group_by,
                "series_key": series_key,
                "comparator": monitor.comparator.as_str(),
                "threshold": monitor.threshold,
                "value": value,
                "window_secs": monitor.window_secs,
                "evaluated_at": now.to_rfc3339(),
            }]);

            // Metric-monitor alerts are not tied to a detection rule, so
            // `rule_id` is NULL (the FK is nullable) and the per-series key
            // (monitor id + series) rides in `source_id`. High severity by
            // default. No event-hash dedup — the durable re-arm gate above is
            // the dedup boundary.
            match alert_repo
                .create_alert(nanosiem_core::db::repository::AlertInsert {
                    kind: "metric_monitor",
                    rule_id: None,
                    source_id: Some(source_id),
                    severity: &nanosiem_core::Severity::High,
                    matched_events: &payload,
                    event_hash: None,
                    // A13 (NAN-1752): metric-monitor alerts have no match count.
                    match_count: None,
                })
                .await
            {
                Ok(alert) => {
                    tracing::info!(
                        monitor = %monitor.name,
                        series = %series_key,
                        value,
                        threshold = monitor.threshold,
                        comparator = monitor.comparator.as_str(),
                        "Metric-monitor breach — alert raised"
                    );

                    // NAN-1741 A1: forward to obs_alert-subscribed webhooks.
                    // kind "metric_monitor" maps to the obs_alert stream
                    // (migration 217); mirrors the synthetic runner's fire shape.
                    // Fire only after the row is durably created (never on error).
                    let severity_str =
                        format!("{:?}", nanosiem_core::Severity::High).to_lowercase();
                    webhook_service
                        .fire_alert(
                            alert.id,
                            "metric_monitor",
                            None,
                            &monitor.name,
                            &severity_str,
                            webhook_entity,
                            &payload,
                            alert.created_at,
                        )
                        .await;
                }
                Err(e) => {
                    tracing::warn!(
                        monitor = %monitor.name,
                        series = %series_key,
                        error = %e,
                        "Metric-monitor: failed to raise alert"
                    );
                }
            }
        }

        Ok(())
    }

    /// Start the SLO burn-rate evaluator (NAN-1563).
    ///
    /// Mirrors the metric-monitor evaluator: a coarse 60s tick that, per enabled
    /// SLO whose per-SLO re-arm interval has elapsed, recomputes the SLI/burn
    /// over the SLO's rolling `window_days` window via
    /// [`nanosiem_core::SearchService::observability_slo_compute`], applies the
    /// same budget/burn/status math as the read path
    /// (`handlers::observability_slos::enrich`), and raises a `kind:"slo"` alert
    /// through the unified alert spine when the SLO is *breaching* (current SLI
    /// below target).
    ///
    /// **Single burn-rate (v1).** The compute fn returns one SLI fraction over a
    /// single window; multi-window (fast+slow) burn-rate alerting would require
    /// two compute calls over distinct windows. v1 alerts on a single
    /// budget-exhaustion / breach signal; multi-window is a follow-up.
    ///
    /// **Durable, time-based re-arm dedup (NAN-1563).** Re-alerting every tick
    /// while a long rolling window stays breaching would be noise. The re-arm
    /// authority is the *durable alerts table*, not a process-local edge-trigger:
    /// before raising for a breaching SLO we look up the most recent
    /// `kind:"slo"` alert for that SLO's id
    /// ([`AlertRepository::latest_alert_at_for_source`]); if its `created_at` is
    /// within the re-arm window (default 1h, `SLO_EVAL_INTERVAL_SECS`) we skip.
    ///
    /// This is deliberately **time-based, not edge-triggered**: a momentary
    /// recovery between ticks does *not* reset anything — the persisted alert row
    /// holds the window open — so an SLI oscillating across `target` each tick
    /// cannot wipe the guard and produce an alert storm. And because the
    /// authority is the persisted table, the gate **survives a jobs-process
    /// restart / leader failover**: the new leader reads the prior leader's last
    /// alert and respects the window instead of re-firing one alert per
    /// currently-breaching SLO. The in-memory map is kept only as a cheap
    /// pre-filter to skip the DB round-trip when we *know* we're still inside the
    /// window; the DB check is the authority on every would-alert path.
    /// `event_hash: None` (no per-event dedup) matches the metric-monitor spine
    /// usage; this durable cadence gate is the dedup boundary.
    ///
    /// Panic-safe (NAN-1102): each SLO's evaluation is isolated with
    /// `catch_unwind`, so a panic in one cannot abort the evaluator task.
    pub fn start_slo_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use futures::FutureExt;
        use std::collections::HashMap;
        use std::time::Instant;
        use uuid::Uuid;

        let pool = self.pool.clone();
        let search_service = self.search_service.clone();
        // NAN-1741 A1: forward SLO breach alerts to observability-subscribed
        // webhooks (kind "slo" → obs_alert stream, migration 217). Same wiring
        // pattern as the synthetics runner / metric-monitor scheduler.
        let webhook_service = nanosiem_core::webhooks::WebhookService::new(
            nanosiem_core::webhooks::WebhookRepository::new(self.pool.clone()),
        );

        // Per-SLO re-arm interval: a persistent breach raises at most one alert
        // per this window. Defaults to 1h.
        let rearm_secs: u64 = std::env::var("SLO_EVAL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        tokio::spawn(async move {
            let repo = nanosiem_core::observability::SloRepository::new(pool.clone());
            let alert_repo = nanosiem_core::db::repository::AlertRepository::new(pool.clone());
            // Cheap in-memory pre-filter: last instant we raised a breach alert
            // per SLO id *in this process*. NOT the authority — the durable
            // alerts table is (see start_slo_scheduler doc). Entries are never
            // cleared on recovery (no edge-trigger); they only short-circuit the
            // DB round-trip while we're provably still inside the re-arm window.
            let mut last_alerted: HashMap<Uuid, Instant> = HashMap::new();

            let interval = tokio::time::interval(std::time::Duration::from_secs(60));
            tokio::pin!(interval);

            tracing::info!("SLO burn-rate evaluator started (60s tick)");

            loop {
                interval.tick().await;

                let slos = match repo.list().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "SLO evaluator: failed to list SLOs");
                        continue;
                    }
                };

                // Drop guard entries for SLOs that no longer exist so the map
                // doesn't grow unbounded across deletes.
                let live: std::collections::HashSet<Uuid> = slos.iter().map(|s| s.id).collect();
                last_alerted.retain(|id, _| live.contains(id));

                let now = Instant::now();
                for slo in slos {
                    // Isolate each SLO's evaluation (NAN-1102).
                    let fut = super::AppState::evaluate_one_slo(&search_service, &pool, &slo);
                    let breaching = match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
                        Ok(Ok(b)) => b,
                        Ok(Err(e)) => {
                            tracing::warn!(slo = %slo.name, error = %e, "SLO evaluation failed");
                            continue;
                        }
                        Err(_) => {
                            tracing::error!(slo = %slo.name, "SLO evaluation PANICKED (isolated)");
                            continue;
                        }
                    };

                    let payload = match breaching {
                        Some(payload) => payload,
                        // Not breaching: do nothing. Deliberately do NOT clear
                        // the in-memory guard — re-arm is time-based off the
                        // durable alerts table, so a momentary recovery must not
                        // reset the window (NAN-1563: fixes the flap storm).
                        None => continue,
                    };

                    // Currently breaching. Cheap pre-filter: if this process
                    // already raised within the window, skip the DB round-trip.
                    if let Some(last) = last_alerted.get(&slo.id) {
                        if now.duration_since(*last).as_secs() < rearm_secs {
                            continue;
                        }
                    }

                    // Durable re-arm authority: consult the persisted alerts
                    // table. If the most recent kind:"slo" alert for this SLO is
                    // within the re-arm window, skip — this survives restart /
                    // leader failover (NAN-1563: fixes the restart duplicate)
                    // and holds the window across momentary recoveries.
                    match alert_repo
                        .latest_alert_at_for_source("slo", &slo.id.to_string())
                        .await
                    {
                        Ok(Some(last_created)) => {
                            if slo_alert_within_rearm(last_created, chrono::Utc::now(), rearm_secs)
                            {
                                // Within window. Refresh the in-memory pre-filter
                                // so subsequent ticks short-circuit the DB query.
                                last_alerted.insert(slo.id, now);
                                continue;
                            }
                        }
                        Ok(None) => {
                            // No prior SLO alert for this source — proceed to raise.
                        }
                        Err(e) => {
                            // Re-arm check failed: skip this tick rather than risk
                            // an alert storm by raising without the durable guard.
                            tracing::warn!(slo = %slo.name, error = %e, "SLO: re-arm lookup failed; skipping tick");
                            continue;
                        }
                    }

                    match alert_repo
                        .create_alert(nanosiem_core::db::repository::AlertInsert {
                            kind: "slo",
                            rule_id: None,
                            source_id: Some(slo.id.to_string()),
                            severity: &nanosiem_core::Severity::High,
                            matched_events: &payload,
                            event_hash: None,
                            // A13 (NAN-1752): SLO alerts have no match count.
                            match_count: None,
                        })
                        .await
                    {
                        Ok(alert) => {
                            last_alerted.insert(slo.id, now);
                            tracing::info!(slo = %slo.name, "SLO breach — alert raised");

                            // NAN-1741 A1: forward to obs_alert-subscribed
                            // webhooks. kind "slo" maps to the obs_alert stream
                            // (migration 217); the SLO's tracked service is the
                            // entity. Fire only after the row is durably created.
                            let severity_str =
                                format!("{:?}", nanosiem_core::Severity::High).to_lowercase();
                            webhook_service
                                .fire_alert(
                                    alert.id,
                                    "slo",
                                    None,
                                    &slo.name,
                                    &severity_str,
                                    Some(slo.service.clone()),
                                    &payload,
                                    alert.created_at,
                                )
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!(slo = %slo.name, error = %e, "SLO: failed to raise alert");
                            // Leave the in-memory guard unset so we retry next tick;
                            // the durable check will also see no new row.
                        }
                    }
                }
            }
        })
    }

    /// Evaluate one SLO: recompute the SLI over its rolling window, apply the
    /// budget/burn/status math, and — if *breaching* — return the burn payload
    /// (single-element JSON array) to be carried in the alert's `matched_events`.
    /// Returns `Ok(None)` when the SLO is not breaching or when the window has
    /// no data.
    ///
    /// The budget/burn math mirrors `handlers::observability_slos::enrich` so the
    /// scheduler and the read path agree on the number.
    async fn evaluate_one_slo(
        search_service: &nanosiem_core::SearchService,
        _pool: &sqlx::PgPool,
        slo: &nanosiem_core::observability::SloDefinition,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        use nanosiem_core::query::TimeRange;

        let now = chrono::Utc::now();
        let begin = now - chrono::Duration::days(slo.window_days.max(1) as i64);
        let time_range = TimeRange::new(begin, now);

        let (current, total_spans, no_data) = search_service
            .observability_slo_compute(
                &slo.service,
                slo.sli_kind.to_query_kind(),
                slo.latency_threshold_ms,
                &time_range,
            )
            .await
            .map_err(|e| anyhow::anyhow!("SLO compute failed: {e}"))?;

        // O17 (Contract #2): a no-data window (total_spans == 0) is neither a
        // breach nor a recovery. A hard-down service / stopped collector emits
        // no spans → `current` computes to 1.0, and the rolling window sliding
        // past old errors would otherwise make the SLO *improve* while the
        // service is dead. Do NOT alert on it (the API surfaces "no_data"
        // status separately).
        if no_data {
            return Ok(None);
        }

        // Error budget math — identical to the read path's `enrich`.
        let allowed = (1.0 - slo.target).max(f64::EPSILON);
        let consumed = (1.0 - current).max(0.0);
        let budget_remaining_pct = ((allowed - consumed) / allowed) * 100.0;
        let burn_rate = consumed / allowed;

        // Breach = SLI below target (the read path's "breaching" status).
        let breaching = current < slo.target;
        if !breaching {
            return Ok(None);
        }

        let payload = serde_json::json!([{
            "slo_id": slo.id.to_string(),
            "name": slo.name,
            "service": slo.service,
            "sli_kind": slo.sli_kind.as_str(),
            "target": slo.target,
            "current": current,
            "burn_rate": burn_rate,
            "budget_remaining_pct": budget_remaining_pct,
            "window_days": slo.window_days,
            "total_spans": total_spans,
            "status": "breaching",
            "evaluated_at": now.to_rfc3339(),
        }]);

        Ok(Some(payload))
    }
}

/// O14: durable per-series re-arm key for metric-monitor alerts.
///
/// Encodes `(monitor id, series key)` into the alert's `source_id` text so the
/// durable [`AlertRepository::latest_alert_at_for_source`] lookup can re-arm per
/// series (a monitor with `group_by` raises independent alerts per series). The
/// monitor id is a hyphenated UUID (never contains `:`), so the first `:` cleanly
/// separates the fixed prefix from the verbatim series key — the mapping is
/// injective, which is all the durable lookup needs (it never parses the key
/// back). A no-`group_by` monitor yields `""` as the series key → `"<id>:"`.
fn metric_monitor_source_id(monitor_id: uuid::Uuid, series_key: &str) -> String {
    format!("{}:{}", monitor_id, series_key)
}

/// NAN-1563: pure re-arm decision for SLO alerting. Returns `true` when the most
/// recent durable SLO alert (`last_created`) falls within the re-arm window
/// ending at `now` — i.e. the SLO is still "armed" and we must *skip* raising.
///
/// Time-based (not edge-triggered): the decision depends only on the persisted
/// alert's age, so a momentary recovery between ticks cannot reset it. A
/// `last_created` in the future (clock skew) is treated as within-window
/// (skip), erring toward dedup rather than a storm.
fn slo_alert_within_rearm(
    last_created: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    rearm_secs: u64,
) -> bool {
    let elapsed = (now - last_created).num_seconds();
    // Future timestamp (elapsed < 0): treat as within window (skip / dedup).
    elapsed < 0 || (elapsed as u64) < rearm_secs
}

#[cfg(test)]
mod tests {
    use super::slo_alert_within_rearm;
    use chrono::{Duration, Utc};

    #[test]
    fn within_window_skips() {
        let now = Utc::now();
        // Alerted 10 minutes ago, 1h re-arm → still armed, must skip.
        let last = now - Duration::minutes(10);
        assert!(
            slo_alert_within_rearm(last, now, 3600),
            "a 10-min-old alert under a 1h re-arm window must suppress (skip)"
        );
    }

    #[test]
    fn outside_window_alerts() {
        let now = Utc::now();
        // Alerted 2 hours ago, 1h re-arm → window elapsed, may alert.
        let last = now - Duration::hours(2);
        assert!(
            !slo_alert_within_rearm(last, now, 3600),
            "a 2h-old alert under a 1h re-arm window must allow a new alert"
        );
    }

    #[test]
    fn boundary_at_window_alerts() {
        let now = Utc::now();
        // Exactly at the boundary (elapsed == rearm_secs) is OUTSIDE the window.
        let last = now - Duration::seconds(3600);
        assert!(
            !slo_alert_within_rearm(last, now, 3600),
            "elapsed == rearm_secs is outside the window (>= window allows alert)"
        );
    }

    #[test]
    fn future_timestamp_skips() {
        let now = Utc::now();
        // Clock skew: last alert appears to be in the future → err toward dedup.
        let last = now + Duration::minutes(5);
        assert!(
            slo_alert_within_rearm(last, now, 3600),
            "a future-dated alert (clock skew) must suppress rather than storm"
        );
    }

    #[test]
    fn flap_does_not_reset_window() {
        // Models the storm scenario: an SLI oscillating across target each tick.
        // Re-arm is time-based off the durable row, so an intervening recovery
        // tick does NOT move `last_created`; the within-window decision is
        // unchanged across ticks until the full window elapses.
        let last_created = Utc::now() - Duration::minutes(30);
        // Tick A (breaching), tick B (recovered, no row written), tick C
        // (breaching again 60s later) — all still reference the same row.
        let tick_c = last_created + Duration::minutes(31);
        assert!(
            slo_alert_within_rearm(last_created, tick_c, 3600),
            "a re-breach 31 min after the last durable alert must stay suppressed"
        );
    }
}
