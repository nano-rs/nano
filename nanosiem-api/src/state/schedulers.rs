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
            handles.push(scheduler_service.start_scheduler(poll_interval));
            tracing::info!(
                "Distributed scheduled jobs loop started ({}s poll)",
                poll_interval
            );
        }

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
                    self.config.schema_profile(),
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

        tokio::spawn(async move {
            let repo =
                nanosiem_core::observability::MetricMonitorRepository::new(pool.clone());
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

                let now = Instant::now();
                for monitor in monitors {
                    // Per-monitor due gate: skip until eval_interval_secs elapsed.
                    let interval_secs = monitor.eval_interval_secs.max(1) as u64;
                    if let Some(last) = last_eval.get(&monitor.id) {
                        if now.duration_since(*last).as_secs() < interval_secs {
                            continue;
                        }
                    }
                    last_eval.insert(monitor.id, now);

                    // Isolate each monitor's evaluation so a panic cannot abort
                    // the evaluator (NAN-1102).
                    let fut = super::AppState::evaluate_one_metric_monitor(
                        &search_service,
                        &pool,
                        &monitor,
                    );
                    match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
                        Ok(Ok(())) => {}
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
    async fn evaluate_one_metric_monitor(
        search_service: &nanosiem_core::SearchService,
        pool: &sqlx::PgPool,
        monitor: &nanosiem_core::observability::MetricMonitor,
    ) -> anyhow::Result<()> {
        use nanosiem_core::query::{MetricAgg, MetricQuery, MetricTagFilter, TimeRange};

        // Re-parse the stored (already-validated) aggregate.
        let agg = MetricAgg::from_str(&monitor.agg).ok_or_else(|| {
            anyhow::anyhow!("monitor has unknown agg '{}'", monitor.agg)
        })?;

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
            service_name: None,
            agg,
            group_by: monitor.group_by.as_deref(),
            filters: &filters,
            step_secs: monitor.window_secs.max(1) as u64,
        };

        // One (series_key, value) per series over the window. Empty => no data
        // in the window, treated as no breach.
        let results = search_service
            .evaluate_metric_monitor(&query, &time_range)
            .await
            .map_err(|e| anyhow::anyhow!("metric query failed: {e}"))?;

        // NAN-1541: raise through the UNIFIED alert spine.
        let alert_repo = nanosiem_core::db::repository::AlertRepository::new(pool.clone());

        for (series_key, value) in results {
            if !monitor.comparator.breached(value, monitor.threshold) {
                continue;
            }

            // Breach payload — captured in the alert's matched_events so the
            // console can render which monitor/series/value tripped.
            let payload = serde_json::json!([{
                "monitor_id": monitor.id.to_string(),
                "monitor_name": monitor.name,
                "metric_name": monitor.metric_name,
                "agg": monitor.agg,
                "group_by": monitor.group_by,
                "series_key": series_key,
                "comparator": monitor.comparator.as_str(),
                "threshold": monitor.threshold,
                "value": value,
                "window_secs": monitor.window_secs,
                "evaluated_at": now.to_rfc3339(),
            }]);

            // Metric-monitor alerts are not tied to a detection rule, so
            // `rule_id` is NULL (the FK is nullable) and the monitor id rides
            // in `source_id`. High severity by default. No event-hash dedup
            // (matches the pre-spine behavior — the evaluator's window cadence
            // is the dedup boundary).
            if let Err(e) = alert_repo
                .create_alert(nanosiem_core::db::repository::AlertInsert {
                    kind: "metric_monitor",
                    rule_id: None,
                    source_id: Some(monitor.id.to_string()),
                    severity: &nanosiem_core::Severity::High,
                    matched_events: &payload,
                    event_hash: None,
                })
                .await
            {
                tracing::warn!(
                    monitor = %monitor.name,
                    series = %series_key,
                    error = %e,
                    "Metric-monitor: failed to raise alert"
                );
            } else {
                tracing::info!(
                    monitor = %monitor.name,
                    series = %series_key,
                    value,
                    threshold = monitor.threshold,
                    comparator = monitor.comparator.as_str(),
                    "Metric-monitor breach — alert raised"
                );
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
                    let breaching =
                        match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
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
                            if slo_alert_within_rearm(last_created, chrono::Utc::now(), rearm_secs) {
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

                    if let Err(e) = alert_repo
                        .create_alert(nanosiem_core::db::repository::AlertInsert {
                            kind: "slo",
                            rule_id: None,
                            source_id: Some(slo.id.to_string()),
                            severity: &nanosiem_core::Severity::High,
                            matched_events: &payload,
                            event_hash: None,
                        })
                        .await
                    {
                        tracing::warn!(slo = %slo.name, error = %e, "SLO: failed to raise alert");
                        // Leave the in-memory guard unset so we retry next tick;
                        // the durable check will also see no new row.
                    } else {
                        last_alerted.insert(slo.id, now);
                        tracing::info!(slo = %slo.name, "SLO breach — alert raised");
                    }
                }
            }
        })
    }

    /// Evaluate one SLO: recompute the SLI over its rolling window, apply the
    /// budget/burn/status math, and — if *breaching* — return the burn payload
    /// (single-element JSON array) to be carried in the alert's `matched_events`.
    /// Returns `Ok(None)` when the SLO is not breaching.
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

        let (current, total_spans) = search_service
            .observability_slo_compute(
                &slo.service,
                slo.sli_kind.to_query_kind(),
                slo.latency_threshold_ms,
                &time_range,
            )
            .await
            .map_err(|e| anyhow::anyhow!("SLO compute failed: {e}"))?;

        // Error budget math — identical to the read path's `enrich`.
        let allowed = (1.0 - slo.target).max(f64::EPSILON);
        let consumed = (1.0 - current).max(0.0);
        let budget_remaining_pct = ((allowed - consumed) / allowed) * 100.0;
        let burn_rate = consumed / allowed;

        // Breach = SLI below target (the read path's "breaching" status). A
        // window with no spans computes current = 1.0 (not breaching), so an
        // idle service never alerts.
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
