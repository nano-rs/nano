// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;

use std::sync::Arc;

impl AppState {
    /// Initialize the real-time evaluator by loading rules
    pub async fn init_realtime_evaluator(&self) -> anyhow::Result<()> {
        self.realtime_evaluator.load_rules().await?;
        Ok(())
    }

    /// Initialize and start the signal processor
    ///
    /// The signal processor polls ClickHouse for new signals (from materialized views)
    /// and creates alerts in PostgreSQL, completing the real-time detection pipeline.
    pub async fn init_signal_processor(&self) -> anyhow::Result<()> {
        let handle = self.signal_processor.start().await?;
        self.add_task_handle(handle).await;
        Ok(())
    }

    /// Configure the enrichment service with IPinfo URL
    pub async fn configure_enrichment(&self, ipinfo_url: Option<String>) {
        let mut enrichment = self.enrichment.write().await;
        if let Some(url) = ipinfo_url {
            enrichment.set_ipinfo_url(url);
        }
    }

    /// Release all distributed claims (detection rules + scheduled jobs).
    ///
    /// Called during graceful shutdown to immediately free claimed work
    /// so other nodes can pick it up.
    pub async fn release_all_distributed_claims(&self) {
        // Release detection rule claims
        if let Some(scheduler) = self.distributed_scheduler.read().await.as_ref() {
            match scheduler.release_all_claims().await {
                Ok(n) if n > 0 => tracing::info!("Released {} detection rule claims", n),
                Ok(_) => {}
                Err(e) => tracing::warn!("Failed to release detection rule claims: {}", e),
            }
        }

        // Release scheduled job claims
        let scheduler_service =
            nanosiem_core::SchedulerService::with_node_id(self.pool.clone(), self.node_id.clone());
        match scheduler_service.release_all_claims().await {
            Ok(n) if n > 0 => tracing::info!("Released {} scheduled job claims", n),
            Ok(_) => {}
            Err(e) => tracing::warn!("Failed to release scheduled job claims: {}", e),
        }
    }

    /// Start the health monitoring scheduler
    ///
    /// This spawns a background task that periodically checks AI provider
    /// health and feed staleness, creating notifications for issues.
    pub fn start_health_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::health::{
            AiProviderConnectivityChecker, HealthScheduler, HealthSchedulerConfig,
        };
        use std::sync::Arc;

        let config = HealthSchedulerConfig::default();

        // Inject the canonical, on-prem-`base_url`-aware provider connectivity
        // test (NAN-1207) so AI-provider health checks honor an operator's
        // on-prem endpoint instead of hardcoding public vendor hosts. The test
        // lives in the enterprise AI-providers handler; open-core has no
        // AI-provider surface, so the checker is `None` there and AI-provider
        // health checks are skipped entirely. (NAN-1231)
        #[cfg(feature = "enterprise")]
        let ai_checker: Option<Arc<dyn AiProviderConnectivityChecker>> =
            Some(Arc::new(crate::handlers::settings::ApiAiProviderChecker));
        #[cfg(not(feature = "enterprise"))]
        let ai_checker: Option<Arc<dyn AiProviderConnectivityChecker>> = None;

        let scheduler = Arc::new(HealthScheduler::with_dual_pool(
            self.pool.clone(),
            self.dual_pool.clone(),
            config,
            ai_checker,
            self.config.airgap,
        ));

        scheduler.start()
    }

    /// Start the rule change listener for real-time cache invalidation.
    ///
    /// Listens on the PostgreSQL `rule_changes` channel. When a detection rule is
    /// created, updated, or deleted on any node, the real-time evaluator reloads
    /// its compiled rules, reducing cache inconsistency to milliseconds.
    pub fn start_rule_change_listener(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let evaluator = self.realtime_evaluator.clone();

        tokio::spawn(async move {
            let mut backoff_secs = 1u64;

            loop {
                let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                    Ok(l) => {
                        backoff_secs = 1; // reset on successful connect
                        l
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to create PgListener for rule_changes: {}, retrying in {}s",
                            e,
                            backoff_secs
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue;
                    }
                };

                if let Err(e) = listener.listen("rule_changes").await {
                    tracing::error!(
                        "Failed to listen on rule_changes channel: {}, retrying in {}s",
                        e,
                        backoff_secs
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }

                tracing::info!("Listening for rule_changes notifications");

                loop {
                    match tokio::time::timeout(
                        tokio::time::Duration::from_secs(300),
                        listener.recv(),
                    )
                    .await
                    {
                        Ok(Ok(notification)) => {
                            tracing::debug!(
                                payload = %notification.payload(),
                                "Received rule_changes notification, reloading rules"
                            );
                            if let Err(e) = evaluator.load_rules().await {
                                tracing::warn!("Failed to reload rules after notification: {}", e);
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                "PgListener error on rule_changes: {}, reconnecting...",
                                e
                            );
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            break; // break inner loop to reconnect
                        }
                        Err(_) => {
                            // Timeout — no notifications in 5 minutes, reconnect to ensure connection is alive
                            tracing::debug!("PgListener keepalive timeout, reconnecting");
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Start the case change listener for real-time SSE notifications.
    ///
    /// Listens on the PostgreSQL `case_changes` channel. When a case is created
    /// or updated on any node, the event is broadcast to all SSE subscribers.
    /// Runs on ALL nodes (not leader-only) so every API instance serves SSE.
    ///
    /// Phase 3.2 (NAN-744): cases SSE moved to enterprise; the listener +
    /// broadcast channel only ship in enterprise builds.
    #[cfg(feature = "enterprise")]
    pub fn start_case_change_listener(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let tx = self.case_events_tx.clone();

        tokio::spawn(async move {
            let mut backoff_secs = 1u64;

            loop {
                let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                    Ok(l) => {
                        backoff_secs = 1;
                        l
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to create PgListener for case_changes: {}, retrying in {}s",
                            e,
                            backoff_secs
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue;
                    }
                };

                if let Err(e) = listener.listen("case_changes").await {
                    tracing::error!(
                        "Failed to listen on case_changes channel: {}, retrying in {}s",
                        e,
                        backoff_secs
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }

                tracing::info!("Listening for case_changes notifications");

                loop {
                    match tokio::time::timeout(
                        tokio::time::Duration::from_secs(300),
                        listener.recv(),
                    )
                    .await
                    {
                        Ok(Ok(notification)) => {
                            match serde_json::from_str::<super::CaseChangeEvent>(
                                notification.payload(),
                            ) {
                                Ok(event) => {
                                    tracing::debug!(
                                        case_id = %event.case_id,
                                        event = %event.event,
                                        "Broadcasting case change event"
                                    );
                                    // Ignore send errors — means no active subscribers
                                    let _ = tx.send(event);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        payload = %notification.payload(),
                                        error = %e,
                                        "Failed to parse case_changes payload"
                                    );
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(
                                "PgListener error on case_changes: {}, reconnecting...",
                                e
                            );
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            break;
                        }
                        Err(_) => {
                            tracing::debug!("PgListener case_changes keepalive timeout, reconnecting");
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Start leader-only schedulers (signal processor, enrichment, tuning, disk pressure).
    ///
    /// Detection rules and scheduled jobs are now distributed (SKIP LOCKED) and
    /// run on ALL nodes via `start_distributed_schedulers()`.
    ///
    /// Called when this instance wins the leader election. Returns task handles so the
    /// caller can abort them if leadership is lost.
    pub async fn start_leader_schedulers(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        // Signal processor (bridges ClickHouse signals to PostgreSQL alerts)
        // Must be single-leader: serial watermark processing
        match self.signal_processor.start().await {
            Ok(handle) => {
                handles.push(handle);
                tracing::info!("Signal processor started (leader-only)");
            }
            Err(e) => tracing::error!("Failed to start signal processor: {}", e),
        }

        // === Egress schedulers — skipped in air-gap mode ===
        // Air-gapped installs have no outbound internet, so any job that fetches
        // from the internet (IPinfo enrichment, GitHub repo sync, model catalog)
        // must NOT start — bundles arrive via the air-gap import surface instead.
        // Internal jobs (signal processor above; tuning / disk-pressure /
        // siem-health / cleanups below) are unaffected.
        if !self.config.egress_jobs_enabled() {
            tracing::info!(
                "AIRGAP_MODE: skipping egress background jobs (enrichment, identity, repo auto-sync, marketplace, model-catalog, docs-rag)"
            );
        } else {
            // Enrichment auto-sync scheduler (low-frequency singleton)
            handles.push(self.start_enrichment_scheduler());
            tracing::info!("Enrichment auto-sync scheduler started (leader-only)");

            // Custom enrichment scheduler — runs Deno data enrichments on their
            // cron schedules. Enterprise only after Phase 3.3 of NAN-744 (the
            // sandbox runtime + scheduler live in nanosiem-enterprise).
            #[cfg(feature = "enterprise")]
            {
                handles.push(self.start_custom_enrichment_scheduler());
                tracing::info!("Custom enrichment scheduler started (leader-only)");
            }

            // Identity provider sync scheduler
            handles.push(self.start_identity_sync_scheduler());
            tracing::info!("Identity sync scheduler started (leader-only)");

            // Repository auto-sync schedulers — staggered to avoid concurrent GitHub clones:
            //   Parsers: 10 min delay (needed first for rule evaluation)
            //   Rules: 20 min delay
            //   Marketplace: 30 min delay
            handles.push(self.start_parser_repo_sync_scheduler());
            tracing::info!(
                "Parser repo auto-sync scheduler started (leader-only, 10m initial delay)"
            );

            handles.push(self.start_rule_repo_sync_scheduler());
            tracing::info!("Rule repo auto-sync scheduler started (leader-only, 20m initial delay)");

            handles.push(self.start_marketplace_sync_scheduler());
            tracing::info!(
                "Marketplace repo auto-sync scheduler started (leader-only, 30m initial delay)"
            );

            // Model catalog auto-sync (daily by default) — enterprise only.
            #[cfg(feature = "enterprise")]
            {
                handles.push(self.start_model_catalog_sync_scheduler());
                tracing::info!("Model catalog auto-sync scheduler started (leader-only)");
            }
        }

        // Tuning scheduler (low-frequency singleton)
        handles.extend(self.start_tuning_scheduler());
        tracing::info!("Tuning scheduler started (leader-only)");

        // Disk pressure scheduler
        handles.push(Arc::clone(&self.disk_pressure_service).start());
        tracing::info!("Disk pressure scheduler started (leader-only)");

        // SIEM health check (AI-driven data quality analysis, every 12 hours)
        handles.push(self.start_siem_health_check_scheduler());
        tracing::info!("SIEM health check scheduler started (leader-only, 12h interval)");

        // Cleanup tasks (leader-only to avoid duplicate work across nodes).
        // Job store / wizard session / melod session cleanups are enterprise-only —
        // the underlying repos live in nanosiem-enterprise::melod.
        #[cfg(feature = "enterprise")]
        {
            handles.push(self.start_job_store_cleanup());
            handles.push(self.start_wizard_session_cleanup());
            handles.push(self.start_melod_session_cleanup());
            // Agent enrichment cache cleanup is enterprise-only after
            // Phase 3.3 (the agent_enrichment module + repository live in
            // nanosiem-enterprise).
            handles.push(self.start_enrichment_cache_cleanup());
        }
        handles.push(self.start_rate_limit_cleanup());
        handles.push(self.start_audit_log_cleanup());
        handles.push(self.start_query_tracker_cleanup());
        handles.push(self.start_search_job_cleanup());
        tracing::info!("Cleanup tasks started (leader-only)");

        handles
    }

    /// Shutdown all background tasks gracefully
    ///
    /// Waits for all tasks to complete, aborting any that take too long.
    pub async fn shutdown_all_tasks(&self) {
        tracing::info!("Initiating graceful shutdown of background tasks");

        let mut handles = self.task_handles.write().await;
        let num_tasks = handles.len();

        if num_tasks == 0 {
            tracing::info!("No background tasks to shutdown");
            return;
        }

        tracing::info!("Waiting for {} background task(s) to complete", num_tasks);

        // Give tasks a reasonable time to complete (30 seconds)
        let timeout = tokio::time::Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + timeout;

        while let Some(handle) = handles.pop() {
            match tokio::time::timeout_at(deadline, handle).await {
                Ok(Ok(())) => {
                    tracing::debug!("Background task completed successfully");
                }
                Ok(Err(e)) => {
                    tracing::warn!("Background task panicked: {:?}", e);
                }
                Err(_) => {
                    tracing::warn!("Background task did not complete within timeout, aborting");
                    // Task is already removed from handles, so it will be dropped and aborted
                }
            }
        }

        tracing::info!("All background tasks shutdown complete");
    }
}
