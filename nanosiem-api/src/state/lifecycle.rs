// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;

use std::sync::Arc;
use tokio::task::{JoinError, JoinHandle};

#[derive(Debug, Default, PartialEq, Eq)]
struct TaskShutdownSummary {
    completed: usize,
    cancelled: usize,
    failed: usize,
}

fn record_task_result(result: Result<(), JoinError>, summary: &mut TaskShutdownSummary) {
    match result {
        Ok(()) => summary.completed += 1,
        Err(error) if error.is_cancelled() => summary.cancelled += 1,
        Err(error) => {
            summary.failed += 1;
            tracing::warn!(?error, "Background task failed during shutdown");
        }
    }
}

async fn shutdown_task_handles(
    mut handles: Vec<JoinHandle<()>>,
    timeout: tokio::time::Duration,
) -> TaskShutdownSummary {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut summary = TaskShutdownSummary::default();

    while let Some(mut handle) = handles.pop() {
        match tokio::time::timeout_at(deadline, &mut handle).await {
            Ok(result) => record_task_result(result, &mut summary),
            Err(_) => {
                tracing::warn!(
                    remaining = handles.len() + 1,
                    "Background task shutdown deadline reached; aborting remaining tasks"
                );

                handle.abort();
                record_task_result(handle.await, &mut summary);

                for handle in &handles {
                    handle.abort();
                }
                while let Some(handle) = handles.pop() {
                    record_task_result(handle.await, &mut summary);
                }
                break;
            }
        }
    }

    summary
}

impl AppState {
    /// Keep a licensed-only worker group aligned with live admission. C05
    /// renewals and online checks are hot, so a one-time startup decision is
    /// insufficient: workers stop at hard expiry and resume after renewal.
    #[cfg(feature = "enterprise")]
    pub fn start_component_worker_supervisor<F>(
        &self,
        capability: crate::license_admission::WorkerCapability,
        name: &'static str,
        start: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(&AppState) -> Vec<tokio::task::JoinHandle<()>> + Send + Sync + 'static,
    {
        let state = self.clone();
        let shutdown = self.shutdown_token();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut workers = ComponentWorkers::default();

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        abort_component_workers(&mut workers).await;
                        return;
                    }
                    _ = interval.tick() => {}
                }

                let allowed = crate::license_admission::licensed_features_available(
                    &*state.license_status.read().await,
                    chrono::Utc::now(),
                );
                if !allowed {
                    if !workers.is_empty() {
                        tracing::warn!(
                            worker_group = name,
                            ?capability,
                            "Stopping licensed workers at license hard stop"
                        );
                        abort_component_workers(&mut workers).await;
                    }
                    continue;
                }

                if workers
                    .handles
                    .iter()
                    .any(tokio::task::JoinHandle::is_finished)
                {
                    abort_component_workers(&mut workers).await;
                    panic!("licensed worker group {name} stopped unexpectedly");
                }
                if workers.is_empty() {
                    workers.handles = start(&state);
                    assert!(
                        !workers.is_empty(),
                        "licensed worker group {name} started no tasks"
                    );
                    tracing::info!(
                        worker_group = name,
                        ?capability,
                        tasks = workers.len(),
                        "Licensed worker group started"
                    );
                }
            }
        })
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

    /// Drain the durable system-health outbox through the existing notification
    /// channel delivery spine. Leader-only invocation prevents duplicate work;
    /// row claims remain fenced with `FOR UPDATE SKIP LOCKED` for safe handover.
    pub fn start_system_health_dispatcher(&self) -> tokio::task::JoinHandle<()> {
        let repository =
            nanosiem_core::system_health::SystemHealthRepository::new(self.pool.clone());
        let dispatcher =
            std::sync::Arc::new(nanosiem_core::system_health::SystemHealthDispatcher::new(
                repository,
                self.node_id.clone(),
            ));
        dispatcher.start(std::time::Duration::from_secs(2))
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
                            tracing::debug!(
                                "PgListener case_changes keepalive timeout, reconnecting"
                            );
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Recover case investigations that were interrupted by a prior process
    /// and sweep due re-triage coordination rows. This is a licensed worker:
    /// callers must place it inside the case component supervisor so it never
    /// starts before admission and is aborted at hard expiry.
    #[cfg(feature = "enterprise")]
    pub fn start_shadow_investigation_recovery(&self) -> tokio::task::JoinHandle<()> {
        let service = self.shadow_investigation_service.clone();

        tokio::spawn(async move {
            // NAN-1490: resume from the durable checkpoint without recharging
            // credit. NAN-1488: also recover orphaned DUE coordination rows.
            service.resume_interrupted().await;
            service.sweep_due_coordination().await;

            // The component supervisor owns persistent worker handles and
            // treats an early return as a crashed group. Recovery is one-shot,
            // but its admitted task stays alive until hard stop/shutdown aborts
            // the whole case group.
            std::future::pending::<()>().await;
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
        // NAN-5214: `start()` reads the watermark from PostgreSQL. A failover
        // right after this node won the lease used to log one error and leave
        // the leader with no signal -> alert pipeline for its whole term.
        // Retry with backoff instead; the task is aborted on step-down, and the
        // guard aborts the processor it started with it.
        let processor = Arc::clone(&self.signal_processor);
        handles.push(tokio::spawn(async move {
            run_signal_processor_until_started(processor).await;
        }));

        // Health monitoring can create notifications and perform paid AI
        // connectivity checks. Keep the entire check + transactional notify
        // path under leadership so replicas do not duplicate external work.
        handles.push(self.start_health_scheduler());
        handles.push(self.start_system_health_dispatcher());
        tracing::info!("System health outbox dispatcher started (leader-only)");
        tracing::info!("Health monitoring scheduler started (leader-only)");

        // Enterprise hosted/BYOC deployments may opt into a compact OTLP
        // health snapshot for the managed monitoring plane. Jobs leadership
        // owns the singleton; the exporter applies its own air-gap hard gate.
        #[cfg(feature = "enterprise")]
        {
            let exporter_handles = self.start_tenant_health_exporter();
            if !exporter_handles.is_empty() {
                tracing::info!(
                    tasks = exporter_handles.len(),
                    "Tenant health exporter started (leader-only)"
                );
                handles.extend(exporter_handles);
            }
        }

        // NAN-4977: migrations commit durable refresh invalidations rather than
        // assuming a one-shot SYSTEM REFRESH/RELOAD can survive deploy races.
        handles.push(self.start_migration_refresh_scheduler());
        tracing::info!("Post-migration refresh activation started (leader-only, 60s tick)");

        // === Egress schedulers — skipped in air-gap mode ===
        // Air-gapped installs have no outbound internet, so any job that fetches
        // from the internet (GitHub repo sync, model/MITRE catalogs)
        // must NOT start — bundles arrive via the air-gap import surface instead.
        // Internal jobs (signal processor above; tuning / disk-pressure /
        // siem-health / cleanups below) are unaffected.
        if !self.config.egress_jobs_enabled() {
            tracing::info!(
                "AIRGAP_MODE: skipping egress background jobs (identity, repo auto-sync, marketplace, model-catalog, MITRE catalog, docs-rag)"
            );
        } else {
            // NAN-4959: no native IPinfo download job. IPinfo Lite comes only
            // from the signed platform feed bundle (consumer started below).

            // Custom enrichment scheduler — runs Deno data enrichments on their
            // cron schedules. Enterprise only after Phase 3.3 of NAN-744 (the
            // sandbox runtime + scheduler live in nanosiem-enterprise).
            #[cfg(feature = "enterprise")]
            {
                handles.push(self.start_component_worker_supervisor(
                    crate::license_admission::WorkerCapability::Collectors,
                    "leader_custom_enrichment",
                    |state| vec![state.start_custom_enrichment_scheduler()],
                ));

                // Collector execution is enterprise-only even though its
                // output is delivered into the open ingest lane.
                handles.push(self.start_component_worker_supervisor(
                    crate::license_admission::WorkerCapability::Collectors,
                    "leader_collectors",
                    |state| vec![state.start_collector_scheduler()],
                ));
            }

            // Identity-provider sync is licensed in enterprise builds. Keep
            // the open-build scheduler wiring unchanged for its core stubs.
            #[cfg(feature = "enterprise")]
            handles.push(self.start_component_worker_supervisor(
                crate::license_admission::WorkerCapability::Sso,
                "leader_sso",
                |state| vec![state.start_identity_sync_scheduler()],
            ));
            #[cfg(not(feature = "enterprise"))]
            handles.push(self.start_identity_sync_scheduler());
            tracing::info!("Identity sync scheduler registered (leader-only)");

            // Repository auto-sync schedulers. Both reconcile the first-party
            // nano-rs catalogs (NAN-4940) and sync at once; rules are staggered
            // 30 s after parsers so the first GitHub pulls don't overlap.
            //   Marketplace: 60 s delay (NAN-4946)
            handles.push(self.start_parser_repo_sync_scheduler());
            tracing::info!(
                "Parser repo auto-sync scheduler started (leader-only, first-party catalogs reconciled)"
            );

            handles.push(self.start_rule_repo_sync_scheduler());
            tracing::info!(
                "Rule repo auto-sync scheduler started (leader-only, 30s initial delay)"
            );

            // Enterprise first-party content follow (NAN-4947), leader-only and
            // egress-gated like the repository schedulers above. One generic
            // seam; the workers are named in the enterprise crate.
            #[cfg(feature = "enterprise")]
            {
                handles.push(self.start_component_worker_supervisor(
                    crate::license_admission::WorkerCapability::Soar,
                    "leader_soar",
                    |state| {
                        nanosiem_enterprise::handlers::extension_leader_egress_jobs(
                            state,
                            state.leader_fence.clone(),
                        )
                    },
                ));
            }

            handles.push(self.start_marketplace_sync_scheduler());
            tracing::info!(
                "Marketplace repo auto-sync scheduler started (leader-only, 60s initial delay)"
            );

            handles.push(self.start_mitre_sync_scheduler());
            tracing::info!("MITRE catalog sync scheduler started (leader-only)");

            // Model catalog auto-sync (daily by default) — enterprise only.
            #[cfg(feature = "enterprise")]
            {
                handles.push(self.start_component_worker_supervisor(
                    crate::license_admission::WorkerCapability::Melod,
                    "leader_melod",
                    |state| vec![state.start_model_catalog_sync_scheduler()],
                ));
            }

            // Synthetic-check runner (NAN-1538) — outbound HTTP probes, so it is
            // egress-gated alongside the other internet-facing jobs.
            handles.push(self.start_synthetics_runner());
            tracing::info!("Synthetic-check runner started (leader-only, 15s tick)");
        }

        // NAN-1810: the risk-decay sweep (NAN-1675) is retired — the
        // `entity_risk_scores` snapshot it maintained is dropped, and every
        // risk read computes decayed scores live from ClickHouse (NAN-1806).

        // NAN-1805: the risk-notable evaluator (NAN-1792) is retired — risk
        // notables now run as an ordinary scheduled detection rule over
        // `dataset=risk` (seeded by enterprise migration 9000033) with the
        // per-(rule, entity) alert_cooldown_minutes throttle carrying the
        // scheduler's durable hysteresis, so no dedicated scheduler starts here.

        // NAN-4948: nano's signed platform feed bundle (IPinfo Lite, ThreatFox,
        // Tor). Leader-only so one node fetches and loads. NOT under the egress
        // gate: the loop skips the online check itself in air-gap mode but
        // still withdraws feeds that pass their hard expiry.
        handles.push(
            std::sync::Arc::new(
                crate::handlers::enrichment::consumer(self).with_fence(self.leader_fence.clone()),
            )
            .start(self.shutdown_token()),
        );
        tracing::info!("Platform feed bundle consumer started (leader-only)");

        // NAN-4955: nano content channels (parsers, rules, playbooks,
        // marketplace / model catalogs, extension channels) from the app
        // as signed bundles; never GitHub. Leader-only; the loop returns at
        // once in air-gap mode (offline import still works through the API).
        handles.push(
            std::sync::Arc::new(
                crate::handlers::content_channels::consumer(self)
                    .with_fence(self.leader_fence.clone()),
            )
            .start(self.shutdown_token()),
        );
        tracing::info!("Content channel consumer started (leader-only)");

        // Tuning scheduler (low-frequency singleton). Enterprise C05
        // renewals can change components without a restart, so its workers
        // are supervised against the live admission snapshot.
        #[cfg(feature = "enterprise")]
        handles.push(self.start_component_worker_supervisor(
            crate::license_admission::WorkerCapability::Pivt,
            "leader_pivt",
            AppState::start_tuning_scheduler,
        ));

        // Disk pressure scheduler
        handles.push(Arc::clone(&self.disk_pressure_service).start(self.leader_fence.clone()));
        tracing::info!("Disk pressure scheduler started (leader-only)");

        // NAN-5170: daily ingest metering (local `daily_usage` record).
        handles.push(self.start_usage_meter());
        tracing::info!("Daily usage meter started (leader-only, 15m interval)");

        // SIEM health check (AI-driven data quality analysis, every 12 hours)
        handles.push(self.start_siem_health_check_scheduler());
        tracing::info!("SIEM health check scheduler started (leader-only, 12h interval)");

        // Disabled means not constructed at all. When enabled, discovery and
        // replica failures are a degraded-coverage signal, never grounds for
        // terminating jobs. The leader-owned retry task is aborted with the
        // rest of this handle set when the lease is lost.
        if nanosiem_core::ingest_watchdog::enabled_from_env() {
            handles.push(tokio::spawn(async move {
                loop {
                    match nanosiem_core::ingest_watchdog::IngestWatchdog::from_env().await {
                        Ok(watchdog) => watchdog.run().await,
                        Err(error) => tracing::warn!(
                            %error,
                            "Ingest watchdog initialization failed; jobs remain up and discovery will retry"
                        ),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            }));
            tracing::info!("Ingest watchdog supervisor started (leader-only)");
        } else {
            tracing::info!("Ingest watchdog disabled; no watchdog client constructed");
        }

        // Metric-monitor evaluator (NAN-1540) — threshold alerts on OTLP metric
        // aggregates. Leader-only so a breach raises exactly one alert per due
        // tick across the jobs fleet.
        handles.push(self.start_metric_monitor_scheduler());
        tracing::info!("Metric-monitor evaluator started (leader-only, 30s tick)");

        // SLO burn-rate evaluator (NAN-1563) — recomputes each SLO's SLI/burn
        // over its rolling window and raises a `kind:"slo"` alert on breach.
        // ClickHouse-internal (no egress), leader-only so a breach raises exactly
        // one alert per re-arm interval across the jobs fleet.
        handles.push(self.start_slo_scheduler());
        tracing::info!("SLO burn-rate evaluator started (leader-only, 60s tick)");

        // Hunt scheduler (NAN-2238) — issues scheduled hunt sweeps, collapses a
        // missed backlog into ONE catch-up sweep, and reclaims sweeps from
        // runners that died holding a lease. PostgreSQL-only, so it is NOT
        // egress-gated and keeps working air-gapped; see
        // `start_hunt_scheduler` for why leadership is load-bearing here.
        #[cfg(feature = "enterprise")]
        {
            handles.push(self.start_hunt_scheduler());
            tracing::info!("Hunt scheduler started (leader-only, 60s tick)");
        }

        // Cleanup tasks (leader-only to avoid duplicate work across nodes).
        // Job store / wizard session / melod session cleanups are enterprise-only —
        // the underlying repos live in nanosiem-enterprise::melod.
        #[cfg(feature = "enterprise")]
        {
            handles.push(self.start_component_worker_supervisor(
                crate::license_admission::WorkerCapability::Melod,
                "leader_melod_cleanup",
                |state| {
                    vec![
                        state.start_job_store_cleanup(),
                        state.start_wizard_session_cleanup(),
                        state.start_melod_session_cleanup(),
                    ]
                },
            ));
            // Agent enrichment cache cleanup is enterprise-only after
            // Phase 3.3 (the agent_enrichment module + repository live in
            // nanosiem-enterprise).
            handles.push(self.start_component_worker_supervisor(
                crate::license_admission::WorkerCapability::Collectors,
                "leader_enrichment_cleanup",
                |state| vec![state.start_enrichment_cache_cleanup()],
            ));
            // G2 (NAN-1749): reconciliation sweep that re-groups alerting-mode
            // alerts left `case_id NULL` by a grouping failure/timeout. Gated to
            // enterprise because open-core uses the no-op grouping hook, so its
            // alerts are caseless by design and the sweep would scan them
            // pointlessly every pass.
            handles.push(self.start_component_worker_supervisor(
                crate::license_admission::WorkerCapability::Cases,
                "leader_cases_cleanup",
                |state| vec![state.start_ungrouped_alert_reconciliation()],
            ));
            tracing::info!("Licensed cleanup supervisors registered (leader-only)");
        }
        handles.push(self.start_rate_limit_cleanup());
        handles.push(self.start_query_tracker_cleanup());
        handles.push(self.start_search_job_cleanup());
        handles.push(self.start_detection_dedup_cleanup());
        handles.push(self.start_lookup_generation_cleanup());
        handles.push(self.start_prevalence_dict_health_monitor());
        tracing::info!("Cleanup tasks started (leader-only)");

        // NAN-4933: move stored secrets onto the active credential key.
        handles.push(self.start_credential_key_rewrap_scheduler());
        tracing::info!("Credential key re-wrap scheduler started (leader-only)");

        handles
    }

    /// Shutdown all background tasks gracefully
    ///
    /// Waits for all tasks to complete, aborting any that take too long.
    pub async fn shutdown_all_tasks(&self) {
        tracing::info!("Initiating graceful shutdown of background tasks");
        let handles = self.task_registry.begin_shutdown().await;
        let num_tasks = handles.len();

        if num_tasks == 0 {
            tracing::info!("No background tasks to shutdown");
            return;
        }

        tracing::info!("Waiting for {} background task(s) to complete", num_tasks);

        // Give in-flight work a shared 30-second deadline before cancellation.
        let timeout = tokio::time::Duration::from_secs(30);
        let summary = shutdown_task_handles(handles, timeout).await;

        tracing::info!(
            completed = summary.completed,
            cancelled = summary.cancelled,
            failed = summary.failed,
            "All tracked background tasks stopped"
        );
    }
}

#[cfg(feature = "enterprise")]
#[derive(Default)]
struct ComponentWorkers {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "enterprise")]
impl ComponentWorkers {
    fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    fn len(&self) -> usize {
        self.handles.len()
    }
}

#[cfg(feature = "enterprise")]
impl Drop for ComponentWorkers {
    fn drop(&mut self) {
        for worker in &self.handles {
            worker.abort();
        }
    }
}

#[cfg(feature = "enterprise")]
async fn abort_component_workers(workers: &mut ComponentWorkers) {
    for worker in workers.handles.iter() {
        worker.abort();
    }
    while let Some(worker) = workers.handles.pop() {
        match worker.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => tracing::warn!(?error, "Licensed worker stopped with an error"),
        }
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RunningGuard(Arc<AtomicBool>);

    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_completes_finished_tasks() {
        let handle = tokio::spawn(async {});

        let summary =
            shutdown_task_handles(vec![handle], tokio::time::Duration::from_secs(1)).await;

        assert_eq!(
            summary,
            TaskShutdownSummary {
                completed: 1,
                cancelled: 0,
                failed: 0,
            }
        );
    }

    #[tokio::test]
    async fn shutdown_aborts_and_awaits_tasks_after_deadline() {
        let running = Arc::new(AtomicBool::new(true));
        let started = Arc::new(tokio::sync::Notify::new());
        let task_running = Arc::clone(&running);
        let task_started = Arc::clone(&started);
        let handle = tokio::spawn(async move {
            let _guard = RunningGuard(task_running);
            task_started.notify_one();
            std::future::pending::<()>().await;
        });
        started.notified().await;

        let summary =
            shutdown_task_handles(vec![handle], tokio::time::Duration::from_millis(10)).await;

        assert_eq!(
            summary,
            TaskShutdownSummary {
                completed: 0,
                cancelled: 1,
                failed: 0,
            }
        );
        assert!(!running.load(Ordering::SeqCst));
    }
}

/// Aborts the wrapped task when dropped (a supervisor that is itself aborted
/// must take the task it spawned down with it).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Start the signal processor, retrying a failed start (PostgreSQL briefly
/// unavailable during a primary switch) with capped exponential backoff, then
/// run it until it ends.
async fn run_signal_processor_until_started(
    processor: Arc<nanosiem_core::detection::signal_processor::SignalProcessor>,
) {
    let mut delay = std::time::Duration::from_secs(1);
    loop {
        match processor.start().await {
            Ok(handle) => {
                tracing::info!("Signal processor started (leader-only)");
                let mut guard = AbortOnDrop(handle);
                if let Err(error) = (&mut guard.0).await {
                    if !error.is_cancelled() {
                        tracing::error!(?error, "Signal processor task failed");
                    }
                }
                return;
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    retry_in_secs = delay.as_secs(),
                    "Failed to start signal processor; retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(30));
            }
        }
    }
}
