// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;

use crate::handlers::AuditExt;
use nanosiem_core::audit::actions::{
    PARSER_REPO_CREATED, PARSER_REPO_SYNCED, PARSER_REPO_UPDATED, RULE_REPO_CREATED,
    RULE_REPO_SYNCED, RULE_REPO_UPDATED,
};
use nanosiem_core::audit::{AuditEvent, AuditSource};
#[cfg(feature = "enterprise")]
use nanosiem_core::crypto::EncryptionService;
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
    /// Start the enterprise tenant-health exporter on the jobs leader.
    ///
    /// Configuration is default-off. Air-gap mode returns before constructing
    /// an HTTP client or task, even if stale exporter variables are present.
    #[cfg(feature = "enterprise")]
    pub fn start_tenant_health_exporter(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let config = match nanosiem_enterprise::health_exporter::HealthExporterConfig::from_env(
            self.config.airgap,
            self.config.deployment_id.as_deref(),
        ) {
            Ok(Some(config)) => config,
            Ok(None) => {
                tracing::info!(
                    "Tenant health export disabled; no exporter client or task constructed"
                );
                return Vec::new();
            }
            Err(error) => {
                tracing::error!(%error, "Tenant health export configuration rejected");
                return Vec::new();
            }
        };
        nanosiem_enterprise::health_exporter::start(
            config,
            self.dual_pool.clone(),
            self.config.schema_id,
            Arc::clone(&self.license_status),
            self.config.is_license_enabled(),
        )
    }

    /// Complete durable refresh-view invalidations created by ClickHouse
    /// migrations. Run immediately on leadership acquisition, then retry every
    /// minute; failures stay durable and are surfaced by SIEM Health.
    pub fn start_migration_refresh_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let admin = self.dual_pool.clickhouse_admin().clone();
        let runtime = self.dual_pool.clickhouse().clone();
        let database =
            std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "nanosiem".to_string());
        let shutdown = self.shutdown_token();

        tokio::spawn(async move {
            loop {
                match nanosiem_core::db::migration_refresh::process_pending(
                    &admin, &runtime, &database,
                )
                .await
                {
                    Ok(summary) if summary.attempted > 0 => tracing::info!(
                        attempted = summary.attempted,
                        succeeded = summary.succeeded,
                        failed = summary.failed,
                        exhausted = summary.exhausted,
                        "Processed durable post-migration refresh activations"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::error!(
                        %error,
                        "Post-migration refresh activation pass failed; will retry"
                    ),
                }

                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                }
            }
        })
    }

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

        // NAN-4954: deliver security-critical audit events whose inline
        // ClickHouse write failed from the PostgreSQL outbox. Every node drains
        // (SKIP LOCKED claims), and it keeps the backlog health event current.
        handles.push(
            Arc::new(nanosiem_core::audit::AuditOutboxDrainer::new(
                self.audit_emitter.clone(),
                self.pool.clone(),
            ))
            .start(self.shutdown_token()),
        );
        tracing::info!("Security audit outbox drainer started (all nodes, 10s tick)");

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
            handles.extend(self.start_distributed_ingest_scheduler());
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
            )
            .with_denied_source_audit(
                nanosiem_core::search::denied_source_audit::EmitterDeniedSourceAuditSink::new(
                    self.audit_emitter.clone(),
                ),
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

    fn start_distributed_ingest_scheduler(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let scheduler_service =
            nanosiem_core::SchedulerService::with_node_id(self.pool.clone(), self.node_id.clone());
        let poll_interval: u64 = std::env::var("SCHEDULER_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        tracing::info!(
            "Distributed scheduled jobs loop started ({}s poll)",
            poll_interval
        );
        vec![scheduler_service.start_scheduler_with_shutdown(poll_interval, self.shutdown_token())]
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
            // NAN-3816: DELETE archives the rule and keeps the row, so an
            // archived real-time rule must have its view dropped, never
            // recreated.
            if rule.detection_mode == DetectionMode::RealTime && !rule.archived {
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

    /// Start the hunt scheduler (NAN-2238).
    ///
    /// Reads `hunt_specs.schedule_cron` — which nothing did before this: the
    /// columns were written by import and the toggle, and only the manual
    /// trigger ever produced a sweep.
    ///
    /// Leader-only, and unlike most of the loops around it that is a
    /// CORRECTNESS requirement rather than a de-duplication nicety. Issuing a
    /// slot advances a durable watermark (`next_due_slot`) and, on catch-up,
    /// a second one (`coalesced_through_slot`); two replicas racing that pair
    /// is how a "one sweep per outage" guarantee turns into one per replica.
    /// The issuance write is additionally guarded on the watermark it planned
    /// against, so a race loses its transaction rather than double-advancing —
    /// leadership is the design, the guard is the proof.
    ///
    /// NOT egress-gated: every read and write is PostgreSQL-local, so hunts
    /// keep sweeping in an air-gapped install. `HUNT_SCHEDULER_ENABLED=false`
    /// leaves hunts manual-only without disabling each one, and the loop parks
    /// until shutdown in an open deployment where enterprise migration 9000054
    /// never created the tables (returning would trip the leader-scheduler
    /// supervisor and exit the jobs process, NAN-3376).
    #[cfg(feature = "enterprise")]
    pub fn start_hunt_scheduler(&self) -> tokio::task::JoinHandle<()> {
        nanosiem_core::hunts::HuntScheduler::from_env(self.pool.clone())
            .with_fence(self.leader_fence.clone())
            .start(self.shutdown_token())
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
    /// Initial delay: 60 seconds (MARKETPLACE_SYNC_INITIAL_DELAY_SECS), then
    /// polls every 12 hours (MARKETPLACE_SYNC_INTERVAL_SECS).
    /// Syncs any repos that have auto_sync_enabled and are past their sync_interval_hours.
    ///
    /// NAN-4946: the delay was 30 minutes, so a fresh install's Marketplace
    /// showed an empty catalog for half an hour. Parsers and rules now sync at
    /// boot (NAN-4940); the marketplace follows a minute later so the first
    /// GitHub pulls don't overlap.
    pub fn start_marketplace_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        // NAN-3405: same zero-panic clamp as the repo syncs (this branch's
        // marketplace loop did not clamp, unlike main's).
        let poll_secs = poll_interval_secs(
            std::env::var("MARKETPLACE_SYNC_INTERVAL_SECS")
                .ok()
                .as_deref(),
            43200,
        );
        let initial_delay_secs = marketplace_initial_delay_secs(
            std::env::var("MARKETPLACE_SYNC_INITIAL_DELAY_SECS")
                .ok()
                .as_deref(),
        );

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(initial_delay_secs)).await;

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
    /// Reconciles the first-party catalogs (NAN-4940), syncs at once, then polls
    /// every 15 minutes (PARSER_REPO_SYNC_INTERVAL_SECS).
    /// Syncs any repos that have auto_sync_enabled and are past their sync_interval_hours.
    /// Runs first among repo schedulers so parsers are available for rule evaluation.
    pub fn start_parser_repo_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::parser_repository::ParserRepositoryRepository;

        let state = self.clone();
        let poll_secs = repo_sync_interval_secs(
            std::env::var("PARSER_REPO_SYNC_INTERVAL_SECS")
                .ok()
                .as_deref(),
        );

        tokio::spawn(async move {
            // NAN-4940: register/reconcile the first-party catalogs, then sync
            // at once so a fresh install has the full catalog at first login
            // and an upgraded one starts following without a click.
            let mut reconciled = reconcile_first_party_catalogs(&state).await;

            let pool = state.pool.clone();
            let repo_repository = ParserRepositoryRepository::new(pool.clone());
            let service = ParserRepositoryService::new(pool.clone());

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                if !reconciled {
                    reconciled = reconcile_first_party_catalogs(&state).await;
                }
                match repo_repository.list_for_auto_sync().await {
                    Ok(repos) if repos.is_empty() => {}
                    Ok(repos) => {
                        tracing::info!(count = repos.len(), "Auto-syncing parser repos");
                        for r in &repos {
                            let result = service.sync_repository(r.id).await;
                            if let Err(e) = &result {
                                tracing::warn!(repo = %r.name, error = %e, "Failed to auto-sync parser repo");
                            }
                            state.emit_audit(scheduled_sync_audit(
                                AuditSource::ParserRepo,
                                PARSER_REPO_SYNCED,
                                "parser_repository",
                                r.id,
                                &r.name,
                                &r.branch,
                                result.as_ref().map(|s| {
                                    serde_json::json!({
                                        "commit": s.commit, "added": s.parsers_added, "updated": s.parsers_updated,
                                        "removed": s.parsers_removed, "total": s.parsers_total,
                                    })
                                }).map_err(|e| e.to_string()),
                            ));
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to list parser repos for auto-sync");
                    }
                }
            }
        })
    }

    /// Start the rule repo auto-sync scheduler
    ///
    /// Reconciles the first-party catalogs (NAN-4940), first pass after 30 s,
    /// then RULE_REPO_SYNC_INTERVAL_SECS (default 15 minutes).
    /// Syncs any repos that have auto_sync_enabled and are past their sync_interval_hours.
    pub fn start_rule_repo_sync_scheduler(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::rule_repository::RuleRepositoryRepository;

        let state = self.clone();
        let poll_secs = repo_sync_interval_secs(
            std::env::var("RULE_REPO_SYNC_INTERVAL_SECS")
                .ok()
                .as_deref(),
        );

        tokio::spawn(async move {
            // NAN-4940: idempotent with the parser scheduler's reconcile; a
            // short stagger keeps the two first GitHub pulls apart.
            let mut reconciled = reconcile_first_party_catalogs(&state).await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;

            let repo_repository = RuleRepositoryRepository::new(state.pool.clone());
            let service = RuleRepositoryService::with_dual_pool(&state.dual_pool);

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                if !reconciled {
                    reconciled = reconcile_first_party_catalogs(&state).await;
                }
                match repo_repository.list_for_auto_sync().await {
                    Ok(repos) if repos.is_empty() => {}
                    Ok(repos) => {
                        tracing::info!(count = repos.len(), "Auto-syncing rule repos");
                        for r in &repos {
                            let result = service.sync_repository(r.id).await;
                            if let Err(e) = &result {
                                tracing::warn!(repo = %r.name, error = %e, "Failed to auto-sync rule repo");
                            }
                            state.emit_audit(scheduled_sync_audit(
                                AuditSource::RuleRepo,
                                RULE_REPO_SYNCED,
                                "rule_repository",
                                r.id,
                                &r.name,
                                &r.branch,
                                result.as_ref().map(|s| {
                                    serde_json::json!({
                                        "commit": s.commit, "added": s.rules_added, "updated": s.rules_updated,
                                        "removed": s.rules_removed, "total": s.rules_total,
                                    })
                                }).map_err(|e| e.to_string()),
                            ));
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to list rule repos for auto-sync");
                    }
                }
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
            .unwrap_or(86400) // 24 hours
            // NAN-3405: tokio::time::interval(0) panics inside a supervised
            // leader loop (exit 70).
            .max(1);

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
            let boot_interval =
                std::time::Duration::from_secs(boot_interval_secs.clamp(15, interval_secs.max(60)));
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
    #[cfg(feature = "enterprise")]
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
        )
        // NAN-3219: each task reads the developer scheduler switch AND the
        // deployment-wide AI tuning mode (`system_settings`) before it runs.
        // Without the pool neither was ever consulted. Open builds have no
        // `ai_tuning_mode` column and read the default `on`.
        .with_pg_pool(self.pool.clone());

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
        ))
        .with_fence(self.leader_fence.clone());
        runner.start()
    }

    /// Start the SIEM health check scheduler (leader-only, every 12 hours)
    /// NAN-5170: meter daily customer ingest into `daily_usage` (leader-only,
    /// every 15 minutes). Local only: it feeds the in-app capacity warning and
    /// the licensed usage report / offline export. Never touches ingest.
    pub fn start_usage_meter(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::settings::usage_meter::{meter_once, METER_INTERVAL_SECS};
        let telemetry = self.log_telemetry_service.clone();
        let tier = nanosiem_core::TierSettings::new(self.pool.clone());
        let shutdown = self.shutdown_token();
        tokio::spawn(async move {
            // Let boot settle before the first rollup read.
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(METER_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = ticker.tick() => {}
                }
                let today = chrono::Utc::now().date_naive();
                match meter_once(&telemetry, &tier, today).await {
                    Ok(days) => tracing::debug!(days, "Daily usage metered"),
                    Err(error) => tracing::warn!(%error, "Daily usage metering failed; will retry"),
                }
            }
        })
    }

    pub fn start_siem_health_check_scheduler(&self) -> tokio::task::JoinHandle<()> {
        #[cfg(not(feature = "enterprise"))]
        use nanosiem_core::extensions::NoopSiemHealthAiAnalyzer;
        use nanosiem_core::extensions::SiemHealthAiAnalyzer;
        use std::sync::Arc;

        let ch_client = self.dual_pool.clickhouse().clone();
        let system_probe_client = self.dual_pool.clickhouse_admin().clone();
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
            let analyzer: Arc<dyn SiemHealthAiAnalyzer> = Arc::new(
                nanosiem_enterprise::siem_health::AiPoweredSiemHealthAnalyzer::new(ai_client),
            );
            Arc::new(crate::license_admission::LicensedSiemHealthAiAnalyzer::new(
                analyzer,
                self.license_status.clone(),
            ))
        };
        #[cfg(not(feature = "enterprise"))]
        let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = Arc::new(NoopSiemHealthAiAnalyzer);

        nanosiem_core::siem_health::scheduler::start(
            self.pool.clone(),
            ch_client,
            system_probe_client,
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

        let fence = self.leader_fence.clone();
        let fence_pool = self.pool.clone();
        tokio::spawn(async move {
            let repo = nanosiem_core::observability::MetricMonitorRepository::new(pool.clone());
            // Last-evaluation instant per monitor id (in-memory due-time gate).
            let mut last_eval: HashMap<Uuid, Instant> = HashMap::new();

            let interval = tokio::time::interval(std::time::Duration::from_secs(30));
            tokio::pin!(interval);

            tracing::info!("Metric-monitor evaluator started (30s tick)");

            loop {
                interval.tick().await;
                // NAN-4933: a superseded jobs leader never raises an alert.
                if !fence.still_leader(&fence_pool).await {
                    continue;
                }

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
    /// Incident lifecycle (NAN-3975): a persistent breach updates ONE open
    /// incident per `(monitor, series)` (latest value, original start); a known
    /// healthy sample closes it; missing data preserves it. Only openings
    /// notify webhooks. Replaces the old 1h time-based re-arm, which opened a
    /// duplicate incident every hour of a continuous breach and never recovered.
    async fn evaluate_one_metric_monitor(
        search_service: &nanosiem_core::SearchService,
        pool: &sqlx::PgPool,
        monitor: &nanosiem_core::observability::MetricMonitor,
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

        // The ClickHouse query runs with NO PostgreSQL transaction or lock
        // held (a slow query must not park pool connections or block analyst
        // acknowledge/close on row locks). Ordering is enforced afterwards by
        // the durable per-series cursor (`advance_cursor`).
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

        // Short apply transaction (lock, reconcile, per-series cursor + incident
        // lifecycle) — see `metric_alert_lifecycle::apply_evaluation`.
        let notifications = nanosiem_core::observability::metric_alert_lifecycle::apply_evaluation(
            pool, monitor, results, now,
        )
        .await?;
        // NAN-1741 A1: forward openings to obs_alert-subscribed webhooks (kind
        // "metric_monitor", migration 217) only after the rows are durable.
        for nanosiem_core::observability::metric_alert_lifecycle::IncidentOpened {
            id,
            entity,
            payload,
        } in notifications
        {
            webhook_service
                .fire_alert(
                    id,
                    "metric_monitor",
                    None,
                    &monitor.name,
                    "high",
                    entity,
                    &payload,
                    now,
                )
                .await;
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

        let fence = self.leader_fence.clone();
        let fence_pool = self.pool.clone();
        tokio::spawn(async move {
            let repo = nanosiem_core::observability::SloRepository::new(pool.clone());
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
                // NAN-4933: a superseded jobs leader never raises an alert.
                if !fence.still_leader(&fence_pool).await {
                    continue;
                }

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

                    let (payload, evaluated_at) = match breaching {
                        Some(found) => found,
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

                    // Durable, atomic admission (NAN-3894 review): one
                    // transaction re-checks that THIS evaluation is still the
                    // current persisted `breaching` result, applies the
                    // durable re-arm check (survives restart / leader
                    // failover, holds the window across momentary
                    // recoveries) and inserts the alert. A result superseded
                    // by a newer evaluation raises nothing.
                    match nanosiem_core::observability::evaluation_state::admit_slo_alert(
                        &pool,
                        &slo,
                        evaluated_at,
                        rearm_secs,
                        &payload,
                    )
                    .await
                    {
                        Ok(Some(alert)) => {
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
                        // Superseded result or within the re-arm window.
                        Ok(None) => {}
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

    /// Evaluate one SLO: recompute the SLI over its rolling window with a
    /// full-window coverage probe (NAN-3894), apply the shared
    /// budget/burn/status math ([`nanosiem_core::observability::eval::slo_evaluation`],
    /// also used by the read path), persist the result, and — if *breaching*
    /// and this result was the newest recorded — return the burn payload
    /// (single-element JSON array) for the alert's `matched_events`.
    ///
    /// Returns `Ok(None)` when the SLO is not breaching, when the window has
    /// no data (O17: zero traffic is neither a breach nor a recovery), when
    /// the window is `partial` (the target service's telemetry does not cover it: no
    /// fabricated attainment, no burn alert), or when the definition changed
    /// or a newer result already landed while the query ran.
    async fn evaluate_one_slo(
        search_service: &nanosiem_core::SearchService,
        pool: &sqlx::PgPool,
        slo: &nanosiem_core::observability::SloDefinition,
    ) -> anyhow::Result<Option<(serde_json::Value, chrono::DateTime<chrono::Utc>)>> {
        use nanosiem_core::observability::{eval, evaluation_state};
        use nanosiem_core::query::TimeRange;

        let now = chrono::Utc::now();
        let begin = now - chrono::Duration::days(slo.window_days.max(1) as i64);
        let time_range = TimeRange::new(begin, now);

        let (current, total_spans, no_data, complete) = search_service
            .observability_slo_compute_with_coverage(
                &slo.service,
                slo.sli_kind.to_query_kind(),
                slo.latency_threshold_ms,
                &time_range,
            )
            .await
            .map_err(|e| anyhow::anyhow!("SLO compute failed: {e}"))?;

        let evaluation = eval::slo_evaluation(slo.target, current, no_data, !complete);
        let fresh = evaluation_state::record_slo_evaluation(
            pool,
            slo,
            current,
            total_spans,
            no_data,
            &evaluation,
            now,
        )
        .await
        .map_err(|e| anyhow::anyhow!("SLO evaluation state write failed: {e}"))?;
        if !fresh || evaluation.status != "breaching" {
            return Ok(None);
        }
        Ok(Some((
            eval::slo_payload(slo, current, total_spans.max(0) as u64, now),
            now,
        )))
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
///
/// The scheduler applies this inside `evaluation_state::admit_slo_alert`
/// (atomically with the alert insert); this wrapper keeps the re-arm
/// boundary tests below pinned to the shared core decision.
#[cfg(test)]
fn slo_alert_within_rearm(
    last_created: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    rearm_secs: u64,
) -> bool {
    nanosiem_core::observability::eval::within_rearm(last_created, now, rearm_secs)
}

/// NAN-4940: register the first-party catalogs on a first boot and reconcile
/// them on an upgrade (see `nanosiem_core::content_catalog_defaults`). Only
/// called from the egress schedulers, which air-gapped installs never start.
/// Never fatal: on a database error it returns `false` and the caller retries
/// on its next poll.
pub(crate) async fn reconcile_first_party_catalogs(state: &AppState) -> bool {
    use nanosiem_core::content_catalog_defaults::{
        ensure_first_party_catalogs, CatalogPlan, FirstPartyCatalog,
    };
    let profile = match nanosiem_core::schema::active_profile_from_env() {
        Ok(profile) => profile.id(),
        Err(error) => {
            // Boot fails fast on a bad profile; never guess a content channel.
            tracing::warn!(%error, "First-party content catalog reconcile skipped: schema profile unresolved");
            return true;
        }
    };
    match ensure_first_party_catalogs(&state.pool, profile).await {
        Ok(outcomes) => {
            for outcome in &outcomes {
                if !outcome.changed() {
                    tracing::debug!(catalog = %outcome.catalog.url(), plan = ?outcome.plan, "First-party content catalog unchanged");
                    continue;
                }
                let created = matches!(outcome.plan, CatalogPlan::Create { .. });
                let parsers = outcome.catalog == FirstPartyCatalog::Parsers.spec();
                let (source, action, resource) = match (parsers, created) {
                    (true, true) => (
                        AuditSource::ParserRepo,
                        PARSER_REPO_CREATED,
                        "parser_repository",
                    ),
                    (true, false) => (
                        AuditSource::ParserRepo,
                        PARSER_REPO_UPDATED,
                        "parser_repository",
                    ),
                    (false, true) => (AuditSource::RuleRepo, RULE_REPO_CREATED, "rule_repository"),
                    (false, false) => (AuditSource::RuleRepo, RULE_REPO_UPDATED, "rule_repository"),
                };
                tracing::info!(
                    catalog = %outcome.catalog.url(),
                    repository_id = ?outcome.repository_id,
                    plan = ?outcome.plan,
                    "First-party content catalog reconciled"
                );
                state.emit_audit(
                    AuditEvent::builder(source, action)
                        .resource(resource, outcome.repository_id, Some(outcome.name.clone()))
                        .details(outcome.audit_details())
                        .build(),
                );
            }
            true
        }
        Err(error) => {
            tracing::warn!(%error, "First-party content catalog reconcile failed; retrying on the next poll");
            false
        }
    }
}

/// Audit record for one scheduled (system-initiated) repository sync.
fn scheduled_sync_audit(
    source: AuditSource,
    action: &str,
    resource: &str,
    id: uuid::Uuid,
    name: &str,
    branch: &str,
    outcome: Result<serde_json::Value, String>,
) -> AuditEvent {
    let success = outcome.is_ok();
    let mut details = serde_json::json!({"scheduled": true, "branch": branch});
    match outcome {
        Ok(summary) => details["summary"] = summary,
        Err(error) => details["error"] = error.into(),
    }
    AuditEvent::builder(source, action)
        .resource(resource, Some(id), Some(name.to_owned()))
        .success(success)
        .details(details)
        .build()
}

/// Repo auto-sync poll interval from its env override (default 15 minutes).
///
/// NAN-3405: clamped to at least one second. `tokio::time::interval(0)`
/// panics, and the jobs binary supervises leader schedulers as loops, so an
/// operator setting `*_REPO_SYNC_INTERVAL_SECS=0` turned into an exit-70
/// crash loop.
///
/// NAN-4940: the default poll is 15 minutes (was 12 hours). A poll only
/// selects repositories past their own `sync_interval_hours`, so it costs one
/// PostgreSQL query; the old 12-hour poll capped every repository at twice a
/// day whatever its interval said, so the hourly first-party catalogs could
/// not stay current.
fn repo_sync_interval_secs(raw: Option<&str>) -> u64 {
    poll_interval_secs(raw, 900)
}

/// NAN-4946: delay before the first marketplace sync. Defaults to 60 s (was a
/// hard-coded 30 minutes); zero is allowed (sync at once).
pub(crate) fn marketplace_initial_delay_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(60)
}

/// Env-override poll interval with a default, clamped to at least one second
/// (NAN-3405). The marketplace sync keeps its 12-hour default.
fn poll_interval_secs(raw: Option<&str>, default_secs: u64) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default_secs)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::{repo_sync_interval_secs, slo_alert_within_rearm};
    use chrono::{Duration, Utc};

    #[test]
    fn repo_sync_interval_defaults_and_never_reaches_zero() {
        assert_eq!(repo_sync_interval_secs(None), 900);
        assert_eq!(repo_sync_interval_secs(Some("not-a-number")), 900);
        assert_eq!(repo_sync_interval_secs(Some("900")), 900);
        assert_eq!(repo_sync_interval_secs(Some(" 900 ")), 900);
        // NAN-3405: zero would panic tokio::time::interval inside a
        // supervised leader loop (exit 70).
        assert_eq!(repo_sync_interval_secs(Some("0")), 1);
    }

    #[tokio::test]
    async fn repo_sync_interval_is_always_a_valid_tokio_interval() {
        for raw in [None, Some("0"), Some(""), Some("1")] {
            let secs = repo_sync_interval_secs(raw);
            // Panics on a zero period; must not for any accepted input.
            let _ = tokio::time::interval(std::time::Duration::from_secs(secs));
        }
    }

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

#[cfg(test)]
#[path = "schedulers_marketplace_tests.rs"]
mod marketplace_delay_tests;
