// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed Detection Scheduler
//!
//! Replaces the single-leader DetectionScheduler with a distributed model where
//! all API nodes compete for work via `SELECT FOR UPDATE SKIP LOCKED`. Each node
//! claims a batch of due rules, executes them concurrently, and releases claims
//! with the next scheduled run time.
//!
//! Key advantages over the old advisory-lock scheduler:
//! - **Horizontal scaling**: N nodes share the rule execution load
//! - **Self-healing**: stale claims from crashed nodes are automatically reclaimed
//! - **No single bottleneck**: no leader election needed for detection rules

use chrono::{DateTime, Duration, Utc};
use futures::stream::{self, StreamExt};
use futures::FutureExt;
use metrics::{counter, histogram};
use sqlx::PgPool;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::db::repository::detection_rules::{DetectionRuleRepository, LateReplayReleaseOutcome};
use crate::models::detection_rule::DetectionMode;
use crate::models::DetectionRule;
use crate::search::TimeRangeInput;
use crate::settings::DeveloperSettingsRepository;
use crate::shutdown::ShutdownToken;

use super::scheduler::{
    calculate_next_run_phased, configured_phase_cap_secs, DEFAULT_PHASE_CAP_SECS,
};
use super::service::DetectionService;

/// Configuration for the distributed detection scheduler
#[derive(Debug, Clone)]
pub struct DistributedSchedulerConfig {
    /// How often to poll for due rules (seconds)
    pub poll_interval_secs: u64,
    /// Maximum rules to claim per poll cycle
    pub batch_size: i64,
    /// Maximum concurrent rule executions per node
    pub max_concurrent_executions: usize,
    /// Seconds after which a claimed rule is considered stale (node crash recovery)
    pub stale_claim_timeout_secs: i64,
    /// Hard cap (seconds) on a rule's deterministic phase offset. Each
    /// scheduled rule fires at `cron tick + hash(rule id) mod min(interval/2,
    /// cap)`, spreading a large rule set across its interval while keeping the
    /// cron's wall-clock time (a daily 09:00 rule runs by 09:05 at the default
    /// 300 s). Real-time micro-batches always use 0. `NRT_PHASE_MAX_SECS`.
    pub phase_max_secs: u64,
    /// Default lookback period for first-run rules (minutes)
    pub default_lookback_minutes: i64,
    /// Upper bound on the catch-up window derived from `last_run_at` (minutes).
    ///
    /// Caps how far back a long-dormant rule scans on its first run after being
    /// resumed/reclaimed (audit D22). Without this, a rule idle for months would
    /// build a multi-month window that times out — and, with the D1 fix leaving
    /// `last_run_at` untouched on failure, would then retry that giant window
    /// forever. The cap bounds the scan so it succeeds and progresses. Explicit
    /// `lookback_minutes` rules are unaffected (their window is intentional).
    pub max_catchup_minutes: i64,
    /// Maximum seconds a single rule execution may run before being timed out (default: 300s)
    pub execution_timeout_secs: u64,
    /// Event-time delay applied to lake log-rule windows.
    ///
    /// The object writer publishes a small batch after its oldest event was
    /// observed. Holding the rule watermark slightly behind wall clock keeps
    /// ordinary batching on the normal scheduler path; genuinely older events
    /// still enter durable late-arrival reconciliation.
    pub lake_event_time_delay_secs: i64,
    /// Independent poll cadence for committed-object late-arrival repair.
    pub late_replay_poll_interval_secs: u64,
    /// Maximum committed-object publications planned per poll.
    ///
    /// Publication planning is metadata-only and must be able to outrun object
    /// creation, including a migration/backfill. Keep this independent from
    /// the much smaller execution claim batch so draining publication metadata
    /// cannot launch an unbounded number of detection queries at once.
    pub late_replay_publication_batch_size: usize,
    /// Maximum repair jobs claimed per poll.
    pub late_replay_batch_size: usize,
    /// Maximum concurrently executing late-arrival repair windows per node.
    pub late_replay_max_concurrent: usize,
    /// Oldest event age eligible for automatic repair.
    pub late_replay_horizon_hours: i64,
    /// Attempts before a persistently failing repair is dead-lettered.
    pub late_replay_max_attempts: i32,
    /// Durable alert side effects claimed per one-second dispatcher tick.
    pub alert_post_create_batch_size: usize,
    /// Maximum finding/case/webhook items executed concurrently per node.
    pub alert_post_create_max_concurrent: usize,
}

impl Default for DistributedSchedulerConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            batch_size: 5,
            max_concurrent_executions: 10,
            stale_claim_timeout_secs: 300,
            phase_max_secs: DEFAULT_PHASE_CAP_SECS,
            default_lookback_minutes: 15,
            max_catchup_minutes: 1440,
            execution_timeout_secs: 300,
            lake_event_time_delay_secs: 10,
            late_replay_poll_interval_secs: 10,
            late_replay_publication_batch_size: 100,
            late_replay_batch_size: 5,
            late_replay_max_concurrent: 2,
            late_replay_horizon_hours: 168,
            late_replay_max_attempts: 8,
            alert_post_create_batch_size: 100,
            alert_post_create_max_concurrent: 16,
        }
    }
}

impl DistributedSchedulerConfig {
    /// Load configuration from environment variables with defaults
    pub fn from_env() -> Self {
        Self {
            poll_interval_secs: parse_env("NRT_CHECK_INTERVAL_SECS", 5),
            batch_size: parse_env("NRT_CLAIM_BATCH_SIZE", 5) as i64,
            max_concurrent_executions: parse_env("NRT_MAX_CONCURRENT_RULES", 10) as usize,
            stale_claim_timeout_secs: parse_env("NRT_STALE_CLAIM_TIMEOUT_SECS", 300) as i64,
            phase_max_secs: configured_phase_cap_secs(),
            default_lookback_minutes: parse_env("NRT_DEFAULT_LOOKBACK_MINUTES", 15) as i64,
            max_catchup_minutes: parse_env("NRT_MAX_CATCHUP_MINUTES", 1440) as i64,
            execution_timeout_secs: parse_env("DETECTION_EXECUTION_TIMEOUT_SECS", 300),
            lake_event_time_delay_secs: parse_env("DETECTION_LAKE_EVENT_TIME_DELAY_SECS", 10)
                as i64,
            late_replay_poll_interval_secs: parse_env(
                "DETECTION_LATE_REPLAY_POLL_INTERVAL_SECS",
                10,
            ),
            late_replay_publication_batch_size: parse_env(
                "DETECTION_LATE_REPLAY_PUBLICATION_BATCH_SIZE",
                100,
            ) as usize,
            late_replay_batch_size: parse_env("DETECTION_LATE_REPLAY_BATCH_SIZE", 5) as usize,
            late_replay_max_concurrent: parse_env("DETECTION_LATE_REPLAY_MAX_CONCURRENT", 2)
                as usize,
            late_replay_horizon_hours: parse_env("DETECTION_LATE_REPLAY_HORIZON_HOURS", 168) as i64,
            late_replay_max_attempts: parse_env("DETECTION_LATE_REPLAY_MAX_ATTEMPTS", 8) as i32,
            alert_post_create_batch_size: parse_env("DETECTION_ALERT_POST_CREATE_BATCH_SIZE", 100)
                as usize,
            alert_post_create_max_concurrent: parse_env(
                "DETECTION_ALERT_POST_CREATE_MAX_CONCURRENT",
                16,
            ) as usize,
        }
    }
}

/// Distributed detection scheduler using SKIP LOCKED for work distribution
pub struct DistributedDetectionScheduler {
    detection_service: DetectionService,
    rule_repo: DetectionRuleRepository,
    config: DistributedSchedulerConfig,
    node_id: String,
    developer_settings: Option<DeveloperSettingsRepository>,
    /// In the canonical lake profile, real-time rules are durable short-window
    /// micro-batches. Legacy ClickHouse profiles leave this false because their
    /// materialized views own real-time execution.
    include_realtime_microbatches: bool,
    /// Enabled only for the canonical object-lake profile. ClickHouse tenants
    /// have no committed-object publication ledger to reconcile.
    late_arrival_reconciliation: bool,
    /// NAN-3064: pool for the once-a-minute scheduling-lag health read.
    pool: PgPool,
}

impl DistributedDetectionScheduler {
    pub fn new(
        detection_service: DetectionService,
        pool: PgPool,
        config: DistributedSchedulerConfig,
        node_id: String,
    ) -> Self {
        Self {
            detection_service,
            rule_repo: DetectionRuleRepository::new(pool.clone()),
            config,
            node_id,
            developer_settings: None,
            include_realtime_microbatches: false,
            late_arrival_reconciliation: false,
            pool,
        }
    }

    /// Route real-time rules through the same durable scheduler as scheduled
    /// rules. This is enabled only for the lake profile, where there is no
    /// server-side materialized-view runtime.
    pub fn with_realtime_microbatches(mut self, enabled: bool) -> Self {
        self.include_realtime_microbatches = enabled;
        self
    }

    pub fn with_late_arrival_reconciliation(mut self, enabled: bool) -> Self {
        self.late_arrival_reconciliation = enabled;
        self
    }

    /// Enable developer settings check (scheduler enable/disable toggle)
    pub fn with_developer_settings(mut self, pool: PgPool) -> Self {
        self.developer_settings = Some(DeveloperSettingsRepository::new(pool));
        self
    }

    /// Backfill `next_run_at` for any eligible rules that are missing it.
    ///
    /// Called once on startup to handle rules created before the migration,
    /// or rules whose next_run_at was cleared by a bug.
    pub async fn backfill_next_run_at(&self) -> anyhow::Result<usize> {
        let rules = self
            .rule_repo
            .list_missing_next_run_at(self.include_realtime_microbatches)
            .await?;
        if rules.is_empty() {
            return Ok(0);
        }

        let count = rules.len();
        info!("Backfilling next_run_at for {} rules", count);

        for rule in rules {
            if let Some(ref cron) = rule.schedule_cron {
                let next_run = calculate_next_run_phased(
                    cron,
                    Utc::now(),
                    rule.id,
                    schedule_phase_cap_secs(&rule, self.config.phase_max_secs),
                );
                if let Err(e) = self
                    .rule_repo
                    .update_next_run_at(rule.id, Some(next_run))
                    .await
                {
                    warn!("Failed to backfill next_run_at for rule {}: {}", rule.id, e);
                }
            }
        }

        info!("Backfilled next_run_at for {} rules", count);
        Ok(count)
    }

    /// Start the distributed scheduler loop.
    ///
    /// Returns a JoinHandle. The no-token form runs until the handle is aborted.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.start_with_shutdown(ShutdownToken::new())
    }

    /// Start with cooperative cancellation at every pre-claim boundary.
    pub fn start_with_shutdown(
        self: Arc<Self>,
        shutdown: ShutdownToken,
    ) -> tokio::task::JoinHandle<()> {
        let scheduler = self;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                scheduler.config.poll_interval_secs,
            ));
            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_SECS: u64 = 300;
            // NAN-3064: scheduling-lag health signal once a minute.
            let mut lag_checked_at: Option<std::time::Instant> = None;

            info!(
                node_id = %scheduler.node_id,
                poll_interval = scheduler.config.poll_interval_secs,
                batch_size = scheduler.config.batch_size,
                max_concurrent = scheduler.config.max_concurrent_executions,
                stale_timeout = scheduler.config.stale_claim_timeout_secs,
                "Distributed detection scheduler started"
            );

            loop {
                if shutdown
                    .run_until_cancelled(interval.tick())
                    .await
                    .is_none()
                {
                    break;
                }

                // Check developer settings toggle
                if let Some(ref settings_repo) = scheduler.developer_settings {
                    let enabled = shutdown
                        .run_until_cancelled(settings_repo.is_detection_scheduler_enabled())
                        .await;
                    match enabled {
                        None => break,
                        Some(Ok(false)) => {
                            debug!("Detection scheduler disabled via developer settings");
                            continue;
                        }
                        Some(Err(e)) => {
                            warn!("Failed to check scheduler enabled status: {}", e);
                            // Fail-open: continue execution
                        }
                        Some(Ok(true)) => {}
                    }
                }

                if lag_checked_at.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(60)) {
                    lag_checked_at = Some(std::time::Instant::now());
                    match super::schedule_lag::read_dedicated_schedule_lag(&scheduler.pool).await {
                        Ok(lag) => super::schedule_lag::record_schedule_lag(&lag, None),
                        Err(e) => warn!("Detection scheduling-lag check failed: {}", e),
                    }
                }

                // Claim and execute due rules
                match scheduler.poll_and_execute(&shutdown).await {
                    Ok(executed) => {
                        if executed > 0 {
                            debug!(node_id = %scheduler.node_id, executed, "Executed rules");
                        }
                        consecutive_errors = 0;
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(scheduler.config.poll_interval_secs),
                            MAX_BACKOFF_SECS,
                        );
                        error!(
                            "Distributed scheduler error (attempt {}, backoff {}s): {}",
                            consecutive_errors, backoff_secs, e
                        );
                        if shutdown
                            .run_until_cancelled(tokio::time::sleep(
                                tokio::time::Duration::from_secs(backoff_secs),
                            ))
                            .await
                            .is_none()
                        {
                            break;
                        }
                    }
                }
            }

            info!(node_id = %scheduler.node_id, "Distributed detection scheduler stopped");
        })
    }

    /// Start the independent late-arrival repair lane.
    ///
    /// It deliberately does not share the normal cron loop: a slow historical
    /// repair must never delay fresh scheduled or real-time micro-batch rules.
    pub fn start_late_arrival_with_shutdown(
        self: Arc<Self>,
        shutdown: ShutdownToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if !self.late_arrival_reconciliation {
                return;
            }
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                self.config.late_replay_poll_interval_secs.max(1),
            ));
            info!(
                node_id = %self.node_id,
                horizon_hours = self.config.late_replay_horizon_hours,
                max_concurrent = self.config.late_replay_max_concurrent,
                "Late-arrival detection reconciliation started"
            );
            loop {
                if shutdown
                    .run_until_cancelled(interval.tick())
                    .await
                    .is_none()
                {
                    break;
                }
                if let Some(ref settings_repo) = self.developer_settings {
                    match shutdown
                        .run_until_cancelled(settings_repo.is_detection_scheduler_enabled())
                        .await
                    {
                        None => break,
                        Some(Ok(false)) => continue,
                        Some(Err(error)) => warn!(
                            %error,
                            "Failed to check scheduler state for late-arrival reconciliation"
                        ),
                        Some(Ok(true)) => {}
                    }
                }
                match self.poll_late_arrivals(&shutdown).await {
                    Ok(executed) if executed > 0 => debug!(
                        node_id = %self.node_id,
                        executed,
                        "Executed late-arrival detection repairs"
                    ),
                    Ok(_) => {}
                    Err(error) => error!(
                        node_id = %self.node_id,
                        %error,
                        "Late-arrival detection reconciliation failed"
                    ),
                }
            }
            info!(node_id = %self.node_id, "Late-arrival detection reconciliation stopped");
        })
    }

    /// Start the independent durable alert side-effect lane. Alert rows and
    /// matched-event checkpoints stay on the rule executor's critical path;
    /// risk publication, case grouping, and webhook fanout drain here.
    pub fn start_alert_post_create_with_shutdown(
        self: Arc<Self>,
        shutdown: ShutdownToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            info!(
                node_id = %self.node_id,
                batch_size = self.config.alert_post_create_batch_size,
                max_concurrent = self.config.alert_post_create_max_concurrent,
                "Alert post-create outbox dispatcher started"
            );
            loop {
                if shutdown
                    .run_until_cancelled(interval.tick())
                    .await
                    .is_none()
                {
                    break;
                }
                let drain = self.detection_service.drain_alert_post_create_outbox(
                    &self.node_id,
                    self.config.alert_post_create_batch_size,
                    self.config.alert_post_create_max_concurrent,
                );
                let result = shutdown.run_until_cancelled(drain).await;
                let Some(result) = result else {
                    match self
                        .detection_service
                        .release_alert_post_create_claims(&self.node_id)
                        .await
                    {
                        Ok(released) if released > 0 => info!(
                            node_id = %self.node_id,
                            released,
                            "Released alert post-create claims during shutdown"
                        ),
                        Ok(_) => {}
                        Err(error) => error!(
                            node_id = %self.node_id,
                            %error,
                            "Failed to release alert post-create claims during shutdown"
                        ),
                    }
                    break;
                };
                match result {
                    Ok(drained) if drained > 0 => debug!(
                        node_id = %self.node_id,
                        drained,
                        "Drained alert post-create outbox items"
                    ),
                    Ok(_) => {}
                    Err(error) => error!(
                        node_id = %self.node_id,
                        %error,
                        "Alert post-create outbox dispatch failed"
                    ),
                }
            }
            info!(node_id = %self.node_id, "Alert post-create outbox dispatcher stopped");
        })
    }

    async fn poll_late_arrivals(&self, shutdown: &ShutdownToken) -> anyhow::Result<usize> {
        let plan = self
            .rule_repo
            .plan_late_replays(
                self.config.late_replay_publication_batch_size.max(1),
                Duration::hours(self.config.late_replay_horizon_hours.max(1)),
                Duration::minutes(self.config.default_lookback_minutes.max(1)),
            )
            .await?;
        if plan.publications > 0 {
            counter!("nanosiem_detection_late_publications_total")
                .increment(plan.publications as u64);
            counter!("nanosiem_detection_late_replay_jobs_planned_total")
                .increment(plan.jobs as u64);
            counter!("nanosiem_detection_late_replay_jobs_coalesced_total")
                .increment(plan.coalesced as u64);
            counter!("nanosiem_detection_late_publications_expired_total")
                .increment(plan.expired as u64);
        }
        counter!("nanosiem_detection_late_publications_pruned_total")
            .increment(plan.pruned_publications as u64);
        counter!("nanosiem_detection_late_replay_jobs_pruned_total")
            .increment(plan.pruned_jobs as u64);

        const STALE_CLAIM_EXEC_BUFFER_SECS: i64 = 60;
        let timeout_secs = self.config.execution_timeout_secs.max(1);
        let stale_secs = self
            .config
            .stale_claim_timeout_secs
            .max(timeout_secs as i64 + STALE_CLAIM_EXEC_BUFFER_SECS);
        let claims = self
            .rule_repo
            .claim_late_replays(
                self.config.late_replay_batch_size.max(1),
                &self.node_id,
                Duration::seconds(stale_secs),
                Duration::seconds(stale_secs),
            )
            .await?;
        let count = claims.len();
        stream::iter(claims)
            .for_each_concurrent(self.config.late_replay_max_concurrent.max(1), |claim| {
                let detection_service = self.detection_service.clone();
                let rule_repo = self.rule_repo.clone();
                let node_id = self.node_id.clone();
                let shutdown = shutdown.clone();
                let max_attempts = self.config.late_replay_max_attempts.max(1);
                let retry_horizon = Duration::hours(self.config.late_replay_horizon_hours.max(1));
                async move {
                    let execution = tokio::time::timeout(
                        tokio::time::Duration::from_secs(timeout_secs),
                        detection_service.execute_rule(&claim.rule, Some(claim.time_range.clone())),
                    );
                    let result = shutdown.run_until_cancelled(execution).await;
                    let drain_pending = matches!(
                        &result,
                        Some(Ok(Err(error))) if error.is_window_drain_pending()
                    );
                    let error = match result {
                        None => Some("late-arrival repair cancelled during shutdown".to_string()),
                        Some(Err(_)) => Some(format!(
                            "late-arrival repair timed out after {timeout_secs}s"
                        )),
                        Some(Ok(Err(error))) => Some(error.to_string()),
                        Some(Ok(Ok(_))) => None,
                    };
                    let release = if drain_pending {
                        rule_repo
                            .release_late_replay_progress(
                                &claim,
                                &node_id,
                                error.as_deref().unwrap_or("detection window drain pending"),
                            )
                            .await
                    } else {
                        rule_repo
                            .release_late_replay(
                                &claim,
                                &node_id,
                                error.as_deref(),
                                max_attempts,
                                retry_horizon,
                            )
                            .await
                    };
                    match release {
                        Ok(LateReplayReleaseOutcome::Completed) => {
                            counter!(
                                "nanosiem_detection_late_replay_executions_total",
                                "outcome" => "completed"
                            )
                            .increment(1);
                        }
                        Ok(LateReplayReleaseOutcome::Draining) => {
                            counter!(
                                "nanosiem_detection_late_replay_executions_total",
                                "outcome" => "draining"
                            )
                            .increment(1);
                        }
                        Ok(LateReplayReleaseOutcome::Retry) => {
                            counter!(
                                "nanosiem_detection_late_replay_executions_total",
                                "outcome" => "retry"
                            )
                            .increment(1);
                        }
                        Ok(LateReplayReleaseOutcome::DeadLetter) => {
                            counter!(
                                "nanosiem_detection_late_replay_executions_total",
                                "outcome" => "dead_letter"
                            )
                            .increment(1);
                            error!(
                                job_id = %claim.job_id,
                                rule_id = %claim.rule.id,
                                attempts = claim.attempt,
                                last_error = error.as_deref().unwrap_or("unknown"),
                                "Late-arrival detection repair exhausted its retry horizon"
                            );
                        }
                        Ok(LateReplayReleaseOutcome::LostClaim) => warn!(
                            job_id = %claim.job_id,
                            rule_id = %claim.rule.id,
                            "Late-arrival repair lost its claim fence before release"
                        ),
                        Err(release_error) => error!(
                            job_id = %claim.job_id,
                            rule_id = %claim.rule.id,
                            %release_error,
                            "Failed to release late-arrival repair claim"
                        ),
                    }
                }
            })
            .await;
        Ok(count)
    }

    /// One poll cycle: claim due rules, execute them concurrently, release claims.
    async fn poll_and_execute(&self, shutdown: &ShutdownToken) -> anyhow::Result<usize> {
        // Audit D21: never let another node reclaim a rule before the node
        // executing it can plausibly finish AND release its claim. The stale and
        // execution timeouts are independent knobs that both default to 300s, so
        // a claim could be reclaimed at exactly the execution timeout → double
        // execution (double-counted stats / detection_matches). Floor the stale
        // timeout at `execution_timeout + buffer` (the buffer covers the permit
        // wait + release round-trip) so reclaim only ever fires for a genuinely
        // dead node.
        const STALE_CLAIM_EXEC_BUFFER_SECS: i64 = 60;
        let effective_stale_timeout = self
            .config
            .stale_claim_timeout_secs
            .max(self.config.execution_timeout_secs as i64 + STALE_CLAIM_EXEC_BUFFER_SECS);

        let claim = self.rule_repo.claim_due_rules(
            self.config.batch_size,
            &self.node_id,
            effective_stale_timeout,
            self.include_realtime_microbatches,
        );
        let Some(claimed) = shutdown.run_until_cancelled(claim).await else {
            return Ok(0);
        };
        let claimed = claimed?;

        if claimed.is_empty() {
            return Ok(0);
        }

        let count = claimed.len();
        debug!(
            node_id = %self.node_id,
            claimed = count,
            "Claimed rules for execution"
        );

        // Keep execution futures owned by the scheduler task. If shutdown aborts
        // the scheduler, dropping this stream cancels every in-flight execution
        // before the scheduler handle resolves and its claims are bulk-released.
        stream::iter(claimed)
            .for_each_concurrent(self.config.max_concurrent_executions.max(1), |rule| {
                let detection_service = self.detection_service.clone();
                let rule_repo = self.rule_repo.clone();
                let node_id = self.node_id.clone();
                let config = self.config.clone();
                async move {
                    let rule_id = rule.id;
                    let execution = execute_and_release(
                        &detection_service,
                        &rule_repo,
                        &rule,
                        &node_id,
                        &config,
                        self.include_realtime_microbatches,
                    );
                    if AssertUnwindSafe(execution).catch_unwind().await.is_err() {
                        error!(%rule_id, "Rule execution task panicked");
                    }
                }
            })
            .await;

        // Track how many rules were executed in this poll cycle
        counter!("nanosiem_detection_rules_executed_total").increment(count as u64);

        Ok(count)
    }

    /// Release all claims held by this node (for graceful shutdown).
    pub async fn release_all_claims(&self) -> anyhow::Result<u64> {
        let released = self.rule_repo.release_all_claims(&self.node_id).await?;
        if released > 0 {
            info!(
                node_id = %self.node_id,
                released,
                "Released all detection rule claims on shutdown"
            );
        }
        Ok(released)
    }
}

/// Execute a single claimed rule and release the claim afterward.
///
/// Always releases the claim, even on execution failure (to avoid permanent stuckness).
async fn execute_and_release(
    detection_service: &DetectionService,
    rule_repo: &DetectionRuleRepository,
    rule: &DetectionRule,
    node_id: &str,
    config: &DistributedSchedulerConfig,
    lake_backend: bool,
) {
    let mode_str = format!("{:?}", rule.mode).to_lowercase();

    // Calculate time range. `end` is captured *before* the query so that, on
    // success, `last_run_at` can be stamped to exactly this value (audit D2) —
    // see `compute_window_start` for the start-of-window precedence rules.
    let wall_now = Utc::now();
    let now = detection_evaluation_now(
        wall_now,
        rule.dataset.as_deref(),
        lake_backend,
        config.lake_event_time_delay_secs,
    );
    let end = compute_window_end(
        rule.lookback_minutes,
        rule.last_run_at,
        now,
        config.max_catchup_minutes,
    );
    let start = compute_window_start(
        rule.lookback_minutes,
        rule.last_run_at,
        end,
        config.default_lookback_minutes,
        config.max_catchup_minutes,
    );
    let backlog_remaining = end < now;
    let time_range = TimeRangeInput::new(start, end);

    debug!(
        rule_id = %rule.id,
        rule_name = %rule.name,
        start = %start,
        end = %end,
        "Executing claimed rule"
    );

    // Execute with timing and timeout
    let exec_start = std::time::Instant::now();
    // Lake real-time rules are deliberately simple and should never occupy a
    // rule lane for the full analytical timeout. A failure keeps the watermark
    // unchanged, so the next durable run safely retries the same window.
    let execution_timeout_secs = if rule.detection_mode == DetectionMode::RealTime {
        config.execution_timeout_secs.min(30)
    } else {
        config.execution_timeout_secs
    };
    let timeout_duration = tokio::time::Duration::from_secs(execution_timeout_secs);
    let result = match tokio::time::timeout(
        timeout_duration,
        detection_service.execute_scheduled_window(rule, time_range.clone()),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            error!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                timeout_secs = execution_timeout_secs,
                "Rule execution timed out"
            );
            Err(crate::detection::DetectionError::QueryExecutionError(
                format!("Rule execution timed out after {}s", execution_timeout_secs),
            ))
        }
    };
    let duration_secs = exec_start.elapsed().as_secs_f64();

    let drain_pending = matches!(
        &result,
        Err(error) if error.is_window_drain_pending()
    );
    let drain_owned = if drain_pending && lake_backend && !rule.is_retro_hunt() {
        match rule_repo.enqueue_window_drain(rule.id, &time_range).await {
            Ok(()) => {
                counter!("nanosiem_detection_window_drains_enqueued_total").increment(1);
                true
            }
            Err(error) => {
                error!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    %error,
                    "Failed to hand the partially committed window to the durable drain lane"
                );
                false
            }
        }
    } else {
        false
    };
    let success = result.is_ok();
    histogram!(
        "nanosiem_detection_execution_duration_seconds",
        "mode" => mode_str.clone(),
        "success" => success.to_string()
    )
    .record(duration_secs);
    counter!(
        "nanosiem_detection_executions_total",
        "mode" => mode_str,
        "success" => success.to_string()
    )
    .increment(1);

    match &result {
        Ok(Some(alert)) => {
            info!(
                rule_name = %rule.name,
                alert_id = %alert.id,
                matched_events = alert.matched_events.as_array().map(|a| a.len()).unwrap_or(0),
                "Rule generated alert"
            );
        }
        Ok(None) => {}
        Err(e) if drain_pending => {
            counter!("nanosiem_detection_window_drain_batches_total").increment(1);
            if drain_owned {
                info!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "{}; exact window handed to the durable drain lane",
                    e
                );
            } else {
                info!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "{}; retrying without advancing the watermark",
                    e
                );
            }
        }
        Err(e) => {
            error!(rule_id = %rule.id, rule_name = %rule.name, "Rule execution failed: {}", e);
        }
    }

    // Compute next_run_at and release claim (always, even on error)
    // Audit D26: re-read the CURRENT cron so a cron edit that landed mid-execution
    // isn't clobbered by a next_run_at computed from the claim-time snapshot. On a
    // fetch error (e.g. the rule was deleted mid-run) fall back to the snapshot.
    let current_cron = rule_repo
        .get_schedule_cron(rule.id)
        .await
        .ok()
        .flatten()
        .or_else(|| rule.schedule_cron.clone());
    let next_run_at = if (drain_pending && !drain_owned) || (success && backlog_remaining) {
        // Drain an old outage as bounded, contiguous slices instead of waiting
        // for another full cron interval between each day of backlog. A
        // partially committed per-event batch likewise retains this exact
        // watermark and is immediately reclaimable.
        Utc::now() + Duration::seconds(1)
    } else {
        current_cron
            .as_ref()
            .map(|cron| {
                calculate_next_run_phased(
                    cron,
                    Utc::now(),
                    rule.id,
                    schedule_phase_cap_secs(rule, config.phase_max_secs),
                )
            })
            .unwrap_or_else(|| Utc::now() + Duration::hours(1))
    };

    // Decide how last_run_at advances (audit D1). Success stamps the executed
    // window end; a normal failure leaves the high-water mark untouched so the
    // failed window is re-scanned next cycle instead of being silently dropped.
    // Once the exact interval is durably owned by the repair queue, advancing
    // the normal watermark is safe. The pending job fences normal claims for
    // this rule and replay execution never mutates the watermark.
    let advance_last_run_to = if drain_owned {
        Some(end)
    } else {
        next_last_run_at(success, rule.last_run_at, start, end)
    };
    if let Err(e) = rule_repo
        .release_claim(rule.id, node_id, next_run_at, advance_last_run_to)
        .await
    {
        error!(
            rule_id = %rule.id,
            "Failed to release claim: {}. Rule will be reclaimed after stale timeout.",
            e
        );
    }
}

fn detection_evaluation_now(
    wall_now: DateTime<Utc>,
    dataset: Option<&str>,
    lake_backend: bool,
    delay_secs: i64,
) -> DateTime<Utc> {
    let is_log_rule = dataset
        .map(|value| value.eq_ignore_ascii_case("logs"))
        .unwrap_or(true);
    if lake_backend && is_log_rule {
        wall_now - Duration::seconds(delay_secs.max(0))
    } else {
        wall_now
    }
}

fn schedule_phase_cap_secs(rule: &DetectionRule, configured: u64) -> u64 {
    schedule_phase_cap_for_mode(rule.detection_mode, configured)
}

/// Real-time micro-batches keep their exact cadence (offset 0); every other
/// scheduled rule is phase-shifted within `configured` seconds.
pub(crate) fn schedule_phase_cap_for_mode(mode: DetectionMode, configured: u64) -> u64 {
    if mode == DetectionMode::RealTime {
        0
    } else {
        configured
    }
}

/// Decide what value `last_run_at` should take after an execution attempt.
///
/// - **Success** → the executed window `end`; the high-water mark advances so
///   the next window starts exactly where this one ended (audit D2).
/// - **Failure with a prior high-water mark** → `None` (leave `last_run_at`
///   as-is; the failed window is re-scanned from the existing mark — audit D1).
/// - **Failure on the *first* run** (no prior mark) → the window `start`, so the
///   bootstrap window is re-covered next cycle instead of sliding forward with a
///   fresh `now() - default_lookback` (which would drop its trailing edge).
fn next_last_run_at(
    success: bool,
    prior_last_run_at: Option<DateTime<Utc>>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if success {
        Some(window_end)
    } else if prior_last_run_at.is_none() {
        Some(window_start)
    } else {
        None
    }
}

/// Compute the start of the query window for a claimed rule.
///
/// Precedence:
/// 1. Explicit `lookback_minutes` → sliding window `end - lookback` (intentional
///    overlap; bounded by the rule's own lookback cap). Not capped here.
/// 2. `last_run_at` → contiguous catch-up from the last successfully-scanned
///    window end, minus a 5s overlap buffer for ingestion lag / clock skew.
///    [`compute_window_end`] bounds long outages into oldest-first slices; the
///    start must never jump forward or an outage becomes permanent data loss.
/// 3. First run (no lookback, never run) → `end - default_lookback_minutes`.
pub fn compute_window_start(
    lookback_minutes: Option<i32>,
    last_run_at: Option<DateTime<Utc>>,
    end: DateTime<Utc>,
    default_lookback_minutes: i64,
    _max_catchup_minutes: i64,
) -> DateTime<Utc> {
    if let Some(lookback_minutes) = lookback_minutes {
        end - Duration::minutes(lookback_minutes as i64)
    } else if let Some(last_run) = last_run_at {
        last_run - Duration::seconds(5)
    } else {
        end - Duration::minutes(default_lookback_minutes)
    }
}

/// Bound catch-up cost without discarding the oldest unprocessed interval.
/// A successful slice advances `last_run_at` to this end; the scheduler then
/// immediately claims the next slice until it reaches `now`.
pub fn compute_window_end(
    lookback_minutes: Option<i32>,
    last_run_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    max_catchup_minutes: i64,
) -> DateTime<Utc> {
    if lookback_minutes.is_some() {
        return now;
    }
    last_run_at
        .map(|last_run| (last_run + Duration::minutes(max_catchup_minutes)).min(now))
        .unwrap_or(now)
}

/// Generate a node ID from environment or random UUID
pub fn generate_node_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("POD_NAME"))
        .unwrap_or_else(|_| format!("node-{}", Uuid::now_v7()))
}

fn parse_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests;
