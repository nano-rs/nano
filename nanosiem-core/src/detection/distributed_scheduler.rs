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

use chrono::{Duration, Utc};
use metrics::{counter, histogram};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::db::repository::detection_rules::DetectionRuleRepository;
use crate::models::DetectionRule;
use crate::search::TimeRangeInput;
use crate::settings::DeveloperSettingsRepository;

use super::scheduler::calculate_next_run_with_jitter;
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
    /// Maximum jitter to apply to rule schedules (seconds)
    pub jitter_max_secs: u64,
    /// Default lookback period for first-run rules (minutes)
    pub default_lookback_minutes: i64,
    /// Maximum seconds a single rule execution may run before being timed out (default: 300s)
    pub execution_timeout_secs: u64,
}

impl Default for DistributedSchedulerConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 5,
            batch_size: 5,
            max_concurrent_executions: 10,
            stale_claim_timeout_secs: 300,
            jitter_max_secs: 30,
            default_lookback_minutes: 15,
            execution_timeout_secs: 300,
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
            jitter_max_secs: parse_env("NRT_JITTER_MAX_SECS", 30),
            default_lookback_minutes: parse_env("NRT_DEFAULT_LOOKBACK_MINUTES", 15) as i64,
            execution_timeout_secs: parse_env("DETECTION_EXECUTION_TIMEOUT_SECS", 300),
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
        }
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
        let rules = self.rule_repo.list_missing_next_run_at().await?;
        if rules.is_empty() {
            return Ok(0);
        }

        let count = rules.len();
        info!("Backfilling next_run_at for {} rules", count);

        for rule in rules {
            if let Some(ref cron) = rule.schedule_cron {
                let next_run = calculate_next_run_with_jitter(
                    cron,
                    Utc::now(),
                    rule.id,
                    self.config.jitter_max_secs,
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
    /// Returns a JoinHandle. On graceful shutdown, abort the handle and then
    /// call `release_all_claims()` to free any in-progress claims.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let scheduler = self;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                scheduler.config.poll_interval_secs,
            ));
            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_SECS: u64 = 300;

            info!(
                node_id = %scheduler.node_id,
                poll_interval = scheduler.config.poll_interval_secs,
                batch_size = scheduler.config.batch_size,
                max_concurrent = scheduler.config.max_concurrent_executions,
                stale_timeout = scheduler.config.stale_claim_timeout_secs,
                "Distributed detection scheduler started"
            );

            loop {
                interval.tick().await;

                // Check developer settings toggle
                if let Some(ref settings_repo) = scheduler.developer_settings {
                    match settings_repo.is_detection_scheduler_enabled().await {
                        Ok(false) => {
                            debug!("Detection scheduler disabled via developer settings");
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to check scheduler enabled status: {}", e);
                            // Fail-open: continue execution
                        }
                        Ok(true) => {}
                    }
                }

                // Claim and execute due rules
                match scheduler.poll_and_execute().await {
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
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
        })
    }

    /// One poll cycle: claim due rules, execute them concurrently, release claims.
    async fn poll_and_execute(&self) -> anyhow::Result<usize> {
        let claimed = self
            .rule_repo
            .claim_due_rules(
                self.config.batch_size,
                &self.node_id,
                self.config.stale_claim_timeout_secs,
            )
            .await?;

        if claimed.is_empty() {
            return Ok(0);
        }

        let count = claimed.len();
        debug!(
            node_id = %self.node_id,
            claimed = count,
            "Claimed rules for execution"
        );

        // Execute with concurrency limit
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent_executions));
        let mut handles = Vec::with_capacity(count);

        for rule in claimed {
            let detection_service = self.detection_service.clone();
            let rule_repo = self.rule_repo.clone();
            let node_id = self.node_id.clone();
            let config = self.config.clone();
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                execute_and_release(&detection_service, &rule_repo, &rule, &node_id, &config).await;
            }));
        }

        // Wait for all executions
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Rule execution task panicked: {}", e);
            }
        }

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
) {
    let mode_str = format!("{:?}", rule.mode).to_lowercase();

    // Calculate time range (same logic as old scheduler)
    let end = Utc::now();
    let start = if let Some(lookback_minutes) = rule.lookback_minutes {
        end - Duration::minutes(lookback_minutes as i64)
    } else if let Some(last_run) = rule.last_run_at {
        // 5-second overlap buffer for ingestion lag / clock skew
        last_run - Duration::seconds(5)
    } else {
        end - Duration::minutes(config.default_lookback_minutes)
    };
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
    let timeout_duration = tokio::time::Duration::from_secs(config.execution_timeout_secs);
    let result = match tokio::time::timeout(
        timeout_duration,
        detection_service.execute_rule(rule, Some(time_range)),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            error!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                timeout_secs = config.execution_timeout_secs,
                "Rule execution timed out"
            );
            Err(crate::detection::DetectionError::QueryExecutionError(
                format!(
                    "Rule execution timed out after {}s",
                    config.execution_timeout_secs
                ),
            ))
        }
    };
    let duration_secs = exec_start.elapsed().as_secs_f64();

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
        Err(e) => {
            error!(rule_id = %rule.id, rule_name = %rule.name, "Rule execution failed: {}", e);
        }
    }

    // Compute next_run_at and release claim (always, even on error)
    let next_run_at = rule
        .schedule_cron
        .as_ref()
        .map(|cron| {
            calculate_next_run_with_jitter(cron, Utc::now(), rule.id, config.jitter_max_secs)
        })
        .unwrap_or_else(|| Utc::now() + Duration::hours(1));

    if let Err(e) = rule_repo.release_claim(rule.id, node_id, next_run_at).await {
        error!(
            rule_id = %rule.id,
            "Failed to release claim: {}. Rule will be reclaimed after stale timeout.",
            e
        );
    }
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
