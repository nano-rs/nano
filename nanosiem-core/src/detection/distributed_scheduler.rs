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

use crate::db::repository::detection_rules::{DetectionCoverageGap, DetectionRuleRepository};
use crate::models::{DetectionMode, DetectionRule};
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
    /// Upper bound on one catch-up slice derived from `last_run_at` (minutes).
    ///
    /// Bounds how much a long-dormant rule scans per execution (audit D22) so
    /// a multi-day backlog never builds one giant window that times out and
    /// retries forever. NAN-4910: the backlog is worked OLDEST-FIRST in slices
    /// of at most this size, starting at `last_run_at` — the older interval is
    /// never skipped (it used to be floored at `now - max_catchup_minutes`,
    /// silently dropping everything older after a > 24 h outage). Each
    /// successful slice is followed immediately by the next. A slice that
    /// fails for a size reason is retried smaller (see
    /// [`catchup_chunk_minutes`]). Explicit `lookback_minutes` rules are
    /// unaffected (their window is intentional).
    pub max_catchup_minutes: i64,
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
            phase_max_secs: DEFAULT_PHASE_CAP_SECS,
            default_lookback_minutes: 15,
            max_catchup_minutes: 1440,
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
            phase_max_secs: configured_phase_cap_secs(),
            default_lookback_minutes: parse_env("NRT_DEFAULT_LOOKBACK_MINUTES", 15) as i64,
            max_catchup_minutes: parse_env("NRT_MAX_CATCHUP_MINUTES", 1440) as i64,
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
            pool,
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
                        Ok(lag) => super::schedule_lag::record_schedule_lag(&lag),
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
                    );
                    if AssertUnwindSafe(execution).catch_unwind().await.is_err() {
                        // NAN-3080: release panics now unwind (they used to
                        // abort the whole jobs process), so one rule's panic
                        // is isolated here. Release the claim with a back-off
                        // and WITHOUT advancing last_run_at, so the window is
                        // re-scanned instead of the rule waiting out the
                        // stale-claim timeout.
                        error!(%rule_id, "Rule execution task panicked; releasing claim with back-off");
                        counter!("nanosiem_detection_execution_panics_total").increment(1);
                        let retry_at = Utc::now() + Duration::seconds(PANIC_RETRY_BACKOFF_SECS);
                        // A panic is not a size failure (NAN-4910): keep the
                        // rule's current catch-up slice size unchanged.
                        let size_failures = rule_repo
                            .get_catchup_size_failures(rule_id)
                            .await
                            .unwrap_or(0);
                        if let Err(e) = rule_repo
                            .release_claim(rule_id, &node_id, retry_at, None, size_failures, None)
                            .await
                        {
                            error!(%rule_id, "Failed to release claim after panic: {}", e);
                        }
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

/// Back-off before a rule whose execution panicked is claimed again (NAN-3080).
const PANIC_RETRY_BACKOFF_SECS: i64 = 300;

/// Back-off for a rule whose query fails deterministically (NAN-4031).
const DETERMINISTIC_FAILURE_BACKOFF_SECS: i64 = 3600;

/// A failure that retrying the same window cannot fix (NAN-4031).
pub(crate) fn is_deterministic_failure<T>(result: &Result<T, crate::detection::DetectionError>) -> bool {
    matches!(
        result,
        Err(crate::detection::DetectionError::InvalidQuery(_)
            | crate::detection::DetectionError::QueryParseError(_))
    )
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

    // Calculate time range. `end` is captured *before* the query so that, on
    // success, `last_run_at` can be stamped to exactly this value (audit D2) —
    // see `compute_window_start` / `compute_window_end` for the precedence
    // rules. NAN-4910: a backlog is worked oldest-first in bounded slices; the
    // slice shrinks after consecutive size-class failures.
    let marker_driven = is_marker_driven(rule);
    let prior_size_failures = if marker_driven {
        rule_repo
            .get_catchup_size_failures(rule.id)
            .await
            .unwrap_or_else(|e| {
                warn!(rule_id = %rule.id, "Failed to read catch-up size failures: {}", e);
                0
            })
    } else {
        0
    };
    let chunk_minutes = catchup_chunk_minutes(config.max_catchup_minutes, prior_size_failures);
    let now = Utc::now();
    let end = compute_window_end(rule.lookback_minutes, rule.last_run_at, now, chunk_minutes);
    let start = compute_window_start(
        rule.lookback_minutes,
        rule.last_run_at,
        end,
        config.default_lookback_minutes,
    );
    let time_range = TimeRangeInput::new(start, end);

    debug!(
        rule_id = %rule.id,
        rule_name = %rule.name,
        start = %start,
        end = %end,
        chunk_minutes,
        backlog_remaining = end < now,
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
    // Audit D26: re-read the CURRENT cron so a cron edit that landed mid-execution
    // isn't clobbered by a next_run_at computed from the claim-time snapshot. On a
    // fetch error (e.g. the rule was deleted mid-run) fall back to the snapshot.
    let current_cron = rule_repo
        .get_schedule_cron(rule.id)
        .await
        .ok()
        .flatten()
        .or_else(|| rule.schedule_cron.clone());
    let outcome = match &result {
        Ok(_) => ExecutionOutcome::Success,
        Err(e) if e.is_window_size_dependent() => ExecutionOutcome::SizeFailure,
        Err(_) => ExecutionOutcome::OtherFailure,
    };
    let decision = decide_release(
        outcome,
        marker_driven,
        rule.last_run_at,
        prior_size_failures,
        start,
        end,
        now,
        config.max_catchup_minutes,
    );

    // A bounded slice left backlog behind (or a size failure can retry a
    // strictly smaller slice): claim again right away instead of waiting a
    // full cron interval per slice, or a multi-day backlog never catches up.
    let mut next_run_at = if decision.reclaim_immediately {
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
    // NAN-4031: a deterministic query failure (the generated SQL fails
    // validation) fails identically on every tick. Back it off to at most
    // once an hour; last_run_at is not advanced (below), so the failed window
    // is still re-scanned once the rule is fixed.
    if is_deterministic_failure(&result) {
        next_run_at = next_run_at.max(Utc::now() + Duration::seconds(DETERMINISTIC_FAILURE_BACKOFF_SECS));
    }

    let coverage_gap = decision.coverage_gap.map(|(window_start, window_end)| {
        let error_message: String = result
            .as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
            .chars()
            .take(1000)
            .collect();
        DetectionCoverageGap {
            window_start,
            window_end,
            attempts: i32::from(prior_size_failures) + 1,
            error_message,
        }
    });
    if let Some(gap) = &coverage_gap {
        counter!("nanosiem_detection_coverage_gaps_total").increment(1);
        warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            window_start = %gap.window_start,
            window_end = %gap.window_end,
            attempts = gap.attempts,
            error = %gap.error_message,
            "Detection window could not be evaluated at the minimum slice; recorded a coverage gap and moved past it"
        );
    } else if outcome == ExecutionOutcome::SizeFailure && marker_driven {
        info!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            failed_chunk_minutes = chunk_minutes,
            next_chunk_minutes =
                catchup_chunk_minutes(config.max_catchup_minutes, decision.catchup_size_failures),
            "Detection window failed on size; retrying a smaller slice"
        );
    }

    // Decide how last_run_at advances (audit D1). Success stamps the executed
    // window end; a normal failure leaves the high-water mark untouched so the
    // failed window is re-scanned next cycle instead of being silently dropped;
    // a recorded coverage gap moves it past the gap (NAN-4910).
    if let Err(e) = rule_repo
        .release_claim(
            rule.id,
            node_id,
            next_run_at,
            decision.advance_last_run_to,
            decision.catchup_size_failures,
            coverage_gap.as_ref(),
        )
        .await
    {
        error!(
            rule_id = %rule.id,
            "Failed to release claim: {}. Rule will be reclaimed after stale timeout.",
            e
        );
    }
}

/// How one execution attempt ended, for the release decision (NAN-4910).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionOutcome {
    Success,
    /// Failed because of the window's size ([`crate::detection::DetectionError::is_window_size_dependent`]).
    SizeFailure,
    OtherFailure,
}

/// What `release_claim` should write after an attempt (NAN-4910).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseDecision {
    advance_last_run_to: Option<DateTime<Utc>>,
    catchup_size_failures: i16,
    /// `[start, end]` of a window recorded as not evaluated.
    coverage_gap: Option<(DateTime<Utc>, DateTime<Utc>)>,
    reclaim_immediately: bool,
}

/// Smallest catch-up slice (minutes). A slice of this size that keeps failing
/// for a size reason is recorded as a coverage gap (NAN-4910).
const MIN_CATCHUP_CHUNK_MINUTES: i64 = 5;

/// Consecutive size-class failures OF THE MINIMUM SLICE before it is recorded
/// as a coverage gap. More than one, so a single transient timeout at the
/// minimum slice does not cost coverage.
const MIN_CHUNK_ATTEMPTS: i16 = 3;

/// A rule whose window is driven by its `last_run_at` high-water mark (no
/// sliding `lookback_minutes`, has run before, not a retro hunt). Only these
/// get shrinking slices and recorded gaps: a sliding-lookback rule never
/// advances a marker, and a retro hunt evaluates its own historical window.
fn is_marker_driven(rule: &DetectionRule) -> bool {
    rule.lookback_minutes.is_none() && rule.last_run_at.is_some() && !rule.is_retro_hunt()
}

/// Maximum slice (minutes) after `size_failures` consecutive size-class
/// failures: `max_catchup_minutes` divided by 4 per failure, floored at
/// [`MIN_CATCHUP_CHUNK_MINUTES`] (1440 → 360 → 90 → 22 → 5).
fn catchup_chunk_minutes(max_catchup_minutes: i64, size_failures: i16) -> i64 {
    let mut chunk = max_catchup_minutes.max(MIN_CATCHUP_CHUNK_MINUTES);
    for _ in 0..size_failures.max(0) {
        chunk /= 4;
        if chunk <= MIN_CATCHUP_CHUNK_MINUTES {
            return MIN_CATCHUP_CHUNK_MINUTES;
        }
    }
    chunk
}

/// Number of consecutive size failures after which the slice is the minimum.
fn size_failures_at_min_chunk(max_catchup_minutes: i64) -> i16 {
    let mut failures = 0i16;
    while catchup_chunk_minutes(max_catchup_minutes, failures) > MIN_CATCHUP_CHUNK_MINUTES {
        failures += 1;
    }
    failures
}

/// Decide the release writes for one attempt (NAN-4910). `now` is the
/// evaluation time the window was derived from.
#[allow(clippy::too_many_arguments)]
fn decide_release(
    outcome: ExecutionOutcome,
    marker_driven: bool,
    prior_last_run_at: Option<DateTime<Utc>>,
    prior_size_failures: i16,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
    max_catchup_minutes: i64,
) -> ReleaseDecision {
    let keep_marker = ReleaseDecision {
        advance_last_run_to: next_last_run_at(false, prior_last_run_at, start, end),
        catchup_size_failures: prior_size_failures,
        coverage_gap: None,
        reclaim_immediately: false,
    };
    match outcome {
        ExecutionOutcome::Success => ReleaseDecision {
            advance_last_run_to: next_last_run_at(true, prior_last_run_at, start, end),
            catchup_size_failures: 0,
            coverage_gap: None,
            reclaim_immediately: end < now,
        },
        ExecutionOutcome::OtherFailure => keep_marker,
        ExecutionOutcome::SizeFailure if !marker_driven => keep_marker,
        ExecutionOutcome::SizeFailure => {
            let failures = prior_size_failures.max(0);
            let first_min = size_failures_at_min_chunk(max_catchup_minutes);
            if failures >= first_min && failures - first_min + 1 >= MIN_CHUNK_ATTEMPTS {
                // The minimum slice failed MIN_CHUNK_ATTEMPTS times in a row
                // for a size reason: a smaller retry does not exist and the
                // same slice will not succeed. Record it and move past it
                // rather than pinning the rule on it forever.
                ReleaseDecision {
                    advance_last_run_to: Some(end),
                    catchup_size_failures: 0,
                    coverage_gap: Some((start, end)),
                    reclaim_immediately: end < now,
                }
            } else {
                let next = failures.saturating_add(1);
                let next_chunk = Duration::minutes(catchup_chunk_minutes(max_catchup_minutes, next));
                ReleaseDecision {
                    advance_last_run_to: None,
                    catchup_size_failures: next,
                    coverage_gap: None,
                    // Retry right away only when the next slice is actually
                    // smaller than the window that just failed.
                    reclaim_immediately: next_chunk < end - start,
                }
            }
        }
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
///    [`compute_window_end`] bounds a long backlog into oldest-first slices;
///    the start never jumps forward, or an outage becomes permanent data loss
///    (NAN-4910 — it used to be floored at `end - max_catchup_minutes`).
/// 3. First run (no lookback, never run) → `end - default_lookback_minutes`.
fn compute_window_start(
    lookback_minutes: Option<i32>,
    last_run_at: Option<DateTime<Utc>>,
    end: DateTime<Utc>,
    default_lookback_minutes: i64,
) -> DateTime<Utc> {
    if let Some(lookback_minutes) = lookback_minutes {
        end - Duration::minutes(lookback_minutes as i64)
    } else if let Some(last_run) = last_run_at {
        last_run - Duration::seconds(5)
    } else {
        end - Duration::minutes(default_lookback_minutes)
    }
}

/// Compute the end of the query window (NAN-4910).
///
/// Bounds catch-up cost without discarding the oldest unprocessed interval: a
/// marker-driven rule scans at most `chunk_minutes` past `last_run_at`. A
/// successful slice advances `last_run_at` to this end and the scheduler
/// immediately claims the next slice until it reaches `now`. Sliding-lookback
/// and first-run rules always end at `now`.
fn compute_window_end(
    lookback_minutes: Option<i32>,
    last_run_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    chunk_minutes: i64,
) -> DateTime<Utc> {
    if lookback_minutes.is_some() {
        return now;
    }
    last_run_at
        .map(|last_run| (last_run + Duration::minutes(chunk_minutes)).min(now))
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

#[cfg(test)]
mod catchup_tests;
