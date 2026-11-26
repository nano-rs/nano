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

use crate::db::repository::detection_rules::{
    ClaimRelease, CrashRelease, DetectionCoverageGap, DetectionRuleRepository,
    RuleFailureCounters,
};
use crate::models::{DetectionMode, DetectionRule};
use crate::search::TimeRangeInput;
use crate::settings::DeveloperSettingsRepository;
use crate::shutdown::ShutdownToken;
use crate::transient_outage::{KeyedOutages, OutageStep, OutageTracker};

/// NAN-5886: one outage tracker PER RULE on this node (review P1-3): a rule
/// that keeps failing escalates even while others succeed, and a partial
/// outage is not reset by the rules that get through. Entries exist only for
/// rules currently failing (bounded, see [`KeyedOutages`]).
static RULE_BACKEND_OUTAGES: std::sync::LazyLock<std::sync::Mutex<KeyedOutages<Uuid>>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(KeyedOutages::new(crate::transient_outage::report_after()))
    });

fn rule_backend_outages<T>(f: impl FnOnce(&mut KeyedOutages<Uuid>) -> T) -> T {
    let mut outages = match RULE_BACKEND_OUTAGES.lock() {
        Ok(outages) => outages,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&mut outages)
}

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
    /// Seconds after which a claim is treated as dead (its process crashed).
    ///
    /// Audit D21: never let another node reclaim a rule before the node
    /// executing it can plausibly finish AND release its claim. The stale and
    /// execution timeouts are independent knobs that both default to 300s, so
    /// a claim could be reclaimed at exactly the execution timeout → double
    /// execution (double-counted stats / detection_matches). Floor the stale
    /// timeout at `execution_timeout + buffer` (the buffer covers the permit
    /// wait + release round-trip) so reclaim only ever fires for a genuinely
    /// dead node.
    pub fn effective_stale_claim_timeout_secs(&self) -> i64 {
        const STALE_CLAIM_EXEC_BUFFER_SECS: i64 = 60;
        self.stale_claim_timeout_secs
            .max(self.execution_timeout_secs as i64 + STALE_CLAIM_EXEC_BUFFER_SECS)
    }

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
            // NAN-5886: a claim poll failing on a down database warns until
            // the outage lasts, then reports once.
            let mut poll_outage = OutageTracker::default();

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
                        if let Some(ended) = poll_outage.record_success(std::time::Instant::now()) {
                            info!(
                                failures = ended.failures,
                                outage_secs = ended.elapsed.as_secs(),
                                "Distributed scheduler recovered after {}s ({} failed polls)",
                                ended.elapsed.as_secs(),
                                ended.failures
                            );
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(scheduler.config.poll_interval_secs),
                            MAX_BACKOFF_SECS,
                        );
                        if crate::transient_outage::is_transient_anyhow(&e) {
                            match poll_outage.record_failure(std::time::Instant::now()) {
                                OutageStep::Report { failures, elapsed } => error!(
                                    failures,
                                    outage_secs = elapsed.as_secs(),
                                    "Distributed scheduler backend unavailable for {}s ({} failed polls): {}",
                                    elapsed.as_secs(),
                                    failures,
                                    e
                                ),
                                OutageStep::Warn { .. } => warn!(
                                    "Distributed scheduler backend unavailable (attempt {}, backoff {}s): {}",
                                    consecutive_errors, backoff_secs, e
                                ),
                            }
                        } else {
                            error!(
                                "Distributed scheduler error (attempt {}, backoff {}s): {}",
                                consecutive_errors, backoff_secs, e
                            );
                        }
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
    ///
    /// NAN-5736: a process crash kills every rule running in it, so a rule
    /// that died mid-run before (a crash suspect) never runs alongside other
    /// rules: suspects execute one at a time, after the healthy rules of the
    /// cycle finished. A crash during such a run is attributable.
    async fn poll_and_execute(&self, shutdown: &ShutdownToken) -> anyhow::Result<usize> {
        let claim = self.rule_repo.claim_due_rules(
            self.config.batch_size,
            &self.node_id,
            self.config.effective_stale_claim_timeout_secs(),
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

        // NAN-5736: read each claim's crash state while this node holds it.
        let mut healthy = Vec::with_capacity(count);
        let mut suspects = Vec::new();
        for rule in claimed {
            match self.rule_repo.get_claimed_failure_counters(rule.id, &self.node_id).await {
                Ok(Some(counters)) if counters.crash_suspected() => suspects.push((rule, counters)),
                Ok(Some(counters)) => healthy.push((rule, counters)),
                Ok(None) => warn!(rule_id = %rule.id, "Claim lost before execution; skipping"),
                Err(e) => warn!(
                    rule_id = %rule.id,
                    "Failed to read rule failure counters: {e}; leaving the claim to expire"
                ),
            }
        }

        // Keep execution futures owned by the scheduler task. If shutdown aborts
        // the scheduler, dropping this stream cancels every in-flight execution
        // before the scheduler handle resolves and its claims are bulk-released.
        stream::iter(healthy)
            .for_each_concurrent(self.config.max_concurrent_executions.max(1), |(rule, counters)| {
                self.run_claimed(rule, counters, false)
            })
            .await;
        for (rule, counters) in suspects {
            self.run_claimed(rule, counters, true).await;
        }

        // Track how many rules were executed in this poll cycle
        counter!("nanosiem_detection_rules_executed_total").increment(count as u64);

        Ok(count)
    }

    /// Execute one claimed rule, isolating a panic in the release bookkeeping.
    async fn run_claimed(&self, rule: DetectionRule, counters: RuleFailureCounters, isolated: bool) {
        let rule_id = rule.id;
        // Boxed: one rule's execution future is large (nested searches).
        let execution = Box::pin(execute_and_release(
            &self.detection_service,
            &self.rule_repo,
            &rule,
            counters,
            isolated,
            &self.node_id,
            &self.config,
        ));
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
            // rule's current catch-up slice size unchanged. An
            // execution panic is caught inside
            // `execute_and_release` and goes through the bounded
            // retry (NAN-5424); this path only sees panics in the
            // release bookkeeping itself, so count and record it.
            let counters = self
                .rule_repo
                .get_failure_counters(rule_id)
                .await
                .unwrap_or_default();
            let release = ClaimRelease {
                next_run_at: retry_at,
                advance_last_run_to: None,
                catchup_size_failures: counters.catchup_size_failures,
                consecutive_failures: counters.consecutive_failures.saturating_add(1),
                failing_since: Some(counters.failing_since.unwrap_or_else(Utc::now)),
                failure_class: Some(ExecutionOutcome::OtherFailure.as_label()),
                error: Some("[other] Rule execution task panicked"),
                coverage_gap: None,
            };
            if let Err(e) = self.rule_repo.release_claim(rule_id, &self.node_id, &release).await {
                error!(%rule_id, "Failed to release claim after panic: {}", e);
            }
        }
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

/// NAN-5565: the `last_error` a SUCCESSFUL run records when it evaluated
/// only part of its input (`None` for a failed run, which records its error).
pub(crate) fn partial_run_error<T>(
    result: &Result<T, crate::detection::DetectionError>,
    notes: &[String],
) -> Option<String> {
    if result.is_err() {
        return None;
    }
    crate::search::partial_run::partial_run_message(notes)
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
///
/// NAN-5736: `counters` were read while this node held the claim. A claim
/// whose previous claim never released records that crash and releases
/// without running (see [`fold_crashed_attempts`]). An `isolated` run marks
/// its claim first, so a crash during it is attributed to this rule; if the
/// claim was lost meanwhile, nothing runs.
async fn execute_and_release(
    detection_service: &DetectionService,
    rule_repo: &DetectionRuleRepository,
    rule: &DetectionRule,
    counters: RuleFailureCounters,
    isolated: bool,
    node_id: &str,
    config: &DistributedSchedulerConfig,
) {
    let mode_str = format!("{:?}", rule.mode).to_lowercase();

    // Calculate time range. `end` is captured *before* the query so that, on
    // success, `last_run_at` can be stamped to exactly this value (audit D2) —
    // see `compute_window_start` / `compute_window_end` for the precedence
    // rules. NAN-4910: a backlog is worked oldest-first in bounded slices; the
    // slice shrinks after consecutive size-class failures. NAN-5424: the
    // consecutive non-size failure count bounds how often one window is
    // retried.
    if counters.crashed_attempts > 0 {
        release_crashed_claim(rule_repo, rule, node_id, config, &counters, Utc::now()).await;
        return;
    }
    if isolated {
        match rule_repo.mark_isolated_claim(rule.id, node_id).await {
            Ok(true) => {}
            Ok(false) => {
                warn!(rule_id = %rule.id, "Claim lost before the isolated run; skipping");
                return;
            }
            Err(e) => {
                error!(rule_id = %rule.id, "Failed to mark the isolated run: {}; leaving the claim to expire", e);
                return;
            }
        }
    }
    let marker_driven = is_marker_driven(rule);
    let now = Utc::now();
    let (start, end, chunk_minutes) = attempt_window(rule, &counters, config, now);
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

    // Execute with timing and timeout. NAN-5424: a panic inside the execution
    // is a failure of THIS window and goes through the same bounded retry as
    // any other failure, so a payload that panics the engine cannot pin the
    // rule either.
    let exec_start = std::time::Instant::now();
    let timeout_duration = tokio::time::Duration::from_secs(config.execution_timeout_secs);
    let mut panicked = false;
    // NAN-5565: collect partial-evaluation notes (a prevalence rescue cut at
    // its key-byte cap) so a run that left input out is marked PARTIAL.
    let (outcome_of_run, partial_notes) = crate::search::partial_run::collect(
        tokio::time::timeout(
            timeout_duration,
            AssertUnwindSafe(detection_service.execute_rule(rule, Some(time_range))).catch_unwind(),
        ),
    )
    .await;
    let result = match outcome_of_run {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            panicked = true;
            error!(rule_id = %rule.id, rule_name = %rule.name, "Rule execution panicked");
            counter!("nanosiem_detection_execution_panics_total").increment(1);
            Err(crate::detection::DetectionError::QueryExecutionError(
                "Rule execution panicked".to_string(),
            ))
        }
        Err(_) => {
            error!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                timeout_secs = config.execution_timeout_secs,
                "Rule execution timed out"
            );
            // NAN-5424: the outer timeout also fires on a stalled backend or
            // a lock; it proves nothing about the window (NAN-4910).
            Err(crate::detection::DetectionError::BackendUnavailable(format!(
                "Rule execution timed out after {}s",
                config.execution_timeout_secs
            )))
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
        // NAN-5886: the backend (search / ClickHouse / PostgreSQL) was
        // unreachable. The window is kept and retried (NAN-5424), so this is
        // WARN until THIS rule's outage has lasted the report threshold; then
        // ERROR once. A rejected connection (TLS) is not transient: below.
        Err(e) if crate::transient_outage::is_transient_error(e) => {
            let step = rule_backend_outages(|t| t.record_failure(&rule.id, std::time::Instant::now()));
            let text = crate::db::repository::detection_rules::rule_error_text(&e.to_string());
            match step {
                OutageStep::Report { failures, elapsed } => error!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    failures,
                    outage_secs = elapsed.as_secs(),
                    "Rule execution backend unavailable for {}s ({} failed runs): {}",
                    elapsed.as_secs(),
                    failures,
                    text
                ),
                OutageStep::Warn { .. } => warn!(
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    "Rule execution failed, backend unavailable (will retry): {}",
                    text
                ),
            }
        }
        Err(e) => {
            // A real error ends any transient streak of this rule.
            rule_backend_outages(|t| t.record_success(&rule.id, std::time::Instant::now()));
            // Errors can quote event bytes; log the sanitized single line.
            error!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                "Rule execution failed: {}",
                crate::db::repository::detection_rules::rule_error_text(&e.to_string())
            );
        }
    }
    if result.is_ok() {
        if let Some(ended) = rule_backend_outages(|t| t.record_success(&rule.id, std::time::Instant::now())) {
            info!(
                failures = ended.failures,
                outage_secs = ended.elapsed.as_secs(),
                rule_id = %rule.id,
                "Rule execution backend recovered after {}s ({} failed runs)",
                ended.elapsed.as_secs(),
                ended.failures
            );
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
    let outcome = classify_outcome(&result);
    if outcome != ExecutionOutcome::Success {
        counter!(
            "nanosiem_detection_execution_failures_total",
            "class" => outcome.as_label()
        )
        .increment(1);
    }
    let decision = decide_release(
        outcome,
        marker_driven,
        rule.last_run_at,
        &counters,
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
    // NAN-3080: a panicking execution backs off like the release-path panic.
    if panicked && decision.coverage_gap.is_none() {
        next_run_at = next_run_at.max(Utc::now() + Duration::seconds(PANIC_RETRY_BACKOFF_SECS));
    }

    // NAN-5424: what the rule API, coverage gaps and SIEM Health show is the
    // class plus the ClickHouse code / PostgreSQL SQLSTATE; database error
    // text can quote event values. The full (sanitized) text is logged above.
    let error_message: Option<String> = result
        .as_ref()
        .err()
        .map(|e| format!("[{}] {}", outcome.as_label(), e.redacted_summary()))
        // NAN-5565: a successful run that left input out records a
        // `[partial] …` last_error, which SIEM Health shows (degraded).
        .or_else(|| partial_run_error(&result, &partial_notes));
    if let Some(partial) = error_message.as_deref().filter(|m| m.starts_with("[partial]")) {
        counter!("nanosiem_detection_partial_runs_total").increment(1);
        warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            partial,
            "Detection run evaluated only part of its input; recorded as PARTIAL"
        );
    }
    let coverage_gap = decision
        .coverage_gap
        .map(|(window_start, window_end, attempts)| DetectionCoverageGap {
            window_start,
            window_end,
            attempts,
            error_message: error_message.clone().unwrap_or_else(|| {
                "[recovered] not evaluated while the rule was failing (its lookback no longer reaches this interval)"
                    .to_string()
            }),
        });
    if let Some(gap) = &coverage_gap {
        counter!(
            "nanosiem_detection_coverage_gaps_total",
            "class" => outcome.as_label()
        )
        .increment(1);
        warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            window_start = %gap.window_start,
            window_end = %gap.window_end,
            attempts = gap.attempts,
            class = outcome.as_label(),
            error = %gap.error_message,
            "Detection window could not be evaluated after bounded retries; recorded a coverage gap and moved past it"
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
    } else if outcome != ExecutionOutcome::Success {
        warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            consecutive_failures = decision.consecutive_failures,
            class = outcome.as_label(),
            "Detection window failed; keeping the high-water mark for a bounded retry"
        );
    }

    // Decide how last_run_at advances (audit D1). Success stamps the executed
    // window end; a retryable failure leaves the high-water mark untouched so
    // the failed window is re-scanned next cycle instead of being silently
    // dropped; a recorded coverage gap moves it past the gap (NAN-4910,
    // NAN-5424) in the same statement that records the gap.
    let release = ClaimRelease {
        next_run_at,
        advance_last_run_to: decision.advance_last_run_to,
        catchup_size_failures: decision.catchup_size_failures,
        consecutive_failures: decision.consecutive_failures,
        failing_since: decision.failing_since,
        failure_class: decision.failure_class,
        error: error_message.as_deref(),
        coverage_gap: coverage_gap.as_ref(),
    };
    if let Err(e) = rule_repo.release_claim(rule.id, node_id, &release).await {
        error!(
            rule_id = %rule.id,
            "Failed to release claim: {}. Rule will be reclaimed after stale timeout.",
            e
        );
    }
}

/// The window one attempt evaluates, and its catch-up slice size (minutes).
fn attempt_window(
    rule: &DetectionRule,
    counters: &RuleFailureCounters,
    config: &DistributedSchedulerConfig,
    now: DateTime<Utc>,
) -> (DateTime<Utc>, DateTime<Utc>, i64) {
    // NAN-4910: a backlog is worked oldest-first in bounded slices; the slice
    // shrinks after consecutive size-class failures.
    let size_failures_for_chunk = if is_marker_driven(rule) {
        counters.catchup_size_failures
    } else {
        0
    };
    let chunk_minutes = catchup_chunk_minutes(config.max_catchup_minutes, size_failures_for_chunk);
    let end = compute_window_end(rule.lookback_minutes, rule.last_run_at, now, chunk_minutes);
    let start = compute_window_start(
        rule.lookback_minutes,
        rule.last_run_at,
        end,
        config.default_lookback_minutes,
    );
    (start, end, chunk_minutes)
}

/// First back-off after a crash attributed to the rule (NAN-5736). Doubles
/// per consecutive attributed crash up to [`CRASH_BACKOFF_MAX_SECS`].
pub(crate) const CRASH_BACKOFF_BASE_SECS: i64 = 300;

/// Longest back-off for a rule whose runs keep killing the process.
pub(crate) const CRASH_BACKOFF_MAX_SECS: i64 = 6 * 3600;

/// Delay before a crash suspect (it died together with other rules) runs
/// again, in isolation (NAN-5736). Short: it is most likely innocent.
pub(crate) const CRASH_SUSPECT_RETRY_SECS: i64 = 60;

/// Spread of the per-rule jitter added to every crash back-off, so the rules
/// one crash killed together never come back in lockstep (NAN-5736).
pub(crate) const CRASH_JITTER_MAX_SECS: u64 = 120;

/// Back-off after `crash_streak` consecutive attributed crashes (NAN-5736):
/// 5 min, 10, 20, 40, … capped at 6 h. Jitter is added separately.
pub(crate) fn crash_backoff(crash_streak: i16) -> Duration {
    let doublings = u32::try_from(crash_streak.saturating_sub(1).max(0)).unwrap_or(0).min(16);
    let secs = CRASH_BACKOFF_BASE_SECS.saturating_mul(1_i64 << doublings);
    Duration::seconds(secs.min(CRASH_BACKOFF_MAX_SECS))
}

/// Deterministic per-rule jitter in `[0, CRASH_JITTER_MAX_SECS)` (NAN-5736).
pub(crate) fn crash_jitter(rule_id: Uuid) -> Duration {
    let bytes = rule_id.as_u128();
    let mixed = (bytes ^ (bytes >> 64)) as u64;
    Duration::seconds((mixed % CRASH_JITTER_MAX_SECS) as i64)
}

/// How a claim's crashed predecessor is handled (NAN-5736). Pure, so the
/// decision is unit-tested without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CrashFold {
    /// Counters to persist; `crashed_attempts` is 0.
    pub counters: RuleFailureCounters,
    /// New `last_run_at` (a coverage gap or first-run bootstrap moved it).
    pub advance_last_run_to: Option<DateTime<Utc>>,
    /// A window recorded as not evaluated after its retry budget was spent.
    pub coverage_gap: Option<(DateTime<Utc>, DateTime<Utc>, i32)>,
    /// When the rule runs again (the claim is released until then).
    pub next_run_at: DateTime<Utc>,
    /// The crash is this rule's: it died running alone.
    pub attributed: bool,
}

/// Decide what a claim's crashed predecessor means (NAN-5736).
///
/// A process crash kills every rule executing in it, so a crash is only
/// ATTRIBUTED to a rule whose dead claim was executing in isolation
/// (`isolated_claim`). Then each crashed attempt is decided exactly as a
/// failed release of class `other` would have been (narrow the slice first,
/// then the bounded retry budget, then a coverage gap), the attributed
/// streak grows and the rule backs off exponentially.
///
/// Otherwise attribution is ambiguous: the rule becomes a crash SUSPECT and
/// nothing else changes — no failure counted, no budget spent, no gap. It
/// runs again shortly, in isolation, which settles it. `failing_since` is set
/// so that, if the outage outlasts a sliding lookback, the interval that was
/// truly never evaluated is recorded when the rule recovers (NAN-5424).
pub(crate) fn fold_crashed_attempts(
    rule: &DetectionRule,
    prior: &RuleFailureCounters,
    config: &DistributedSchedulerConfig,
    now: DateTime<Utc>,
) -> CrashFold {
    let jitter = crash_jitter(rule.id);
    if !prior.isolated_claim {
        return CrashFold {
            counters: RuleFailureCounters {
                crashed_attempts: 0,
                crash_suspect: true,
                isolated_claim: false,
                failing_since: Some(prior.failing_since.unwrap_or(now)),
                ..prior.clone()
            },
            advance_last_run_to: None,
            coverage_gap: None,
            next_run_at: now + Duration::seconds(CRASH_SUSPECT_RETRY_SECS) + jitter,
            attributed: false,
        };
    }
    let crashes = prior.crashed_attempts.max(0);
    let mut counters = RuleFailureCounters { crashed_attempts: 0, ..prior.clone() };
    let mut probe = rule.clone();
    let mut advance_last_run_to = None;
    let mut coverage_gap = None;
    for _ in 0..crashes {
        let (start, end, _) = attempt_window(&probe, &counters, config, now);
        let decision = decide_release(
            ExecutionOutcome::OtherFailure,
            is_marker_driven(&probe),
            probe.last_run_at,
            &counters,
            start,
            end,
            now,
            config.max_catchup_minutes,
        );
        if let Some(mark) = decision.advance_last_run_to {
            probe.last_run_at = Some(mark);
            advance_last_run_to = Some(mark);
        }
        counters = RuleFailureCounters {
            catchup_size_failures: decision.catchup_size_failures,
            consecutive_failures: decision.consecutive_failures,
            failing_since: decision.failing_since,
            failure_class: decision.failure_class.map(str::to_string),
            ..counters
        };
        if decision.coverage_gap.is_some() {
            // One gap row per release; the remaining crashes were attempts at
            // the window just recorded.
            coverage_gap = decision.coverage_gap;
            break;
        }
    }
    let streak = prior.crash_streak.max(0).saturating_add(crashes);
    counters.crash_streak = streak;
    counters.crash_suspect = true;
    counters.isolated_claim = false;
    CrashFold {
        counters,
        advance_last_run_to,
        coverage_gap,
        next_run_at: now + crash_backoff(streak) + jitter,
        attributed: true,
    }
}

/// The `last_error` a rule records when its dead claim is found (NAN-5736).
pub(crate) fn crash_error_message(fold: &CrashFold, now: DateTime<Utc>) -> String {
    let wait = (fold.next_run_at - now).num_minutes().max(1);
    if fold.attributed {
        format!(
            "[crash] the jobs process was killed while this rule ran ALONE (most often out of memory): {} crash(es) in a row; next attempt in {wait} min",
            fold.counters.crash_streak
        )
    } else {
        format!(
            "[crash?] the jobs process was killed while this rule ran together with other rules; it runs again in isolation in about {wait} min to find which rule causes it"
        )
    }
}

/// NAN-5736: a claim found its rule's previous claim never released (the
/// process died mid-run). Record it and RELEASE the claim without running:
/// the back-off is the new `next_run_at`, never a held claim.
async fn release_crashed_claim(
    rule_repo: &DetectionRuleRepository,
    rule: &DetectionRule,
    node_id: &str,
    config: &DistributedSchedulerConfig,
    counters: &RuleFailureCounters,
    now: DateTime<Utc>,
) {
    let fold = fold_crashed_attempts(rule, counters, config, now);
    let error = crash_error_message(&fold, now);
    counter!(
        "nanosiem_detection_execution_crashes_total",
        "attributed" => fold.attributed.to_string()
    )
    .increment(counters.crashed_attempts.max(0) as u64);
    if fold.attributed {
        error!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            crash_streak = fold.counters.crash_streak,
            consecutive_failures = fold.counters.consecutive_failures,
            next_run_at = %fold.next_run_at,
            "Detection rule's run killed the process while running alone; counted as a failure and backed off"
        );
    } else {
        warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            next_run_at = %fold.next_run_at,
            "Process died while this rule ran with others; rerunning it in isolation"
        );
    }
    let coverage_gap = fold.coverage_gap.map(|(window_start, window_end, attempts)| {
        counter!("nanosiem_detection_coverage_gaps_total", "class" => "crash").increment(1);
        warn!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            window_start = %window_start,
            window_end = %window_end,
            attempts,
            "Detection window kept killing the process; recorded a coverage gap and moved past it"
        );
        DetectionCoverageGap { window_start, window_end, attempts, error_message: error.clone() }
    });
    let crash = CrashRelease {
        release: ClaimRelease {
            next_run_at: fold.next_run_at,
            advance_last_run_to: fold.advance_last_run_to,
            catchup_size_failures: fold.counters.catchup_size_failures,
            consecutive_failures: fold.counters.consecutive_failures,
            failing_since: fold.counters.failing_since,
            failure_class: fold.counters.failure_class.as_deref(),
            error: Some(&error),
            coverage_gap: coverage_gap.as_ref(),
        },
        crash_streak: fold.counters.crash_streak,
        crash_suspect: fold.counters.crash_suspect,
    };
    match rule_repo.release_crashed_claim(rule.id, node_id, &crash).await {
        Ok(true) => {}
        Ok(false) => warn!(rule_id = %rule.id, "Claim lost before the crash was recorded; another node owns it"),
        Err(e) => error!(rule_id = %rule.id, "Failed to record the crashed run: {}", e),
    }
}

/// How one execution attempt ended, for the release decision (NAN-4910,
/// NAN-5424).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionOutcome {
    Success,
    /// Failed because of the window's size ([`crate::detection::DetectionError::is_window_size_dependent`]).
    SizeFailure,
    /// The rule's own query is invalid (NAN-4031): independent of the data,
    /// so the window is kept for when the rule is fixed.
    DeterministicFailure,
    /// PostgreSQL refused the data being persisted
    /// ([`crate::detection::DetectionError::is_persistence_data_error`]).
    DataFailure,
    /// The backend was unreachable or stalled
    /// ([`crate::detection::DetectionError::is_transient_infrastructure`]).
    TransientFailure,
    /// Anything else, including an execution panic.
    OtherFailure,
}

impl ExecutionOutcome {
    fn as_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::SizeFailure => "size",
            Self::DeterministicFailure => "deterministic",
            Self::DataFailure => "data",
            Self::TransientFailure => "transient",
            Self::OtherFailure => "other",
        }
    }
}

fn classify_outcome<T>(result: &Result<T, crate::detection::DetectionError>) -> ExecutionOutcome {
    match result {
        Ok(_) => ExecutionOutcome::Success,
        Err(e) if e.is_window_size_dependent() => ExecutionOutcome::SizeFailure,
        Err(_) if is_deterministic_failure(result) => ExecutionOutcome::DeterministicFailure,
        Err(e) if e.is_persistence_data_error() => ExecutionOutcome::DataFailure,
        Err(e) if e.is_transient_infrastructure() => ExecutionOutcome::TransientFailure,
        Err(_) => ExecutionOutcome::OtherFailure,
    }
}

/// What `release_claim` should write after an attempt (NAN-4910, NAN-5424).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseDecision {
    advance_last_run_to: Option<DateTime<Utc>>,
    catchup_size_failures: i16,
    consecutive_failures: i16,
    failing_since: Option<DateTime<Utc>>,
    failure_class: Option<&'static str>,
    /// `[start, end]` of a window recorded as not evaluated, and the attempts
    /// it took.
    coverage_gap: Option<(DateTime<Utc>, DateTime<Utc>, i32)>,
    reclaim_immediately: bool,
}

/// Smallest catch-up slice (minutes). A slice of this size that keeps failing
/// for a size reason is recorded as a coverage gap (NAN-4910).
const MIN_CATCHUP_CHUNK_MINUTES: i64 = 5;

/// Consecutive size-class failures OF THE MINIMUM SLICE before it is recorded
/// as a coverage gap. More than one, so a single transient timeout at the
/// minimum slice does not cost coverage.
const MIN_CHUNK_ATTEMPTS: i16 = 3;

/// NAN-5424: attempts at one window that PostgreSQL refused for its data
/// (SQLSTATE 22xxx / 54xxx) before the window is recorded as a coverage gap.
/// Re-running writes the same rows, so only a short budget (for a fix that
/// lands mid-incident) is useful.
pub(crate) const DATA_FAILURE_ATTEMPTS: i16 = 3;

/// NAN-5424: an unclassified failure (including an execution panic or a
/// crash mid-run) becomes a coverage gap only after at least this many
/// attempts AND [`OTHER_FAILURE_MIN_PIN`] of continuous failure. Only failures
/// POSITIVELY identified as data-caused get the short budget.
pub(crate) const OTHER_FAILURE_ATTEMPTS: i16 = 5;

/// See [`OTHER_FAILURE_ATTEMPTS`].
pub(crate) const OTHER_FAILURE_MIN_PIN: Duration = Duration::hours(1);

/// NAN-5424: an infrastructure failure (backend unreachable or stalled)
/// becomes a coverage gap only after at least this many attempts AND
/// [`TRANSIENT_FAILURE_MAX_PIN`] of continuous failure. Shorter outages keep
/// the window, which is caught up once the backend is back (NAN-4910); the
/// rule reads as failing the whole time.
pub(crate) const TRANSIENT_FAILURE_ATTEMPTS: i16 = 10;

/// See [`TRANSIENT_FAILURE_ATTEMPTS`].
pub(crate) const TRANSIENT_FAILURE_MAX_PIN: Duration = Duration::hours(6);

/// A rule whose window is driven by its `last_run_at` high-water mark (no
/// sliding `lookback_minutes`, has run before, not a retro hunt). Only these
/// get shrinking slices: a sliding-lookback rule never advances a marker, and
/// a retro hunt evaluates its own historical window.
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

/// Decide the release writes for one attempt (NAN-4910, NAN-5424). `now` is
/// the evaluation time the window was derived from.
///
/// Coverage invariant: every interval the rule did not successfully evaluate
/// is either still ahead of the high-water mark (it will be retried) or
/// recorded in `coverage_gap`:
/// - a marker-driven rule only moves its mark past a failed window together
///   with a gap row for exactly that window;
/// - a sliding-lookback rule cannot hold a window. When its retry budget is
///   spent, the gap covers everything since its last successful run
///   (`[last_run_at, end]`); when it recovers after a failure streak whose
///   length outran its lookback, `[last_run_at, start)` is recorded.
///
/// A failure streak is per class: a failure of another class starts a new
/// one, so one class's attempts never spend another's budget.
#[allow(clippy::too_many_arguments)]
fn decide_release(
    outcome: ExecutionOutcome,
    marker_driven: bool,
    prior_last_run_at: Option<DateTime<Utc>>,
    prior: &RuleFailureCounters,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
    max_catchup_minutes: i64,
) -> ReleaseDecision {
    let class = outcome.as_label();
    let same_class = prior.failure_class.as_deref() == Some(class);
    let (prior_consecutive, prior_since) = if same_class {
        (prior.consecutive_failures.max(0), prior.failing_since)
    } else {
        (0, None)
    };
    let failing_since = Some(prior_since.unwrap_or(now));
    let streak_age = now - failing_since.unwrap_or(now);
    let failure_class = Some(class);
    let keep_marker = |consecutive_failures: i16| ReleaseDecision {
        advance_last_run_to: next_last_run_at(false, prior_last_run_at, start, end),
        catchup_size_failures: prior.catchup_size_failures,
        consecutive_failures,
        failing_since,
        failure_class,
        coverage_gap: None,
        reclaim_immediately: false,
    };
    // Everything since the last successful run, for a sliding-lookback rule.
    let sliding_gap_start = match prior_last_run_at {
        Some(last) if !marker_driven && last < start => last,
        _ => start,
    };
    // NAN-5424: retry the same window while `exhausted` says the budget is
    // not spent, then record it as a coverage gap and move past it.
    let bounded = |exhausted: &dyn Fn(i16) -> bool| {
        let failures = prior_consecutive.saturating_add(1);
        if !exhausted(failures) || start >= end {
            return keep_marker(failures);
        }
        ReleaseDecision {
            advance_last_run_to: Some(end),
            catchup_size_failures: 0,
            consecutive_failures: 0,
            failing_since: None,
            failure_class: None,
            coverage_gap: Some((sliding_gap_start, end, i32::from(failures))),
            reclaim_immediately: marker_driven && end < now,
        }
    };
    // NAN-5424: for a marker-driven rule, a data / unclassified failure first
    // narrows the window through the NAN-4910 slice ladder, so a value that
    // breaks one window costs at most the minimum slice, not a whole catch-up
    // chunk. Narrowing steps do not spend the retry budget.
    let shrink_first = |budgeted: &dyn Fn() -> ReleaseDecision| {
        let current = catchup_chunk_minutes(max_catchup_minutes, prior.catchup_size_failures);
        if marker_driven
            && current > MIN_CATCHUP_CHUNK_MINUTES
            && end - start > Duration::minutes(MIN_CATCHUP_CHUNK_MINUTES)
        {
            let next = prior.catchup_size_failures.saturating_add(1);
            let next_chunk = Duration::minutes(catchup_chunk_minutes(max_catchup_minutes, next));
            return ReleaseDecision {
                advance_last_run_to: None,
                catchup_size_failures: next,
                consecutive_failures: prior_consecutive,
                failing_since,
                failure_class,
                coverage_gap: None,
                reclaim_immediately: next_chunk < end - start,
            };
        }
        budgeted()
    };
    match outcome {
        ExecutionOutcome::Success => {
            // A sliding-lookback rule recovering from a streak longer than
            // its lookback never evaluated [last_run_at, start).
            let was_failing = prior.consecutive_failures > 0 || prior.failing_since.is_some();
            let missed = match prior_last_run_at {
                Some(last) if !marker_driven && was_failing && last < start => {
                    Some((last, start, i32::from(prior.consecutive_failures.max(0))))
                }
                _ => None,
            };
            ReleaseDecision {
                advance_last_run_to: next_last_run_at(true, prior_last_run_at, start, end),
                catchup_size_failures: 0,
                consecutive_failures: 0,
                failing_since: None,
                failure_class: None,
                coverage_gap: missed,
                reclaim_immediately: end < now,
            }
        }
        // NAN-4031: independent of the data; keep the window for when the
        // rule is fixed, but count the failure so the rule reads as failing.
        ExecutionOutcome::DeterministicFailure => {
            keep_marker(prior_consecutive.saturating_add(1))
        }
        ExecutionOutcome::DataFailure => {
            shrink_first(&|| bounded(&|n| n >= DATA_FAILURE_ATTEMPTS))
        }
        ExecutionOutcome::OtherFailure => shrink_first(&|| {
            bounded(&|n| n >= OTHER_FAILURE_ATTEMPTS && streak_age >= OTHER_FAILURE_MIN_PIN)
        }),
        ExecutionOutcome::TransientFailure => bounded(&|n| {
            n >= TRANSIENT_FAILURE_ATTEMPTS && streak_age >= TRANSIENT_FAILURE_MAX_PIN
        }),
        // A sliding-lookback rule cannot shrink its window: treat a size
        // failure like an unclassified bounded failure.
        ExecutionOutcome::SizeFailure if !marker_driven => bounded(&|n| {
            n >= OTHER_FAILURE_ATTEMPTS && streak_age >= OTHER_FAILURE_MIN_PIN
        }),
        ExecutionOutcome::SizeFailure => {
            let failures = prior.catchup_size_failures.max(0);
            let first_min = size_failures_at_min_chunk(max_catchup_minutes);
            if failures >= first_min && failures - first_min + 1 >= MIN_CHUNK_ATTEMPTS {
                // The minimum slice failed MIN_CHUNK_ATTEMPTS times in a row
                // for a size reason: a smaller retry does not exist and the
                // same slice will not succeed. Record it and move past it
                // rather than pinning the rule on it forever.
                ReleaseDecision {
                    advance_last_run_to: Some(end),
                    catchup_size_failures: 0,
                    consecutive_failures: 0,
                    failing_since: None,
                    failure_class: None,
                    coverage_gap: Some((start, end, i32::from(failures) + 1)),
                    reclaim_immediately: end < now,
                }
            } else {
                let next = failures.saturating_add(1);
                let next_chunk = Duration::minutes(catchup_chunk_minutes(max_catchup_minutes, next));
                ReleaseDecision {
                    advance_last_run_to: None,
                    catchup_size_failures: next,
                    consecutive_failures: prior_consecutive,
                    failing_since,
                    failure_class,
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

#[cfg(test)]
mod bounded_retry_tests;

#[cfg(test)]
mod nul_persistence_integration_tests;

#[cfg(test)]
mod crash_checkpoint_tests;
