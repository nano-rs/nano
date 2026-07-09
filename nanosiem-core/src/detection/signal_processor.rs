// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signal Processor Service
//!
//! Bridges ClickHouse signals (from materialized views) to PostgreSQL alerts,
//! completing the real-time detection pipeline.
//!
//! ## Overview
//!
//! Materialized views in ClickHouse write detected signals to the `signals` table.
//! This service polls that table every 1.5 seconds and:
//! 1. Creates alerts in PostgreSQL
//! 2. Groups alerts into cases
//! 3. Logs findings for analytics
//!
//! ## Architecture
//!
//! ```text
//! ClickHouse MV → signals table → SignalProcessor → PostgreSQL alerts
//!                                       ↓
//!                                 CaseService (auto-grouping)
//!                                       ↓
//!                                 FindingLogger (analytics)
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::db::DualPool;
use crate::db::repository::detection_rules::DetectionRuleRepositoryError;
use crate::db::repository::{AlertRepository, AlertRepositoryError, DetectionRuleRepository};
use crate::detection::findings::FindingLogger;
use crate::detection::risk::{score_rule_match, RiskModifier, RiskResult, ScoreCalculator};
use crate::detection::service::helpers::{
    realtime_finding_candidate, record_finding_emissions_with_pool, retain_unemitted_with_pool,
};
use crate::detection::service::ClaimedFinding;
use crate::extensions::{
    AlertCasePermissions, CaseGroupingHook, NoopCaseGroupingHook, NoopShadowInvestigationHook,
    ShadowInvestigationHook,
};
use crate::models::{AlertMode, DetectionRule, NewAlert, RuleMode};
use crate::webhooks::WebhookService;

/// Configuration for the signal processor
#[derive(Debug, Clone)]
pub struct SignalProcessorConfig {
    /// Polling interval in milliseconds (default: 1500ms = 1.5 seconds)
    pub poll_interval_ms: u64,
    /// Maximum signals to process per batch (default: 100)
    pub batch_size: usize,
    /// Maximum retry attempts for transient errors (default: 3)
    pub max_retries: u32,
    /// Base seconds for exponential backoff (default: 2)
    pub backoff_base_secs: u64,
    /// After this many consecutive errors, advance the watermark to skip stuck signals (default: 10)
    pub max_skip_threshold: u32,
    /// Settling lag in seconds applied to the poll watermark (default: 5).
    ///
    /// `_inserted_at` is a `DEFAULT now64()` stamp; a row's column value is set
    /// at row creation but the containing part does not become queryable in
    /// strict `_inserted_at` order. Two concurrent inserts can therefore be made
    /// visible out of order — a row with a *smaller* `_inserted_at` may appear
    /// only after we have already advanced the watermark past a peer with a
    /// larger stamp, which would silently drop the earlier signal.
    ///
    /// The poll query only considers signals older than `now64() - lag`, so we
    /// never advance the watermark into a band where inserts may still be
    /// settling. As long as the lag exceeds the max insert-visibility skew,
    /// strict `_inserted_at > watermark` advancement can never skip a concurrent
    /// insert. It costs `watermark_lag_secs` of added processing latency.
    pub watermark_lag_secs: u64,
}

impl Default for SignalProcessorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1500,
            batch_size: 100,
            max_retries: 3,
            backoff_base_secs: 2,
            max_skip_threshold: 10,
            watermark_lag_secs: 5,
        }
    }
}

/// Outcome of processing a single signal, so the batch loop can aggregate
/// high-volume skip reasons into ONE summary log per poll cycle instead of
/// one line per signal. Draining a large backlog of unenrichable signals
/// (e.g. matched logs TTL'd out, or stale/synthetic seed rows) otherwise
/// floods the log — a bounded `fetch_matched_log` (R5) made each skip fast
/// enough to turn that flood into a storm (NAN-1661 follow-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalOutcome {
    /// Alert created (or a real finding path ran) for this signal.
    Processed,
    /// Alert deduplicated against an existing one.
    Duplicate,
    /// The matched log was not found within the bounded window.
    MatchedLogMissing,
    /// The signal's detection rule no longer exists.
    RuleMissing,
    /// The rule's mode (Staging/Paused) means this signal must not produce an
    /// alert or finding (audit D11).
    ModeSkipped,
    /// A Grouped rule already alerted this (rule, entity, window) — the signal
    /// is a genuine match (counted in stats) but its alert/finding is
    /// suppressed by the per-window dedup (audit D13).
    WindowDeduped,
}

/// Watermark for tracking processed signals
#[derive(Debug, Clone)]
pub struct ProcessorWatermark {
    pub last_inserted_at: DateTime<Utc>,
    pub last_signal_id: Option<Uuid>,
    pub processed_count: u64,
    /// Transient (in-memory only): the `(inserted_at, id)` of the signal that
    /// stalled the current batch, so the force-skip can dead-letter *exactly*
    /// that signal instead of a coarse 1-second window (audit D7). Cleared on
    /// any fully-successful poll.
    pub last_error_signal: Option<(DateTime<Utc>, Uuid)>,
}

impl Default for ProcessorWatermark {
    fn default() -> Self {
        Self {
            last_inserted_at: DateTime::from_timestamp(0, 0).unwrap_or_else(Utc::now),
            last_signal_id: None,
            processed_count: 0,
            last_error_signal: None,
        }
    }
}

/// A signal from the ClickHouse signals table (internal row type)
/// UUIDs are converted to strings in the SQL query via toString() for compatibility
/// Field names match the SQL aliases to avoid column name conflicts
#[derive(Debug, Clone, Row, Deserialize)]
struct ClickHouseSignalRow {
    pub signal_id: String,
    pub ts: i64, // Microseconds since epoch
    pub detection_rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub risk_score: i32,
    pub risk_entity: String,
    pub log_id: String,
    pub metadata: String,
    pub inserted_ts: i64, // Microseconds since epoch
}

/// A signal from the ClickHouse signals table
#[derive(Debug, Clone)]
pub struct ClickHouseSignal {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub severity: String,
    pub risk_score: i32,
    pub risk_entity: String,
    pub matched_log_id: Uuid,
    pub metadata: String,
    pub inserted_at: DateTime<Utc>,
}

impl TryFrom<ClickHouseSignalRow> for ClickHouseSignal {
    type Error = uuid::Error;

    fn try_from(row: ClickHouseSignalRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&row.signal_id)?,
            timestamp: DateTime::from_timestamp_micros(row.ts).unwrap_or_else(Utc::now),
            rule_id: Uuid::parse_str(&row.detection_rule_id)?,
            rule_name: row.rule_name,
            severity: row.severity,
            risk_score: row.risk_score,
            risk_entity: row.risk_entity,
            matched_log_id: Uuid::parse_str(&row.log_id)?,
            metadata: row.metadata,
            inserted_at: DateTime::from_timestamp_micros(row.inserted_ts).unwrap_or_else(Utc::now),
        })
    }
}

/// Signal processor that bridges ClickHouse signals to PostgreSQL alerts
pub struct SignalProcessor {
    dual_pool: DualPool,
    config: SignalProcessorConfig,
    watermark: Arc<RwLock<ProcessorWatermark>>,
    running: Arc<AtomicBool>,
    /// Case grouping hook (open-core default no-op skips grouping)
    case_grouping: Arc<dyn CaseGroupingHook>,
    /// Shadow investigation hook for auto-triage on new case creation
    /// (open-core default no-op)
    shadow_investigation: Arc<dyn ShadowInvestigationHook>,
    /// Webhook delivery service. NAN-1741 A2: real-time (materialized-view)
    /// detection alerts fire webhooks through this, mirroring the scheduled
    /// path's `DetectionService::webhook_service`. Optional/None-safe:
    /// open-core builds and tests that don't wire it leave `None` and simply
    /// skip webhook delivery (mirrors how `case_grouping` is optional).
    webhook_service: Option<WebhookService>,
}

impl SignalProcessor {
    /// Create a new signal processor with DualPool
    pub fn new(dual_pool: DualPool, config: SignalProcessorConfig) -> Self {
        Self {
            dual_pool,
            config,
            watermark: Arc::new(RwLock::new(ProcessorWatermark::default())),
            running: Arc::new(AtomicBool::new(false)),
            case_grouping: Arc::new(NoopCaseGroupingHook),
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
            webhook_service: None,
        }
    }

    /// Create with default configuration
    pub fn with_defaults(dual_pool: DualPool) -> Self {
        Self::new(dual_pool, SignalProcessorConfig::default())
    }

    /// Set the shadow investigation hook for auto-triage on new case creation.
    ///
    /// Open-core builds default to a no-op; the enterprise crate injects a
    /// real `ShadowInvestigationHook` impl at AppState construction time.
    pub fn with_shadow_investigation(mut self, hook: Arc<dyn ShadowInvestigationHook>) -> Self {
        self.shadow_investigation = hook;
        self
    }

    /// Set the case grouping hook for auto-grouping alerts into cases.
    ///
    /// Open-core builds default to a no-op (alerts skip case grouping); the
    /// enterprise crate injects a real `CaseGroupingHook` impl at AppState
    /// construction time.
    pub fn with_case_grouping(mut self, hook: Arc<dyn CaseGroupingHook>) -> Self {
        self.case_grouping = hook;
        self
    }

    /// Set the webhook delivery service so real-time (materialized-view)
    /// detection alerts fire webhooks (NAN-1741 A2). Mirrors the scheduled
    /// path, which wires the same `WebhookService` onto `DetectionService`.
    /// Optional: open-core builds and tests that don't wire it leave `None`
    /// and simply skip webhook delivery (like the no-op `case_grouping`).
    pub fn with_webhook_service(mut self, service: WebhookService) -> Self {
        self.webhook_service = Some(service);
        self
    }

    /// Start the signal processor background task
    #[instrument(skip(self))]
    pub async fn start(&self) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        // Load watermark from PostgreSQL
        self.load_watermark().await?;

        // Mark as running
        self.running.store(true, Ordering::SeqCst);

        info!(
            poll_interval_ms = self.config.poll_interval_ms,
            batch_size = self.config.batch_size,
            "Starting signal processor"
        );

        // Clone what we need for the background task
        let dual_pool = self.dual_pool.clone();
        let rule_repo = DetectionRuleRepository::new(self.dual_pool.postgres().clone());
        let alert_repo = AlertRepository::new(self.dual_pool.postgres().clone());
        let finding_logger = FindingLogger::with_dual_pool(&self.dual_pool);
        let config = self.config.clone();
        let watermark = self.watermark.clone();
        let running = self.running.clone();
        let case_grouping = self.case_grouping.clone();
        let shadow_investigation = self.shadow_investigation.clone();
        // NAN-1741 A2: clone the optional webhook service into the task so
        // real-time alerts fire webhooks. `None` in open-core / tests → no-op.
        let webhook_service = self.webhook_service.clone();

        let handle = tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;

            while running.load(Ordering::SeqCst) {
                // Poll for new signals
                match Self::poll_and_process(
                    &dual_pool,
                    &rule_repo,
                    &alert_repo,
                    case_grouping.as_ref(),
                    &finding_logger,
                    &config,
                    &watermark,
                    shadow_investigation.as_ref(),
                    webhook_service.as_ref(),
                )
                .await
                {
                    Ok(processed) => {
                        consecutive_errors = 0;
                        // Fully-successful poll → we're unstuck; forget any
                        // dead-letter candidate.
                        watermark.write().await.last_error_signal = None;
                        if processed > 0 {
                            debug!("Processed {} signals", processed);
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);

                        if consecutive_errors >= config.max_skip_threshold {
                            // After too many consecutive errors, dead-letter the
                            // problematic batch by advancing the watermark to
                            // prevent permanent stuckness. Audit D7/D33: this must
                            // advance the PERSISTED watermark — poll_and_process
                            // re-reads the PG row each cycle, so the previous
                            // in-memory-only advance was ignored while the seeded
                            // row exists, making the force-skip a no-op.
                            error!(
                                consecutive_errors,
                                "Signal processor stuck for {} consecutive errors, advancing persisted watermark to skip problematic signals",
                                consecutive_errors
                            );
                            if let Err(e) =
                                Self::force_advance_watermark(&dual_pool, &watermark).await
                            {
                                error!("Failed to persist force-skip watermark advance: {}", e);
                            }
                            consecutive_errors = 0;
                        } else if consecutive_errors >= config.max_retries {
                            error!(
                                consecutive_errors,
                                "Signal processor experiencing repeated errors: {}", e
                            );
                        } else {
                            warn!(
                                consecutive_errors,
                                "Signal processor error (will retry): {}", e
                            );
                        }

                        // Exponential backoff
                        let backoff_secs =
                            config.backoff_base_secs.saturating_pow(consecutive_errors);
                        let backoff_secs = backoff_secs.min(60); // Cap at 60 seconds
                        sleep(Duration::from_secs(backoff_secs)).await;
                        continue;
                    }
                }

                // Sleep until next poll
                sleep(Duration::from_millis(config.poll_interval_ms)).await;
            }

            info!("Signal processor stopped");
        });

        Ok(handle)
    }

    /// Stop the signal processor
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Signal processor stop requested");
    }

    /// Check if the processor is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Load watermark from PostgreSQL
    #[instrument(skip(self))]
    async fn load_watermark(&self) -> anyhow::Result<()> {
        let row: Option<(DateTime<Utc>, Option<Uuid>, i64)> = sqlx::query_as(
            r#"
            SELECT last_inserted_at, last_signal_id, processed_count
            FROM signal_processor_watermarks
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(self.dual_pool.postgres())
        .await?;

        if let Some((last_inserted_at, last_signal_id, processed_count)) = row {
            let mut wm = self.watermark.write().await;
            wm.last_inserted_at = last_inserted_at;
            wm.last_signal_id = last_signal_id;
            wm.processed_count = processed_count as u64;

            info!(
                last_inserted_at = %last_inserted_at,
                last_signal_id = ?last_signal_id,
                processed_count,
                "Loaded signal processor watermark"
            );
        } else {
            info!("No existing watermark found, starting from beginning");
        }

        Ok(())
    }

    /// Format a DateTime for ClickHouse query interpolation
    fn format_datetime_for_ch(dt: &DateTime<Utc>) -> String {
        crate::sql_hygiene::format_ch_bound_micros(dt)
    }

    /// Build the incremental signals-poll query for the current watermark.
    ///
    /// The watermark advances strictly by `_inserted_at` (with `id` as the
    /// tie-break at an identical microsecond), but `_inserted_at` is not
    /// commit-ordered: concurrent inserts can become queryable out of stamp
    /// order, so a row with a smaller `_inserted_at` may appear *after* the
    /// watermark has already advanced past a peer with a larger stamp. Left
    /// unguarded, that earlier signal is skipped forever (R7).
    ///
    /// The `AND _inserted_at <= now64(6) - toIntervalSecond(lag)` settling
    /// clause makes the poll ignore any signal newer than `lag` seconds, so the
    /// watermark is only ever advanced into a band where all concurrent inserts
    /// have already settled into a visible part. Provided `lag` exceeds the max
    /// insert-visibility skew, no concurrent insert can be missed.
    ///
    /// The strict `_inserted_at > W OR (_inserted_at = W AND id > last_id)` lower
    /// bound is wrapped in parentheses so the trailing settling `AND` binds to
    /// the whole disjunction rather than only its final term.
    fn build_poll_signals_query(
        signals_table: &str,
        watermark_str: &str,
        last_signal_id: Option<Uuid>,
        batch_size: usize,
        watermark_lag_secs: u64,
    ) -> String {
        // Only consider signals that have had at least `watermark_lag_secs` to
        // settle into a queryable part before the watermark can cross them.
        let settle_clause =
            format!("AND _inserted_at <= now64(6) - toIntervalSecond({watermark_lag_secs})");

        if let Some(last_id) = last_signal_id {
            format!(
                r#"
                SELECT
                    toString(id) as signal_id,
                    reinterpretAsInt64(timestamp) as ts,
                    toString(rule_id) as detection_rule_id,
                    rule_name,
                    severity,
                    risk_score,
                    risk_entity,
                    toString(matched_log_id) as log_id,
                    metadata,
                    reinterpretAsInt64(_inserted_at) as inserted_ts
                FROM {signals_table}
                WHERE (_inserted_at > toDateTime64('{watermark_str}', 6)
                       OR (_inserted_at = toDateTime64('{watermark_str}', 6) AND id > '{last_id}'))
                  {settle_clause}
                ORDER BY _inserted_at ASC, id ASC
                LIMIT {batch_size}
                "#,
            )
        } else {
            format!(
                r#"
                SELECT
                    toString(id) as signal_id,
                    reinterpretAsInt64(timestamp) as ts,
                    toString(rule_id) as detection_rule_id,
                    rule_name,
                    severity,
                    risk_score,
                    risk_entity,
                    toString(matched_log_id) as log_id,
                    metadata,
                    reinterpretAsInt64(_inserted_at) as inserted_ts
                FROM {signals_table}
                WHERE _inserted_at > toDateTime64('{watermark_str}', 6)
                  {settle_clause}
                ORDER BY _inserted_at ASC, id ASC
                LIMIT {batch_size}
                "#,
            )
        }
    }

    /// Poll ClickHouse for new signals and process them.
    ///
    /// Uses `SELECT ... FOR UPDATE` on the watermark row to prevent duplicate
    /// processing during leader election flaps. The row lock is held for the
    /// entire poll cycle so a second leader blocks until the first commits.
    #[instrument(skip_all)]
    async fn poll_and_process(
        dual_pool: &DualPool,
        rule_repo: &DetectionRuleRepository,
        alert_repo: &AlertRepository,
        case_grouping: &dyn CaseGroupingHook,
        finding_logger: &FindingLogger,
        config: &SignalProcessorConfig,
        watermark: &Arc<RwLock<ProcessorWatermark>>,
        shadow_investigation: &dyn ShadowInvestigationHook,
        webhook_service: Option<&WebhookService>,
    ) -> anyhow::Result<usize> {
        // Acquire row-level lock on the watermark within a transaction.
        // This prevents two leaders from processing the same signals concurrently.
        // Set a statement timeout as a safety net — if the ClickHouse query stalls,
        // the lock is released after 5 minutes rather than waiting for
        // idle_in_transaction_session_timeout.
        let mut tx = dual_pool.postgres().begin().await?;
        sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '5min'")
            .execute(&mut *tx)
            .await?;

        let row: Option<(chrono::DateTime<chrono::Utc>, Option<uuid::Uuid>, i64)> = sqlx::query_as(
            r#"
            SELECT last_inserted_at, last_signal_id, processed_count
            FROM signal_processor_watermarks
            WHERE id = 'default'
            FOR UPDATE
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let (last_inserted_at, last_signal_id, processed_count) = if let Some((ts, sid, cnt)) = row
        {
            (ts, sid, cnt as u64)
        } else {
            let wm = watermark.read().await;
            (wm.last_inserted_at, wm.last_signal_id, wm.processed_count)
        };

        // Format watermark timestamp for ClickHouse
        let watermark_str = Self::format_datetime_for_ch(&last_inserted_at);

        // Query ClickHouse for new signals
        // Use _inserted_at for watermark (when the signal was written)
        // Handle tie-breaking with signal ID for signals at the same microsecond
        // Use reinterpretAsInt64 to convert DateTime64 to microseconds
        // Use toString() for UUIDs because clickhouse-rs UUID support has compatibility issues
        let signals_table = dual_pool.table_names().read("signals");
        let query = Self::build_poll_signals_query(
            &signals_table,
            &watermark_str,
            last_signal_id,
            config.batch_size,
            config.watermark_lag_secs,
        );

        let ch_client = dual_pool.clickhouse();

        let signal_rows: Vec<ClickHouseSignalRow> = ch_client.query(&query).fetch_all().await?;

        // Convert rows to signals, filtering out any with invalid UUIDs
        let signals: Vec<ClickHouseSignal> = signal_rows
            .into_iter()
            .filter_map(|r| match ClickHouseSignal::try_from(r) {
                Ok(signal) => Some(signal),
                Err(e) => {
                    warn!("Failed to parse signal row UUID: {}", e);
                    None
                }
            })
            .collect();

        if signals.is_empty() {
            return Ok(0);
        }

        let signal_count = signals.len();
        debug!("Found {} new signals to process", signal_count);

        // Build the scoring inputs ONCE per batch (not per signal): the global
        // risk weight and a ScoreCalculator bound to the active schema profile —
        // the same inputs the scheduled path feeds ScoreCalculator, so real-time
        // findings score identically (NAN-1663).
        let global_weight = Self::load_risk_weight(dual_pool).await;
        let score_calculator = match crate::schema::active_profile_from_env() {
            Ok(profile) => ScoreCalculator::new().with_profile(profile),
            Err(e) => {
                warn!("SignalProcessor: invalid schema profile ({e}); using UDM default");
                ScoreCalculator::new()
            }
        };

        let mut processed = 0;
        let mut last_processed_signal: Option<ClickHouseSignal> = None;
        // Audit D7: a signal that fails to process stops the batch here so the
        // watermark is NOT advanced past it. The error is propagated after the
        // watermark commits progress up to the last SUCCESSFUL signal.
        let mut batch_error: Option<anyhow::Error> = None;
        // The exact (inserted_at, id) of the stalled signal, so the force-skip
        // can dead-letter precisely it rather than a coarse 1s window (audit D7).
        let mut stuck_signal: Option<(DateTime<Utc>, Uuid)> = None;
        // Per-cycle skip aggregation (see the summary logs after the loop).
        let mut missing_log_count: u64 = 0;
        let mut missing_rule_count: u64 = 0;
        let mut mode_skipped_count: u64 = 0;
        let mut window_deduped_count: u64 = 0;
        let mut missing_log_sample: Option<(Uuid, Uuid, DateTime<Utc>)> = None;

        for signal in signals {
            match Self::process_signal(
                dual_pool,
                rule_repo,
                alert_repo,
                case_grouping,
                finding_logger,
                &signal,
                shadow_investigation,
                &score_calculator,
                global_weight,
                webhook_service,
            )
            .await
            {
                Ok(outcome) => {
                    processed += 1;
                    match outcome {
                        SignalOutcome::MatchedLogMissing => {
                            missing_log_count += 1;
                            if missing_log_sample.is_none() {
                                missing_log_sample =
                                    Some((signal.id, signal.matched_log_id, signal.timestamp));
                            }
                        }
                        SignalOutcome::RuleMissing => missing_rule_count += 1,
                        SignalOutcome::ModeSkipped => mode_skipped_count += 1,
                        SignalOutcome::WindowDeduped => window_deduped_count += 1,
                        SignalOutcome::Processed | SignalOutcome::Duplicate => {}
                    }
                    last_processed_signal = Some(signal);
                }
                Err(e) => {
                    // Audit D7: do NOT advance the watermark past a signal that
                    // failed to process — a transient CH/PG/alert error would
                    // otherwise drop the detection forever. Stop the batch here
                    // (watermark stays at the last successful signal) and
                    // propagate below so the run loop retries next poll; its
                    // consecutive-error force-skip dead-letters a poison signal.
                    warn!(
                        signal_id = %signal.id,
                        rule_id = %signal.rule_id,
                        "Failed to process signal, holding watermark for retry: {}",
                        e
                    );
                    batch_error = Some(e);
                    stuck_signal = Some((signal.inserted_at, signal.id));
                    break;
                }
            }
        }

        // Aggregate skip reasons into ONE summary line per poll cycle rather than
        // one per signal, so draining a large backlog of unenrichable signals
        // can't flood the log (NAN-1661).
        if missing_log_count > 0 {
            if let Some((sid, lid, ts)) = missing_log_sample {
                warn!(
                    skipped = missing_log_count,
                    sample_signal_id = %sid,
                    sample_matched_log_id = %lid,
                    sample_event_ts = %ts,
                    "Skipped signals whose matched log was not found within the bounded \
                     window (event TTL'd, or stale/synthetic signal)"
                );
            }
        }
        if missing_rule_count > 0 {
            warn!(
                skipped = missing_rule_count,
                "Skipped signals whose detection rule no longer exists"
            );
        }
        if mode_skipped_count > 0 {
            debug!(
                skipped = mode_skipped_count,
                "Skipped signals for rules in Staging/Paused mode (audit D11)"
            );
        }
        if window_deduped_count > 0 {
            debug!(
                deduped = window_deduped_count,
                "Suppressed signals whose (rule, entity, window) was already alerted (audit D13)"
            );
        }

        // Update watermark after processing and commit the transaction
        // (releasing the FOR UPDATE row lock)
        if let Some(signal) = last_processed_signal {
            let new_count = processed_count.saturating_add(processed as u64);

            // Audit D33: UPSERT (not UPDATE-only) so a missing/deleted 'default'
            // row is recreated instead of silently persisting nothing — which
            // would reprocess the whole signals table on every restart.
            sqlx::query(
                r#"
                INSERT INTO signal_processor_watermarks
                    (id, last_inserted_at, last_signal_id, processed_count, updated_at)
                VALUES ('default', $1, $2, $3, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    last_inserted_at = EXCLUDED.last_inserted_at,
                    last_signal_id = EXCLUDED.last_signal_id,
                    processed_count = EXCLUDED.processed_count,
                    updated_at = NOW()
                "#,
            )
            .bind(signal.inserted_at)
            .bind(Some(signal.id))
            .bind(new_count as i64)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            // Update the in-memory watermark cache
            let mut wm = watermark.write().await;
            wm.last_inserted_at = signal.inserted_at;
            wm.last_signal_id = Some(signal.id);
            wm.processed_count = new_count;
        } else {
            // No signals processed, just release the lock
            tx.commit().await?;
        }

        // Record the stalled signal (in-memory only) so the run loop's force-skip
        // can dead-letter exactly it.
        if stuck_signal.is_some() {
            watermark.write().await.last_error_signal = stuck_signal;
        }

        // Audit D7: if a signal errored mid-batch, propagate now — AFTER
        // committing progress up to the last successful signal — so the run
        // loop counts it toward the force-skip threshold and retries the failed
        // signal on the next poll (rather than skipping past it).
        if let Some(e) = batch_error {
            return Err(e);
        }

        Ok(processed)
    }

    /// Advance the PERSISTED watermark by 1s (dropping the tie-break signal id)
    /// to dead-letter signals that have failed `max_skip_threshold` polls in a
    /// row. `poll_and_process` re-reads the PG row each cycle, so the previous
    /// in-memory-only advance was ignored while the seeded row exists — the
    /// force-skip was a no-op (audit D7/D33). Upserts so a missing row is
    /// recreated rather than silently dropped.
    async fn force_advance_watermark(
        dual_pool: &DualPool,
        watermark: &Arc<RwLock<ProcessorWatermark>>,
    ) -> anyhow::Result<()> {
        let (stuck, seed_ts) = {
            let wm = watermark.read().await;
            (
                wm.last_error_signal,
                wm.last_inserted_at + chrono::Duration::seconds(1),
            )
        };

        // Advance the PERSISTED watermark MONOTONICALLY against the authoritative
        // PG value (GREATEST / self-referential increment) so a stale in-memory
        // cache can never move it backward — which would reprocess signals and
        // re-attempt alerts (codex). When the exact stalled signal is known,
        // dead-letter precisely it; otherwise (a poll-level failure) skip the
        // current 1s window. RETURNING syncs the in-memory cache to what PG now
        // holds.
        let (new_ts, new_id): (DateTime<Utc>, Option<Uuid>) = match stuck {
            Some((ts, id)) => {
                // Advance to exactly the stalled signal, but ONLY if that
                // position is strictly ahead of the persisted watermark in the
                // poll's `(inserted_at, id)` tie-break order — where a NULL
                // persisted id means "already past every signal at that
                // microsecond", so it must never be regressed to a concrete id.
                // Both columns move together under one predicate so the tuple
                // can't rewind (codex). `updated_at` always changes, so
                // RETURNING yields the current row even when the position holds.
                sqlx::query_as(
                    r#"
                    INSERT INTO signal_processor_watermarks
                        (id, last_inserted_at, last_signal_id, updated_at)
                    VALUES ('default', $1, $2, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        last_inserted_at = CASE
                            WHEN EXCLUDED.last_inserted_at > signal_processor_watermarks.last_inserted_at
                              OR (EXCLUDED.last_inserted_at = signal_processor_watermarks.last_inserted_at
                                  AND signal_processor_watermarks.last_signal_id IS NOT NULL
                                  AND EXCLUDED.last_signal_id > signal_processor_watermarks.last_signal_id)
                            THEN EXCLUDED.last_inserted_at
                            ELSE signal_processor_watermarks.last_inserted_at
                        END,
                        last_signal_id = CASE
                            WHEN EXCLUDED.last_inserted_at > signal_processor_watermarks.last_inserted_at
                              OR (EXCLUDED.last_inserted_at = signal_processor_watermarks.last_inserted_at
                                  AND signal_processor_watermarks.last_signal_id IS NOT NULL
                                  AND EXCLUDED.last_signal_id > signal_processor_watermarks.last_signal_id)
                            THEN EXCLUDED.last_signal_id
                            ELSE signal_processor_watermarks.last_signal_id
                        END,
                        updated_at = NOW()
                    RETURNING last_inserted_at, last_signal_id
                    "#,
                )
                .bind(ts)
                .bind(id)
                .fetch_one(dual_pool.postgres())
                .await?
            }
            None => {
                sqlx::query_as(
                    r#"
                    INSERT INTO signal_processor_watermarks
                        (id, last_inserted_at, last_signal_id, updated_at)
                    VALUES ('default', $1, NULL, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        last_inserted_at =
                            signal_processor_watermarks.last_inserted_at + INTERVAL '1 second',
                        last_signal_id = NULL,
                        updated_at = NOW()
                    RETURNING last_inserted_at, last_signal_id
                    "#,
                )
                .bind(seed_ts)
                .fetch_one(dual_pool.postgres())
                .await?
            }
        };

        let mut wm = watermark.write().await;
        wm.last_inserted_at = new_ts;
        wm.last_signal_id = new_id;
        wm.last_error_signal = None;
        Ok(())
    }

    /// Process a single signal: create alert, group into case, log finding
    #[instrument(skip_all, fields(signal_id = %signal.id, rule_id = %signal.rule_id))]
    #[allow(clippy::too_many_arguments)]
    async fn process_signal(
        dual_pool: &DualPool,
        rule_repo: &DetectionRuleRepository,
        alert_repo: &AlertRepository,
        case_grouping: &dyn CaseGroupingHook,
        finding_logger: &FindingLogger,
        signal: &ClickHouseSignal,
        shadow_investigation: &dyn ShadowInvestigationHook,
        score_calculator: &ScoreCalculator,
        global_weight: f64,
        webhook_service: Option<&WebhookService>,
    ) -> anyhow::Result<SignalOutcome> {
        // Fetch the rule FIRST — its `risk_modifiers` decide which extra columns
        // the matched-log fetch must project so the real-time score sees the same
        // fields the scheduled path does (NAN-1663).
        let rule = match rule_repo.find_by_id(signal.rule_id).await {
            Ok(rule) => rule,
            Err(DetectionRuleRepositoryError::NotFound(_)) => {
                // Rule genuinely deleted. Aggregated by the batch loop (see
                // MatchedLogMissing) so a large backlog of signals for a deleted
                // rule cannot flood the log.
                return Ok(SignalOutcome::RuleMissing);
            }
            Err(e) => {
                // Transient error (PG saturation / connection blip). Audit D6:
                // propagate — do NOT classify as RuleMissing, or the whole batch
                // is dropped and the watermark advances past real detections.
                return Err(anyhow::anyhow!(
                    "Transient error fetching rule {}: {}",
                    signal.rule_id,
                    e
                ));
            }
        };

        // Audit D11: honor rule.mode in the real-time path. Staging and Paused
        // rules must NOT produce alerts or findings — a paused noisy rule that
        // keeps paging, or a rule created in default Staging that immediately
        // alerts production, breaks the Staging→Live→Alerting contract. Skip
        // before the matched-log fetch so we don't pay CH cost for a no-op.
        if matches!(rule.mode, RuleMode::Staging | RuleMode::Paused) {
            return Ok(SignalOutcome::ModeSkipped);
        }

        // Fetch the matched log from ClickHouse, bounded to a tight window around
        // the signal's event time so `id =` prunes to a single partition instead
        // of full-scanning `logs` (R5). The projection carries the entity fields,
        // message, metadata AND every column the rule's `risk_modifiers` reference
        // (NAN-1663), so the score below sees the same fields the scheduled path
        // does.
        let matched_log = match Self::fetch_matched_log(
            dual_pool,
            signal.matched_log_id,
            signal.timestamp,
            &rule.risk_modifiers,
        )
        .await?
        {
            Some(log) => log,
            None => {
                // A genuine miss (the bounded window is guaranteed to contain the
                // row, so this means the matched event is gone/TTL'd, or the signal
                // is stale/synthetic). Do NOT log per-signal here — the batch loop
                // aggregates these into one summary line so a backlog drain can't
                // flood the log (NAN-1661).
                return Ok(SignalOutcome::MatchedLogMissing);
            }
        };

        // Create matched_events JSON array with detection timing metadata
        let mut events_vec = vec![matched_log];
        crate::detection::service::helpers::inject_detected_at(
            &mut events_vec,
            chrono::Utc::now(),
        );

        // Score the match through the SAME engine the scheduled path uses (audit
        // R1 / NAN-1663): apply the rule's base score, its `risk_modifiers`, and
        // the global `risk_weight` to the matched event — instead of the STATIC
        // score the MV baked into `signal.risk_score`. The fetch above projects
        // every modifier-referenced column, so modifiers evaluate identically to
        // the scheduled path. Computed here, before `events_vec` is consumed into
        // the JSON array below.
        let mut risk_result = score_rule_match(score_calculator, &rule, &events_vec, global_weight);

        // Entity ATTRIBUTION: prefer what the scorer resolved from the event, but
        // when it couldn't (`entity_field` None — e.g. `risk_entity_field` is a
        // column outside the fetch projection like `process_name`), fall back to
        // the MV-computed `signal.risk_entity` (the MV already resolved
        // `risk_entity_field` per matching row). This avoids regressing to the
        // "unknown" default while keeping the scorer's own auto-detected field for
        // rules without an explicit `risk_entity_field` (NAN-1663). Only the SCORE
        // is recomputed; entity stays authoritative.
        if risk_result.entity_field.is_none() && !signal.risk_entity.is_empty() {
            risk_result.entity = signal.risk_entity.clone();
            risk_result.entity_field = rule.risk_entity_field.clone();
        }

        // Audit D13: Grouped rules (the default) dedup per (rule, entity, window
        // bucket) through the SAME persistent emission store the scheduled path
        // uses (`detection_finding_emissions`), so a burst of N signals for one
        // entity within a bucket yields ONE alert/finding — not an alert storm.
        // PerEvent rules get `None`: each event is its own alert by design, gated
        // only by the single-event `event_hash` (mirroring the scheduled
        // per-event path, which also skips the emission store).
        let dedup_candidate =
            Self::build_window_dedup_candidate(&rule, &risk_result, signal.timestamp);

        // Audit D11/D12: Live mode BAKES IN — record the match for tuning and log
        // a live finding, but never create a production alert or open a case.
        // Only Alerting pages. This also gives real-time Live rules real
        // match/sparkline data instead of looking dead (D12).
        if matches!(rule.mode, RuleMode::Live) {
            // Match counters accrue per signal (the scheduled path counts every
            // matched event too, before finding dedup).
            if let Err(e) = rule_repo.update_live_match_count(rule.id, 1).await {
                warn!(rule_id = %rule.id, "Real-time bake-in: update_live_match_count failed: {}", e);
            }
            let today = chrono::Utc::now().date_naive();
            if let Err(e) = rule_repo.record_daily_stats(rule.id, today, 1, 0).await {
                warn!(rule_id = %rule.id, "Real-time bake-in: record_daily_stats failed: {}", e);
            }

            // Audit D13: Grouped rules emit ONE live finding per (rule, entity,
            // window) — repeated signals for the same entity in the bucket would
            // otherwise inflate entity risk the scheduled Live path dedups.
            if let Some(candidate) = dedup_candidate {
                let mut new_findings = retain_unemitted_with_pool(
                    dual_pool.postgres(),
                    rule.id,
                    vec![candidate],
                )
                .await;
                let Some(candidate) = new_findings.pop() else {
                    debug!(
                        rule_id = %rule.id,
                        entity = %risk_result.entity,
                        "Real-time bake-in: live finding already emitted for this (entity, window) — suppressing (audit D13)"
                    );
                    return Ok(SignalOutcome::WindowDeduped);
                };
                // Record before logging, mirroring the scheduled
                // `log_live_findings` ordering. Best-effort: a failed write only
                // risks a duplicate live finding later (fail open).
                record_finding_emissions_with_pool(
                    dual_pool.postgres(),
                    rule.id,
                    std::slice::from_ref(&candidate),
                )
                .await;
            }

            if let Err(e) = finding_logger
                .log_detection_match(&rule, &events_vec, true, risk_result)
                .await
            {
                error!(rule_id = %rule.id, "Real-time bake-in: log_detection_match failed: {}", e);
            }
            return Ok(SignalOutcome::Processed);
        }

        // Audit D13: Alerting + Grouped — claim the (rule, entity, window) slot
        // BEFORE creating the alert. Read-only here (fail-open on store errors:
        // `retain_unemitted_with_pool` treats every candidate as new); the
        // emission is recorded only after the alert durably exists, mirroring the
        // scheduled `handle_grouped_alert` ordering (audit D5/D20).
        let claimed_finding: Option<ClaimedFinding> = match dedup_candidate {
            Some(candidate) => {
                let mut new_findings = retain_unemitted_with_pool(
                    dual_pool.postgres(),
                    rule.id,
                    vec![candidate],
                )
                .await;
                match new_findings.pop() {
                    Some(candidate) => Some(candidate),
                    None => {
                        // Already alerted this (entity, window). The signal is a
                        // genuine match — count it like the scheduled path counts
                        // matches on a suppressed duplicate alert — but do not
                        // page again.
                        if let Err(e) = rule_repo.update_execution_stats(rule.id, 1).await {
                            warn!(rule_id = %rule.id, "Real-time window-dedup: update_execution_stats failed: {}", e);
                        }
                        let today = chrono::Utc::now().date_naive();
                        if let Err(e) =
                            rule_repo.record_daily_stats(rule.id, today, 1, 0).await
                        {
                            warn!(rule_id = %rule.id, "Real-time window-dedup: record_daily_stats failed: {}", e);
                        }
                        debug!(
                            rule_id = %rule.id,
                            entity = %risk_result.entity,
                            event_ts = %signal.timestamp,
                            "Grouped rule already alerted this (entity, window) — suppressing duplicate real-time alert (audit D13)"
                        );
                        return Ok(SignalOutcome::WindowDeduped);
                    }
                }
            }
            // PerEvent: one alert per signal by design (no window dedup).
            None => None,
        };

        let matched_events = serde_json::Value::Array(events_vec);

        // Create alert with deduplication
        let new_alert = NewAlert {
            rule_id: signal.rule_id,
            severity: rule.severity,
            matched_events: matched_events.clone(),
            event_hash: None, // Will be computed by AlertRepository
            // A13 (NAN-1752): the real-time path creates one alert per signal
            // (a single matched event — `events_vec = vec![matched_log]`).
            match_count: Some(1),
        };

        let alert = match alert_repo.create(&new_alert).await {
            Ok(alert) => {
                info!(
                    alert_id = %alert.id,
                    rule_id = %signal.rule_id,
                    rule_name = %signal.rule_name,
                    "Created alert from signal"
                );
                alert
            }
            Err(AlertRepositoryError::DuplicateAlert(rule_id, hash)) => {
                // Audit D20 parity: a crash between the alert INSERT and the
                // emission record below leaves an alert without its emission row;
                // the replayed signal passes the window-dedup check and hits the
                // (rule_id, event_hash) unique index here. Record the emission
                // now so later same-window signals dedup instead of re-alerting.
                if let Some(candidate) = &claimed_finding {
                    record_finding_emissions_with_pool(
                        dual_pool.postgres(),
                        rule_id,
                        std::slice::from_ref(candidate),
                    )
                    .await;
                    // The (rule, entity, window) match is genuine but the alert
                    // already exists (crash-recovery: the first pass created the
                    // alert then crashed before recording stats — otherwise the
                    // WindowDeduped branch above would have caught it). Count the
                    // match (1, 0 alerts) like that branch and the scheduled D20
                    // arm. Grouped only: a PerEvent exact-content duplicate has no
                    // `claimed_finding` and is the SAME event — it must not
                    // double-count.
                    if let Err(e) = rule_repo.update_execution_stats(rule.id, 1).await {
                        warn!(rule_id = %rule.id, "Real-time dup-repair: update_execution_stats failed: {}", e);
                    }
                    let today = chrono::Utc::now().date_naive();
                    if let Err(e) = rule_repo.record_daily_stats(rule.id, today, 1, 0).await {
                        warn!(rule_id = %rule.id, "Real-time dup-repair: record_daily_stats failed: {}", e);
                    }
                }
                debug!(
                    rule_id = %rule_id,
                    event_hash = %hash,
                    "Duplicate alert, skipping"
                );
                return Ok(SignalOutcome::Duplicate);
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to create alert: {}", e));
            }
        };

        // Audit D13: record the (rule, entity, window) emission only now that the
        // alert durably exists (scheduled `handle_grouped_alert` ordering, audit
        // D5) — a failed alert insert must not orphan a dedup row that would
        // silently suppress a future alert. Best-effort: a failed write here
        // fails OPEN (a later same-window signal may re-alert; never suppressed).
        if let Some(candidate) = &claimed_finding {
            record_finding_emissions_with_pool(
                dual_pool.postgres(),
                rule.id,
                std::slice::from_ref(candidate),
            )
            .await;
        }

        // Audit D12: real-time Alerting rules must accrue execution stats too, or
        // they show match_count=0 / an empty sparkline and look dead. Bumped
        // (1 match, 1 alert) after a NEW alert. Genuine-but-deduped matches count
        // (1, 0) elsewhere — the window-dedup branch and the grouped dup-repair
        // arm above; only a PerEvent exact-content duplicate returns without
        // stats (same event, must not inflate the counters).
        if let Err(e) = rule_repo.update_execution_stats(rule.id, 1).await {
            warn!(rule_id = %rule.id, "Real-time: update_execution_stats failed: {}", e);
        }
        let today = chrono::Utc::now().date_naive();
        if let Err(e) = rule_repo.record_daily_stats(rule.id, today, 1, 1).await {
            warn!(rule_id = %rule.id, "Real-time: record_daily_stats failed: {}", e);
        }

        // Group alert into case with case permissions from the rule.
        // Open-core builds use a no-op CaseGroupingHook that returns Ok(None);
        // shadow investigation is skipped in that path.
        let has_non_public_visibility = rule.case_visibility != "public";
        let has_assigned_group = rule.case_assigned_group.is_some();
        let case_permissions = if has_non_public_visibility || has_assigned_group {
            let case_groups = if has_non_public_visibility {
                rule_repo.get_case_groups(rule.id).await.unwrap_or_default()
            } else {
                vec![]
            };
            Some(AlertCasePermissions {
                visibility: rule.case_visibility.clone(),
                group_ids: if case_groups.is_empty() {
                    None
                } else {
                    Some(case_groups.iter().map(|g| g.id).collect())
                },
                assigned_group: rule.case_assigned_group,
                playbook_selector_mode: rule.playbook_selector_mode.clone(),
                playbook_id: rule.playbook_id,
            })
        } else {
            None
        };

        match case_grouping
            .group_alert(&alert, Some(&signal.rule_name), case_permissions)
            .await
        {
            Ok(Some(grouped)) => {
                info!(
                    alert_id = %alert.id,
                    case_id = %grouped.case_id,
                    case_number = grouped.case_number,
                    is_new_case = grouped.is_new_case,
                    "Alert grouped into case"
                );

                // Trigger shadow investigation for NEW cases only.
                // Errors are advisory — log and continue.
                if grouped.is_new_case {
                    let _ = shadow_investigation
                        .on_case_created(grouped.case_id, &alert, grouped.notebook_id)
                        .await;
                }
            }
            Ok(None) => {
                debug!(
                    alert_id = %alert.id,
                    "Case grouping disabled (open-core build or hook returned None)"
                );
            }
            Err(e) => {
                error!(
                    alert_id = %alert.id,
                    error = %e,
                    "Failed to group alert into case"
                );
                // Don't fail the whole signal processing
            }
        }

        // Fire webhook notifications for the real-time detection alert (NAN-1741
        // A2). Mirrors the scheduled path
        // (`detection::service::alerts::process_alert_post_create`): the alert's
        // `kind` is "detection", which maps to the `siem_alert` subscription
        // stream (migration 217); the webhook service filters by subscription +
        // severity. The primary entity is pulled from the first matched event via
        // the rule's risk-entity field so the consumer gets "who/what" without
        // parsing the raw events. Optional/None-safe: open-core builds and tests
        // without a wired `webhook_service` simply skip.
        if let Some(webhook_service) = webhook_service {
            let severity_str = format!("{:?}", rule.severity).to_lowercase();
            let entity = rule.risk_entity_field.as_deref().and_then(|field| {
                alert
                    .matched_events
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|ev| ev.get(field))
                    .and_then(|v| match v {
                        serde_json::Value::String(s) => Some(s.clone()),
                        serde_json::Value::Null => None,
                        other => Some(other.to_string()),
                    })
            });
            webhook_service
                .fire_alert(
                    alert.id,
                    &alert.kind,
                    Some(rule.id),
                    &rule.name,
                    &severity_str,
                    entity,
                    &alert.matched_events,
                    alert.created_at,
                )
                .await;
        }

        // Log finding for analytics with the unified risk result (computed above).
        if let Err(e) = finding_logger
            .log_alert(&rule, &alert, true, risk_result)
            .await
        {
            error!(
                alert_id = %alert.id,
                error = %e,
                "Failed to log alert finding"
            );
            // Don't fail the whole signal processing
        }

        Ok(SignalOutcome::Processed)
    }

    /// Derive the per-(rule, entity, window) dedup candidate for a signal
    /// (audit D13), or `None` when the rule's `alert_mode` is PerEvent (each
    /// event is its own alert by design — only the exact-content `event_hash`
    /// dedup applies, mirroring the scheduled per-event path).
    ///
    /// The identity reuses the scheduled path's derivation
    /// (`finding_dedup_identity` via `realtime_finding_candidate`): kind + rule
    /// + entity field + entity + a fixed 60s bucket floored from the signal's
    /// EVENT time (see `REALTIME_DEDUP_BUCKET_SECS` for why 60s). `kind`
    /// namespaces Live bake-in (`"live"`) apart from Alerting (`"alert"`) so a
    /// bake-in emission can't suppress the first real alert after promotion
    /// (audit D17). The entity/field are the ATTRIBUTED values `process_signal`
    /// resolved (scorer first, MV `risk_entity` fallback), so dedup keys on the
    /// same entity the finding is emitted for.
    fn build_window_dedup_candidate(
        rule: &DetectionRule,
        risk_result: &RiskResult,
        event_ts: DateTime<Utc>,
    ) -> Option<ClaimedFinding> {
        if !matches!(rule.alert_mode, AlertMode::Grouped) {
            return None;
        }
        let kind = if matches!(rule.mode, RuleMode::Live) {
            "live"
        } else {
            "alert"
        };
        let field = risk_result.entity_field.as_deref().unwrap_or_default();
        Some(realtime_finding_candidate(
            kind,
            rule.id,
            field,
            &risk_result.entity,
            event_ts,
            // The emission store persists only (entity, hash, window_end); the
            // event payload is not part of the identity — skip the clone.
            Vec::new(),
        ))
    }

    /// Build the matched-log fetch SQL for the active schema profile (NAN-1377).
    ///
    /// Every identifier is profile-resolved so the query is valid against both
    /// physical schemas:
    /// - `metadata` (the full-context JSON blob): UDM has a literal `metadata`
    ///   String column; OCSF has no such column — it is read from the profile's
    ///   `json_tail_column` as `toString(...) AS metadata`. NAN-1443 repointed
    ///   that tail from the full `event` (now EPHEMERAL) to the stored `unmapped`
    ///   spill, so OCSF metadata is the spill object (which carries a finding's
    ///   `risk_entity_field`); the matched event's entities + `message` are
    ///   selected as their own columns below, so alert context is preserved.
    ///   Selecting a literal `event`/`metadata` under OCSF was CH Code 47 → every
    ///   real-time signal warn-skipped (zero alerts, G1).
    /// - `ts`: `toUnixTimestamp64Micro(timestamp)` is precision-independent —
    ///   it yields µs ticks for both UDM's DateTime64(6) (byte-identical to the
    ///   old `reinterpretAsInt64`) and OCSF's DateTime64(3), where the raw
    ///   reinterpret returned ms ticks that `from_timestamp_micros` silently
    ///   decoded to 1970 dates (G10).
    /// Resolve the `(field_name, column_sql)` pairs a rule's `risk_modifiers`
    /// need at fetch time (NAN-1663). Each field is gated on `is_known_field`, so
    /// only a REAL column of the active schema is selected — injection-safe (known
    /// field names) and never 500s the fetch on an unknown column. Fields already
    /// in the base projection, nested (`metadata.*`, resolved from the metadata
    /// blob), or absent from the schema are skipped. Keyed by the UDM-semantic
    /// name the modifier tests; OCSF resolves the value from its promoted column.
    fn resolve_modifier_columns(
        profile: &dyn crate::schema::SchemaProfile,
        modifiers: &[RiskModifier],
    ) -> Vec<(String, String)> {
        const BASE_PROJECTION: &[&str] = &[
            "src_ip", "dest_ip", "src_host", "dest_host", "src_user", "dest_user",
            "message", "source_type", "risk_entity", "id", "timestamp",
        ];
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut cols: Vec<(String, String)> = Vec::new();
        for m in modifiers {
            let Some(field) = m.field_name() else { continue };
            if field.contains('.') || BASE_PROJECTION.contains(&field) {
                continue;
            }
            if !seen.insert(field.to_string()) || !profile.is_known_field(field) {
                continue;
            }
            if let Some(col_sql) = profile.udm_column_sql(field) {
                cols.push((field.to_string(), col_sql));
            }
        }
        cols
    }

    fn build_fetch_matched_log_query(
        profile: &dyn crate::schema::SchemaProfile,
        logs_table: &str,
        log_id: Uuid,
        ts_lower: &str,
        ts_upper: &str,
        modifier_cols: &[(String, String)],
    ) -> String {
        // Resolve a UDM-semantic entity field to a SELECT clause aliased back to
        // the canonical name. When the active schema has no column for that
        // concept, emit `'' AS <field>` so the typed row keeps its shape.
        let entity_col = |udm_field: &str| -> String {
            match profile.udm_column_sql(udm_field) {
                Some(sql) => format!("{sql} AS {udm_field}"),
                None => format!("'' AS {udm_field}"),
            }
        };

        // UDM carries the full original log in its `metadata` String column;
        // OCSF reads the JSON tail column (`unmapped` spill, NAN-1443).
        let metadata_expr = match profile.id() {
            // Spans/metrics are never a tenant detection schema (NAN-1555); UDM default.
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics => "metadata".to_string(),
            crate::schema::SchemaId::Ocsf => {
                format!("toString({}) AS metadata", profile.json_tail_column())
            }
        };

        // The rule's modifier-referenced columns as a JSON object under one
        // `modifier_fields` alias (NAN-1663). `toString` each so the Map is
        // homogeneous and the values decode as strings — RiskModifier parses
        // strings to numbers for `>`/`<` and compares strings for `=`/`contains`,
        // so string values evaluate correctly for every operator. The field name
        // (the Map key) is a `is_known_field`-gated schema field, so it is a safe
        // identifier; escape it defensively anyway.
        let modifier_expr = if modifier_cols.is_empty() {
            "'{}' AS modifier_fields".to_string()
        } else {
            let pairs = modifier_cols
                .iter()
                .map(|(name, col_sql)| {
                    format!(
                        "'{}', toString({})",
                        crate::sql_hygiene::escape_sql_string(name),
                        col_sql
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("toJSONString(map({pairs})) AS modifier_fields")
        };

        // Only fetch key fields for alert context - metadata contains the full original log
        format!(
            r#"
            SELECT
                toString(id) as log_id,
                toUnixTimestamp64Micro(timestamp) as ts,
                message,
                {metadata},
                source_type,
                {src_ip},
                {dest_ip},
                {src_host},
                {dest_host},
                {src_user},
                {dest_user},
                {risk_entity},
                {modifier_expr}
            FROM {logs_table}
            WHERE timestamp BETWEEN '{ts_lower}' AND '{ts_upper}' AND id = '{}'
            LIMIT 1
            "#,
            log_id,
            metadata = metadata_expr,
            src_ip = entity_col("src_ip"),
            dest_ip = entity_col("dest_ip"),
            src_host = entity_col("src_host"),
            dest_host = entity_col("dest_host"),
            src_user = entity_col("src_user"),
            dest_user = entity_col("dest_user"),
            risk_entity = entity_col("risk_entity"),
            modifier_expr = modifier_expr,
        )
    }

    /// Half-width of the timestamp window used to bound the matched-log fetch.
    ///
    /// The matched event's `timestamp` is copied verbatim from the log into the
    /// signal by the detection MV, so the event lives at (essentially) the same
    /// instant as `signal.timestamp`. A ±1h window is far wider than any
    /// precision/clock skew yet still prunes the read to a single daily
    /// partition and a handful of primary-index granules (R5: 2262/2271 →
    /// 1/2271 granules measured on local CH).
    const MATCHED_LOG_WINDOW: chrono::Duration = chrono::Duration::hours(1);

    /// Fetch a matched log from ClickHouse by ID, bounded to a tight timestamp
    /// window around the signal's event time.
    ///
    /// Returns key identifying fields plus the metadata JSON blob for full
    /// context. `event_ts` is the matched event's timestamp (from the signal);
    /// it bounds the scan so `id =` never triggers a full-table scan (R5). The
    /// `logs` sort key is `(source_type, timestamp, …, cityHash64(id))` — `id`
    /// only appears hashed last with no skip index, so an unbounded `WHERE id =`
    /// scanned every granule and, at Saturn scale, hit the 300s
    /// `max_execution_time` (18.2 GiB / 1.22B rows), whose error propagated up
    /// and silently dropped the alert.
    async fn fetch_matched_log(
        dual_pool: &DualPool,
        log_id: Uuid,
        event_ts: DateTime<Utc>,
        modifiers: &[RiskModifier],
    ) -> anyhow::Result<Option<serde_json::Value>> {
        // Resolve the active schema profile so column resolution + the FROM table
        // follow UDM vs OCSF. UDM keeps the literal column names (byte-identical);
        // OCSF maps the UDM-semantic entity fields to their promoted columns and
        // falls back to an empty string for concepts it does not carry
        // (`risk_entity`), so the strongly-typed row below still deserializes.
        let profile = crate::schema::active_profile_from_env()
            .map_err(|e| anyhow::anyhow!("invalid schema profile: {e}"))?;

        // Resolve the extra columns the rule's risk_modifiers need so the scored
        // event carries them (NAN-1663).
        let modifier_cols = Self::resolve_modifier_columns(profile.as_ref(), modifiers);
        // Same table-key derivation the search service uses: OCSF reads
        // `ocsf_logs`, UDM reads `logs`, both through the tenant-aware registry.
        let logs_table_key = match profile.id() {
            crate::schema::SchemaId::Ocsf => "ocsf_logs",
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics => "logs",
        };
        let logs_table = dual_pool.table_names().read(logs_table_key);

        // Bound the scan to a tight window around the event time. The window is
        // guaranteed to contain the row (the MV copies the log's `timestamp`
        // into the signal), so this never causes a spurious miss.
        let ts_lower = crate::sql_hygiene::format_ch_bound_micros(
            &(event_ts - Self::MATCHED_LOG_WINDOW),
        );
        let ts_upper = crate::sql_hygiene::format_ch_bound_micros(
            &(event_ts + Self::MATCHED_LOG_WINDOW),
        );
        let query = Self::build_fetch_matched_log_query(
            profile.as_ref(),
            &logs_table,
            log_id,
            &ts_lower,
            &ts_upper,
            &modifier_cols,
        );

        let ch_client = dual_pool.clickhouse();

        #[derive(Row, Deserialize)]
        struct LogRow {
            log_id: String,
            ts: i64,
            message: String,
            metadata: String,
            source_type: String,
            src_ip: String,
            dest_ip: String,
            src_host: String,
            dest_host: String,
            src_user: String,
            dest_user: String,
            risk_entity: String,
            /// JSON object of the rule's modifier-referenced columns (NAN-1663),
            /// `{}` when the rule has none. Merged flat into the event below so
            /// modifiers resolve them by their bare UDM-semantic name.
            modifier_fields: String,
        }

        let rows: Vec<LogRow> = ch_client.query(&query).fetch_all().await?;

        if let Some(row) = rows.into_iter().next() {
            let timestamp = DateTime::from_timestamp_micros(row.ts)
                .unwrap_or_else(Utc::now)
                .to_rfc3339();

            // Parse metadata JSON if valid, otherwise use empty object
            let metadata: serde_json::Value =
                serde_json::from_str(&row.metadata).unwrap_or_else(|_| serde_json::json!({}));

            let mut json = serde_json::json!({
                "id": row.log_id,
                "timestamp": timestamp,
                "message": row.message,
                "metadata": metadata,
                "source_type": row.source_type,
                "src_ip": row.src_ip,
                "dest_ip": row.dest_ip,
                "src_host": row.src_host,
                "dest_host": row.dest_host,
                "src_user": row.src_user,
                "dest_user": row.dest_user,
                "risk_entity": row.risk_entity,
            });

            // Merge the modifier columns as flat keys (never overwriting a base
            // field), so a risk_modifier on e.g. `auth_result` resolves exactly as
            // it does on the scheduled path (NAN-1663).
            if let (serde_json::Value::Object(obj), Ok(serde_json::Value::Object(extra))) = (
                &mut json,
                serde_json::from_str::<serde_json::Value>(&row.modifier_fields),
            ) {
                for (k, v) in extra {
                    obj.entry(k).or_insert(v);
                }
            }

            Ok(Some(json))
        } else {
            Ok(None)
        }
    }

    /// Load the global risk-weight multiplier from `system_settings` (mirrors
    /// `DetectionService::load_risk_weight`; called once per poll batch so the
    /// real-time path applies the same weight the scheduled path does). Defaults
    /// to 1.0 (no attenuation) when the setting is absent or unreadable.
    async fn load_risk_weight(dual_pool: &DualPool) -> f64 {
        match sqlx::query_scalar::<_, f64>(
            "SELECT COALESCE(risk_weight, 1.0)::float8 FROM system_settings WHERE id = 'default'",
        )
        .fetch_optional(dual_pool.postgres())
        .await
        {
            Ok(Some(w)) => w.clamp(0.0, 1.0),
            Ok(None) => 1.0,
            Err(e) => {
                warn!("SignalProcessor: failed to load risk_weight ({e}); using 1.0");
                1.0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SignalProcessorConfig::default();
        assert_eq!(config.poll_interval_ms, 1500);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.backoff_base_secs, 2);
        assert_eq!(config.watermark_lag_secs, 5);
    }

    #[test]
    fn test_default_watermark() {
        let wm = ProcessorWatermark::default();
        assert!(wm.last_signal_id.is_none());
        assert_eq!(wm.processed_count, 0);
    }

    #[test]
    fn test_format_datetime_for_ch() {
        use chrono::TimeZone;
        let dt = Utc.with_ymd_and_hms(2024, 1, 15, 10, 30, 45).unwrap();
        let formatted = SignalProcessor::format_datetime_for_ch(&dt);
        assert_eq!(formatted, "2024-01-15 10:30:45.000000");
    }

    // NAN-1377 (G1+G10): the matched-log fetch SQL must be valid against the
    // active profile's physical schema. Under OCSF the old query selected the
    // nonexistent literal `metadata` column (CH Code 47 → every real-time
    // signal warn-skipped → zero alerts) and decoded DateTime64(3) ms ticks as
    // µs (1970 timestamps).

    #[test]
    fn test_fetch_matched_log_query_udm() {
        let profile = crate::schema::UdmProfile::new();
        let log_id = Uuid::parse_str("019e3bf3-ff47-7273-936a-8d426d333343").unwrap();
        let query = SignalProcessor::build_fetch_matched_log_query(
            &profile,
            "nanosiem.logs",
            log_id,
            "2026-07-02 20:25:55.774000",
            "2026-07-02 22:25:55.774000",
            &[],
        );

        // UDM keeps the literal `metadata` column and identity entity aliases.
        // `toUnixTimestamp64Micro(timestamp)` on DateTime64(6) yields the same
        // µs ticks as the old `reinterpretAsInt64` (verified against CH), so
        // UDM decode behavior is unchanged. R5: the WHERE now carries a single
        // `timestamp BETWEEN … AND id = …` bound (no PREWHERE) so the primary
        // index prunes to one partition instead of a full-table `id` scan.
        let expected = r#"
            SELECT
                toString(id) as log_id,
                toUnixTimestamp64Micro(timestamp) as ts,
                message,
                metadata,
                source_type,
                src_ip AS src_ip,
                dest_ip AS dest_ip,
                src_host AS src_host,
                dest_host AS dest_host,
                src_user AS src_user,
                dest_user AS dest_user,
                risk_entity AS risk_entity,
                '{}' AS modifier_fields
            FROM nanosiem.logs
            WHERE timestamp BETWEEN '2026-07-02 20:25:55.774000' AND '2026-07-02 22:25:55.774000' AND id = '019e3bf3-ff47-7273-936a-8d426d333343'
            LIMIT 1
            "#;
        assert_eq!(query, expected);
    }

    #[test]
    fn resolve_modifier_columns_gates_to_known_non_base_fields() {
        use crate::detection::risk::RiskModifier;
        let profile = crate::schema::UdmProfile::new();
        let m = |c: &str| RiskModifier { condition: c.to_string(), score: 50 };
        let mods = vec![
            m("auth_result = failure"),  // known UDM column, not in base → included
            m("bytes_out > 1000000"),    // known UDM column → included
            m("src_ip = 10.0.0.1"),      // in base projection → skipped
            m("metadata.count > 5"),     // nested → skipped (metadata blob resolves it)
            m("not_a_real_field = x"),   // unknown → skipped (no unknown-column 500)
            m("auth_result = success"),  // duplicate field → deduped
        ];
        let cols = SignalProcessor::resolve_modifier_columns(&profile, &mods);
        let fields: Vec<&str> = cols.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(fields, vec!["auth_result", "bytes_out"]);
        // UDM resolves the column SQL to the field itself.
        assert!(cols.iter().any(|(f, sql)| f == "auth_result" && sql.contains("auth_result")));
    }

    #[test]
    fn build_query_emits_modifier_map_when_columns_present() {
        let profile = crate::schema::UdmProfile::new();
        let log_id = Uuid::parse_str("019e3bf3-ff47-7273-936a-8d426d333343").unwrap();
        let cols = vec![("auth_result".to_string(), "auth_result".to_string())];
        let query = SignalProcessor::build_fetch_matched_log_query(
            &profile,
            "nanosiem.logs",
            log_id,
            "2026-07-02 20:25:55.774000",
            "2026-07-02 22:25:55.774000",
            &cols,
        );
        assert!(
            query.contains("toJSONString(map('auth_result', toString(auth_result))) AS modifier_fields"),
            "modifier map must select the resolved column: {query}"
        );
    }

    // R5: the matched-log fetch must never emit a bare `WHERE id = …`. `logs` is
    // sorted `(source_type, timestamp, …, cityHash64(id))` — `id` appears only
    // hashed last with no skip index, so an unbounded fetch full-scanned every
    // granule and, at Saturn scale, hit the 300s max_execution_time whose error
    // propagated up and silently dropped the alert.
    #[test]
    fn test_fetch_matched_log_query_is_timestamp_bounded() {
        for profile in [
            Box::new(crate::schema::UdmProfile::new()) as Box<dyn crate::schema::SchemaProfile>,
            Box::new(crate::schema::OcsfProfile::new()) as Box<dyn crate::schema::SchemaProfile>,
        ] {
            let log_id = Uuid::parse_str("019ea2f0-9453-7db5-aec0-12fb99f7b373").unwrap();
            let query = SignalProcessor::build_fetch_matched_log_query(
                profile.as_ref(),
                "nanosiem.logs",
                log_id,
                "2026-07-02 20:25:55.774000",
                "2026-07-02 22:25:55.774000",
                &[],
            );
            assert!(
                query.contains(
                    "WHERE timestamp BETWEEN '2026-07-02 20:25:55.774000' AND '2026-07-02 22:25:55.774000' AND id ="
                ),
                "fetch must be timestamp-bounded ahead of the id equality: {query}"
            );
            // No explicit PREWHERE — let optimize_move_to_prewhere place the bound.
            assert!(
                !query.contains("PREWHERE"),
                "fetch must not emit an explicit PREWHERE: {query}"
            );
        }
    }

    // R7: the poll query must apply a settling lag so the watermark never
    // advances into a band where concurrent inserts may still be becoming
    // visible out of `_inserted_at` order, and the strict lower bound must be
    // parenthesized so the settling `AND` binds to the whole disjunction.
    #[test]
    fn test_poll_signals_query_has_settling_lag() {
        let last_id = Uuid::parse_str("019ea2f0-9453-7db5-aec0-12fb99f7b373").unwrap();

        // First poll (no tie-break id yet).
        let q0 = SignalProcessor::build_poll_signals_query(
            "nanosiem.signals",
            "2026-07-02 21:00:00.000000",
            None,
            100,
            5,
        );
        assert!(
            q0.contains("AND _inserted_at <= now64(6) - toIntervalSecond(5)"),
            "settling lag missing on first poll: {q0}"
        );

        // Subsequent poll (with tie-break) — the disjunction must be wrapped so
        // the settling AND does not bind only to the id tie-break term.
        let q1 = SignalProcessor::build_poll_signals_query(
            "nanosiem.signals",
            "2026-07-02 21:00:00.000000",
            Some(last_id),
            100,
            5,
        );
        assert!(
            q1.contains("AND _inserted_at <= now64(6) - toIntervalSecond(5)"),
            "settling lag missing on tie-break poll: {q1}"
        );
        assert!(
            q1.contains("WHERE (_inserted_at >")
                && q1.contains("AND id > '019ea2f0-9453-7db5-aec0-12fb99f7b373'))"),
            "strict lower bound must be parenthesized as a unit: {q1}"
        );
    }

    // ------------------------------------------------------------------------
    // Audit D13: per-(rule, entity, window) dedup candidate dispatch
    // ------------------------------------------------------------------------

    fn d13_test_rule(mode: RuleMode, alert_mode: AlertMode) -> DetectionRule {
        use crate::models::detection_rule::{AiTriageHints, DetectionMode, Severity};
        DetectionRule {
            id: Uuid::parse_str("00000000-0000-0000-0000-0000000000d1").unwrap(),
            name: "d13 test rule".to_string(),
            description: None,
            query: "source_type=\"d13_test\"".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            mode,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: true,
            detection_mode: DetectionMode::RealTime,
            materialized_view_name: None,
            risk_score: Some(75),
            risk_entity_field: Some("src_ip".to_string()),
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            archived: false,
            folder: None,
            ai_triage_hints: sqlx::types::Json(AiTriageHints::default()),
            lookback_minutes: None,
            dataset: None,
            auto_tuning_enabled: false,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            case_visibility: "public".to_string(),
            case_assigned_group: None,
            alert_mode,
            next_run_at: None,
            claimed_by: None,
            claimed_at: None,
            playbook_selector_mode: "none".to_string(),
            playbook_id: None,
            source_path: None,
            source_repo_url: None,
        }
    }

    fn d13_risk_result(entity: &str) -> RiskResult {
        RiskResult::new(
            75,
            75,
            entity.to_string(),
            Some("src_ip".to_string()),
            vec![],
        )
    }

    /// Grouped rules get a window-dedup candidate; PerEvent rules must get NONE
    /// (each event is its own alert by design — only event_hash dedup applies).
    #[test]
    fn window_dedup_candidate_honors_alert_mode() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 7, 6, 10, 0, 30).unwrap();
        let rr = d13_risk_result("10.0.0.9");

        let grouped = d13_test_rule(RuleMode::Alerting, AlertMode::Grouped);
        assert!(
            SignalProcessor::build_window_dedup_candidate(&grouped, &rr, ts).is_some(),
            "Grouped rules must dedup per (rule, entity, window)"
        );

        let per_event = d13_test_rule(RuleMode::Alerting, AlertMode::PerEvent);
        assert!(
            SignalProcessor::build_window_dedup_candidate(&per_event, &rr, ts).is_none(),
            "PerEvent rules keep one-alert-per-signal (no window dedup)"
        );
    }

    /// Regression (D13): repeated signals for the same entity within one window
    /// bucket collide; a later bucket or a different entity re-keys and emits.
    #[test]
    fn window_dedup_candidate_collides_within_window_re_emits_across() {
        use chrono::TimeZone;
        let rule = d13_test_rule(RuleMode::Alerting, AlertMode::Grouped);
        let rr = d13_risk_result("10.0.0.9");

        let burst_1 = Utc.with_ymd_and_hms(2026, 7, 6, 10, 0, 2).unwrap();
        let burst_2 = Utc.with_ymd_and_hms(2026, 7, 6, 10, 0, 57).unwrap(); // same bucket
        let later = Utc.with_ymd_and_hms(2026, 7, 6, 10, 1, 5).unwrap(); // next bucket

        let c1 = SignalProcessor::build_window_dedup_candidate(&rule, &rr, burst_1).unwrap();
        let c2 = SignalProcessor::build_window_dedup_candidate(&rule, &rr, burst_2).unwrap();
        let c3 = SignalProcessor::build_window_dedup_candidate(&rule, &rr, later).unwrap();

        assert_eq!(
            c1.finding_hash, c2.finding_hash,
            "a burst within one window must collide to ONE alert"
        );
        assert_ne!(
            c1.finding_hash, c3.finding_hash,
            "a genuinely later window must re-emit"
        );

        let other = d13_risk_result("10.0.0.10");
        let c4 = SignalProcessor::build_window_dedup_candidate(&rule, &other, burst_1).unwrap();
        assert_ne!(
            c1.finding_hash, c4.finding_hash,
            "a different entity in the same window must emit its own alert"
        );
        assert_eq!(c4.entity, "10.0.0.10");
        assert_eq!(c4.field, "src_ip");
    }

    /// Live bake-in emissions are namespaced apart from Alerting emissions so a
    /// bake-in record can't suppress the first real alert after promotion
    /// (audit D17 parity).
    #[test]
    fn window_dedup_candidate_namespaces_live_vs_alerting() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 7, 6, 10, 0, 30).unwrap();
        let rr = d13_risk_result("10.0.0.9");

        let live = d13_test_rule(RuleMode::Live, AlertMode::Grouped);
        let alerting = d13_test_rule(RuleMode::Alerting, AlertMode::Grouped);

        let c_live = SignalProcessor::build_window_dedup_candidate(&live, &rr, ts).unwrap();
        let c_alert = SignalProcessor::build_window_dedup_candidate(&alerting, &rr, ts).unwrap();
        assert_ne!(c_live.finding_hash, c_alert.finding_hash);
    }

    #[test]
    fn test_fetch_matched_log_query_ocsf() {
        let profile = crate::schema::OcsfProfile::new();
        let log_id = Uuid::parse_str("019ea2f0-9453-7db5-aec0-12fb99f7b373").unwrap();
        let query = SignalProcessor::build_fetch_matched_log_query(
            &profile,
            "nanosiem.ocsf_logs",
            log_id,
            "2026-07-02 20:25:55.774000",
            "2026-07-02 22:25:55.774000",
            &[],
        );

        // The full-context blob comes from the OCSF JSON tail column — the
        // `unmapped` spill (NAN-1443; was `event`, now EPHEMERAL) — never the
        // bare `metadata` identifier, which does not exist on ocsf_logs.
        assert!(
            query.contains("toString(unmapped) AS metadata"),
            "OCSF metadata must read the unmapped spill column: {query}"
        );
        assert!(
            !query.contains("\n                metadata,"),
            "OCSF query must not select the bare `metadata` column: {query}"
        );
        // Precision-independent µs decode (DateTime64(3) on ocsf_logs).
        assert!(
            query.contains("toUnixTimestamp64Micro(timestamp) as ts"),
            "timestamp must decode via toUnixTimestamp64Micro: {query}"
        );
        assert!(
            !query.contains("reinterpretAsInt64"),
            "raw reinterpret reads DateTime64(3) as ms ticks: {query}"
        );
        // Entity concepts resolve to promoted OCSF columns, aliased back to the
        // UDM-semantic names the typed row deserializes by.
        assert!(query.contains(r#""src_endpoint.ip" AS src_ip"#), "{query}");
        assert!(query.contains(r#""dst_endpoint.ip" AS dest_ip"#), "{query}");
        // Concepts OCSF does not carry keep the row shape via '' fallbacks.
        assert!(query.contains("'' AS risk_entity"), "{query}");
        assert!(query.contains("FROM nanosiem.ocsf_logs"), "{query}");
    }
}
