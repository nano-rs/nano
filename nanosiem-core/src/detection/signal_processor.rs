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
use crate::db::repository::{AlertRepository, AlertRepositoryError, DetectionRuleRepository};
use crate::detection::findings::FindingLogger;
use crate::detection::risk::RiskResult;
use crate::extensions::{
    AlertCasePermissions, CaseGroupingHook, NoopCaseGroupingHook, NoopShadowInvestigationHook,
    ShadowInvestigationHook,
};
use crate::models::NewAlert;

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
}

impl Default for SignalProcessorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1500,
            batch_size: 100,
            max_retries: 3,
            backoff_base_secs: 2,
            max_skip_threshold: 10,
        }
    }
}

/// Watermark for tracking processed signals
#[derive(Debug, Clone)]
pub struct ProcessorWatermark {
    pub last_inserted_at: DateTime<Utc>,
    pub last_signal_id: Option<Uuid>,
    pub processed_count: u64,
}

impl Default for ProcessorWatermark {
    fn default() -> Self {
        Self {
            last_inserted_at: DateTime::from_timestamp(0, 0).unwrap_or_else(Utc::now),
            last_signal_id: None,
            processed_count: 0,
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
                )
                .await
                {
                    Ok(processed) => {
                        consecutive_errors = 0;
                        if processed > 0 {
                            debug!("Processed {} signals", processed);
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);

                        if consecutive_errors >= config.max_skip_threshold {
                            // After too many consecutive errors, advance the watermark
                            // to skip the problematic batch and prevent permanent stuckness
                            error!(
                                consecutive_errors,
                                "Signal processor stuck for {} consecutive errors, advancing watermark to skip problematic signals",
                                consecutive_errors
                            );
                            let mut wm = watermark.write().await;
                            // Advance watermark by 1 second to skip the current batch
                            wm.last_inserted_at =
                                wm.last_inserted_at + chrono::Duration::seconds(1);
                            wm.last_signal_id = None; // Reset signal ID to avoid tie-breaking issues
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
        dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
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
        let query = if let Some(last_id) = last_signal_id {
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
                WHERE _inserted_at > toDateTime64('{}', 6)
                   OR (_inserted_at = toDateTime64('{}', 6) AND id > '{}')
                ORDER BY _inserted_at ASC, id ASC
                LIMIT {}
                "#,
                watermark_str, watermark_str, last_id, config.batch_size
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
                WHERE _inserted_at > toDateTime64('{}', 6)
                ORDER BY _inserted_at ASC, id ASC
                LIMIT {}
                "#,
                watermark_str, config.batch_size
            )
        };

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

        let mut processed = 0;
        let mut last_processed_signal: Option<ClickHouseSignal> = None;

        for signal in signals {
            match Self::process_signal(
                dual_pool,
                rule_repo,
                alert_repo,
                case_grouping,
                finding_logger,
                &signal,
                shadow_investigation,
            )
            .await
            {
                Ok(_) => {
                    processed += 1;
                    last_processed_signal = Some(signal);
                }
                Err(e) => {
                    // Log error but continue processing other signals
                    warn!(
                        signal_id = %signal.id,
                        rule_id = %signal.rule_id,
                        "Failed to process signal: {}",
                        e
                    );
                    // Still update watermark to avoid reprocessing this signal forever
                    last_processed_signal = Some(signal);
                }
            }
        }

        // Update watermark after processing and commit the transaction
        // (releasing the FOR UPDATE row lock)
        if let Some(signal) = last_processed_signal {
            let new_count = processed_count.saturating_add(processed as u64);

            sqlx::query(
                r#"
                UPDATE signal_processor_watermarks
                SET last_inserted_at = $1,
                    last_signal_id = $2,
                    processed_count = $3,
                    updated_at = NOW()
                WHERE id = 'default'
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

        Ok(processed)
    }

    /// Process a single signal: create alert, group into case, log finding
    #[instrument(skip_all, fields(signal_id = %signal.id, rule_id = %signal.rule_id))]
    async fn process_signal(
        dual_pool: &DualPool,
        rule_repo: &DetectionRuleRepository,
        alert_repo: &AlertRepository,
        case_grouping: &dyn CaseGroupingHook,
        finding_logger: &FindingLogger,
        signal: &ClickHouseSignal,
        shadow_investigation: &dyn ShadowInvestigationHook,
    ) -> anyhow::Result<()> {
        // Fetch the matched log from ClickHouse
        let matched_log = Self::fetch_matched_log(dual_pool, signal.matched_log_id).await?;

        let matched_log = match matched_log {
            Some(log) => log,
            None => {
                warn!(
                    signal_id = %signal.id,
                    matched_log_id = %signal.matched_log_id,
                    "Matched log not found, skipping signal"
                );
                return Ok(());
            }
        };

        // Fetch the rule to get full details
        let rule = match rule_repo.find_by_id(signal.rule_id).await {
            Ok(rule) => rule,
            Err(e) => {
                warn!(
                    signal_id = %signal.id,
                    rule_id = %signal.rule_id,
                    "Rule not found: {}, skipping signal",
                    e
                );
                return Ok(());
            }
        };

        // Create matched_events JSON array with detection timing metadata
        let mut events_vec = vec![matched_log];
        crate::detection::service::helpers::inject_detected_at(
            &mut events_vec,
            chrono::Utc::now(),
        );
        let matched_events = serde_json::Value::Array(events_vec);

        // Create alert with deduplication
        let new_alert = NewAlert {
            rule_id: signal.rule_id,
            severity: rule.severity,
            matched_events: matched_events.clone(),
            event_hash: None, // Will be computed by AlertRepository
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
                debug!(
                    rule_id = %rule_id,
                    event_hash = %hash,
                    "Duplicate alert, skipping"
                );
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to create alert: {}", e));
            }
        };

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

        // Log finding for analytics
        // Extract risk entity field from metadata if available
        let risk_entity_field = Self::extract_risk_entity_field(&signal.metadata);
        let risk_result = RiskResult::new(
            signal.risk_score,
            signal.risk_score,
            signal.risk_entity.clone(),
            risk_entity_field,
            vec![format!("from_signal:{}", signal.id)],
        );

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

        Ok(())
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
    fn build_fetch_matched_log_query(
        profile: &dyn crate::schema::SchemaProfile,
        logs_table: &str,
        log_id: Uuid,
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
            crate::schema::SchemaId::Udm => "metadata".to_string(),
            crate::schema::SchemaId::Ocsf => {
                format!("toString({}) AS metadata", profile.json_tail_column())
            }
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
                {risk_entity}
            FROM {logs_table}
            WHERE id = '{}'
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
        )
    }

    /// Fetch a matched log from ClickHouse by ID
    /// Returns key identifying fields plus the metadata JSON blob for full context
    async fn fetch_matched_log(
        dual_pool: &DualPool,
        log_id: Uuid,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        // Resolve the active schema profile so column resolution + the FROM table
        // follow UDM vs OCSF. UDM keeps the literal column names (byte-identical);
        // OCSF maps the UDM-semantic entity fields to their promoted columns and
        // falls back to an empty string for concepts it does not carry
        // (`risk_entity`), so the strongly-typed row below still deserializes.
        let profile = crate::schema::active_profile_from_env()
            .map_err(|e| anyhow::anyhow!("invalid schema profile: {e}"))?;
        // Same table-key derivation the search service uses: OCSF reads
        // `ocsf_logs`, UDM reads `logs`, both through the tenant-aware registry.
        let logs_table_key = match profile.id() {
            crate::schema::SchemaId::Ocsf => "ocsf_logs",
            crate::schema::SchemaId::Udm => "logs",
        };
        let logs_table = dual_pool.table_names().read(logs_table_key);

        let query = Self::build_fetch_matched_log_query(profile.as_ref(), &logs_table, log_id);

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
        }

        let rows: Vec<LogRow> = ch_client.query(&query).fetch_all().await?;

        if let Some(row) = rows.into_iter().next() {
            let timestamp = DateTime::from_timestamp_micros(row.ts)
                .unwrap_or_else(Utc::now)
                .to_rfc3339();

            // Parse metadata JSON if valid, otherwise use empty object
            let metadata: serde_json::Value =
                serde_json::from_str(&row.metadata).unwrap_or_else(|_| serde_json::json!({}));

            let json = serde_json::json!({
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
            Ok(Some(json))
        } else {
            Ok(None)
        }
    }

    /// Extract risk_entity_field from signal metadata JSON
    fn extract_risk_entity_field(metadata: &str) -> Option<String> {
        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(metadata) {
            meta.get("risk_entity_field")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        } else {
            None
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
    }

    #[test]
    fn test_default_watermark() {
        let wm = ProcessorWatermark::default();
        assert!(wm.last_signal_id.is_none());
        assert_eq!(wm.processed_count, 0);
    }

    #[test]
    fn test_extract_risk_entity_field() {
        // Valid metadata with risk_entity_field
        let metadata = r#"{"risk_entity_field": "src_ip", "other": "value"}"#;
        assert_eq!(
            SignalProcessor::extract_risk_entity_field(metadata),
            Some("src_ip".to_string())
        );

        // Metadata without risk_entity_field
        let metadata = r#"{"other": "value"}"#;
        assert_eq!(SignalProcessor::extract_risk_entity_field(metadata), None);

        // Invalid JSON
        let metadata = "not json";
        assert_eq!(SignalProcessor::extract_risk_entity_field(metadata), None);

        // Empty metadata
        let metadata = "{}";
        assert_eq!(SignalProcessor::extract_risk_entity_field(metadata), None);
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
        let query =
            SignalProcessor::build_fetch_matched_log_query(&profile, "nanosiem.logs", log_id);

        // UDM keeps the literal `metadata` column and identity entity aliases.
        // `toUnixTimestamp64Micro(timestamp)` on DateTime64(6) yields the same
        // µs ticks as the old `reinterpretAsInt64` (verified against CH), so
        // UDM decode behavior is unchanged.
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
                risk_entity AS risk_entity
            FROM nanosiem.logs
            WHERE id = '019e3bf3-ff47-7273-936a-8d426d333343'
            LIMIT 1
            "#;
        assert_eq!(query, expected);
    }

    #[test]
    fn test_fetch_matched_log_query_ocsf() {
        let profile = crate::schema::OcsfProfile::new();
        let log_id = Uuid::parse_str("019ea2f0-9453-7db5-aec0-12fb99f7b373").unwrap();
        let query =
            SignalProcessor::build_fetch_matched_log_query(&profile, "nanosiem.ocsf_logs", log_id);

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
