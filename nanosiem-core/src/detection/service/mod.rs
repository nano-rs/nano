// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection Service
//!
//! Provides CRUD operations for detection rules with query validation,
//! and methods for executing rules and generating alerts.
//!
//! This service supports both PostgreSQL-only and dual-pool (PostgreSQL + ClickHouse) modes:
//! - PostgreSQL is always used for rule and alert storage (metadata)
//! - ClickHouse is used for log queries when DualPool is configured
//! - PostgreSQL is used for log queries in legacy mode
//! - Signal logging: detection matches and alerts are logged as searchable events
//! - Prevalence-based detection: supports filtering by artifact prevalence

mod alerts;
mod analysis;
#[cfg(test)]
mod cooldown_tests;
mod execution;
pub(crate) mod helpers;
mod retro_hunt;
mod rules;
#[cfg(test)]
mod source_stamp_tests;
#[cfg(test)]
mod tests;

// Audit D13: the real-time SignalProcessor shares the scheduled path's
// finding-emission dedup (candidate type + store helpers in `helpers`).
pub(crate) use alerts::ClaimedFinding;
pub(crate) use analysis::tuning_test_windows;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use uuid::Uuid;

/// Cache TTL for system settings (5 minutes)
const SETTINGS_CACHE_TTL_SECS: u64 = 300;

/// Autonomous tuning replays are intentionally tighter than the interactive
/// rule tester because they can run without an analyst explicitly admitting
/// the ClickHouse workload.
pub(crate) const MAX_AUTONOMOUS_TUNING_WINDOWS: usize = 500;
pub(crate) const AUTONOMOUS_TUNING_REPLAY_QUERY_COUNT: i64 = 2;
pub(crate) const MAX_AUTONOMOUS_TUNING_TOTAL_SCAN_SECONDS: i64 = 7 * 24 * 60 * 60;
pub(crate) const MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW: u64 = 10_000;
pub(crate) const MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_AUTONOMOUS_TUNING_TOTAL_ROWS: u64 = 100_000;
pub(crate) const MAX_AUTONOMOUS_TUNING_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

use crate::db::repository::{AlertRepository, DetectionRuleRepository};
use crate::db::DualPool;
use crate::extensions::{
    CaseGroupingHook, NoopCaseGroupingHook, NoopShadowInvestigationHook, ShadowInvestigationHook,
};
use crate::prevalence::PrevalenceService;
use crate::search::{SearchService, TimeRangeInput};
use crate::tuning::versions::RuleVersionManager;

use super::error::DetectionError;
use super::findings::FindingLogger;
use super::risk::ScoreCalculator;
use crate::webhooks::WebhookService;

/// Configuration for the detection service
#[derive(Debug, Clone)]
pub struct DetectionServiceConfig {
    /// Default lookback period for rule execution (in minutes)
    pub default_lookback_minutes: i64,
    /// Maximum number of events to include in an alert
    pub max_events_per_alert: usize,
    /// Default historical analysis period (in days)
    pub default_historical_days: i64,
    /// Whether to log signals for detection matches and alerts
    pub signal_logging_enabled: bool,
    /// Whether to enable prevalence-based detection conditions
    pub prevalence_enabled: bool,
}

impl Default for DetectionServiceConfig {
    fn default() -> Self {
        Self {
            default_lookback_minutes: 15,
            max_events_per_alert: 100,
            default_historical_days: 7,
            signal_logging_enabled: true,
            prevalence_enabled: true,
        }
    }
}

/// Result of historical analysis for false positive tuning
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HistoricalAnalysisResult {
    /// Rule ID that was analyzed
    pub rule_id: Uuid,
    /// Rule name
    pub rule_name: String,
    /// Time range analyzed
    pub time_range: TimeRangeInput,
    /// Total number of matches found
    pub total_matches: u64,
    /// Sample of matched events (limited to max_events_per_alert)
    pub sample_events: Vec<serde_json::Value>,
    /// Matches grouped by day for trend analysis (back-compat).
    /// Derived from `matches_by_bucket` — empty when the test endpoint can't
    /// derive a histogram (e.g. parse failure in the query).
    pub matches_by_day: Vec<DailyMatchCount>,
    /// Match counts bucketed at a granularity that adapts to the test window.
    /// For aggregated rules (`| stats`, `| chart`, `| timechart`, etc.) the
    /// counts come from the pre-aggregation filter, not the collapsed rows,
    /// so the histogram still reflects raw event volume.
    #[serde(default)]
    pub matches_by_bucket: Vec<TimeBucket>,
    /// Bucket size used for `matches_by_bucket`, in seconds.
    /// `0` when no histogram could be computed.
    #[serde(default)]
    pub bucket_size_seconds: u32,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Number of per-window sub-queries that errored during a stepped backtest.
    /// `> 0` means `total_matches`/the histogram UNDERCOUNT — the tester must
    /// surface this instead of showing a misleading "0 matches" for a rule that
    /// actually errors every cycle (audit D3b). Non-stepped paths propagate the
    /// error directly and leave this `0`.
    #[serde(default)]
    pub failed_windows: u32,
    /// A representative error message from a failed window, for display when
    /// `failed_windows > 0`.
    #[serde(default)]
    pub error_sample: Option<String>,
}

/// Daily match count for trend analysis
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DailyMatchCount {
    pub date: String,
    pub count: u64,
}

/// Match count for a single time bucket (sub-daily granularity).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TimeBucket {
    /// Start of the bucket window (UTC, ISO-8601).
    pub bucket_start: chrono::DateTime<chrono::Utc>,
    /// Number of pre-aggregation events that fell in this bucket.
    pub count: u64,
}

/// Exact evidence from replaying one identity-preserving query over fixed
/// production schedule/lookback windows.
#[derive(Debug, Clone, Default)]
pub(crate) struct TuningWindowEvidence {
    pub total_matches: u64,
    pub source_ids: std::collections::HashSet<Uuid>,
    pub sample_events: Vec<serde_json::Value>,
    pub rows_examined: u64,
    pub bytes_examined: u64,
    pub failed_windows: u32,
    pub truncated_windows: u32,
    pub identity_errors: u64,
    pub budget_exceeded: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TuningReplayBudget {
    pub rows: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub(crate) struct TuningWindowPlan {
    pub schedule_cron: String,
    pub lookback_minutes: i64,
    pub windows: Vec<TimeRangeInput>,
}

/// Detection service for managing detection rules and alerts
///
/// Supports two modes:
/// - PostgreSQL-only mode: Uses PostgreSQL for both metadata and log queries (legacy)
/// - DualPool mode: Uses PostgreSQL for metadata, ClickHouse for log queries
///
/// Also supports prevalence-based detection conditions when a PrevalenceService is configured.
#[derive(Clone)]
pub struct DetectionService {
    pub(super) rule_repo: DetectionRuleRepository,
    pub(super) alert_repo: AlertRepository,
    pub(super) search_service: SearchService,
    pub(super) finding_logger: Option<FindingLogger>,
    pub(super) config: DetectionServiceConfig,
    /// Score calculator for risk-based alerting
    pub(super) score_calculator: ScoreCalculator,
    /// PostgreSQL pool for loading settings
    pub(super) pg_pool: PgPool,
    /// Cached risk_weight value with TTL (value, cached_at)
    pub(super) risk_weight_cache: Arc<RwLock<Option<(f64, Instant)>>>,
    /// Version manager for tracking rule changes
    pub(super) version_manager: RuleVersionManager,
    /// Case grouping hook for auto-grouping alerts into cases.
    /// Defaults to a no-op; the enterprise crate injects the real impl.
    pub(super) case_grouping: Arc<dyn CaseGroupingHook>,
    /// Webhook service for alert notifications
    pub(super) webhook_service: Option<WebhookService>,
    /// Shadow investigation hook for auto-triage on new case creation.
    /// Defaults to a no-op; the enterprise crate injects the real impl.
    pub(super) shadow_investigation: Arc<dyn ShadowInvestigationHook>,
    /// Active schema profile (OCSF Phase 5, NAN-1241). Drives auto-detect entity
    /// extraction so an OCSF deployment groups/scoring on OCSF physical fields
    /// (`src_endpoint.ip`, `user.name`, …). Defaults to [`UdmProfile`] so existing
    /// call sites stay byte-identical; the API injects the configured profile via
    /// [`with_profile`](DetectionService::with_profile). The scheduled query SQL
    /// is already schema-aware through `search_service` (Phase 3a); this field
    /// covers the entity-extraction half of the scheduled path.
    pub(super) active_profile: Arc<dyn crate::schema::SchemaProfile>,
    /// NAN-2155: restricted-source registry used to build the FAIL-CLOSED
    /// `source_types` stamp for aggregate matches
    /// (`annotate_source_types_for_scoping`).
    ///
    /// Self-built from the PG pool, exactly like [`FindingLogger`]'s copy — no
    /// external wiring, and the resolver is Arc-backed so cloning is cheap.
    /// Reading the registry THROUGH the resolver (rather than issuing a raw
    /// `SELECT`) is the point of the field: the resolver RETAINS its last-known
    /// registry past a PostgreSQL failure, so a transient blip degrades to the
    /// same deny-all-restricted stamp the read side degrades to, instead of
    /// writing an empty (visible-to-everyone) stamp that can never be repaired.
    pub(super) source_scopes: crate::auth::source_scope_resolver::SourceScopeResolver,
}

impl DetectionService {
    /// Serialize materialized-view writers for one rule across API nodes.
    pub async fn acquire_rule_runtime_lock(
        &self,
        rule_id: Uuid,
    ) -> Result<super::materialized_view::RuleRuntimeLockGuard, DetectionError> {
        Ok(super::materialized_view::acquire_rule_runtime_lock(&self.pg_pool, rule_id).await?)
    }

    /// Create a new detection service with DualPool and prevalence support
    ///
    /// This is the recommended constructor for production use with prevalence-based detection:
    /// - PostgreSQL is used for rule and alert storage
    /// - ClickHouse is used for log queries
    /// - PrevalenceService enables prevalence filtering and enrichment in detection queries
    ///
    /// Requirements: 6.1, 6.2, 6.3
    pub fn with_dual_pool_and_prevalence(
        dual_pool: &DualPool,
        lookup_service: crate::lookup::LookupService,
        prevalence_service: PrevalenceService,
    ) -> Self {
        Self::with_dual_pool_prevalence_and_profile(
            dual_pool,
            lookup_service,
            prevalence_service,
            Arc::new(crate::schema::UdmProfile::new()),
        )
    }

    /// Profile-aware variant of [`with_dual_pool_and_prevalence`]
    /// (OCSF Phase 5, NAN-1241).
    ///
    /// Threads the active schema profile through BOTH halves of the scheduled
    /// detection path:
    /// - the internal `SearchService` (so the scheduled rule query targets the
    ///   profile's logs table — OCSF `ocsf_logs` — and resolves fields/default
    ///   view under the active schema), and
    /// - entity extraction (`ScoreCalculator` + `group_events_by_entity` via
    ///   `active_profile`), so auto-detect entity grouping/scoring uses the
    ///   profile's `entity_extraction_order()`.
    ///
    /// UDM is byte-identical to [`with_dual_pool_and_prevalence`].
    ///
    /// [`with_dual_pool_and_prevalence`]: DetectionService::with_dual_pool_and_prevalence
    pub fn with_dual_pool_prevalence_and_profile(
        dual_pool: &DualPool,
        lookup_service: crate::lookup::LookupService,
        prevalence_service: PrevalenceService,
        profile: Arc<dyn crate::schema::SchemaProfile>,
    ) -> Self {
        let finding_logger = FindingLogger::with_dual_pool(dual_pool);
        let pg_pool = dual_pool.postgres().clone();

        // Create SearchService with both lookup and prevalence support, under the
        // active schema profile so the scheduled rule query is schema-aware.
        let search_service = SearchService::with_dual_pool_lookup_and_prevalence_and_profile(
            dual_pool,
            lookup_service,
            prevalence_service,
            profile.clone(),
        );

        Self {
            rule_repo: DetectionRuleRepository::new(pg_pool.clone()),
            alert_repo: AlertRepository::new(pg_pool.clone()),
            search_service,
            source_scopes: crate::auth::source_scope_resolver::SourceScopeResolver::new(
                pg_pool.clone(),
            ),
            finding_logger: Some(finding_logger),
            config: DetectionServiceConfig::default(),
            score_calculator: ScoreCalculator::new().with_profile(profile.clone()),
            pg_pool: pg_pool.clone(),
            risk_weight_cache: Arc::new(RwLock::new(None)),
            version_manager: RuleVersionManager::new(pg_pool),
            case_grouping: Arc::new(NoopCaseGroupingHook),
            webhook_service: None,
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
            active_profile: profile,
        }
    }

    /// Set the active schema profile for the entity-extraction half of the
    /// scheduled detection path (OCSF Phase 5, NAN-1241).
    ///
    /// Drives the auto-detect entity-extraction order used when a rule has no
    /// explicit `risk_entity_field`, and propagates the profile into the
    /// [`ScoreCalculator`]. NOTE: this does NOT rebuild the internal
    /// `SearchService` (the pool/lookup/prevalence handles needed to do so are
    /// not retained), so the scheduled query SQL keeps whatever profile the
    /// service was constructed with. For a fully schema-aware scheduled path,
    /// construct via [`with_dual_pool_prevalence_and_profile`] instead; use this
    /// builder only to adjust entity extraction on an already-built service
    /// (e.g. in tests). UDM is the default so existing call sites are unchanged.
    ///
    /// [`with_dual_pool_prevalence_and_profile`]: DetectionService::with_dual_pool_prevalence_and_profile
    pub fn with_profile(mut self, profile: Arc<dyn crate::schema::SchemaProfile>) -> Self {
        self.score_calculator = ScoreCalculator::new().with_profile(profile.clone());
        self.active_profile = profile;
        self
    }

    /// Set the webhook service for alert notifications
    pub fn with_webhook_service(mut self, webhook_service: WebhookService) -> Self {
        self.webhook_service = Some(webhook_service);
        self
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

    /// Load the global risk weight from system settings (with 5-minute cache)
    ///
    /// Returns the risk_weight value (0.0-1.0) from the system_settings table.
    /// Uses a TTL cache to avoid hitting the database on every rule execution.
    /// Defaults to 1.0 if the setting cannot be loaded.
    ///
    /// Requirements: 9.2
    pub async fn load_risk_weight(&self) -> f64 {
        // Check cache first (read lock)
        {
            let cache = self.risk_weight_cache.read().await;
            if let Some((value, cached_at)) = *cache {
                if cached_at.elapsed().as_secs() < SETTINGS_CACHE_TTL_SECS {
                    return value;
                }
            }
        }

        // Cache miss or expired - fetch from database
        let weight = match sqlx::query_scalar::<_, f64>(
            "SELECT COALESCE(risk_weight, 1.0)::float8 FROM system_settings WHERE id = 'default'",
        )
        .fetch_optional(&self.pg_pool)
        .await
        {
            Ok(Some(w)) => w.clamp(0.0, 1.0),
            Ok(None) => {
                debug!("No system_settings row found, using default risk_weight=1.0");
                1.0
            }
            Err(e) => {
                warn!(
                    "Failed to load risk_weight from settings: {}, using default 1.0",
                    e
                );
                1.0
            }
        };

        // Update cache (write lock)
        {
            let mut cache = self.risk_weight_cache.write().await;
            *cache = Some((weight, Instant::now()));
        }

        weight
    }

    /// Get a reference to the score calculator
    pub fn score_calculator(&self) -> &ScoreCalculator {
        &self.score_calculator
    }
}
