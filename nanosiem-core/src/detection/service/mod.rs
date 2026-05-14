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
mod execution;
pub(crate) mod helpers;
mod rules;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use uuid::Uuid;

/// Cache TTL for system settings (5 minutes)
const SETTINGS_CACHE_TTL_SECS: u64 = 300;

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
use super::prevalence::PrevalenceEvaluator;
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
    /// Optional prevalence evaluator for prevalence-based detection
    pub(super) prevalence_evaluator: Option<Arc<PrevalenceEvaluator>>,
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
}

impl DetectionService {
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
        let finding_logger = FindingLogger::with_dual_pool(dual_pool);
        let pg_pool = dual_pool.postgres().clone();

        // Create SearchService with both lookup and prevalence support
        let search_service = SearchService::with_dual_pool_lookup_and_prevalence(
            dual_pool,
            lookup_service,
            prevalence_service.clone(),
        );

        Self {
            rule_repo: DetectionRuleRepository::new(pg_pool.clone()),
            alert_repo: AlertRepository::new(pg_pool.clone()),
            search_service,
            finding_logger: Some(finding_logger),
            config: DetectionServiceConfig::default(),
            score_calculator: ScoreCalculator::new(),
            pg_pool: pg_pool.clone(),
            prevalence_evaluator: Some(Arc::new(PrevalenceEvaluator::new(prevalence_service))),
            risk_weight_cache: Arc::new(RwLock::new(None)),
            version_manager: RuleVersionManager::new(pg_pool),
            case_grouping: Arc::new(NoopCaseGroupingHook),
            webhook_service: None,
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
        }
    }

    /// Set the prevalence evaluator for prevalence-based detection conditions
    ///
    /// This enables detection rules to use prevalence conditions like:
    /// - `hash_prevalence < 5` - Filter to hashes seen on fewer than 5 hosts
    /// - `domain_first_seen > now() - 24h` - Filter to newly observed domains
    ///
    /// Requirements: 6.1, 6.2
    pub fn with_prevalence_service(mut self, prevalence_service: PrevalenceService) -> Self {
        self.prevalence_evaluator = Some(Arc::new(PrevalenceEvaluator::new(prevalence_service)));
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

    /// Get a reference to the prevalence evaluator if configured
    pub fn prevalence_evaluator(&self) -> Option<&Arc<PrevalenceEvaluator>> {
        self.prevalence_evaluator.as_ref()
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
