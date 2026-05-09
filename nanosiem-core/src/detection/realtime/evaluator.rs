// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-time rule evaluator.
//!
//! Contains the `RealtimeEvaluator` struct and all methods for loading rules,
//! evaluating events, and processing cumulative risk.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::db::repository::{
    compute_event_hash, AlertRepository, AlertRepositoryError, DetectionRuleRepository,
};
use crate::db::DualPool;
use crate::extensions::{
    AlertCasePermissions, CaseGroupingHook, NoopCaseGroupingHook, NoopShadowInvestigationHook,
    ShadowInvestigationHook,
};
use crate::models::{Alert, DetectionRule, NewAlert};
use crate::query::parse_query;

use super::super::error::DetectionError;
use super::super::findings::{FindingEvent, FindingLogger};
use super::super::risk::{
    extract_cumulative_risk_config, is_cumulative_risk_rule, CumulativeRiskResult, RiskResult,
};
use super::config::{CompiledCumulativeRiskRule, CompiledRule, RealtimeConfig};
use super::matching::evaluate_query_against_event;

/// Real-time rule evaluator
///
/// Evaluates incoming log events against compiled detection rules in-memory.
/// Uses PostgreSQL for rule storage and alert generation.
pub struct RealtimeEvaluator {
    rule_repo: DetectionRuleRepository,
    alert_repo: AlertRepository,
    finding_logger: Option<FindingLogger>,
    config: RealtimeConfig,
    /// Cached compiled rules for fast evaluation
    compiled_rules: Arc<RwLock<HashMap<Uuid, CompiledRule>>>,
    /// Cached cumulative risk rules for meta-detection
    cumulative_risk_rules: Arc<RwLock<Vec<CompiledCumulativeRiskRule>>>,
    /// PostgreSQL pool for cumulative risk queries
    pg_pool: sqlx::PgPool,
    /// Case grouping hook (open-core default no-op skips grouping)
    case_grouping: Arc<dyn CaseGroupingHook>,
    /// Shadow investigation hook for auto-triage on new case creation
    /// (open-core default no-op)
    shadow_investigation: Arc<dyn ShadowInvestigationHook>,
}

impl RealtimeEvaluator {
    /// Create a new real-time evaluator with PostgreSQL only (legacy mode)
    pub fn new(pool: sqlx::PgPool) -> Self {
        let finding_logger = FindingLogger::new(pool.clone());
        Self {
            rule_repo: DetectionRuleRepository::new(pool.clone()),
            alert_repo: AlertRepository::new(pool.clone()),
            finding_logger: Some(finding_logger),
            config: RealtimeConfig::default(),
            compiled_rules: Arc::new(RwLock::new(HashMap::new())),
            cumulative_risk_rules: Arc::new(RwLock::new(Vec::new())),
            pg_pool: pool,
            case_grouping: Arc::new(NoopCaseGroupingHook),
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
        }
    }

    /// Create a new real-time evaluator with custom configuration (PostgreSQL only)
    pub fn with_config(pool: sqlx::PgPool, config: RealtimeConfig) -> Self {
        let finding_logger = if config.signal_logging_enabled {
            Some(FindingLogger::new(pool.clone()))
        } else {
            None
        };
        Self {
            rule_repo: DetectionRuleRepository::new(pool.clone()),
            alert_repo: AlertRepository::new(pool.clone()),
            finding_logger,
            config,
            compiled_rules: Arc::new(RwLock::new(HashMap::new())),
            cumulative_risk_rules: Arc::new(RwLock::new(Vec::new())),
            pg_pool: pool,
            case_grouping: Arc::new(NoopCaseGroupingHook),
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
        }
    }

    /// Create a new real-time evaluator with DualPool
    ///
    /// Uses PostgreSQL from the DualPool for rule and alert storage. Case
    /// grouping and shadow investigation default to no-op hooks; the
    /// enterprise crate injects real impls via setters at AppState construction.
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        let finding_logger = FindingLogger::with_dual_pool(dual_pool);
        Self {
            rule_repo: DetectionRuleRepository::new(dual_pool.postgres().clone()),
            alert_repo: AlertRepository::new(dual_pool.postgres().clone()),
            finding_logger: Some(finding_logger),
            config: RealtimeConfig::default(),
            compiled_rules: Arc::new(RwLock::new(HashMap::new())),
            cumulative_risk_rules: Arc::new(RwLock::new(Vec::new())),
            pg_pool: dual_pool.postgres().clone(),
            case_grouping: Arc::new(NoopCaseGroupingHook),
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
        }
    }

    /// Create a new real-time evaluator with DualPool and custom configuration
    pub fn with_dual_pool_and_config(dual_pool: &DualPool, config: RealtimeConfig) -> Self {
        let finding_logger = if config.signal_logging_enabled {
            Some(FindingLogger::with_dual_pool(dual_pool))
        } else {
            None
        };
        Self {
            rule_repo: DetectionRuleRepository::new(dual_pool.postgres().clone()),
            alert_repo: AlertRepository::new(dual_pool.postgres().clone()),
            finding_logger,
            config,
            compiled_rules: Arc::new(RwLock::new(HashMap::new())),
            cumulative_risk_rules: Arc::new(RwLock::new(Vec::new())),
            pg_pool: dual_pool.postgres().clone(),
            case_grouping: Arc::new(NoopCaseGroupingHook),
            shadow_investigation: Arc::new(NoopShadowInvestigationHook),
        }
    }

    /// Set the shadow investigation hook for auto-triage on new case creation.
    ///
    /// Open-core builds default to a no-op; the enterprise crate injects a
    /// real `ShadowInvestigationHook` impl at AppState construction time.
    pub fn set_shadow_investigation(&mut self, hook: Arc<dyn ShadowInvestigationHook>) {
        self.shadow_investigation = hook;
    }

    /// Set the case grouping hook for auto-grouping alerts into cases.
    ///
    /// Open-core builds default to a no-op (alerts skip case grouping); the
    /// enterprise crate injects a real `CaseGroupingHook` impl at AppState
    /// construction time.
    pub fn set_case_grouping(&mut self, hook: Arc<dyn CaseGroupingHook>) {
        self.case_grouping = hook;
    }

    /// Load and compile all realtime-enabled rules
    /// Only loads rules that are: mode = alerting, realtime_enabled = true
    #[instrument(skip(self))]
    pub async fn load_rules(&self) -> Result<(), DetectionError> {
        let rules = self.rule_repo.list_realtime_enabled().await?;
        let mut compiled = self.compiled_rules.write().await;
        let mut cumulative_rules = self.cumulative_risk_rules.write().await;
        compiled.clear();
        cumulative_rules.clear();

        for rule in rules {
            // Check if this is a cumulative risk rule
            if is_cumulative_risk_rule(&rule) {
                if let Some(config) = extract_cumulative_risk_config(&rule) {
                    cumulative_rules.push(CompiledCumulativeRiskRule {
                        rule: rule.clone(),
                        config,
                    });
                    debug!(
                        "Loaded cumulative risk rule {} for meta-detection",
                        rule.name
                    );
                    continue;
                }
            }

            // Regular rule - compile the query
            match parse_query(&rule.query) {
                Ok(query) => {
                    compiled.insert(
                        rule.id,
                        CompiledRule {
                            rule: rule.clone(),
                            query,
                        },
                    );
                    debug!("Compiled rule {} for real-time evaluation", rule.name);
                }
                Err(e) => {
                    warn!("Failed to compile rule {} ({}): {}", rule.name, rule.id, e);
                }
            }
        }

        info!(
            "Loaded {} rules for real-time evaluation, {} cumulative risk rules",
            compiled.len(),
            cumulative_rules.len()
        );
        Ok(())
    }

    /// Load cumulative risk rules from all enabled alerting rules
    /// This is called separately to load meta-detection rules that may not be realtime-enabled
    #[instrument(skip(self))]
    pub async fn load_cumulative_risk_rules(&self) -> Result<(), DetectionError> {
        let rules = self.rule_repo.list_alerting().await?;
        let mut cumulative_rules = self.cumulative_risk_rules.write().await;
        cumulative_rules.clear();

        for rule in rules {
            if is_cumulative_risk_rule(&rule) {
                if let Some(config) = extract_cumulative_risk_config(&rule) {
                    cumulative_rules.push(CompiledCumulativeRiskRule {
                        rule: rule.clone(),
                        config,
                    });
                    debug!(
                        "Loaded cumulative risk rule {} for meta-detection",
                        rule.name
                    );
                }
            }
        }

        info!("Loaded {} cumulative risk rules", cumulative_rules.len());
        Ok(())
    }

    /// Add or update a rule in the cache
    /// Only adds rules that are: mode = alerting, realtime_enabled = true
    #[instrument(skip(self))]
    pub async fn add_rule(&self, rule: &DetectionRule) -> Result<(), DetectionError> {
        // Only add rules that are in alerting mode and have realtime_enabled
        if rule.mode != crate::models::RuleMode::Alerting || !rule.realtime_enabled {
            self.remove_rule(rule.id).await;
            return Ok(());
        }

        let query =
            parse_query(&rule.query).map_err(|e| DetectionError::QueryParseError(e.to_string()))?;

        let mut compiled = self.compiled_rules.write().await;
        compiled.insert(
            rule.id,
            CompiledRule {
                rule: rule.clone(),
                query,
            },
        );

        debug!("Added rule {} to real-time evaluation cache", rule.id);
        Ok(())
    }

    /// Remove a rule from the cache
    #[instrument(skip(self))]
    pub async fn remove_rule(&self, rule_id: Uuid) {
        let mut compiled = self.compiled_rules.write().await;
        if compiled.remove(&rule_id).is_some() {
            debug!("Removed rule {} from real-time evaluation cache", rule_id);
        }
    }

    /// Evaluate a single log event against all enabled rules
    #[instrument(skip(self, event))]
    pub async fn evaluate(&self, event: &serde_json::Value) -> Result<Vec<Alert>, DetectionError> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let compiled = self.compiled_rules.read().await;
        let mut alerts = Vec::new();

        for (rule_id, compiled_rule) in compiled.iter().take(self.config.max_rules_per_event) {
            if evaluate_query_against_event(&compiled_rule.query, event) {
                info!(
                    "Rule {} ({}) matched event (mode: {:?})",
                    compiled_rule.rule.name, rule_id, compiled_rule.rule.mode
                );

                // Check if rule is in alerting mode
                if compiled_rule.rule.mode == crate::models::RuleMode::Alerting {
                    // Compute event hash for deduplication (before timing injection)
                    let matched_events = serde_json::json!([event]);
                    let event_hash = compute_event_hash(&matched_events);

                    // Inject _nano_detected_at for frontend latency calculation
                    let mut enriched_event = event.clone();
                    crate::detection::service::helpers::inject_detected_at(
                        std::slice::from_mut(&mut enriched_event),
                        chrono::Utc::now(),
                    );
                    let matched_events = serde_json::json!([enriched_event]);

                    // Create alert for alerting mode rules
                    let new_alert = NewAlert {
                        rule_id: *rule_id,
                        severity: compiled_rule.rule.severity,
                        matched_events,
                        event_hash: Some(event_hash),
                    };

                    match self.alert_repo.create(&new_alert).await {
                        Ok(alert) => {
                            // Log finding for the alert
                            // TODO: Task 7 will integrate proper risk scoring here
                            if let Some(ref logger) = self.finding_logger {
                                let risk_result =
                                    RiskResult::default_with_entity("unknown".to_string());
                                if let Err(e) = logger
                                    .log_alert(&compiled_rule.rule, &alert, true, risk_result)
                                    .await
                                {
                                    error!("Failed to log alert finding: {}", e);
                                }
                            }

                            // Auto-group alert into a case via the
                            // CaseGroupingHook extension (alerting mode only).
                            // Open-core builds use a no-op hook that returns
                            // Ok(None) and skips downstream shadow investigation.
                            let rule_name = Some(compiled_rule.rule.name.as_str());

                            // Get case permissions from the rule
                            let case_permissions = if compiled_rule.rule.case_visibility != "public"
                            {
                                let case_groups = self
                                    .rule_repo
                                    .get_case_groups(compiled_rule.rule.id)
                                    .await
                                    .unwrap_or_default();
                                Some(AlertCasePermissions {
                                    visibility: compiled_rule.rule.case_visibility.clone(),
                                    group_ids: if case_groups.is_empty() {
                                        None
                                    } else {
                                        Some(case_groups.iter().map(|g| g.id).collect())
                                    },
                                    assigned_group: compiled_rule.rule.case_assigned_group,
                                    playbook_selector_mode: compiled_rule
                                        .rule
                                        .playbook_selector_mode
                                        .clone(),
                                    playbook_id: compiled_rule.rule.playbook_id,
                                })
                            } else {
                                None
                            };

                            match self
                                .case_grouping
                                .group_alert(&alert, rule_name, case_permissions)
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
                                        let _ = self
                                            .shadow_investigation
                                            .on_case_created(
                                                grouped.case_id,
                                                &alert,
                                                grouped.notebook_id,
                                            )
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
                                }
                            }

                            alerts.push(alert);

                            // Update rule match count
                            if let Err(e) = self.rule_repo.update_execution_stats(*rule_id, 1).await
                            {
                                error!("Failed to update rule stats: {}", e);
                            }
                        }
                        Err(AlertRepositoryError::DuplicateAlert(rule_id, hash)) => {
                            debug!(
                                "Skipping duplicate alert for rule {} with event_hash {}",
                                rule_id, hash
                            );
                        }
                        Err(e) => {
                            error!("Failed to create alert for rule {}: {}", rule_id, e);
                        }
                    }
                } else {
                    // For live mode rules, log finding and update the live match count (no alert)
                    debug!(
                        "Rule {} is in live mode - logging finding and updating match count",
                        compiled_rule.rule.name
                    );

                    // Log finding for the detection match (live mode)
                    // TODO: Task 7 will integrate proper risk scoring here
                    if let Some(ref logger) = self.finding_logger {
                        let mut enriched_event = event.clone();
                        crate::detection::service::helpers::inject_detected_at(
                            std::slice::from_mut(&mut enriched_event),
                            chrono::Utc::now(),
                        );
                        let matched_events = vec![enriched_event];
                        let risk_result = RiskResult::default_with_entity("unknown".to_string());
                        if let Err(e) = logger
                            .log_detection_match(
                                &compiled_rule.rule,
                                &matched_events,
                                true,
                                risk_result,
                            )
                            .await
                        {
                            error!("Failed to log detection match finding: {}", e);
                        }
                    }

                    if let Err(e) = self.rule_repo.update_live_match_count(*rule_id, 1).await {
                        error!(
                            "Failed to update live match count for rule {}: {}",
                            rule_id, e
                        );
                    }
                }
            }
        }

        Ok(alerts)
    }

    /// Evaluate multiple log events in batch
    #[instrument(skip(self, events))]
    pub async fn evaluate_batch(
        &self,
        events: &[serde_json::Value],
    ) -> Result<Vec<Alert>, DetectionError> {
        if !self.config.enabled || events.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_alerts = Vec::new();

        for event in events {
            let alerts = self.evaluate(event).await?;
            all_alerts.extend(alerts);
        }

        Ok(all_alerts)
    }

    /// Get the number of loaded rules
    pub async fn rule_count(&self) -> usize {
        self.compiled_rules.read().await.len()
    }

    /// Check if a specific rule is loaded
    pub async fn has_rule(&self, rule_id: Uuid) -> bool {
        self.compiled_rules.read().await.contains_key(&rule_id)
    }

    /// Get the number of loaded cumulative risk rules
    pub async fn cumulative_risk_rule_count(&self) -> usize {
        self.cumulative_risk_rules.read().await.len()
    }

    // ========================================================================
    // Cumulative Risk Detection
    // ========================================================================

    /// Sum the risk scores for an entity within a time window
    ///
    /// Queries the findings table (source_type='findings') for the given entity
    /// and returns the sum of risk_score values within the specified window.
    ///
    /// Requirements: 4.1, 4.2, 4.3
    #[instrument(skip(self))]
    pub async fn sum_entity_risk(
        &self,
        entity: &str,
        window_start: DateTime<Utc>,
    ) -> Result<CumulativeRiskResult, DetectionError> {
        // Query findings for this entity within the time window
        let result = sqlx::query_as::<_, (i64, i64)>(
            r#"
            SELECT
                COALESCE(SUM((metadata->>'risk_score')::integer), 0) as total_risk,
                COUNT(*) as signal_count
            FROM logs
            WHERE source_type = 'findings'
              AND metadata->>'risk_entity' = $1
              AND timestamp >= $2
            "#,
        )
        .bind(entity)
        .bind(window_start)
        .fetch_one(&self.pg_pool)
        .await?;

        let window_seconds = (Utc::now() - window_start).num_seconds();

        Ok(CumulativeRiskResult::new(
            entity.to_string(),
            result.0,
            result.1,
            0, // Threshold will be set by caller
            window_seconds,
        ))
    }

    /// Check cumulative risk thresholds after a finding is logged
    ///
    /// This method is called after logging a finding to check if any
    /// cumulative risk meta-detection rules should fire.
    ///
    /// Requirements: 5.1, 5.2, 5.3
    #[instrument(skip(self, finding))]
    pub async fn check_cumulative_risk(
        &self,
        finding: &FindingEvent,
    ) -> Result<Vec<Alert>, DetectionError> {
        if !self.config.cumulative_risk_enabled {
            return Ok(Vec::new());
        }

        let cumulative_rules = self.cumulative_risk_rules.read().await;
        if cumulative_rules.is_empty() {
            return Ok(Vec::new());
        }

        let mut alerts = Vec::new();
        let entity = &finding.risk_entity;

        // Skip if entity is unknown
        if entity == "unknown" || entity.is_empty() {
            debug!("Skipping cumulative risk check for unknown entity");
            return Ok(Vec::new());
        }

        for compiled_rule in cumulative_rules.iter() {
            let config = &compiled_rule.config;
            let rule = &compiled_rule.rule;

            // Calculate the window start time
            let window_start = config.window_start();

            // Query cumulative risk for this entity
            let mut risk_result = self.sum_entity_risk(entity, window_start).await?;
            risk_result.threshold = config.threshold;

            debug!(
                "Cumulative risk for entity '{}': {} (threshold: {}, window: {}s)",
                entity, risk_result.total_risk, config.threshold, config.window_seconds
            );

            // Check if threshold is exceeded
            if risk_result.threshold_exceeded {
                info!(
                    "Cumulative risk threshold exceeded for entity '{}': {} >= {} (rule: {})",
                    entity, risk_result.total_risk, config.threshold, rule.name
                );

                // Create alert for the cumulative risk threshold breach
                let mut events_vec = vec![serde_json::json!({
                    "entity": entity,
                    "total_risk": risk_result.total_risk,
                    "signal_count": risk_result.signal_count,
                    "threshold": config.threshold,
                    "window_seconds": config.window_seconds,
                    "triggered_by_finding": finding.to_log_json(),
                })];

                let event_hash = compute_event_hash(&serde_json::Value::Array(events_vec.clone()));

                // Inject _nano_detected_at for frontend latency calculation
                crate::detection::service::helpers::inject_detected_at(
                    &mut events_vec,
                    chrono::Utc::now(),
                );
                let matched_events = serde_json::Value::Array(events_vec);

                let new_alert = NewAlert {
                    rule_id: rule.id,
                    severity: rule.severity,
                    matched_events,
                    event_hash: Some(event_hash),
                };

                match self.alert_repo.create(&new_alert).await {
                    Ok(alert) => {
                        // Log finding for the cumulative risk alert
                        if let Some(ref logger) = self.finding_logger {
                            let risk_result = RiskResult::new(
                                risk_result.total_risk as i32,
                                risk_result.total_risk as i32,
                                entity.clone(),
                                Some("risk_entity".to_string()),
                                vec![format!("cumulative_risk_threshold:{}", config.threshold)],
                            );
                            if let Err(e) = logger.log_alert(rule, &alert, true, risk_result).await
                            {
                                error!("Failed to log cumulative risk alert finding: {}", e);
                            }
                        }

                        // Auto-group alert into a case via the CaseGroupingHook
                        // extension (cumulative risk alerts are always alerting).
                        // Open-core builds use a no-op hook that returns Ok(None)
                        // and skips downstream shadow investigation.
                        let rule_name = Some(rule.name.as_str());

                        // Get case permissions from the rule
                        let case_permissions = if rule.case_visibility != "public" {
                            let case_groups = self
                                .rule_repo
                                .get_case_groups(rule.id)
                                .await
                                .unwrap_or_default();
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

                        match self
                            .case_grouping
                            .group_alert(&alert, rule_name, case_permissions)
                            .await
                        {
                            Ok(Some(grouped)) => {
                                info!(
                                    alert_id = %alert.id,
                                    case_id = %grouped.case_id,
                                    case_number = grouped.case_number,
                                    is_new_case = grouped.is_new_case,
                                    "Cumulative risk alert grouped into case"
                                );

                                // Trigger shadow investigation for NEW cases only.
                                // Errors are advisory — log and continue.
                                if grouped.is_new_case {
                                    let _ = self
                                        .shadow_investigation
                                        .on_case_created(
                                            grouped.case_id,
                                            &alert,
                                            grouped.notebook_id,
                                        )
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
                                    "Failed to group cumulative risk alert into case"
                                );
                            }
                        }

                        alerts.push(alert);

                        // Update rule match count
                        if let Err(e) = self.rule_repo.update_execution_stats(rule.id, 1).await {
                            error!("Failed to update cumulative risk rule stats: {}", e);
                        }
                    }
                    Err(AlertRepositoryError::DuplicateAlert(rule_id, hash)) => {
                        debug!(
                            "Skipping duplicate cumulative risk alert for rule {} with event_hash {}",
                            rule_id, hash
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to create cumulative risk alert for rule {}: {}",
                            rule.id, e
                        );
                    }
                }
            }
        }

        Ok(alerts)
    }

    /// Evaluate a finding and check cumulative risk thresholds
    ///
    /// This is a convenience method that combines finding logging with
    /// cumulative risk checking. Call this after a detection match to:
    /// 1. Log the finding
    /// 2. Check if any cumulative risk thresholds are exceeded
    /// 3. Generate alerts for exceeded thresholds
    ///
    /// Requirements: 5.1, 5.2, 5.3
    #[instrument(skip(self, finding))]
    pub async fn process_finding_with_cumulative_risk(
        &self,
        finding: &FindingEvent,
    ) -> Result<Vec<Alert>, DetectionError> {
        // Log the finding first
        if let Some(ref logger) = self.finding_logger {
            if let Err(e) = logger.log_finding(finding).await {
                error!("Failed to log finding: {}", e);
            }
        }

        // Then check cumulative risk thresholds
        self.check_cumulative_risk(finding).await
    }
}
