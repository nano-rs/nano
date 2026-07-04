// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-time rule evaluator.
//!
//! Contains the `RealtimeEvaluator` struct and all methods for loading rules
//! and evaluating events.

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
use super::super::findings::FindingLogger;
use super::super::risk::RiskResult;
use super::config::{CompiledRule, RealtimeConfig};
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
    /// Case grouping hook (open-core default no-op skips grouping)
    case_grouping: Arc<dyn CaseGroupingHook>,
    /// Shadow investigation hook for auto-triage on new case creation
    /// (open-core default no-op)
    shadow_investigation: Arc<dyn ShadowInvestigationHook>,
}

impl RealtimeEvaluator {
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
        compiled.clear();

        for rule in rules {
            // Compile the rule's query for real-time evaluation.
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
            "Loaded {} rules for real-time evaluation",
            compiled.len()
        );
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

}
