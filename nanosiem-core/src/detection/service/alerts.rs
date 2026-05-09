// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert Management
//!
//! Alert CRUD operations, grouped/per-event alert handling,
//! signal logging, case grouping, and webhook notifications.

use tracing::{debug, error, info, instrument};
use uuid::Uuid;

use crate::db::repository::alerts::AlertRepositoryError;
use crate::extensions::AlertCasePermissions;
use crate::db::repository::DailyStat;
use crate::models::{
    AcknowledgeAlert, Alert, AlertStatus, CloseAlert, DetectionRule, Disposition, NewAlert,
    Severity,
};

use super::DetectionError;
use super::DetectionService;

impl DetectionService {
    // ========================================================================
    // Alert Generation Helpers
    // ========================================================================

    /// Get case permissions from a detection rule for case grouping
    pub(super) async fn get_case_permissions(
        &self,
        rule: &DetectionRule,
    ) -> Option<AlertCasePermissions> {
        let has_non_public_visibility = rule.case_visibility != "public";
        let has_assigned_group = rule.case_assigned_group.is_some();

        if has_non_public_visibility || has_assigned_group {
            let case_groups = if has_non_public_visibility {
                self.rule_repo
                    .get_case_groups(rule.id)
                    .await
                    .unwrap_or_default()
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
        }
    }

    /// Log risk signals for an alert's matched events, grouped by entity
    pub(super) async fn log_alert_signals(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        events: &[serde_json::Value],
        global_weight: f64,
    ) {
        let events_by_entity =
            self.group_events_by_entity(rule.risk_entity_field.as_deref(), events);

        if let Some(ref logger) = self.finding_logger {
            for ((entity, field_name), entity_events) in events_by_entity {
                let risk_result = self.score_calculator.calculate(
                    rule.risk_score,
                    rule.severity,
                    Some(&field_name),
                    &rule.risk_modifiers,
                    &entity_events,
                    global_weight,
                );

                let risk_result = super::super::risk::RiskResult::new(
                    risk_result.raw_score,
                    risk_result.weighted_score,
                    entity.clone(),
                    Some(field_name.clone()),
                    risk_result.factors,
                );

                debug!(
                    "Risk score for entity {} (field: {}): raw={}, weighted={}",
                    entity, field_name, risk_result.raw_score, risk_result.weighted_score
                );

                if let Err(e) = logger.log_alert(rule, alert, false, risk_result).await {
                    error!("Failed to log alert signal for entity {}: {}", entity, e);
                }
            }
        }
    }

    /// Group alert into a case and fire webhooks
    pub(super) async fn process_alert_post_create(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        case_permissions: Option<AlertCasePermissions>,
    ) {
        // Auto-group alert into a case via the CaseGroupingHook extension.
        // Open-core builds use a no-op hook that returns Ok(None) and skips
        // case grouping (and downstream shadow investigation) entirely.
        let rule_name = Some(rule.name.as_str());
        match self
            .case_grouping
            .group_alert(alert, rule_name, case_permissions)
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

                if grouped.is_new_case {
                    if let Err(e) = self
                        .shadow_investigation
                        .on_case_created(grouped.case_id, alert, grouped.notebook_id)
                        .await
                    {
                        debug!(
                            alert_id = %alert.id,
                            case_id = %grouped.case_id,
                            error = %e,
                            "Shadow investigation hook returned error"
                        );
                    }
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

        // Fire webhook notifications
        if let Some(ref webhook_service) = self.webhook_service {
            let severity_str = format!("{:?}", rule.severity).to_lowercase();
            webhook_service
                .fire_alert_created(
                    alert.id,
                    rule.id,
                    &rule.name,
                    &severity_str,
                    &alert.matched_events,
                    alert.created_at,
                )
                .await;
        }
    }

    /// Handle grouped alert mode: all matched events -> single alert (default behavior)
    pub(super) async fn handle_grouped_alert(
        &self,
        rule: &DetectionRule,
        results: &[serde_json::Value],
        match_count: i64,
        today: chrono::NaiveDate,
        global_weight: f64,
    ) -> Result<Option<Alert>, DetectionError> {
        self.rule_repo
            .record_daily_stats(rule.id, today, match_count, 1)
            .await?;

        self.store_detection_match(rule, results).await?;

        let matched_events = serde_json::Value::Array(results.to_vec());
        let new_alert = NewAlert {
            rule_id: rule.id,
            severity: rule.severity,
            matched_events,
            event_hash: None,
        };

        let alert = self.alert_repo.create(&new_alert).await?;

        info!(
            "Rule {} (ALERTING/grouped) matched {} events, generated alert {}",
            rule.name, match_count, alert.id
        );

        self.log_alert_signals(rule, &alert, results, global_weight)
            .await;

        let case_permissions = self.get_case_permissions(rule).await;
        self.process_alert_post_create(rule, &alert, case_permissions)
            .await;

        Ok(Some(alert))
    }

    /// Handle per-event alert mode: each matched event -> its own alert
    /// Used for vendor pass-through (e.g., CrowdStrike/SentinelOne detections)
    pub(super) async fn handle_per_event_alerts(
        &self,
        rule: &DetectionRule,
        results: &[serde_json::Value],
        match_count: i64,
        today: chrono::NaiveDate,
        global_weight: f64,
    ) -> Result<Option<Alert>, DetectionError> {
        let case_permissions = self.get_case_permissions(rule).await;
        let mut first_alert: Option<Alert> = None;
        let mut alerts_created: i64 = 0;

        for event in results {
            // Store each event as its own detection match (1:1 with alerts)
            self.store_detection_match(rule, std::slice::from_ref(event))
                .await?;
            let matched_events = serde_json::json!([event]);
            let new_alert = NewAlert {
                rule_id: rule.id,
                severity: rule.severity,
                matched_events,
                event_hash: None, // Hash computed from single event -- dedup works per-event
            };

            // Call repo directly to catch DuplicateAlert before conversion to DetectionError
            let alert = match self.alert_repo.create(&new_alert).await {
                Ok(alert) => alert,
                Err(AlertRepositoryError::DuplicateAlert(rule_id, hash)) => {
                    debug!(
                        "Skipped duplicate per-event alert for rule {} with hash {}",
                        rule_id, hash
                    );
                    continue;
                }
                Err(e) => return Err(DetectionError::from(e)),
            };

            alerts_created += 1;

            // Log signals for this single event
            self.log_alert_signals(rule, &alert, std::slice::from_ref(event), global_weight)
                .await;

            // Group into case and fire webhooks
            self.process_alert_post_create(rule, &alert, case_permissions.clone())
                .await;

            if first_alert.is_none() {
                first_alert = Some(alert);
            }
        }

        // Record daily stats with actual number of alerts created
        self.rule_repo
            .record_daily_stats(rule.id, today, match_count, alerts_created)
            .await?;

        info!(
            "Rule {} (ALERTING/per_event) matched {} events, created {} alerts",
            rule.name, match_count, alerts_created
        );

        Ok(first_alert)
    }

    // ========================================================================
    // Alert Management
    // ========================================================================

    /// Get an alert by ID
    #[instrument(skip(self))]
    pub async fn get_alert(&self, id: Uuid) -> Result<Alert, DetectionError> {
        let alert = self.alert_repo.find_by_id(id).await?;
        Ok(alert)
    }

    /// List alerts with optional filters
    #[instrument(skip(self))]
    pub async fn list_alerts(
        &self,
        status: Option<AlertStatus>,
        severity: Option<Severity>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self
            .alert_repo
            .list(status, severity, limit, offset)
            .await?;
        Ok(alerts)
    }

    /// List alerts for a specific rule (limited to 100 most recent)
    #[instrument(skip(self))]
    pub async fn list_alerts_by_rule(&self, rule_id: Uuid) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self.alert_repo.list_by_rule(rule_id).await?;
        Ok(alerts)
    }

    /// List alerts for a specific rule with custom limit
    #[instrument(skip(self))]
    pub async fn list_alerts_by_rule_limited(
        &self,
        rule_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self.alert_repo.list_by_rule_limited(rule_id, limit).await?;
        Ok(alerts)
    }

    /// List alerts after a specific cursor (timestamp + ID)
    #[instrument(skip(self))]
    pub async fn list_alerts_after(
        &self,
        after_timestamp: chrono::DateTime<chrono::Utc>,
        after_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self
            .alert_repo
            .list_after(after_timestamp, after_id, limit)
            .await?;
        Ok(alerts)
    }

    /// Acknowledge an alert
    #[instrument(skip(self))]
    pub async fn acknowledge_alert(
        &self,
        id: Uuid,
        acknowledged_by: &str,
    ) -> Result<Alert, DetectionError> {
        info!("Acknowledging alert {} by {}", id, acknowledged_by);
        let ack = AcknowledgeAlert {
            acknowledged_by: acknowledged_by.to_string(),
        };
        let alert = self.alert_repo.acknowledge(id, &ack).await?;
        Ok(alert)
    }

    /// Close an alert with disposition
    #[instrument(skip(self))]
    pub async fn close_alert(
        &self,
        id: Uuid,
        closed_by: &str,
        disposition: Disposition,
    ) -> Result<Alert, DetectionError> {
        info!(
            "Closing alert {} by {} with disposition {:?}",
            id, closed_by, disposition
        );
        let close = CloseAlert {
            closed_by: closed_by.to_string(),
            disposition,
        };
        let alert = self.alert_repo.close(id, &close).await?;
        Ok(alert)
    }

    /// Assign an alert to an analyst
    #[instrument(skip(self))]
    pub async fn assign_alert(&self, id: Uuid, assignee: &str) -> Result<Alert, DetectionError> {
        info!("Assigning alert {} to {}", id, assignee);
        let alert = self.alert_repo.assign(id, assignee).await?;
        Ok(alert)
    }

    /// Bulk acknowledge alerts
    #[instrument(skip(self, ids))]
    pub async fn bulk_acknowledge_alerts(
        &self,
        ids: &[Uuid],
        acknowledged_by: &str,
    ) -> Result<usize, DetectionError> {
        info!(
            "Bulk acknowledging {} alerts by {}",
            ids.len(),
            acknowledged_by
        );
        let count = self
            .alert_repo
            .bulk_acknowledge(ids, acknowledged_by)
            .await?;
        Ok(count)
    }

    /// Bulk close alerts
    #[instrument(skip(self, ids))]
    pub async fn bulk_close_alerts(
        &self,
        ids: &[Uuid],
        closed_by: &str,
        disposition: Disposition,
    ) -> Result<usize, DetectionError> {
        info!(
            "Bulk closing {} alerts by {} with disposition {:?}",
            ids.len(),
            closed_by,
            disposition
        );
        let count = self
            .alert_repo
            .bulk_close(ids, disposition, closed_by)
            .await?;
        Ok(count)
    }

    /// Get alert counts by status
    #[instrument(skip(self))]
    pub async fn get_alert_counts(&self) -> Result<Vec<(AlertStatus, i64)>, DetectionError> {
        let counts = self.alert_repo.count_by_status().await?;
        Ok(counts)
    }

    // ========================================================================
    // Daily Stats
    // ========================================================================

    /// Get daily stats for a specific rule
    #[instrument(skip(self))]
    pub async fn get_rule_daily_stats(
        &self,
        rule_id: Uuid,
        days: i32,
    ) -> Result<Vec<DailyStat>, DetectionError> {
        let stats = self.rule_repo.get_daily_stats(rule_id, days).await?;
        Ok(stats)
    }

    /// Get daily stats for all rules (for the detections list)
    #[instrument(skip(self))]
    pub async fn get_all_daily_stats(
        &self,
        days: i32,
    ) -> Result<std::collections::HashMap<Uuid, Vec<DailyStat>>, DetectionError> {
        let stats = self.rule_repo.get_all_daily_stats(days).await?;

        // Group by rule_id
        let mut grouped: std::collections::HashMap<Uuid, Vec<DailyStat>> =
            std::collections::HashMap::new();
        for (rule_id, stat) in stats {
            grouped.entry(rule_id).or_default().push(stat);
        }

        Ok(grouped)
    }
}
