// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection Rule CRUD Operations
//!
//! Create, read, update, delete operations for detection rules,
//! including mode-based routing and lifecycle management.

use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::models::{DetectionRule, NewDetectionRule, RuleMode, Severity, UpdateDetectionRule};

use super::DetectionError;
use super::DetectionService;

impl DetectionService {
    // ========================================================================
    // Detection Rule CRUD Operations
    // ========================================================================

    /// Create a new detection rule with query validation
    /// New rules default to Live mode for bake-in period
    #[instrument(skip(self, rule), fields(rule_name = %rule.name))]
    pub async fn create_rule(
        &self,
        rule: NewDetectionRule,
    ) -> Result<DetectionRule, DetectionError> {
        // Validate the query syntax
        self.validate_query(&rule.query)?;

        // Validate cron expression if provided
        if let Some(ref cron) = rule.schedule_cron {
            self.validate_cron(cron)?;
        }

        // NAN-1561: spans/metrics rules are scheduled-only. `create_rule` is the
        // un-moded create path used by rule import (and other non-MV callers), so
        // it must enforce the same real-time/dataset guard as `create_rule_with_mode`
        // — otherwise `/api/rules/import` could persist a non-logs real-time rule
        // that never gets a materialized view and never runs scheduled.
        {
            use crate::models::detection_rule::DetectionMode;
            let effective_mode = rule.detection_mode.unwrap_or(DetectionMode::Scheduled);
            if effective_mode == DetectionMode::RealTime {
                if let Some(ds) = rule.dataset.as_deref() {
                    if crate::query::Dataset::from_selector(ds) != crate::query::Dataset::Logs {
                        return Err(DetectionError::InvalidRealtimeRule(format!(
                            "dataset '{ds}' is scheduled-only (spans/metrics cannot use real-time materialized views)"
                        )));
                    }
                }
            }
        }

        info!(
            "Creating detection rule: {} (mode: {:?})",
            rule.name,
            rule.mode.unwrap_or(RuleMode::Staging)
        );
        let created = self.rule_repo.create(&rule).await?;

        // If rule is in stash, immediately archive it
        if let Some(ref folder) = created.folder {
            if folder == "stash" && !created.archived {
                let update = UpdateDetectionRule {
                    archived: Some(true),
                    ..Default::default()
                };
                return Ok(self.rule_repo.update(created.id, &update).await?);
            }
        }

        Ok(created)
    }

    /// Create a new detection rule with mode-based routing
    ///
    /// This method validates the rule based on its detection mode and routes it to the
    /// appropriate execution tier:
    /// - Real-Time: Creates a ClickHouse materialized view for instant detection
    /// - Near Real-Time: Registers with the NRT engine for micro-batch processing
    /// - Scheduled: Uses the existing scheduler for cron-based execution
    ///
    /// Requirements: 2.2, 2.3, 2.4, 5.3
    #[instrument(skip(self, rule, materialized_view_generator), fields(rule_name = %rule.name, detection_mode = ?rule.detection_mode))]
    pub async fn create_rule_with_mode(
        &self,
        rule: NewDetectionRule,
        materialized_view_generator: &super::super::materialized_view::MaterializedViewGenerator,
    ) -> Result<DetectionRule, DetectionError> {
        use crate::models::detection_rule::DetectionMode;

        // Validate the query syntax
        self.validate_query(&rule.query)?;

        // Validate cron expression if provided
        if let Some(ref cron) = rule.schedule_cron {
            self.validate_cron(cron)?;
        }

        // Get detection mode (default to Scheduled)
        let detection_mode = rule.detection_mode.unwrap_or(DetectionMode::Scheduled);

        info!(
            "Creating detection rule: {} (mode: {:?}, detection_mode: {:?})",
            rule.name,
            rule.mode.unwrap_or(RuleMode::Staging),
            detection_mode
        );

        // Validate rule based on detection mode
        match detection_mode {
            DetectionMode::RealTime => {
                // NAN-1561: spans/metrics rules are scheduled-only. The MV path
                // reads FROM the logs table and assumes UDM/OCSF columns. Reject
                // before persisting so the user sees the error up front (belt-and-
                // suspenders to the generate_view_ddl guard).
                if let Some(ds) = rule.dataset.as_deref() {
                    if crate::query::Dataset::from_selector(ds) != crate::query::Dataset::Logs {
                        return Err(DetectionError::InvalidRealtimeRule(format!(
                            "dataset '{ds}' is scheduled-only (spans/metrics cannot use real-time materialized views)"
                        )));
                    }
                }

                // Real-time rules must be simple filters (no aggregations, no joins)
                // risk_entity_field is optional (auto-detects or defaults to src_ip)
                self.validate_realtime_rule(&rule)?;

                // Create the rule in the database first
                let created_rule = self.rule_repo.create(&rule).await?;

                // Create materialized view
                match materialized_view_generator.create_view(&created_rule).await {
                    Ok(view_name) => {
                        info!(
                            "Created materialized view {} for real-time rule {}",
                            view_name, created_rule.name
                        );

                        // Update the rule with the materialized view name
                        let update = crate::models::UpdateDetectionRule {
                            materialized_view_name: Some(Some(view_name)),
                            ..Default::default()
                        };
                        Ok(self.rule_repo.update(created_rule.id, &update).await?)
                    }
                    Err(e) => {
                        // If materialized view creation fails, delete the rule and return error
                        error!(
                            "Failed to create materialized view for rule {}: {}",
                            created_rule.name, e
                        );
                        let _ = self.rule_repo.delete(created_rule.id).await;
                        Err(DetectionError::MaterializedViewError(e.to_string()))
                    }
                }
            }
            DetectionMode::Scheduled => {
                // Scheduled rules — next_run_at is persisted by the API handler
                let created_rule = self.rule_repo.create(&rule).await?;
                Ok(created_rule)
            }
        }
    }

    /// Get a detection rule by ID
    #[instrument(skip(self))]
    pub async fn get_rule(&self, id: Uuid) -> Result<DetectionRule, DetectionError> {
        let rule = self.rule_repo.find_by_id(id).await?;
        Ok(rule)
    }

    /// List all detection rules
    #[instrument(skip(self))]
    pub async fn list_rules(&self) -> Result<Vec<DetectionRule>, DetectionError> {
        let rules = self.rule_repo.list().await?;
        Ok(rules)
    }

    /// List active detection rules (not staging and not paused)
    #[instrument(skip(self))]
    pub async fn list_active_rules(&self) -> Result<Vec<DetectionRule>, DetectionError> {
        let rules = self.rule_repo.list_active().await?;
        Ok(rules)
    }

    /// List rules in alerting mode (production rules that generate alerts)
    #[instrument(skip(self))]
    pub async fn list_alerting_rules(&self) -> Result<Vec<DetectionRule>, DetectionError> {
        let rules = self.rule_repo.list_alerting().await?;
        Ok(rules)
    }

    /// List rules in live mode (bake-in rules that don't generate alerts)
    #[instrument(skip(self))]
    pub async fn list_live_rules(&self) -> Result<Vec<DetectionRule>, DetectionError> {
        let rules = self.rule_repo.list_live().await?;
        Ok(rules)
    }

    /// List rules in staging mode (rules being developed, not executed)
    #[instrument(skip(self))]
    pub async fn list_staging_rules(&self) -> Result<Vec<DetectionRule>, DetectionError> {
        let rules = self.rule_repo.list_staging().await?;
        Ok(rules)
    }

    /// List rules by severity
    #[instrument(skip(self))]
    pub async fn list_rules_by_severity(
        &self,
        severity: Severity,
    ) -> Result<Vec<DetectionRule>, DetectionError> {
        let rules = self.rule_repo.list_by_severity(severity).await?;
        Ok(rules)
    }

    /// Update a detection rule with query validation
    #[instrument(skip(self, update))]
    pub async fn update_rule(
        &self,
        id: Uuid,
        update: UpdateDetectionRule,
    ) -> Result<DetectionRule, DetectionError> {
        // Get the existing rule to check if it's archived
        let existing_rule = self.get_rule(id).await?;

        // Prevent changing mode of archived rules (except to staging)
        if existing_rule.archived {
            if let Some(mode) = update.mode {
                if mode != RuleMode::Staging {
                    return Err(DetectionError::InvalidStateTransition(
                        "Cannot change mode of an archived rule. Unarchive it first.".to_string(),
                    ));
                }
            }
        }

        // Prevent archiving active rules (must be staging or paused first)
        if let Some(true) = update.archived {
            if existing_rule.mode == RuleMode::Live || existing_rule.mode == RuleMode::Alerting {
                return Err(DetectionError::InvalidStateTransition(
                    "Cannot archive a live/alerting rule. Set to staging or paused first."
                        .to_string(),
                ));
            }
        }

        // Validate the query if it's being updated
        if let Some(ref query) = update.query {
            self.validate_query(query)?;
        }

        // Validate cron expression if it's being updated
        if let Some(ref cron) = update.schedule_cron {
            self.validate_cron(cron)?;
        }

        // Auto-archive rules moved to stash folder
        let update = if let Some(ref folder) = update.folder {
            if folder == "stash" {
                info!("Auto-archiving rule {} - moved to stash folder", id);
                UpdateDetectionRule {
                    mode: Some(RuleMode::Staging),
                    archived: Some(true),
                    ..update
                }
            } else {
                update
            }
        } else {
            update
        };

        info!("Updating detection rule: {}", id);
        let updated = self.rule_repo.update(id, &update).await?;
        Ok(updated)
    }

    /// Update a detection rule with mode-based routing
    ///
    /// This method handles mode transitions and updates the appropriate execution tier:
    /// - Scheduled -> Real-Time: Creates materialized view, unschedules from scheduler
    /// - Real-Time -> Scheduled: Drops materialized view, schedules with scheduler
    /// - Real-Time rule updates: Recreates materialized view with new definition
    ///
    /// Requirements: 4.4
    #[instrument(skip(self, update, materialized_view_generator))]
    pub async fn update_rule_with_mode(
        &self,
        id: Uuid,
        update: UpdateDetectionRule,
        materialized_view_generator: &super::super::materialized_view::MaterializedViewGenerator,
        created_by: Option<Uuid>,
    ) -> Result<DetectionRule, DetectionError> {
        use crate::models::detection_rule::DetectionMode;

        // Validate the query if it's being updated
        if let Some(ref query) = update.query {
            self.validate_query(query)?;
        }

        // Validate cron expression if it's being updated
        if let Some(ref cron) = update.schedule_cron {
            self.validate_cron(cron)?;
        }

        // Get the existing rule to check for mode changes
        let existing_rule = self.get_rule(id).await?;
        let old_mode = existing_rule.detection_mode;
        let new_mode = update.detection_mode.unwrap_or(old_mode);

        info!(
            "Updating detection rule: {} (mode: {:?} → {:?})",
            id, old_mode, new_mode
        );

        // NAN-1561: spans/metrics rules are scheduled-only. If the resulting
        // (post-patch) rule would run real-time over a non-logs dataset, reject
        // before any MV is created. Effective dataset = patch value, else
        // existing value.
        if new_mode == DetectionMode::RealTime {
            let effective_dataset = update
                .dataset
                .clone()
                .or_else(|| existing_rule.dataset.clone());
            if let Some(ds) = effective_dataset.as_deref() {
                if crate::query::Dataset::from_selector(ds) != crate::query::Dataset::Logs {
                    return Err(DetectionError::InvalidRealtimeRule(format!(
                        "dataset '{ds}' is scheduled-only (spans/metrics cannot use real-time materialized views)"
                    )));
                }
            }
        }

        // If detection mode is changing to real-time, validate the rule
        if new_mode == DetectionMode::RealTime && old_mode != DetectionMode::RealTime {
            // Create a temporary NewDetectionRule for validation
            let validation_rule = crate::models::NewDetectionRule {
                name: update.name.clone().unwrap_or(existing_rule.name.clone()),
                description: update
                    .description
                    .clone()
                    .or(existing_rule.description.clone()),
                query: update.query.clone().unwrap_or(existing_rule.query.clone()),
                severity: update.severity.unwrap_or(existing_rule.severity),
                mitre_tactics: update.mitre_tactics.clone(),
                mitre_techniques: update.mitre_techniques.clone(),
                schedule_cron: update
                    .schedule_cron
                    .clone()
                    .or(existing_rule.schedule_cron.clone()),
                mode: update.mode.or(Some(existing_rule.mode)),
                narrative: update.narrative.clone().or(existing_rule.narrative.clone()),
                reference_url: update
                    .reference_url
                    .clone()
                    .or(existing_rule.reference_url.clone()),
                author: update.author.clone().or(existing_rule.author.clone()),
                tags: update.tags.clone(),
                ai_generated: update.ai_generated.or(Some(existing_rule.ai_generated)),
                realtime_enabled: update
                    .realtime_enabled
                    .or(Some(existing_rule.realtime_enabled)),
                detection_mode: Some(new_mode),
                risk_score: update.risk_score.or(existing_rule.risk_score),
                risk_entity_field: update
                    .risk_entity_field
                    .clone()
                    .or(existing_rule.risk_entity_field.clone()),
                risk_modifiers: update.risk_modifiers.clone(),
                lookback_minutes: update.lookback_minutes.or(existing_rule.lookback_minutes),
                auto_tuning_enabled: update
                    .auto_tuning_enabled
                    .or(Some(existing_rule.auto_tuning_enabled)),
                auto_tuning_min_confidence: update
                    .auto_tuning_min_confidence
                    .or(Some(existing_rule.auto_tuning_min_confidence)),
                auto_tuning_critical: update
                    .auto_tuning_critical
                    .or(Some(existing_rule.auto_tuning_critical)),
                ai_triage_hints: update
                    .ai_triage_hints
                    .clone()
                    .or_else(|| Some(existing_rule.ai_triage_hints.0.clone())),
                folder: update.folder.clone().or(existing_rule.folder.clone()),
                case_visibility: update
                    .case_visibility
                    .clone()
                    .or(Some(existing_rule.case_visibility.clone())),
                case_group_ids: update.case_group_ids.clone(),
                case_assigned_group: update.case_assigned_group.or(existing_rule.case_assigned_group),
                alert_mode: update.alert_mode.or(Some(existing_rule.alert_mode)),
                playbook_selector_mode: update
                    .playbook_selector_mode
                    .clone()
                    .or(Some(existing_rule.playbook_selector_mode.clone())),
                playbook_id: update.playbook_id.or(existing_rule.playbook_id),
                dataset: update.dataset.clone().or(existing_rule.dataset.clone()),
            };
            self.validate_realtime_rule(&validation_rule)?;
        }

        // Handle mode transitions
        match (old_mode, new_mode) {
            // No mode change - Real-Time
            (DetectionMode::RealTime, DetectionMode::RealTime) => {
                // The MV DDL bakes the query filter, risk_score, risk_entity (from
                // risk_entity_field) and severity — so a change to ANY of them must
                // recreate the view, not just the query. Previously only `query`
                // triggered recreation, so editing e.g. risk_entity_field on a live
                // real-time rule silently left the MV emitting the stale entity (NAN-1665).
                let mv_affecting_change = update.query.is_some()
                    || update.severity.is_some()
                    || update.risk_score.is_some()
                    || update.risk_entity_field.is_some();
                if mv_affecting_change {
                    // Update the rule first
                    let updated_rule = self.rule_repo.update(id, &update).await?;

                    // Recreate materialized view
                    match materialized_view_generator.recreate_view(&updated_rule).await {
                        Ok(view_name) => {
                            info!(
                                "Recreated materialized view {} for updated real-time rule {}",
                                view_name, updated_rule.name
                            );
                            // Update the rule with the new view name (should be the same)
                            let view_update = crate::models::UpdateDetectionRule {
                                materialized_view_name: Some(Some(view_name)),
                                ..Default::default()
                            };
                            let final_rule =
                                self.rule_repo.update(updated_rule.id, &view_update).await?;

                            // Create version entry
                            self.create_version_entry(
                                &final_rule,
                                created_by,
                                "manual_edit",
                                None,
                            )
                            .await;

                            Ok(final_rule)
                        }
                        Err(e) => {
                            error!(
                                "Failed to recreate materialized view for rule {}: {}",
                                updated_rule.name, e
                            );
                            Err(DetectionError::MaterializedViewError(e.to_string()))
                        }
                    }
                } else {
                    // No query change, just update
                    let updated_rule = self.rule_repo.update(id, &update).await?;
                    self.create_version_entry(&updated_rule, created_by, "manual_edit", None)
                        .await;
                    Ok(updated_rule)
                }
            }

            // No mode change - Scheduled
            (DetectionMode::Scheduled, DetectionMode::Scheduled) => {
                // next_run_at is recomputed by the API handler after this call
                let updated_rule = self.rule_repo.update(id, &update).await?;

                // Create version entry
                self.create_version_entry(&updated_rule, created_by, "manual_edit", None)
                    .await;

                Ok(updated_rule)
            }

            // Transitioning TO Real-Time
            (DetectionMode::Scheduled, DetectionMode::RealTime) => {
                // next_run_at will be cleared by the API handler (rule is no longer scheduled)

                // Update the rule
                let updated_rule = self.rule_repo.update(id, &update).await?;

                // Create materialized view
                match materialized_view_generator.create_view(&updated_rule).await {
                    Ok(view_name) => {
                        info!(
                            "Created materialized view {} for rule {} (transitioned to real-time)",
                            view_name, updated_rule.name
                        );
                        // Update the rule with the view name
                        let view_update = crate::models::UpdateDetectionRule {
                            materialized_view_name: Some(Some(view_name)),
                            ..Default::default()
                        };
                        let final_rule =
                            self.rule_repo.update(updated_rule.id, &view_update).await?;

                        // Create version entry
                        self.create_version_entry(
                            &final_rule,
                            created_by,
                            "mode_change_to_realtime",
                            None,
                        )
                        .await;

                        Ok(final_rule)
                    }
                    Err(e) => {
                        error!(
                            "Failed to create materialized view for rule {}: {}",
                            updated_rule.name, e
                        );
                        Err(DetectionError::MaterializedViewError(e.to_string()))
                    }
                }
            }

            // Transitioning FROM Real-Time
            (DetectionMode::RealTime, DetectionMode::Scheduled) => {
                // Drop materialized view
                if let Some(ref view_name) = existing_rule.materialized_view_name {
                    match materialized_view_generator.drop_view(view_name).await {
                        Ok(_) => {
                            info!(
                                "Dropped materialized view {} for rule {} (transitioned from real-time)",
                                view_name, existing_rule.name
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to drop materialized view {} for rule {}: {}",
                                view_name, existing_rule.name, e
                            );
                        }
                    }
                }

                // Clear materialized_view_name
                let mut update_with_cleared_view = update.clone();
                update_with_cleared_view.materialized_view_name = Some(None);

                // Update the rule (next_run_at will be set by the API handler)
                let updated_rule = self.rule_repo.update(id, &update_with_cleared_view).await?;

                // Create version entry
                self.create_version_entry(
                    &updated_rule,
                    created_by,
                    "mode_change_to_scheduled",
                    None,
                )
                .await;

                Ok(updated_rule)
            }
        }
    }

    /// Delete a detection rule
    #[instrument(skip(self))]
    pub async fn delete_rule(&self, id: Uuid) -> Result<(), DetectionError> {
        info!("Deleting detection rule: {}", id);
        self.rule_repo.delete(id).await?;
        Ok(())
    }

    /// Delete a detection rule with mode-based cleanup
    ///
    /// This method cleans up the appropriate execution tier before deleting the rule:
    /// - Real-Time: Drops the materialized view from ClickHouse
    /// - Scheduled: Unschedules from the scheduler
    ///
    /// Requirements: 4.5
    #[instrument(skip(self, materialized_view_generator))]
    pub async fn delete_rule_with_mode(
        &self,
        id: Uuid,
        materialized_view_generator: &super::super::materialized_view::MaterializedViewGenerator,
    ) -> Result<(), DetectionError> {
        use crate::models::detection_rule::DetectionMode;

        // Get the rule to check its detection mode
        let rule = self.get_rule(id).await?;

        info!(
            "Deleting detection rule: {} (mode: {:?})",
            id, rule.detection_mode
        );

        // Clean up based on detection mode
        match rule.detection_mode {
            DetectionMode::RealTime => {
                // Drop materialized view
                if let Some(ref view_name) = rule.materialized_view_name {
                    match materialized_view_generator.drop_view(view_name).await {
                        Ok(_) => {
                            info!(
                                "Dropped materialized view {} for deleted rule {}",
                                view_name, rule.name
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to drop materialized view {} for rule {}: {}",
                                view_name, rule.name, e
                            );
                            // Continue with deletion even if view drop fails
                        }
                    }
                }
            }
            DetectionMode::Scheduled => {
                // Row deletion will clear next_run_at automatically
            }
        }

        // Delete the rule from the database
        self.rule_repo.delete(id).await?;

        info!("Successfully deleted detection rule: {}", id);
        Ok(())
    }

    /// Pause a detection rule (set mode to paused)
    #[instrument(skip(self))]
    pub async fn pause_rule(&self, id: Uuid) -> Result<DetectionRule, DetectionError> {
        info!("Pausing detection rule: {}", id);
        let rule = self.rule_repo.pause(id).await?;
        Ok(rule)
    }

    /// Resume a paused detection rule (set mode back to alerting)
    #[instrument(skip(self))]
    pub async fn resume_rule(&self, id: Uuid) -> Result<DetectionRule, DetectionError> {
        info!("Resuming detection rule: {}", id);
        let rule = self.rule_repo.resume(id).await?;
        Ok(rule)
    }

    /// Promote a rule from live to alerting mode
    /// Call this after bake-in period when you're confident the rule has low false positives
    #[instrument(skip(self))]
    pub async fn promote_to_alerting(&self, id: Uuid) -> Result<DetectionRule, DetectionError> {
        info!("Promoting rule {} to alerting mode", id);
        let rule = self.rule_repo.promote_to_alerting(id).await?;
        Ok(rule)
    }

    /// Demote a rule from alerting to live mode for tuning
    /// Use this if a production rule starts generating too many false positives
    #[instrument(skip(self))]
    pub async fn demote_to_live(&self, id: Uuid) -> Result<DetectionRule, DetectionError> {
        info!("Demoting rule {} to live mode for tuning", id);
        let rule = self.rule_repo.demote_to_live(id).await?;
        Ok(rule)
    }

    /// Set a rule's mode directly (used by bulk operations)
    #[instrument(skip(self))]
    pub async fn set_mode(&self, id: Uuid, mode: &str) -> Result<DetectionRule, DetectionError> {
        info!("Setting rule {} mode to {}", id, mode);
        let rule = self.rule_repo.set_mode(id, mode).await?;
        Ok(rule)
    }

    /// Update the next_run_at timestamp for a rule (for distributed scheduling).
    ///
    /// Pass None to clear next_run_at (e.g., when disabling or archiving a rule).
    pub async fn update_next_run_at(
        &self,
        rule_id: Uuid,
        next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), DetectionError> {
        self.rule_repo
            .update_next_run_at(rule_id, next_run_at)
            .await?;
        Ok(())
    }

    /// Sync `next_run_at` for distributed scheduling based on the rule's current state.
    ///
    /// Sets next_run_at if the rule is active (not staging/paused), scheduled, and has a cron.
    /// Clears next_run_at otherwise (paused, staging, real-time, or no cron).
    pub async fn sync_next_run_at(&self, rule: &DetectionRule) {
        use crate::models::detection_rule::{DetectionMode, RuleMode};

        let should_schedule = rule.detection_mode == DetectionMode::Scheduled
            && rule.mode != RuleMode::Staging
            && rule.mode != RuleMode::Paused
            && rule.schedule_cron.is_some();

        let next_run = if should_schedule {
            rule.schedule_cron.as_ref().map(|cron| {
                super::super::scheduler::calculate_next_run_with_jitter(
                    cron,
                    chrono::Utc::now(),
                    rule.id,
                    30,
                )
            })
        } else {
            None
        };

        if let Err(e) = self.update_next_run_at(rule.id, next_run).await {
            tracing::warn!(rule_id = %rule.id, "Failed to sync next_run_at: {}", e);
        }
    }
}
