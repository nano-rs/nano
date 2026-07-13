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

/// A per-entity finding candidate with its stable cross-execution identity
/// (NAN-1305). Built by `build_finding_candidates`, filtered to the new ones by
/// `retain_unemitted`, then recorded by `record_finding_emissions`.
///
/// `pub(crate)` (audit D13): the real-time `SignalProcessor` reuses the same
/// candidate type + emission store for its per-(rule, entity, window) dedup —
/// see `helpers::realtime_finding_candidate`.
pub(crate) struct ClaimedFinding {
    /// Entity value (e.g. the `src_ip`).
    pub entity: String,
    /// Field the entity was extracted from (e.g. `src_ip`).
    pub field: String,
    /// This entity's matched events (an aggregate row, or grouped raw events).
    pub events: Vec<serde_json::Value>,
    /// Source-event window end (`_last_seen` / latest `timestamp`) — stamped on
    /// the finding.
    pub window_end: chrono::DateTime<chrono::Utc>,
    /// Stable dedup key for `(rule_id, finding_hash)`.
    pub finding_hash: String,
}

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

    /// Partition a result set into per-entity finding groups, honoring the nPL
    /// `| risk` command's per-event score/entity when present (R1).
    ///
    /// Returns `(has_query_scores, groups)` where each group is
    /// `(entity, field, events)`. When the query produced per-event risk scores
    /// (`| risk score=… entity=…`), **each event is its own group** keyed on the
    /// query-derived entity; otherwise events are grouped by the rule's
    /// risk-entity field and scored at rule level. This is the single source of
    /// truth for grouping shared by the Live (`log_live_findings`) and Alerting
    /// (`handle_grouped_alert` / `log_alert_signals`) paths, so promoting a rule
    /// Live→Alerting can no longer silently revert per-event scoring/entity back
    /// to the rule-level value.
    pub(super) fn partition_entity_groups(
        &self,
        rule: &DetectionRule,
        results: &[serde_json::Value],
        global_weight: f64,
    ) -> (bool, Vec<(String, String, Vec<serde_json::Value>)>) {
        // Audit D10: inspect the WHOLE batch, not just the first row. Sampling
        // `results.first()` meant a leading null-scored row disabled query
        // scoring for the entire batch. The query produced per-event scores iff
        // ANY event carries a real (non-null) score. An all-null batch is now
        // `false` → rule-level grouping → the alert fires (instead of empty
        // groups being misread as "already alerted" and suppressed).
        //
        // In a genuinely mixed batch, an event whose `| risk` score is null
        // produces no per-event finding — the query authored it as no-risk
        // (`score=if(cond, X, null)`), so this is intentional, not a drop.
        let has_query_scores = results
            .iter()
            .any(super::super::risk::ScoreCalculator::has_query_risk_score);

        let groups = if has_query_scores {
            results
                .iter()
                .filter_map(|event| {
                    let rr = self
                        .score_calculator
                        .calculate_from_query_result(event, global_weight)?;
                    let field = rr.entity_field.clone().unwrap_or_default();
                    Some((rr.entity, field, vec![event.clone()]))
                })
                .collect()
        } else {
            self.group_events_by_entity(rule.risk_entity_field.as_deref(), results)
                .into_iter()
                .map(|((entity, field), events)| (entity, field, events))
                .collect()
        };
        (has_query_scores, groups)
    }

    /// Compute the risk result for one entity group, honoring query-derived
    /// per-event scores when the rule's `| risk` command produced them (R1),
    /// else the rule-level score for the group (`rule.risk_score` + severity
    /// default, `rule.risk_modifiers`, and the global `risk_weight`).
    ///
    /// Shared by every finding-emission path (Live + Alerting) so a rule scores
    /// identically regardless of mode. Returns `None` only when a query-scored
    /// event can no longer be scored (caller skips it).
    pub(super) fn risk_result_for_group(
        &self,
        rule: &DetectionRule,
        has_query_scores: bool,
        entity: &str,
        field: &str,
        events: &[serde_json::Value],
        global_weight: f64,
    ) -> Option<super::super::risk::RiskResult> {
        let result = if has_query_scores {
            self.score_calculator
                .calculate_from_query_result(&events[0], global_weight)
        } else {
            let r = self.score_calculator.calculate(
                rule.risk_score,
                rule.severity,
                Some(field),
                &rule.risk_modifiers,
                events,
                global_weight,
            );
            Some(super::super::risk::RiskResult::new(
                r.raw_score,
                r.weighted_score,
                entity.to_string(),
                Some(field.to_string()),
                r.factors,
            ))
        };

        // NAN-1805: execution-side feedback-loop guard. A dataset=risk rule's
        // findings feed the risk dataset itself, so its score is FORCED to 0 at
        // this single choke point (shared by the Live, grouped-Alerting, and
        // per-event paths) — covering the rule-level score, severity defaults,
        // modifiers, and any query-derived `| risk` score alike. The finding is
        // still emitted (audit trail / signal visibility); it contributes 0.
        if Self::is_risk_dataset_rule(rule) {
            return result.map(|mut r| {
                r.raw_score = 0;
                r.weighted_score = 0;
                r.factors = vec![
                    "dataset=risk rule: score forced to 0 (feedback-loop guard, NAN-1805)"
                        .to_string(),
                ];
                r
            });
        }
        result
    }

    /// Log risk signals for an alert's matched events, grouped by entity.
    ///
    /// Used by the per-event alert path. Grouped / aggregate rules do NOT use
    /// this — they go through [`claim_new_grouped_findings`] +
    /// [`emit_grouped_findings`] so emissions are deduped across executions and
    /// stamped with the source-event window (NAN-1305). Per-event rules keep the
    /// legacy `now()` stamp; their re-alerting is already gated upstream by the
    /// single-event `event_hash`.
    pub(super) async fn log_alert_signals(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        events: &[serde_json::Value],
        global_weight: f64,
    ) {
        let Some(ref logger) = self.finding_logger else {
            return;
        };

        // R1: honor the `| risk` command's per-event score/entity here too — the
        // per-event alert path must score identically to Live/grouped, not revert
        // to the rule-level score/entity.
        let (has_query_scores, groups) = self.partition_entity_groups(rule, events, global_weight);
        for (entity, field_name, entity_events) in groups {
            let Some(risk_result) = self.risk_result_for_group(
                rule,
                has_query_scores,
                &entity,
                &field_name,
                &entity_events,
                global_weight,
            ) else {
                continue;
            };

            debug!(
                "Risk score for entity {} (field: {}): raw={}, weighted={}",
                entity, field_name, risk_result.raw_score, risk_result.weighted_score
            );

            if let Err(e) = logger.log_alert(rule, alert, false, risk_result).await {
                error!("Failed to log alert signal for entity {}: {}", entity, e);
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

        // Fire webhook notifications. Scheduled detection alerts are always
        // kind = "detection" (SIEM stream); the webhook service filters by each
        // webhook's subscription + severity. The primary entity is pulled from
        // the first matched event via the rule's risk-entity field so the
        // consumer gets "who/what" without parsing the raw events.
        if let Some(ref webhook_service) = self.webhook_service {
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
    }

    /// G2 (NAN-1749): reconcile alerting-mode alerts that were never grouped
    /// into a case.
    ///
    /// Grouping is fire-once and terminal: a transient PG blip during
    /// `process_alert_for_grouping`, or the rule-execution `tokio::time::timeout`
    /// cancelling `process_alert_post_create` mid-flight, leaves the alert row
    /// created but `case_id IS NULL` forever — no case, no queue, no retry. This
    /// periodic sweep finds those orphans and re-runs grouping for them.
    ///
    /// Bounded + idempotent:
    /// * only `kind = 'detection'` alerts whose rule is still in `alerting` mode
    ///   (observability alerts have no rule and never group; deleted-rule alerts
    ///   are excluded by the JOIN),
    /// * `case_id IS NULL` AND older than `min_age_minutes` (so we don't race the
    ///   normal inline grouping that runs right after alert creation),
    /// * within a `lookback_hours` window so a pre-deploy backlog can't trigger
    ///   an unbounded scan,
    /// * `LIMIT max_per_pass` per invocation.
    ///
    /// Idempotent because a successful `group_alert` sets `alerts.case_id`
    /// (create path: `create_with_primary_alert`; attach path: `add_alert`), so a
    /// reconciled alert drops out of the next pass' result set.
    ///
    /// GAP: this re-runs GROUPING only, not the webhook fire. Re-firing webhooks
    /// from a sweep would double-deliver for the common case where grouping
    /// failed but the (later) webhook block still ran, so it is intentionally
    /// omitted. Returns the number of alerts successfully (re-)grouped.
    pub async fn reconcile_ungrouped_alerts(
        &self,
        min_age_minutes: i64,
        lookback_hours: i64,
        max_per_pass: i64,
    ) -> Result<usize, DetectionError> {
        // Fetch the orphan (alert_id, rule_id) pairs. Kept minimal — full alert
        // rows are loaded per-id below only for the ones we actually re-group.
        let orphans: Vec<(Uuid, Uuid)> = sqlx::query_as::<_, (Uuid, Uuid)>(
            r#"
            SELECT a.id, a.rule_id
            FROM alerts a
            JOIN detection_rules r ON r.id = a.rule_id
            WHERE a.case_id IS NULL
              AND a.kind = 'detection'
              AND r.mode = 'alerting'
              AND a.created_at < NOW() - make_interval(mins => $1::int)
              AND a.created_at > NOW() - make_interval(hours => $2::int)
            ORDER BY a.created_at ASC
            LIMIT $3
            "#,
        )
        .bind(min_age_minutes as i32)
        .bind(lookback_hours as i32)
        .bind(max_per_pass)
        .fetch_all(&self.pg_pool)
        .await?;

        if orphans.is_empty() {
            return Ok(0);
        }

        let mut reconciled = 0usize;
        for (alert_id, rule_id) in orphans {
            // Load the rule + full alert. Skip (don't abort the whole sweep) on
            // any per-item error — a subsequent pass retries.
            let rule = match self.rule_repo.find_by_id(rule_id).await {
                Ok(r) => r,
                Err(e) => {
                    debug!(alert_id = %alert_id, rule_id = %rule_id, error = %e, "Reconcile: rule load failed; skipping");
                    continue;
                }
            };
            // SYSTEM caller: the reconcile sweep repairs grouping for ALL
            // alerts regardless of any viewer's per-source scope (NAN-1800).
            let system_scope = crate::auth::ScopeSet::unrestricted();
            let alert = match self.alert_repo.find_by_id(alert_id, system_scope.deny_set()).await {
                Ok(a) => a,
                Err(e) => {
                    debug!(alert_id = %alert_id, error = %e, "Reconcile: alert load failed; skipping");
                    continue;
                }
            };

            let permissions = self.get_case_permissions(&rule).await;
            match self
                .case_grouping
                .group_alert(&alert, Some(rule.name.as_str()), permissions)
                .await
            {
                Ok(Some(grouped)) => {
                    reconciled += 1;
                    info!(
                        alert_id = %alert_id,
                        case_id = %grouped.case_id,
                        is_new_case = grouped.is_new_case,
                        "Reconcile: grouped previously-orphaned alert into a case"
                    );
                    if grouped.is_new_case {
                        if let Err(e) = self
                            .shadow_investigation
                            .on_case_created(grouped.case_id, &alert, grouped.notebook_id)
                            .await
                        {
                            debug!(alert_id = %alert_id, case_id = %grouped.case_id, error = %e, "Reconcile: shadow investigation hook returned error");
                        }
                    }
                }
                // Open-core no-op hook returns Ok(None) — nothing to do.
                Ok(None) => {}
                Err(e) => {
                    // Still failing — leave case_id NULL for the next pass.
                    error!(alert_id = %alert_id, error = %e, "Reconcile: re-grouping failed; will retry next pass");
                }
            }
        }

        Ok(reconciled)
    }

    /// Handle grouped alert mode: all matched events -> single alert (default behavior)
    ///
    /// NAN-1305: before creating the alert, claim a per-entity finding for each
    /// entity in this result set keyed on the aggregated event window (not the
    /// execution time). If *every* entity was already alerted by a prior
    /// execution over the same window (the re-evaluation case: rule edit/enable,
    /// jobs restart, scheduler gap), the whole alert is suppressed — no duplicate
    /// alert row, no findings, no webhook, no case — which is what prevents the
    /// re-alert storms and entity-risk inflation. Genuinely new entities (or a
    /// later `_last_seen`) still produce an alert and findings as normal.
    pub(super) async fn handle_grouped_alert(
        &self,
        rule: &DetectionRule,
        results: &[serde_json::Value],
        match_count: i64,
        today: chrono::NaiveDate,
        global_weight: f64,
    ) -> Result<Option<Alert>, DetectionError> {
        // Read-only dedup check first: which entities in this window are new?
        // (No writes yet — we only record emissions after the alert is created,
        // so a failed alert insert can't orphan a dedup row and silently
        // suppress a future alert.)
        // R1: build candidates from the same query-score-aware grouping the Live
        // path uses, so a `| risk` rule keeps its per-event score/entity after a
        // Live→Alerting promotion instead of reverting to rule-level grouping.
        let (has_query_scores, groups) = self.partition_entity_groups(rule, results, global_weight);
        let candidates = Self::build_finding_candidates("alert", rule.id, groups.into_iter());
        let mut new_findings = self.retain_unemitted(rule.id, candidates).await;

        // NAN-1805: per-(rule, entity) alert cooldown. Window-dedup above keys
        // on the entity's newest activity, so an entity producing NEW activity
        // every cycle re-surfaces every cycle; when the rule sets a cooldown,
        // entities that alerted within the window are additionally suppressed
        // here. Their emissions are deliberately NOT recorded, so the same
        // finding re-surfaces next cycle and fires once the window expires —
        // the cooldown DELAYS an alert, it never terminally drops one. The
        // durable anchors make this restart/failover-safe and time-based (a
        // flap across the rule's threshold inside the window cannot re-fire).
        let cooldown_minutes = rule.alert_cooldown_minutes.unwrap_or(0);
        let mut cooldown_suppressed = 0usize;
        if cooldown_minutes > 0 && !new_findings.is_empty() {
            let entities: Vec<String> = new_findings.iter().map(|f| f.entity.clone()).collect();
            let cooled = self
                .entities_in_alert_cooldown(rule.id, cooldown_minutes, &entities)
                .await?;
            if !cooled.is_empty() {
                let before = new_findings.len();
                new_findings.retain(|f| !cooled.contains(&f.entity));
                cooldown_suppressed = before - new_findings.len();
            }
        }

        if new_findings.is_empty() {
            // Every entity over this window was already alerted (or is inside
            // its alert cooldown) — suppress the duplicate alert entirely
            // (matches counted, no new alert/finding, no webhook, no case).
            self.rule_repo
                .record_daily_stats(rule.id, today, match_count, 0)
                .await?;
            debug!(
                "Rule {} (ALERTING/grouped) matched {} events but all entities were already alerted for this window ({} in cooldown) — suppressing duplicate alert",
                rule.name, match_count, cooldown_suppressed
            );
            return Ok(None);
        }
        if cooldown_suppressed > 0 {
            debug!(
                "Rule {} (ALERTING/grouped): {} entities suppressed by the {}m alert cooldown; alerting on the remaining {}",
                rule.name,
                cooldown_suppressed,
                cooldown_minutes,
                new_findings.len()
            );
        }

        self.store_detection_match(rule, results).await?;

        // Audit D19: the query now returns ALL matches (not the newest 100), so
        // match_count/grouping are accurate — but bound the sample STORED in the
        // alert row to `max_events_per_alert` so a large grouped match can't write
        // a multi-MB jsonb blob. The stored sample is the newest N (SQL orders
        // timestamp DESC); the full count lives in match_count / detection_matches.
        let sample: Vec<serde_json::Value> = results
            .iter()
            .take(self.config.max_events_per_alert)
            .cloned()
            .collect();
        let matched_events = serde_json::Value::Array(sample);
        let new_alert = NewAlert {
            rule_id: rule.id,
            severity: rule.severity,
            matched_events,
            event_hash: None,
            // A13 (NAN-1752): the stored `matched_events` is capped at
            // max_events_per_alert (D19), so persist the TRUE match count for
            // this window rather than letting the read side undercount from the
            // capped sample.
            match_count: Some(match_count),
        };

        let alert = match self.alert_repo.create(&new_alert).await {
            Ok(alert) => alert,
            Err(AlertRepositoryError::DuplicateAlert(_, _)) => {
                // Audit D20: a fail-open dedup read, or a crash between the alert
                // INSERT and record_finding_emissions, can leave an alert whose
                // emissions weren't recorded; the next run re-tries the SAME
                // insert and hits the unique index. Treat it as already-alerted
                // (mirroring the per-event path's `continue`) instead of erroring
                // the whole execution every cycle until the window slides past.
                //
                // The alert already exists for these entities, so record the
                // emissions now (repairing the crash-before-emissions case) — this
                // stops retain_unemitted from re-surfacing them every cycle — and
                // count no new alert. NAN-1805: repair the cooldown anchors the
                // same way (the crash may have preceded the anchor write too);
                // slightly conservative — the anchor is stamped now() rather
                // than the earlier alert's created_at.
                self.record_finding_emissions(rule.id, &new_findings).await;
                if cooldown_minutes > 0 {
                    let entities: Vec<String> =
                        new_findings.iter().map(|f| f.entity.clone()).collect();
                    self.record_alert_cooldown_anchors(rule.id, &entities).await;
                }
                self.rule_repo
                    .record_daily_stats(rule.id, today, match_count, 0)
                    .await?;
                debug!(
                    "Rule {} (ALERTING/grouped) alert already exists (dedup conflict) — recording emissions, suppressing",
                    rule.name
                );
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        // Audit D20: count alert_count=1 only now that the alert was actually
        // created. The old code recorded it BEFORE the insert, so a dedup/failure
        // counted an alert that never existed.
        self.rule_repo
            .record_daily_stats(rule.id, today, match_count, 1)
            .await?;

        // Record the emissions only now that the alert exists, then emit a
        // finding per new entity stamped with its source event window.
        self.record_finding_emissions(rule.id, &new_findings).await;

        // NAN-1805: anchor the alert cooldown for the entities that just
        // alerted (durable upsert; best-effort like the emissions record).
        if cooldown_minutes > 0 {
            let entities: Vec<String> = new_findings.iter().map(|f| f.entity.clone()).collect();
            self.record_alert_cooldown_anchors(rule.id, &entities).await;
        }

        info!(
            "Rule {} (ALERTING/grouped) matched {} events ({} new entities), generated alert {}",
            rule.name,
            match_count,
            new_findings.len(),
            alert.id
        );

        self.emit_grouped_findings(rule, &alert, &new_findings, has_query_scores, global_weight)
            .await;

        let case_permissions = self.get_case_permissions(rule).await;
        self.process_alert_post_create(rule, &alert, case_permissions)
            .await;

        Ok(Some(alert))
    }

    /// Emit one risk-scored finding per already-recorded entity, stamped with the
    /// entity's source event window rather than `now()` (NAN-1305).
    pub(super) async fn emit_grouped_findings(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        new_findings: &[ClaimedFinding],
        has_query_scores: bool,
        global_weight: f64,
    ) {
        let Some(ref logger) = self.finding_logger else {
            return;
        };
        for nf in new_findings {
            // R1: score with the query-derived per-event value when the rule's
            // `| risk` command produced one, else the rule-level score — the same
            // rule scores identically in Live and Alerting.
            let Some(risk_result) = self.risk_result_for_group(
                rule,
                has_query_scores,
                &nf.entity,
                &nf.field,
                &nf.events,
                global_weight,
            ) else {
                continue;
            };

            debug!(
                "Risk score for entity {} (field: {}): raw={}, weighted={}",
                nf.entity, nf.field, risk_result.raw_score, risk_result.weighted_score
            );

            if let Err(e) = logger
                .log_alert_at(rule, alert, false, risk_result, Some(nf.window_end))
                .await
            {
                error!("Failed to log alert signal for entity {}: {}", nf.entity, e);
            }
        }
    }

    /// Log live-mode (bake-in) detection-match findings for a rule's results,
    /// deduped per `(rule, entity, window)` and stamped with the source event
    /// window so overlapping re-evaluations don't re-emit findings or re-inflate
    /// entity risk (NAN-1305). Returns the number of findings emitted.
    pub(super) async fn log_live_findings(
        &self,
        rule: &DetectionRule,
        results: &[serde_json::Value],
        global_weight: f64,
    ) -> usize {
        let Some(logger) = self.finding_logger.as_ref() else {
            return 0;
        };

        // Query-derived scores (`| risk` command) score each event individually;
        // otherwise group by entity and score per group. Shared with the Alerting
        // path so Live and Alerting group + score identically (R1).
        let (has_query_scores, groups) = self.partition_entity_groups(rule, results, global_weight);

        let candidates = Self::build_finding_candidates("live", rule.id, groups);
        let new_findings = self.retain_unemitted(rule.id, candidates).await;
        if new_findings.is_empty() {
            return 0;
        }
        self.record_finding_emissions(rule.id, &new_findings).await;

        let mut emitted = 0;
        for nf in &new_findings {
            // Re-derive the risk result for this entity/event (query-derived
            // score per event, else rule-derived score per group) — shared with
            // the Alerting path (R1).
            let Some(risk_result) = self.risk_result_for_group(
                rule,
                has_query_scores,
                &nf.entity,
                &nf.field,
                &nf.events,
                global_weight,
            ) else {
                continue;
            };

            debug!(
                "Live finding for entity {} (field: {}): raw={}, weighted={}",
                nf.entity, nf.field, risk_result.raw_score, risk_result.weighted_score
            );

            if let Err(e) = logger
                .log_detection_match_at(rule, &nf.events, false, risk_result, Some(nf.window_end))
                .await
            {
                error!(
                    "Failed to log detection match signal for entity {}: {}",
                    nf.entity, e
                );
            } else {
                emitted += 1;
            }
        }
        emitted
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

        // Audit D19: the detection query now returns ALL matches (so match_count
        // is accurate), but per-event mode creates one alert per event. Cap the
        // number of ALERTS created per window at max_events_per_alert so a broad
        // or misconfigured per-event rule can't storm PG with up to 1M
        // inserts/case-groupings/findings in a single cycle. The overflow is
        // VISIBLE (warn + accurate match_count), not silently dropped at 100.
        let alert_cap = self.config.max_events_per_alert;
        if results.len() > alert_cap {
            tracing::warn!(
                "Rule {} (per-event) matched {} events but is capping alert creation at {} this window — narrow the rule or use grouped mode",
                rule.name,
                results.len(),
                alert_cap
            );
        }

        // NAN-1805: per-(rule, entity) alert cooldown for per-event mode. One
        // batched anchor read up front; an event is suppressed when EVERY
        // entity it carries is inside the window (an event with at least one
        // non-cooled entity still alerts, mirroring the grouped path's
        // any-entity-passes semantics). Entities that alert within THIS batch
        // join the suppression set, so two events for the same entity in one
        // window produce one alert.
        let cooldown_minutes = rule.alert_cooldown_minutes.unwrap_or(0);
        let cooled: std::collections::HashSet<String> = if cooldown_minutes > 0 {
            let (_, groups) = self.partition_entity_groups(rule, results, global_weight);
            let entities: Vec<String> = groups
                .into_iter()
                .map(|(entity, _, _)| entity)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            self.entities_in_alert_cooldown(rule.id, cooldown_minutes, &entities)
                .await?
        } else {
            std::collections::HashSet::new()
        };
        let mut fired_entities: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut cooldown_suppressed = 0usize;

        for event in results.iter().take(alert_cap) {
            // NAN-1805: cooldown gate before any per-event writes.
            let event_entities: Vec<String> = if cooldown_minutes > 0 {
                let (_, ev_groups) =
                    self.partition_entity_groups(rule, std::slice::from_ref(event), global_weight);
                ev_groups.into_iter().map(|(entity, _, _)| entity).collect()
            } else {
                Vec::new()
            };
            if cooldown_minutes > 0
                && !event_entities.is_empty()
                && event_entities
                    .iter()
                    .all(|e| cooled.contains(e) || fired_entities.contains(e))
            {
                cooldown_suppressed += 1;
                continue;
            }

            // Store each event as its own detection match (1:1 with alerts)
            self.store_detection_match(rule, std::slice::from_ref(event))
                .await?;
            let matched_events = serde_json::json!([event]);
            let new_alert = NewAlert {
                rule_id: rule.id,
                severity: rule.severity,
                matched_events,
                event_hash: None, // Hash computed from single event -- dedup works per-event
                // A13 (NAN-1752): per-event mode is exactly one event per alert.
                match_count: Some(1),
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
            fired_entities.extend(event_entities);

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

        // NAN-1805: anchor the cooldown for every entity that alerted in this
        // batch (single durable upsert; best-effort).
        if cooldown_minutes > 0 && !fired_entities.is_empty() {
            let entities: Vec<String> = fired_entities.into_iter().collect();
            self.record_alert_cooldown_anchors(rule.id, &entities).await;
        }
        if cooldown_suppressed > 0 {
            debug!(
                "Rule {} (ALERTING/per_event): {} events suppressed by the {}m alert cooldown",
                rule.name, cooldown_suppressed, cooldown_minutes
            );
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

    /// Get an alert by ID.
    ///
    /// NAN-1800: `deny` is the effective viewer per-source deny set (see the
    /// handler-side scope composition). System callers pass
    /// `ScopeSet::unrestricted().deny_set()` — greppable opt-out.
    #[instrument(skip(self, deny))]
    pub async fn get_alert(
        &self,
        id: Uuid,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Alert, DetectionError> {
        let alert = self.alert_repo.find_by_id(id, deny).await?;
        Ok(alert)
    }

    /// List alerts with optional filters (deny-scoped per NAN-1800)
    #[instrument(skip(self, deny))]
    pub async fn list_alerts(
        &self,
        status: Option<AlertStatus>,
        severity: Option<Severity>,
        kinds: Option<&[String]>,
        limit: i64,
        offset: i64,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self
            .alert_repo
            .list(status, severity, kinds, limit, offset, deny)
            .await?;
        Ok(alerts)
    }

    /// List alerts for a specific rule (limited to 100 most recent)
    #[instrument(skip(self, deny))]
    pub async fn list_alerts_by_rule(
        &self,
        rule_id: Uuid,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self.alert_repo.list_by_rule(rule_id, deny).await?;
        Ok(alerts)
    }

    /// List alerts for a specific rule with custom limit
    #[instrument(skip(self, deny))]
    pub async fn list_alerts_by_rule_limited(
        &self,
        rule_id: Uuid,
        limit: i64,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self
            .alert_repo
            .list_by_rule_limited(rule_id, limit, deny)
            .await?;
        Ok(alerts)
    }

    /// List alerts after a specific cursor (timestamp + ID)
    #[instrument(skip(self, deny))]
    pub async fn list_alerts_after(
        &self,
        after_timestamp: chrono::DateTime<chrono::Utc>,
        after_id: Uuid,
        limit: i64,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<Alert>, DetectionError> {
        let alerts = self
            .alert_repo
            .list_after(after_timestamp, after_id, limit, deny)
            .await?;
        Ok(alerts)
    }

    /// Acknowledge an alert
    #[instrument(skip(self, deny))]
    pub async fn acknowledge_alert(
        &self,
        id: Uuid,
        acknowledged_by: &str,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Alert, DetectionError> {
        info!("Acknowledging alert {} by {}", id, acknowledged_by);
        let ack = AcknowledgeAlert {
            acknowledged_by: acknowledged_by.to_string(),
        };
        let alert = self.alert_repo.acknowledge(id, &ack, deny).await?;
        Ok(alert)
    }

    /// Close an alert with disposition
    #[instrument(skip(self, deny))]
    pub async fn close_alert(
        &self,
        id: Uuid,
        closed_by: &str,
        disposition: Disposition,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Alert, DetectionError> {
        info!(
            "Closing alert {} by {} with disposition {:?}",
            id, closed_by, disposition
        );
        let close = CloseAlert {
            closed_by: closed_by.to_string(),
            disposition,
        };
        let alert = self.alert_repo.close(id, &close, deny).await?;
        Ok(alert)
    }

    /// Assign an alert to an analyst
    #[instrument(skip(self, deny))]
    pub async fn assign_alert(
        &self,
        id: Uuid,
        assignee: &str,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Alert, DetectionError> {
        info!("Assigning alert {} to {}", id, assignee);
        let alert = self.alert_repo.assign(id, assignee, deny).await?;
        Ok(alert)
    }

    /// Bulk acknowledge alerts
    #[instrument(skip(self, ids, deny))]
    pub async fn bulk_acknowledge_alerts(
        &self,
        ids: &[Uuid],
        acknowledged_by: &str,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<usize, DetectionError> {
        info!(
            "Bulk acknowledging {} alerts by {}",
            ids.len(),
            acknowledged_by
        );
        let count = self
            .alert_repo
            .bulk_acknowledge(ids, acknowledged_by, deny)
            .await?;
        Ok(count)
    }

    /// Bulk close alerts
    #[instrument(skip(self, ids, deny))]
    pub async fn bulk_close_alerts(
        &self,
        ids: &[Uuid],
        closed_by: &str,
        disposition: Disposition,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<usize, DetectionError> {
        info!(
            "Bulk closing {} alerts by {} with disposition {:?}",
            ids.len(),
            closed_by,
            disposition
        );
        let count = self
            .alert_repo
            .bulk_close(ids, disposition, closed_by, deny)
            .await?;
        Ok(count)
    }

    /// Get alert counts by status
    #[instrument(skip(self, deny))]
    pub async fn get_alert_counts(
        &self,
        kinds: Option<&[String]>,
        deny: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<(AlertStatus, i64)>, DetectionError> {
        let counts = self.alert_repo.count_by_status(kinds, deny).await?;
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
