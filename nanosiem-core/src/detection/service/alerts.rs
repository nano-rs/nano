// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert Management
//!
//! Alert CRUD operations, grouped/per-event alert handling,
//! signal logging, case grouping, and webhook notifications.

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

use crate::db::repository::alerts::AlertRepositoryError;
use crate::db::repository::DailyStat;
use crate::extensions::AlertCasePermissions;
use crate::models::{
    AcknowledgeAlert, Alert, AlertStatus, CloseAlert, DetectionRule, Disposition, NewAlert,
    Severity,
};

use super::helpers::MatchedEventKind;
use super::DetectionError;
use super::DetectionService;

/// Maximum number of independent per-event alert writes in flight at once.
///
/// Each alert writes its review row, durable alert, finding outbox entry, and
/// optional case/webhook side effects. Serial execution made a 100-event drain
/// batch take several minutes; unbounded fanout can exhaust the PostgreSQL pool
/// and downstream hooks. Eight keeps pressure bounded while allowing the
/// independent writes to overlap. Cooldown rules retain their ordered path
/// below because same-batch entity suppression is stateful.
const PER_EVENT_FANOUT_CONCURRENCY: usize = 8;

const ALERT_POST_CREATE_CONTEXT_VERSION: u32 = 1;

/// Immutable inputs for the durable work that follows creation of a per-event
/// alert. The dispatcher must never rebuild finding, case, or webhook content
/// from the current rule: users can edit or delete a rule while this row is
/// waiting, and the deterministic finding ID deliberately rejects changed
/// content for an existing alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertPostCreateContext {
    schema_version: u32,
    rule: DetectionRule,
    case_permissions: Option<AlertCasePermissions>,
    global_risk_weight: f64,
}

impl AlertPostCreateContext {
    fn new(
        rule: &DetectionRule,
        case_permissions: Option<AlertCasePermissions>,
        global_risk_weight: f64,
    ) -> Self {
        Self {
            schema_version: ALERT_POST_CREATE_CONTEXT_VERSION,
            rule: rule.clone(),
            case_permissions,
            global_risk_weight,
        }
    }

    fn validate_for_alert(&self, alert: &Alert) -> Result<(), DetectionError> {
        if self.schema_version != ALERT_POST_CREATE_CONTEXT_VERSION {
            return Err(DetectionError::QueryExecutionError(format!(
                "unsupported alert post-create context version {} for alert {}",
                self.schema_version, alert.id
            )));
        }
        if alert.rule_id.is_some_and(|rule_id| rule_id != self.rule.id) {
            return Err(DetectionError::QueryExecutionError(format!(
                "alert post-create context rule {} does not match alert {} rule {:?}",
                self.rule.id, alert.id, alert.rule_id
            )));
        }
        Ok(())
    }
}

fn enforce_per_event_window_envelope(
    result_count: usize,
    alert_cap: usize,
) -> Result<(), DetectionError> {
    if alert_cap == 0 || result_count > alert_cap {
        return Err(DetectionError::QueryExecutionError(format!(
            "per-event detection window produced {result_count} alerts above its {alert_cap}-alert storm envelope; the window remains pending for durable fanout"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PerEventBatchPlan {
    pub batch_len: usize,
    pub remaining: usize,
}

pub(super) fn plan_per_event_batch(
    result_count: usize,
    alert_cap: usize,
) -> Result<PerEventBatchPlan, DetectionError> {
    if alert_cap == 0 {
        return Err(DetectionError::QueryExecutionError(
            "per-event detection alert batch size must be greater than zero".to_string(),
        ));
    }
    let batch_len = result_count.min(alert_cap);
    Ok(PerEventBatchPlan {
        batch_len,
        remaining: result_count.saturating_sub(batch_len),
    })
}

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
        // Shared with the hosted-shared publish path (NAN-2713): one
        // implementation, so both engines partition identically.
        crate::detection::entity_risk::partition_entity_groups(
            &self.score_calculator,
            self.active_profile.as_ref(),
            rule,
            results,
            global_weight,
        )
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
        // NAN-2713: single implementation shared with the hosted-shared
        // publish path (incl. the NAN-1805 dataset=risk zeroing).
        crate::detection::entity_risk::risk_result_for_group(
            &self.score_calculator,
            rule,
            has_query_scores,
            entity,
            field,
            events,
            global_weight,
        )
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
    ) -> Result<(), DetectionError> {
        let Some(ref logger) = self.finding_logger else {
            return Ok(());
        };

        // R1: honor the `| risk` command's per-event score/entity here too — the
        // per-event alert path must score identically to Live/grouped, not revert
        // to the rule-level score/entity.
        let (has_query_scores, groups) = self.partition_entity_groups(rule, events, global_weight);
        let mut failures = Vec::new();
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

            let realtime =
                rule.detection_mode == crate::models::detection_rule::DetectionMode::RealTime;
            if let Err(e) = logger.log_alert(rule, alert, realtime, risk_result).await {
                error!("Failed to log alert signal for entity {}: {}", entity, e);
                failures.push(format!("{entity}: {e}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(DetectionError::QueryExecutionError(format!(
                "failed to publish {} alert finding(s): {}",
                failures.len(),
                failures.join("; ")
            )))
        }
    }

    /// Group alert into a case and fire webhooks
    pub(super) async fn process_alert_post_create(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        case_permissions: Option<AlertCasePermissions>,
    ) {
        if let Err(error) = self
            .process_alert_post_create_with_mode(rule, alert, case_permissions, false)
            .await
        {
            error!(
                alert_id = %alert.id,
                %error,
                "Alert post-create side effect failed"
            );
        }
    }

    async fn process_alert_post_create_durable(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        case_permissions: Option<AlertCasePermissions>,
    ) -> Result<(), DetectionError> {
        self.process_alert_post_create_with_mode(rule, alert, case_permissions, true)
            .await
    }

    async fn process_alert_post_create_with_mode(
        &self,
        rule: &DetectionRule,
        alert: &Alert,
        case_permissions: Option<AlertCasePermissions>,
        durable: bool,
    ) -> Result<(), DetectionError> {
        // Auto-group alert into a case via the CaseGroupingHook extension.
        // Open-core builds use a no-op hook that returns Ok(None) and skips
        // case grouping (and downstream shadow investigation) entirely.
        let grouping = if alert.case_id.is_some() {
            debug!(
                alert_id = %alert.id,
                case_id = ?alert.case_id,
                "Alert is already grouped; skipping idempotent outbox replay"
            );
            None
        } else {
            Some(
                self.case_grouping
                    .group_alert(alert, Some(rule.name.as_str()), case_permissions)
                    .await,
            )
        };
        match grouping {
            None => {}
            Some(Ok(Some(grouped))) => {
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
            Some(Ok(None)) => {
                debug!(
                    alert_id = %alert.id,
                    "Case grouping disabled (open-core build or hook returned None)"
                );
            }
            Some(Err(e)) => {
                error!(
                    alert_id = %alert.id,
                    error = %e,
                    "Failed to group alert into case"
                );
                if durable {
                    return Err(DetectionError::QueryExecutionError(format!(
                        "failed to group alert {} into a case: {e}",
                        alert.id
                    )));
                }
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
            if durable {
                webhook_service
                    .fire_alert_durable(
                        alert.id,
                        &alert.kind,
                        Some(rule.id),
                        &rule.name,
                        &severity_str,
                        entity,
                        &alert.matched_events,
                        alert.created_at,
                    )
                    .await
                    .map_err(|error| {
                        DetectionError::QueryExecutionError(format!(
                            "durable webhook delivery failed for alert {}: {error}",
                            alert.id
                        ))
                    })?;
            } else {
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
        Ok(())
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
            let alert = match self
                .alert_repo
                .find_by_id(alert_id, system_scope.deny_set())
                .await
            {
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
        let mut new_findings = self.retain_unemitted(rule.id, candidates).await?;

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
                .log_alert_at(
                    rule,
                    alert,
                    rule.detection_mode == crate::models::detection_rule::DetectionMode::RealTime,
                    risk_result,
                    Some(nf.window_end),
                )
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
        let new_findings = self.retain_unemitted_bake_in(rule.id, candidates).await;
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
                .log_detection_match_at(
                    rule,
                    &nf.events,
                    rule.detection_mode == crate::models::detection_rule::DetectionMode::RealTime,
                    risk_result,
                    Some(nf.window_end),
                )
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
    async fn emit_one_per_event_alert(
        &self,
        rule: &DetectionRule,
        event: &serde_json::Value,
        global_weight: f64,
        case_permissions: Option<AlertCasePermissions>,
    ) -> Result<Option<Alert>, DetectionError> {
        // Store each event as its own detection match (1:1 with alerts).
        self.store_detection_match(rule, std::slice::from_ref(event))
            .await?;
        let new_alert = NewAlert {
            rule_id: rule.id,
            severity: rule.severity,
            matched_events: serde_json::json!([event]),
            event_hash: None, // Hash computed from single event -- dedup works per-event
            // A13 (NAN-1752): per-event mode is exactly one event per alert.
            match_count: Some(1),
        };

        // Call repo directly to catch DuplicateAlert before conversion to
        // DetectionError. A duplicate is a completed event: its durable alert
        // already exists, so the caller may safely checkpoint it.
        let (alert, created) = match self.alert_repo.create(&new_alert).await {
            Ok(alert) => (alert, true),
            Err(AlertRepositoryError::DuplicateAlert(rule_id, hash)) => {
                debug!(
                    "Skipped duplicate per-event alert for rule {} with hash {}",
                    rule_id, hash
                );
                let alert = sqlx::query_as::<_, Alert>(
                    "SELECT * FROM alerts WHERE rule_id = $1 AND event_hash = $2",
                )
                .bind(rule_id)
                .bind(&hash)
                .fetch_one(&self.pg_pool)
                .await?;
                (alert, false)
            }
            Err(e) => return Err(DetectionError::from(e)),
        };

        if self.primary_lake_detection_backend() {
            // Finding publication, case grouping, and webhook fanout are
            // durable side effects, but they are not allowed to hold a lake
            // rule window open. An idempotent outbox row makes a crash after
            // alert creation safe: a retry finds the duplicate alert and
            // re-enqueues the same alert id.
            self.enqueue_alert_post_create(alert.id, rule, case_permissions.clone(), global_weight)
                .await?;
        } else if created {
            // Preserve the legacy ClickHouse execution contract. Its jobs
            // profile does not start the lake outbox dispatcher.
            if let Err(error) = self
                .log_alert_signals(rule, &alert, std::slice::from_ref(event), global_weight)
                .await
            {
                error!(alert_id = %alert.id, %error, "Failed to log legacy alert signals");
            }
            self.process_alert_post_create(rule, &alert, case_permissions)
                .await;
        }

        Ok(created.then_some(alert))
    }

    async fn enqueue_alert_post_create(
        &self,
        alert_id: Uuid,
        rule: &DetectionRule,
        case_permissions: Option<AlertCasePermissions>,
        global_risk_weight: f64,
    ) -> Result<(), DetectionError> {
        let context = AlertPostCreateContext::new(rule, case_permissions, global_risk_weight);
        sqlx::query(
            concat!(r#"
            INSERT INTO alert_post_create_outbox (alert_id, context)
            VALUES ($1, $2)
            ON CONFLICT ("#, crate::tenant_key!(), r#"alert_id) DO NOTHING
            "#),
        )
        .bind(alert_id)
        .bind(sqlx::types::Json(context))
        .execute(&self.pg_pool)
        .await?;
        Ok(())
    }

    /// Claim and execute a bounded batch of alert side effects. The claim is
    /// fenced by node id and stale processing rows are recoverable after five
    /// minutes. This lane is deliberately independent of rule execution.
    pub async fn drain_alert_post_create_outbox(
        &self,
        node_id: &str,
        limit: usize,
        max_concurrent: usize,
    ) -> Result<usize, DetectionError> {
        let alert_ids = sqlx::query_scalar::<_, Uuid>(
            r#"
            WITH candidates AS (
                SELECT alert_id
                FROM alert_post_create_outbox
                WHERE attempts < 10
                  AND available_at <= NOW()
                  AND (
                    status = 'pending'
                    OR (status = 'processing' AND claimed_at < NOW() - INTERVAL '5 minutes')
                  )
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE alert_post_create_outbox AS outbox
            SET status = 'processing',
                attempts = outbox.attempts + 1,
                claimed_by = $2,
                claimed_at = NOW(),
                last_error = NULL
            FROM candidates
            WHERE outbox.alert_id = candidates.alert_id
            RETURNING outbox.alert_id
            "#,
        )
        .bind(i64::try_from(limit.clamp(1, 100)).unwrap_or(100))
        .bind(node_id)
        .fetch_all(&self.pg_pool)
        .await?;
        let claimed = alert_ids.len();

        stream::iter(alert_ids)
            .for_each_concurrent(max_concurrent.clamp(1, 100), |alert_id| {
                let service = self.clone();
                let node_id = node_id.to_string();
                async move {
                    if let Err(error) = service
                        .process_alert_post_create_outbox_item(alert_id)
                        .await
                    {
                        error!(%alert_id, %error, "Alert post-create outbox item failed");
                        if let Err(release_error) = service
                            .release_alert_post_create_outbox(alert_id, &node_id, &error.to_string())
                            .await
                        {
                            error!(%alert_id, %release_error, "Failed to release alert post-create outbox item");
                        }
                    } else if let Err(error) = service
                        .complete_alert_post_create_outbox(alert_id, &node_id)
                        .await
                    {
                        error!(%alert_id, %error, "Failed to complete alert post-create outbox item");
                    }
                }
            })
            .await;

        Ok(claimed)
    }

    /// Graceful-shutdown cleanup for this dispatcher's fenced claims. A hard
    /// crash still relies on the five-minute stale-claim recovery; a normal
    /// pod drain makes the work immediately available to another replica.
    pub async fn release_alert_post_create_claims(
        &self,
        node_id: &str,
    ) -> Result<u64, DetectionError> {
        let released = sqlx::query(
            r#"
            UPDATE alert_post_create_outbox
            SET status = 'pending',
                available_at = NOW(),
                claimed_by = NULL,
                claimed_at = NULL,
                last_error = 'dispatcher stopped before completion'
            WHERE status = 'processing' AND claimed_by = $1
            "#,
        )
        .bind(node_id)
        .execute(&self.pg_pool)
        .await?
        .rows_affected();
        Ok(released)
    }

    async fn process_alert_post_create_outbox_item(
        &self,
        alert_id: Uuid,
    ) -> Result<(), DetectionError> {
        let alert = sqlx::query_as::<_, Alert>("SELECT * FROM alerts WHERE id = $1")
            .bind(alert_id)
            .fetch_one(&self.pg_pool)
            .await?;
        let context = sqlx::query_scalar::<_, Option<sqlx::types::Json<AlertPostCreateContext>>>(
            "SELECT context FROM alert_post_create_outbox WHERE alert_id = $1",
        )
        .bind(alert_id)
        .fetch_one(&self.pg_pool)
        .await?;
        let (rule, permissions, global_weight) = if let Some(sqlx::types::Json(context)) = context {
            context.validate_for_alert(&alert)?;
            (
                context.rule,
                context.case_permissions,
                context.global_risk_weight,
            )
        } else {
            // Upgrade compatibility for rows queued before migration 306. New
            // rows always carry immutable context; a legacy row can only fall
            // back to the still-existing current rule.
            let rule_id = alert.rule_id.ok_or_else(|| {
                DetectionError::QueryExecutionError(format!(
                    "legacy detection alert {alert_id} has no rule id or immutable post-create context"
                ))
            })?;
            let rule = self.rule_repo.find_by_id(rule_id).await?;
            let permissions = self.get_case_permissions(&rule).await;
            let global_weight = self.load_risk_weight().await;
            (rule, permissions, global_weight)
        };
        let events = alert.matched_events.as_array().cloned().unwrap_or_default();
        self.log_alert_signals(&rule, &alert, &events, global_weight)
            .await?;
        self.process_alert_post_create_durable(&rule, &alert, permissions)
            .await
    }

    async fn complete_alert_post_create_outbox(
        &self,
        alert_id: Uuid,
        node_id: &str,
    ) -> Result<(), DetectionError> {
        sqlx::query(
            r#"
            UPDATE alert_post_create_outbox
            SET status = 'completed', completed_at = NOW(), claimed_by = NULL, claimed_at = NULL
            WHERE alert_id = $1 AND status = 'processing' AND claimed_by = $2
            "#,
        )
        .bind(alert_id)
        .bind(node_id)
        .execute(&self.pg_pool)
        .await?;
        Ok(())
    }

    async fn release_alert_post_create_outbox(
        &self,
        alert_id: Uuid,
        node_id: &str,
        last_error: &str,
    ) -> Result<(), DetectionError> {
        sqlx::query(
            r#"
            UPDATE alert_post_create_outbox
            SET status = CASE WHEN attempts >= 10 THEN 'failed' ELSE 'pending' END,
                available_at = NOW() + INTERVAL '5 seconds',
                claimed_by = NULL,
                claimed_at = NULL,
                last_error = LEFT($3, 2000)
            WHERE alert_id = $1 AND status = 'processing' AND claimed_by = $2
            "#,
        )
        .bind(alert_id)
        .bind(node_id)
        .bind(last_error)
        .execute(&self.pg_pool)
        .await?;
        Ok(())
    }

    /// Owned wrapper for the bounded fanout stream. Keeping every input inside
    /// the future avoids borrowing a scheduler-owned rule/result slice across
    /// `.await`, which in turn keeps the scheduler task `Send` for
    /// `tokio::spawn`.
    async fn emit_one_per_event_alert_owned(
        self,
        rule: DetectionRule,
        event: serde_json::Value,
        global_weight: f64,
        case_permissions: Option<AlertCasePermissions>,
    ) -> (serde_json::Value, Result<Option<Alert>, DetectionError>) {
        let result = self
            .emit_one_per_event_alert(&rule, &event, global_weight, case_permissions)
            .await;
        (event, result)
    }

    pub(super) async fn handle_per_event_alerts(
        &self,
        rule: &DetectionRule,
        results: &[serde_json::Value],
        match_count: i64,
        today: chrono::NaiveDate,
        global_weight: f64,
        matched_kind: MatchedEventKind,
    ) -> Result<Option<Alert>, DetectionError> {
        let case_permissions = self.get_case_permissions(rule).await;
        let mut first_alert: Option<Alert> = None;
        let mut alerts_created: i64 = 0;

        // `execute_rule` feeds this method exactly one bounded drain batch. Keep
        // the envelope assertion here as a defense in depth for alternate call
        // sites such as retro replay; an oversized direct call must fail before
        // its first write, never silently drop a tail.
        let alert_cap = self.config.max_events_per_alert;
        enforce_per_event_window_envelope(results.len(), alert_cap)?;

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
        let mut fired_entities: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut cooldown_suppressed = 0usize;

        // Cooldown is intentionally ordered: an alert for an entity earlier in
        // this batch suppresses later events for the same entity. Keep that
        // stateful path serial and checkpoint every completed event. The common
        // no-cooldown path below is independent and uses bounded concurrency.
        if cooldown_minutes > 0 {
            for event in results {
                // NAN-1805: cooldown gate before any per-event writes.
                let (_, ev_groups) =
                    self.partition_entity_groups(rule, std::slice::from_ref(event), global_weight);
                let event_entities: Vec<String> =
                    ev_groups.into_iter().map(|(entity, _, _)| entity).collect();
                if crate::detection::entity_risk::event_suppressed_by_cooldown(
                    &event_entities,
                    &cooled,
                    &fired_entities,
                ) {
                    cooldown_suppressed += 1;
                    self.record_matched_events(rule.id, matched_kind, std::slice::from_ref(event))
                        .await?;
                    continue;
                }

                let alert = self
                    .emit_one_per_event_alert(rule, event, global_weight, case_permissions.clone())
                    .await?;
                self.record_matched_events(rule.id, matched_kind, std::slice::from_ref(event))
                    .await?;

                if let Some(alert) = alert {
                    alerts_created += 1;
                    fired_entities.extend(event_entities);
                    if first_alert.is_none() {
                        first_alert = Some(alert);
                    }
                }
            }
            // NAN-1805: anchor every entity that alerted in this batch.
            if !fired_entities.is_empty() {
                let entities: Vec<String> = fired_entities.into_iter().collect();
                self.record_alert_cooldown_anchors(rule.id, &entities).await;
            }
            if cooldown_suppressed > 0 {
                debug!(
                    "Rule {} (ALERTING/per_event): {} events suppressed by the {}m alert cooldown",
                    rule.name, cooldown_suppressed, cooldown_minutes
                );
            }
        } else {
            for wave in results.chunks(PER_EVENT_FANOUT_CONCURRENCY) {
                // Materialize owned work before awaiting the stream. Retaining
                // the slice iterator here would make the spawned scheduler
                // future borrow `results` across the fanout await.
                let work: Vec<_> = wave
                    .iter()
                    .enumerate()
                    .map(|(index, event)| {
                        (
                            index,
                            self.clone(),
                            rule.clone(),
                            event.clone(),
                            case_permissions.clone(),
                        )
                    })
                    .collect();
                let mut outcomes = stream::iter(work.into_iter().map(
                    |(index, service, rule, event, case_permissions)| async move {
                        let (event, result) = service
                            .emit_one_per_event_alert_owned(
                                rule,
                                event,
                                global_weight,
                                case_permissions,
                            )
                            .await;
                        (index, event, result)
                    },
                ))
                .buffer_unordered(PER_EVENT_FANOUT_CONCURRENCY)
                .collect::<Vec<_>>()
                .await;
                outcomes.sort_by_key(|(index, _, _)| *index);

                // Checkpoint all successful (including duplicate) events before
                // surfacing a sibling failure. A retry then resumes after this
                // wave instead of replaying every alert already committed.
                let completed: Vec<serde_json::Value> = outcomes
                    .iter()
                    .filter_map(|(_, event, result)| result.as_ref().ok().map(|_| event.clone()))
                    .collect();
                self.record_matched_events(rule.id, matched_kind, &completed)
                    .await?;

                let mut first_error = None;
                for (_, _, outcome) in outcomes {
                    match outcome {
                        Ok(Some(alert)) => {
                            alerts_created += 1;
                            if first_alert.is_none() {
                                first_alert = Some(alert);
                            }
                        }
                        Ok(None) => {}
                        Err(error) if first_error.is_none() => first_error = Some(error),
                        Err(_) => {}
                    }
                }
                if let Some(error) = first_error {
                    return Err(error);
                }
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

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use crate::extensions::AlertCasePermissions;
    use crate::models::detection_rule::{AlertMode, DetectionMode};
    use crate::models::{Alert, AlertStatus, DetectionRule, RuleMode, Severity};

    use super::{enforce_per_event_window_envelope, plan_per_event_batch, AlertPostCreateContext};

    fn sample_rule() -> DetectionRule {
        DetectionRule {
            id: Uuid::now_v7(),
            name: "Original rule".to_string(),
            description: None,
            query: "metadata.log_source=windows_sysmon".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            detection_mode: DetectionMode::Scheduled,
            materialized_view_name: None,
            near_real_time_interval_seconds: None,
            execution_mode: None,
            risk_score: Some(72),
            risk_entity_field: Some("device.hostname".to_string()),
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            archived: false,
            folder: None,
            ai_triage_hints: sqlx::types::Json(Default::default()),
            lookback_minutes: None,
            dataset: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            case_visibility: "group".to_string(),
            case_assigned_group: Some(Uuid::now_v7()),
            alert_mode: AlertMode::PerEvent,
            next_run_at: None,
            claimed_by: None,
            claimed_at: None,
            playbook_selector_mode: "none".to_string(),
            playbook_id: None,
            source_path: None,
            source_repo_url: None,
            kind: "standard".to_string(),
            alert_cooldown_minutes: None,
        }
    }

    fn sample_alert(rule_id: Option<Uuid>) -> Alert {
        Alert {
            id: Uuid::now_v7(),
            rule_id,
            rule_name: Some("Original rule".to_string()),
            severity: Severity::High,
            status: AlertStatus::New,
            disposition: None,
            matched_events: serde_json::json!([]),
            matched_event_count: Some(1),
            event_hash: None,
            assigned_to: None,
            acknowledged_by: None,
            acknowledged_at: None,
            closed_by: None,
            closed_at: None,
            created_at: Utc::now(),
            triage_verdict: None,
            triage_confidence: None,
            triage_verdict_details: None,
            case_id: None,
            kind: "detection".to_string(),
            source_id: None,
            source_types: vec![],
        }
    }

    #[test]
    fn per_event_storm_guard_never_allows_a_partial_success() {
        assert!(enforce_per_event_window_envelope(100, 100).is_ok());
        assert!(enforce_per_event_window_envelope(101, 100).is_err());
        assert!(enforce_per_event_window_envelope(0, 0).is_err());
    }

    #[test]
    fn per_event_batch_plan_drains_without_dropping_the_tail() {
        let exact = plan_per_event_batch(100, 100).unwrap();
        assert_eq!(exact.batch_len, 100);
        assert_eq!(exact.remaining, 0);

        let overflow = plan_per_event_batch(251, 100).unwrap();
        assert_eq!(overflow.batch_len, 100);
        assert_eq!(overflow.remaining, 151);
        assert!(plan_per_event_batch(1, 0).is_err());
    }

    #[test]
    fn alert_post_create_context_survives_rule_edits_and_deletion() {
        let mut live_rule = sample_rule();
        let rule_id = live_rule.id;
        let permissions = AlertCasePermissions {
            visibility: "group".to_string(),
            group_ids: Some(vec![Uuid::now_v7()]),
            assigned_group: live_rule.case_assigned_group,
            playbook_selector_mode: "none".to_string(),
            playbook_id: None,
        };
        let frozen = AlertPostCreateContext::new(&live_rule, Some(permissions), 0.65);

        live_rule.name = "Renamed after alert".to_string();
        live_rule.query = "severity=Critical".to_string();
        live_rule.risk_score = Some(5);

        let frozen: AlertPostCreateContext =
            serde_json::from_value(serde_json::to_value(frozen).unwrap()).unwrap();
        assert_eq!(frozen.rule.name, "Original rule");
        assert_eq!(frozen.rule.risk_score, Some(72));
        assert_eq!(frozen.global_risk_weight, 0.65);
        assert!(frozen
            .validate_for_alert(&sample_alert(Some(rule_id)))
            .is_ok());
        // ON DELETE SET NULL must not strand already-queued side effects.
        assert!(frozen.validate_for_alert(&sample_alert(None)).is_ok());
        assert!(frozen
            .validate_for_alert(&sample_alert(Some(Uuid::now_v7())))
            .is_err());
    }
}
