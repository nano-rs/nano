// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto retro-hunt rule execution + management (NAN-1791).
//!
//! A retro-hunt rule (`DetectionRule.kind == "retro_hunt"`) is a first-class
//! scheduled detection. On each run it:
//!
//! 1. Pulls the DELTA of newly-landed feed indicators from
//!    `custom_enrichment_results` above the rule's watermark, minus the values it
//!    has already hunted (the per-rule hunted-indicator set).
//! 2. Caps the batch at `max_indicators_per_run`; the overflow is carried to the
//!    next run (the watermark only advances over the timestamp range this run
//!    fully covered, and the hunted-set anti-join drains the rest — no silent
//!    caps: truncation is recorded in the run-history row).
//! 3. Runs the retro engine over the delta as ONE batched list rollup, over the
//!    configured lookback window.
//! 4. Synthesizes a detection-match event per HIT and emits it through the SAME
//!    signal-processor path standard rules use — so alert creation, per-entity
//!    finding dedup (keyed on indicator + last-seen), case grouping, risk
//!    attribution, and webhooks all apply for free.
//!
//! Re-run safety is triple-layered: (a) the hunted-set anti-join never re-hunts
//! a value; (b) `filter_already_matched_events` drops any synthesized event whose
//! stable id was already recorded; (c) `finding_dedup_identity` collapses a
//! re-emitted (indicator, last-seen) finding. Any one of these alone prevents a
//! double-alert; the test suite exercises the combination.
//!
//! ## Concurrency
//!
//! The distributed scheduler serializes scheduled executions per rule (SKIP
//! LOCKED claim), but `POST /api/rules/{id}/trigger` calls `execute_rule`
//! WITHOUT a claim — so a manual trigger can overlap a scheduled run. That
//! overlap is safe, not merely unlikely: both runs read the same watermark and
//! hunt the same delta, and every write they make is idempotent — the watermark
//! upsert writes the same value, `record_hunted` is `ON CONFLICT DO NOTHING`,
//! the grouped alert insert collides on its unique `(rule_id, event_hash)` index
//! (handled as already-alerted), and finding emissions collide on
//! `(rule_id, finding_hash)`. The only cost of an overlap is a duplicated
//! ClickHouse scan, which the per-run cap already bounds. We deliberately do NOT
//! take the per-rule advisory lock here: it carries a 30s acquisition deadline
//! and pins a PostgreSQL connection, which fits a fast MV swap but not a
//! multi-minute historical scan.

use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::db::repository::retro_hunt::RetroHuntRepository;
use crate::models::retro_hunt::{
    CreateRetroHuntRequest, RetroHuntConfig, RetroHuntRuleView, RetroHuntRun,
    UpdateRetroHuntConfigRequest, DEFAULT_RETRO_HUNT_CRON, DEFAULT_RETRO_HUNT_LOOKBACK_DAYS,
    DEFAULT_RETRO_HUNT_MAX_INDICATORS,
};
use crate::models::{
    Alert, AlertMode, DetectionMode, DetectionRule, NewDetectionRule, RuleMode, Severity,
};
use crate::search::{RetroFeedCandidate, RetroHuntHit};

use super::helpers::{inject_detected_at, MatchedEventKind};
use super::DetectionError;
use super::DetectionService;

impl DetectionService {
    fn retro_hunt_repo(&self) -> RetroHuntRepository {
        RetroHuntRepository::new(self.pg_pool.clone())
    }

    // ========================================================================
    // Execution
    // ========================================================================

    /// Execute one run of an auto retro-hunt rule (NAN-1791).
    ///
    /// Called by [`DetectionService::execute_rule`] when `rule.is_retro_hunt()`.
    /// Staging → no-op; Paused → error (mirrors the standard path). Every run
    /// records a `retro_hunt_runs` history row, even on the empty-delta path.
    pub(super) async fn execute_retro_hunt_rule(
        &self,
        rule: &DetectionRule,
    ) -> Result<Option<Alert>, DetectionError> {
        if rule.mode == RuleMode::Paused {
            warn!("Attempted to execute paused retro-hunt rule: {}", rule.id);
            return Err(DetectionError::RulePaused(rule.id));
        }
        if rule.mode == RuleMode::Staging {
            debug!("Skipping execution of staging retro-hunt rule: {}", rule.name);
            return Ok(None);
        }

        let repo = self.retro_hunt_repo();
        let config = match repo
            .get_config(rule.id)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?
        {
            Some(c) => c,
            None => {
                warn!(
                    rule_id = %rule.id,
                    "Retro-hunt rule has no config row; skipping run"
                );
                return Ok(None);
            }
        };

        let state = repo
            .get_state(rule.id)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?;
        // The keyset cursor. Both halves must be present to be usable; a state row
        // with a timestamp but no value (impossible via this engine, but cheap to
        // guard) restarts from the beginning rather than skipping the tie group.
        let watermark_before = state.as_ref().and_then(|s| s.watermark);
        let cursor_before: Option<(i64, String)> = state.as_ref().and_then(|s| {
            match (s.watermark, s.watermark_value.as_ref()) {
                (Some(ts), Some(v)) => Some((ts.timestamp_millis(), v.clone())),
                _ => None,
            }
        });

        let run_id = repo
            .start_run(rule.id, watermark_before)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?;

        // Everything after the run row is opened runs through this inner result so
        // a failure still closes the run history row with status='error'.
        match self
            .run_retro_hunt(rule, &config, &repo, cursor_before)
            .await
        {
            Ok(outcome) => {
                if let Err(e) = repo
                    .finish_run(
                        run_id,
                        "ok",
                        outcome.candidates_considered as i32,
                        outcome.indicators_hunted as i32,
                        outcome.hits as i32,
                        outcome.truncated,
                        outcome.overflow_remaining as i32,
                        outcome.watermark_after,
                        None,
                    )
                    .await
                {
                    warn!(rule_id = %rule.id, "Failed to finalize retro-hunt run row: {}", e);
                }
                Ok(outcome.alert)
            }
            Err(e) => {
                if let Err(fe) = repo
                    .finish_run(
                        run_id, "error", 0, 0, 0, false, 0, watermark_before, Some(&e.to_string()),
                    )
                    .await
                {
                    warn!(rule_id = %rule.id, "Failed to finalize errored retro-hunt run row: {}", fe);
                }
                Err(e)
            }
        }
    }

    /// The delta computation + hunt + emission, isolated so the caller can wrap
    /// it in run-history bookkeeping.
    async fn run_retro_hunt(
        &self,
        rule: &DetectionRule,
        config: &RetroHuntConfig,
        repo: &RetroHuntRepository,
        cursor_before: Option<(i64, String)>,
    ) -> Result<RetroHuntOutcome, DetectionError> {
        let cap = config.max_indicators_per_run.max(1) as usize;

        // Fetch the cap+1 candidates strictly after the cursor, ordered by
        // (fetched_at, value); the +1 detects truncation without a second query.
        let candidates: Vec<RetroFeedCandidate> = self
            .search_service
            .retro_hunt_feed_candidates(
                &config.feeds,
                &config.artifact_types,
                cursor_before.as_ref().map(|(ms, v)| (*ms, v.as_str())),
                cap + 1,
            )
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))?;

        // The "covered" window this run advances past: the first `cap` candidates.
        // Advancing over the whole covered set — hunted or not — is what
        // guarantees forward progress even if every covered candidate turns out to
        // be already hunted (the cursor advance is independent of the anti-join).
        let covered: Vec<&RetroFeedCandidate> = candidates.iter().take(cap).collect();

        let keys: Vec<(i64, String)> = candidates
            .iter()
            .map(|c| (c.fetched_at_ms, c.value.clone()))
            .collect();
        let (truncated, cursor_after) = plan_cursor(&keys, cap, cursor_before);
        let watermark_after = cursor_after
            .as_ref()
            .and_then(|(ms, _)| chrono::DateTime::from_timestamp_millis(*ms));

        // Anti-join against the per-rule hunted set: only hunt values not yet
        // hunted. Preserves oldest-first order.
        let covered_values: Vec<String> = covered.iter().map(|c| c.value.clone()).collect();
        let already = repo
            .already_hunted(rule.id, &covered_values)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?;
        let to_hunt: Vec<&RetroFeedCandidate> = covered
            .iter()
            .copied()
            .filter(|c| !already.contains(&c.value))
            .collect();
        // The batched retro hunt. Batched PER ARTIFACT TYPE (at most 4 queries —
        // ip/domain/hash/url — not one per indicator): the retro engine's
        // `scope_observables` narrows the scanned columns to those an indicator
        // type can appear in (an IP collapses ~17 observable legs to 3), but a
        // MIXED-type batch has to fall back to the full observable set. Grouping
        // the delta by type keeps every query index-pruned.
        let mut by_type: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for c in &to_hunt {
            by_type
                .entry(c.key_type.clone())
                .or_default()
                .push(c.value.clone());
        }
        let mut hits: Vec<RetroHuntHit> = Vec::new();
        for (key_type, values) in &by_type {
            let group_hits = self
                .search_service
                .retro_hunt_over_indicators(values, config.lookback_days as i64)
                .await
                .map_err(|e| DetectionError::SearchError(e.to_string()))?;
            debug!(
                rule_id = %rule.id,
                key_type = %key_type,
                indicators = values.len(),
                hits = group_hits.len(),
                "Retro-hunt type batch complete"
            );
            hits.extend(group_hits);
        }

        // Emit the hits through the standard signal-processor path.
        let alert = if hits.is_empty() {
            None
        } else {
            let results = build_hit_events(rule.id, &hits, &to_hunt);
            self.emit_retro_matches(rule, results).await?
        };

        // Record the hunted values AFTER emission (a crash before here re-hunts
        // rather than silently skipping). Record ALL to_hunt — including
        // no-hit indicators — so a value with no logs isn't re-scanned every run.
        if !to_hunt.is_empty() {
            let pairs: Vec<(String, String)> = to_hunt
                .iter()
                .map(|c| (c.value.clone(), c.key_type.clone()))
                .collect();
            if let Err(e) = repo.record_hunted(rule.id, &pairs).await {
                warn!(rule_id = %rule.id, "Failed to record hunted indicators: {}", e);
            }
        }

        // Advance the keyset cursor + stamp last_run_at.
        if let Err(e) = repo
            .upsert_state(
                rule.id,
                watermark_after,
                cursor_after.as_ref().map(|(_, v)| v.as_str()),
                Utc::now(),
            )
            .await
        {
            warn!(rule_id = %rule.id, "Failed to persist retro-hunt cursor: {}", e);
        }

        // Honest overflow figure: candidates still remaining after the new cursor.
        // The cursor is strict, so this is exactly the not-yet-covered set (only
        // worth the extra query when we actually truncated).
        let overflow_remaining = if truncated {
            self.search_service
                .retro_hunt_candidate_count(
                    &config.feeds,
                    &config.artifact_types,
                    cursor_after.as_ref().map(|(ms, v)| (*ms, v.as_str())),
                )
                .await
                .unwrap_or(0)
        } else {
            0
        };

        if truncated {
            info!(
                rule_id = %rule.id,
                covered = covered.len(),
                hunted = to_hunt.len(),
                hits = hits.len(),
                overflow_remaining,
                "Retro-hunt run TRUNCATED at the per-run cap; overflow carried to next run"
            );
        }

        Ok(RetroHuntOutcome {
            candidates_considered: covered.len() as u64,
            indicators_hunted: to_hunt.len() as u64,
            hits: hits.len() as u64,
            truncated,
            overflow_remaining,
            watermark_after,
            alert,
        })
    }

    /// Emit synthesized retro-hit events through the standard alert/finding path.
    ///
    /// Deliberately mirrors the tail of [`DetectionService::execute_rule`] (dedup
    /// → mode branch) rather than restructuring it, so the shared alert helpers
    /// (`handle_grouped_alert`, `log_live_findings`, `store_detection_match`,
    /// matched-event dedup, finding-emission dedup) do all the heavy lifting and
    /// retro-hunt findings behave exactly like standard-rule findings.
    async fn emit_retro_matches(
        &self,
        rule: &DetectionRule,
        mut results: Vec<serde_json::Value>,
    ) -> Result<Option<Alert>, DetectionError> {
        let matched_kind = MatchedEventKind::for_mode(rule.mode);

        // Read-only dedup: drop synthesized events already recorded as matched
        // (re-run safety layer 2). Recording happens after durable emission.
        results = self
            .filter_already_matched_events(rule.id, matched_kind, &results)
            .await?;
        if results.is_empty() {
            debug!(rule_id = %rule.id, "All retro-hunt hits were already matched; nothing to emit");
            return Ok(None);
        }

        inject_detected_at(&mut results, Utc::now());
        let match_count = results.len() as i64;
        let today = Utc::now().date_naive();
        let global_weight = self.load_risk_weight().await;

        match rule.mode {
            RuleMode::Live => {
                self.rule_repo
                    .update_live_match_count(rule.id, match_count)
                    .await?;
                self.rule_repo
                    .record_daily_stats(rule.id, today, match_count, 0)
                    .await?;
                match rule.alert_mode {
                    AlertMode::PerEvent => {
                        for event in &results {
                            self.store_detection_match(rule, std::slice::from_ref(event))
                                .await?;
                        }
                    }
                    AlertMode::Grouped => {
                        self.store_detection_match(rule, &results).await?;
                    }
                }
                let emitted = self.log_live_findings(rule, &results, global_weight).await;
                self.record_matched_events(rule.id, matched_kind, &results)
                    .await?;
                info!(
                    "Retro-hunt rule {} (LIVE) found {} indicators in logs, emitted {} findings",
                    rule.name, match_count, emitted
                );
                Ok(None)
            }
            RuleMode::Alerting => {
                self.rule_repo
                    .update_execution_stats(rule.id, match_count)
                    .await?;
                let alert = match rule.alert_mode {
                    AlertMode::Grouped => {
                        self.handle_grouped_alert(rule, &results, match_count, today, global_weight)
                            .await?
                    }
                    AlertMode::PerEvent => {
                        self.handle_per_event_alerts(
                            rule,
                            &results,
                            match_count,
                            today,
                            global_weight,
                        )
                        .await?
                    }
                };
                self.record_matched_events(rule.id, matched_kind, &results)
                    .await?;
                Ok(alert)
            }
            // Staging/Paused are handled by the caller.
            RuleMode::Staging | RuleMode::Paused => Ok(None),
        }
    }

    // ========================================================================
    // Management (create / update config / views)
    // ========================================================================

    /// Create a retro-hunt rule: a `detection_rules` row (`kind = 'retro_hunt'`)
    /// plus its `retro_hunt_rule_config`, scheduled to run promptly.
    pub async fn create_retro_hunt_rule(
        &self,
        req: &CreateRetroHuntRequest,
    ) -> Result<(DetectionRule, RetroHuntConfig), DetectionError> {
        req.validate()
            .map_err(|e| DetectionError::InvalidQuery(e.to_string()))?;

        let cron = req
            .schedule_cron
            .clone()
            .unwrap_or_else(|| DEFAULT_RETRO_HUNT_CRON.to_string());
        self.validate_cron(&cron)?;

        let lookback_days = req.lookback_days.unwrap_or(DEFAULT_RETRO_HUNT_LOOKBACK_DAYS);
        let max_indicators = req
            .max_indicators_per_run
            .unwrap_or(DEFAULT_RETRO_HUNT_MAX_INDICATORS);

        // Human-readable, display-only query. The retro-hunt executor NEVER parses
        // rule.query (it builds its own delta query), so this is purely for the
        // rules list / editor. Kept short so it renders in the query cell.
        let feeds_label = if req.feeds.is_empty() {
            "all feeds".to_string()
        } else {
            req.feeds.join(", ")
        };
        let display_query = format!(
            "retro-hunt: new IOCs from {feeds_label} over last {lookback_days}d"
        );

        let new_rule = NewDetectionRule {
            name: req.name.clone(),
            description: req.description.clone(),
            query: display_query,
            severity: req.severity.unwrap_or(Severity::High),
            mitre_tactics: None,
            mitre_techniques: None,
            schedule_cron: Some(cron.clone()),
            // Default to Live (bake-in): a retro-hunt rule "consumes" indicators
            // as it hunts them, so promote to Alerting to alert on indicators that
            // land after promotion, or create directly in Alerting to alert on the
            // current backlog.
            mode: Some(req.mode.unwrap_or(RuleMode::Live)),
            narrative: None,
            reference_url: None,
            author: None,
            tags: req.tags.clone(),
            ai_generated: Some(false),
            realtime_enabled: Some(false),
            detection_mode: Some(DetectionMode::Scheduled),
            risk_score: req.risk_score,
            // Findings/alerts are attributed to the malicious indicator itself; the
            // synthesized event always carries an `indicator` field. Fixed here so
            // finding dedup keys on (rule, indicator, last-seen).
            risk_entity_field: Some("indicator".to_string()),
            risk_modifiers: None,
            lookback_minutes: None,
            dataset: None,
            // Auto-tuning replays the nPL query; a retro-hunt rule has none, so keep
            // it off.
            auto_tuning_enabled: Some(false),
            auto_tuning_min_confidence: None,
            auto_tuning_critical: None,
            ai_triage_hints: None,
            folder: req.folder.clone(),
            case_visibility: None,
            case_group_ids: None,
            case_assigned_group: None,
            alert_mode: Some(AlertMode::Grouped),
            playbook_selector_mode: None,
            playbook_id: None,
            source_path: None,
            source_repo_url: None,
            alert_cooldown_minutes: None,
        };

        let rule = self.rule_repo.create(&new_rule).await?;

        // The rule row now exists but is NOT yet a valid retro-hunt rule: it still
        // carries kind='standard' with a placeholder query that is deliberately not
        // valid nPL. If the discriminator flip or the config insert fails here we
        // MUST NOT leave it behind — `backfill_next_run_at` would later hand a
        // live+cron rule to the scheduler, which would try to parse that
        // placeholder as nPL and fail on every cycle. Roll the rule back instead
        // and surface the error.
        if let Err(e) = self.finish_retro_hunt_create(&rule, req, lookback_days, max_indicators, &cron).await {
            if let Err(cleanup) = self.rule_repo.delete(rule.id).await {
                error!(
                    rule_id = %rule.id,
                    "Retro-hunt create failed AND rollback failed ({cleanup}); a half-built rule may remain"
                );
            } else {
                warn!(rule_id = %rule.id, "Retro-hunt create failed; rolled back the rule row");
            }
            return Err(e);
        }

        let config = self
            .retro_hunt_repo()
            .get_config(rule.id)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?
            .ok_or_else(|| {
                DetectionError::RepositoryError("retro-hunt config vanished after create".into())
            })?;

        // Re-fetch so the returned rule carries kind + next_run_at.
        let rule = self.rule_repo.find_by_id(rule.id).await?;
        info!(rule_id = %rule.id, "Created retro-hunt rule '{}'", rule.name);
        Ok((rule, config))
    }

    /// The part of retro-hunt creation that must fully succeed or be rolled back:
    /// flip the kind discriminator, write the config, and schedule the first run.
    async fn finish_retro_hunt_create(
        &self,
        rule: &DetectionRule,
        req: &CreateRetroHuntRequest,
        lookback_days: i32,
        max_indicators: i32,
        cron: &str,
    ) -> Result<(), DetectionError> {
        // Flip the discriminator (create() always inserts kind='standard').
        sqlx::query("UPDATE detection_rules SET kind = 'retro_hunt' WHERE id = $1")
            .bind(rule.id)
            .execute(&self.pg_pool)
            .await?;

        self.retro_hunt_repo()
            .upsert_config(
                rule.id,
                &req.feeds,
                &req.artifact_types,
                lookback_days,
                max_indicators,
            )
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?;

        // Schedule the first run promptly (like a promoted standard rule). Done
        // LAST so the scheduler can only ever pick up a fully-built rule.
        let next_run =
            crate::detection::scheduler::calculate_next_run_with_jitter(cron, Utc::now(), rule.id, 30);
        self.rule_repo
            .update_next_run_at(rule.id, Some(next_run))
            .await?;
        Ok(())
    }

    /// Update a retro-hunt rule's config (feeds / artifact types / lookback / cap).
    pub async fn update_retro_hunt_config(
        &self,
        rule_id: uuid::Uuid,
        update: &UpdateRetroHuntConfigRequest,
    ) -> Result<RetroHuntConfig, DetectionError> {
        update
            .validate()
            .map_err(|e| DetectionError::InvalidQuery(e.to_string()))?;
        self.retro_hunt_repo()
            .update_config(rule_id, update)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))
    }

    /// Fetch a rule's retro-hunt config + current delta state.
    pub async fn get_retro_hunt_view(
        &self,
        rule_id: uuid::Uuid,
    ) -> Result<Option<RetroHuntRuleView>, DetectionError> {
        let repo = self.retro_hunt_repo();
        let config = repo
            .get_config(rule_id)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?;
        let Some(config) = config else {
            return Ok(None);
        };
        let state = repo
            .get_state(rule_id)
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))?;
        Ok(Some(RetroHuntRuleView { config, state }))
    }

    /// List a retro-hunt rule's recent run history.
    pub async fn list_retro_hunt_runs(
        &self,
        rule_id: uuid::Uuid,
        limit: i64,
    ) -> Result<Vec<RetroHuntRun>, DetectionError> {
        self.retro_hunt_repo()
            .list_runs(rule_id, limit.clamp(1, 200))
            .await
            .map_err(|e| DetectionError::RepositoryError(e.to_string()))
    }

    /// List the IOC feed names available for a retro-hunt rule's feed picker.
    pub async fn list_retro_hunt_feeds(&self) -> Result<Vec<String>, DetectionError> {
        self.search_service
            .list_ioc_feed_names()
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))
    }
}

/// Outcome of one retro-hunt run, threaded to the run-history writer.
struct RetroHuntOutcome {
    candidates_considered: u64,
    indicators_hunted: u64,
    hits: u64,
    truncated: bool,
    overflow_remaining: u64,
    watermark_after: Option<chrono::DateTime<Utc>>,
    alert: Option<Alert>,
}

/// Decide `(truncated, cursor_after)` from the `cap + 1` candidate probe
/// (ordered by `(fetched_at, value)`), given the prior cursor.
///
/// The cursor is the `(fetched_at_ms, value)` of the LAST candidate this run
/// covered, and the candidate query selects rows STRICTLY after it. Because the
/// ordering key is unique per candidate (value is the group key), the cursor is
/// strictly monotonic: every run advances past exactly the candidates it covered,
/// so nothing is skipped and nothing stalls.
///
/// A bare-timestamp cursor CANNOT do this. A feed sync stamps thousands of
/// indicators with the same `fetched_at`; if such a tie group exceeds `cap`, a
/// timestamp cursor must either skip the group's unprocessed tail (advance past
/// the timestamp) or stall forever (not advance — the capped ordered query then
/// keeps returning the same already-hunted rows, and `to_hunt` is empty every
/// run). The value tiebreak is what makes the tail reachable.
///
/// * No candidates → cursor unchanged (nothing new landed).
/// * `> cap` candidates (truncation) → advance to the last COVERED candidate
///   (index `cap - 1`); the rest is carried to the next run.
/// * `<= cap` candidates → everything after the cursor was covered; advance to
///   the newest.
///
/// Pure + deterministic so the drain/skip invariants are unit-tested.
fn plan_cursor(
    candidates: &[(i64, String)],
    cap: usize,
    cursor_before: Option<(i64, String)>,
) -> (bool, Option<(i64, String)>) {
    if candidates.is_empty() {
        return (false, cursor_before);
    }
    let truncated = candidates.len() > cap;
    let last_covered = if truncated {
        candidates.get(cap - 1)
    } else {
        candidates.last()
    };
    (truncated, last_covered.cloned())
}

/// Deterministic per-hit event id so the matched-event dedup is stable across
/// re-runs: the same (rule, indicator, last-seen) always hashes identically.
fn hit_event_id(rule_id: uuid::Uuid, value: &str, last_seen: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"retro-hunt|");
    h.update(rule_id.as_bytes());
    h.update(b"|");
    h.update(value.as_bytes());
    h.update(b"|");
    h.update(last_seen.as_bytes());
    format!("retro_{}", hex::encode(h.finalize()))
}

/// Synthesize one detection-match event per retro HIT, carrying the indicator as
/// the risk entity plus retro context for the alert/matches UI.
fn build_hit_events(
    rule_id: uuid::Uuid,
    hits: &[RetroHuntHit],
    candidates: &[&RetroFeedCandidate],
) -> Vec<serde_json::Value> {
    use std::collections::HashMap;
    let by_value: HashMap<&str, &RetroFeedCandidate> =
        candidates.iter().map(|c| (c.value.as_str(), *c)).collect();

    hits.iter()
        .map(|hit| {
            let cand = by_value.get(hit.value.as_str());
            let feed = cand
                .map(|c| c.enrichment_name.clone())
                .unwrap_or_default();
            let confidence = cand.map(|c| c.confidence).unwrap_or(0);
            // last_seen anchors both the dedup identity (aggregate branch keys on
            // `_last_seen`) and the synthesized event timestamp.
            let last_seen = hit.last_seen.clone().unwrap_or_else(|| {
                Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
            });
            let first_seen = hit.first_seen.clone().unwrap_or_else(|| last_seen.clone());

            let message = format!(
                "Retro-hunt: threat-intel indicator {} ({}, feed {}) was seen in your logs {} time(s) across {} host(s) — first {}, last {} [{}]",
                hit.value,
                hit.indicator_type,
                if feed.is_empty() { "unknown" } else { feed.as_str() },
                hit.hits,
                hit.hosts,
                first_seen,
                last_seen,
                hit.verdict,
            );

            let mut obj = serde_json::Map::new();
            obj.insert("id".into(), serde_json::json!(hit_event_id(rule_id, &hit.value, &last_seen)));
            // Risk entity + display: the malicious indicator itself.
            obj.insert("indicator".into(), serde_json::json!(hit.value));
            obj.insert("indicator_type".into(), serde_json::json!(hit.indicator_type));
            // Populate the matched observable column too (realistic alert row).
            if !hit.field.is_empty() {
                obj.insert(hit.field.clone(), serde_json::json!(hit.value));
            }
            obj.insert("message".into(), serde_json::json!(message));
            obj.insert("timestamp".into(), serde_json::json!(last_seen));
            // Canonical activity window → aggregate dedup branch keys on _last_seen.
            obj.insert("_first_seen".into(), serde_json::json!(first_seen));
            obj.insert("_last_seen".into(), serde_json::json!(last_seen));
            // Retro context for the alert / matches UI.
            obj.insert("retro_feed".into(), serde_json::json!(feed));
            obj.insert("retro_source".into(), serde_json::json!(feed));
            obj.insert("retro_confidence".into(), serde_json::json!(confidence));
            obj.insert("retro_verdict".into(), serde_json::json!(hit.verdict));
            obj.insert("retro_hits".into(), serde_json::json!(hit.hits));
            obj.insert("retro_hosts".into(), serde_json::json!(hit.hosts));
            obj.insert("retro_total_hosts".into(), serde_json::json!(hit.total_hosts));
            obj.insert("retro_field".into(), serde_json::json!(hit.field));
            obj.insert("retro_first_seen".into(), serde_json::json!(first_seen));
            obj.insert("retro_last_seen".into(), serde_json::json!(last_seen));
            serde_json::Value::Object(obj)
        })
        .collect()
}

#[cfg(test)]
mod tests;
