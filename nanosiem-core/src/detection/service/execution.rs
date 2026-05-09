// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Execution
//!
//! Execute detection rules against log data and generate alerts/signals.

use chrono::{DateTime, Duration, FixedOffset, Utc};
use metrics::{counter, histogram};
use tracing::{debug, error, info, instrument, warn};

use crate::detection::query_enrichment::inject_timestamp_bounds;
use crate::models::{Alert, AlertMode, DetectionRule, RuleMode};
use crate::query::{parse_query, PrettyPrint};
use crate::search::{SearchRequest, TimeRangeInput};

use super::DetectionError;
use super::DetectionService;

impl DetectionService {
    // ========================================================================
    // Rule Execution
    // ========================================================================

    /// Run a query against a single time window and return the matched rows.
    ///
    /// This is the **pure per-window evaluator**. It performs no DB writes —
    /// no dedup, no live counter updates, no signal logging — so it's safe to
    /// call repeatedly during a backtest. Both production `execute_rule`
    /// (one window per cron tick) and the historical "Test Rule" feature
    /// (many windows in parallel) call this so they cannot diverge in
    /// query semantics.
    #[instrument(
        skip(self, query),
        fields(window_start = %time_range.start, window_end = %time_range.end)
    )]
    pub async fn evaluate_window(
        &self,
        query: &str,
        time_range: TimeRangeInput,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        // Enrich aggregation queries with timestamp bounds so results always carry
        // _first_seen/_last_seen for detection latency calculation.
        let enriched_query = match parse_query(query) {
            Ok(parsed) => inject_timestamp_bounds(&parsed).pretty_print(),
            Err(_) => query.to_string(),
        };

        let request = SearchRequest {
            query: enriched_query,
            time_range,
            limit: Some(self.config.max_events_per_alert),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
        };

        self.search_service
            .search(request)
            .await
            .map(|r| r.results)
            .map_err(|e| DetectionError::SearchError(e.to_string()))
    }

    /// Execute a detection rule and generate alerts for matches (if in alerting mode)
    ///
    /// This method:
    /// - Queries logs using SearchService (ClickHouse when DualPool is configured) - Requirement 6.1
    /// - Evaluates prevalence conditions if present in the rule query - Requirements 6.1, 6.2
    /// - Stores matched events in alerts (PostgreSQL) - Requirement 6.4
    /// - Includes prevalence context in alerts - Requirement 6.5
    /// - Updates rule statistics (PostgreSQL)
    /// - Calculates risk scores using ScoreCalculator - Requirements 1.3, 8.2
    ///
    /// In live mode, matches are counted but no alerts are generated.
    /// In staging mode, the rule is not executed at all.
    #[instrument(
        skip_all,
        fields(rule_id = %rule.id, rule_name = %rule.name)
    )]
    pub async fn execute_rule(
        &self,
        rule: &DetectionRule,
        time_range: Option<TimeRangeInput>,
    ) -> Result<Option<Alert>, DetectionError> {
        // Don't execute paused rules
        if rule.mode == RuleMode::Paused {
            warn!("Attempted to execute paused rule: {}", rule.id);
            return Err(DetectionError::RulePaused(rule.id));
        }

        // Don't execute staging rules
        if rule.mode == RuleMode::Staging {
            debug!("Skipping execution of staging rule: {}", rule.name);
            return Ok(None);
        }

        // Determine time range
        let time_range = time_range.unwrap_or_else(|| {
            let end = Utc::now();
            let start = end - Duration::minutes(self.config.default_lookback_minutes);
            TimeRangeInput::new(start, end)
        });

        debug!(
            "Executing rule {} (mode: {:?}) with time range: {} to {}",
            rule.name, rule.mode, time_range.start, time_range.end
        );

        // Run the rule's query against this window. Shared with the historical
        // tester so test ≡ prod by construction.
        let mut results = self.evaluate_window(&rule.query, time_range).await?;

        // Filter out events that have already been matched by this rule
        // This prevents re-detection when rules have long lookback windows
        if rule.lookback_minutes.is_some() {
            let original_count = results.len();
            results = self
                .filter_already_matched_events(rule.id, &results)
                .await?;
            let filtered_count = original_count - results.len();
            if filtered_count > 0 {
                debug!(
                    "Filtered out {} already-matched events for rule {} (lookback window deduplication)",
                    filtered_count, rule.name
                );
            }
        }

        // Inject _nano_detected_at into all matched events for frontend latency calculation
        let detected_at = Utc::now();
        super::helpers::inject_detected_at(&mut results, detected_at);

        let match_count = results.len() as i64;
        let today = Utc::now().date_naive();

        // Record detection match metrics
        if match_count > 0 {
            let mode_str = format!("{:?}", rule.mode).to_lowercase();
            let severity_str = format!("{:?}", rule.severity).to_lowercase();

            counter!(
                "nanosiem_detection_matches_total",
                "mode" => mode_str,
                "severity" => severity_str.clone()
            )
            .increment(match_count as u64);

            // MTTD: find earliest event timestamp and measure time-to-detect
            let detection_time = Utc::now();
            let earliest_ts = results
                .iter()
                .filter_map(|e| e.get("timestamp").and_then(|t| t.as_str()))
                .filter_map(|t| {
                    // Try ClickHouse format first, then ISO 8601
                    DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S%.f")
                        .ok()
                        .or_else(|| t.parse::<DateTime<FixedOffset>>().ok())
                })
                .min();

            if let Some(earliest) = earliest_ts {
                let mttd = (detection_time - earliest.with_timezone(&Utc)).num_milliseconds()
                    as f64
                    / 1000.0;
                if mttd > 0.0 {
                    histogram!(
                        "nanosiem_detection_mttd_seconds",
                        "severity" => severity_str
                    )
                    .record(mttd);
                }
            }
        }

        // Load global risk weight for risk score calculation (Requirement 9.2)
        let global_weight = self.load_risk_weight().await;

        // Update stats based on mode
        match rule.mode {
            RuleMode::Staging => {
                // Staging rules should never be executed (caught earlier)
                unreachable!("Staging rules should not reach execution")
            }
            RuleMode::Live => {
                // In live mode, update live_match_count (for bake-in tracking)
                self.rule_repo
                    .update_live_match_count(rule.id, match_count)
                    .await?;

                // Record daily stats (no alerts in live mode)
                if match_count > 0 {
                    self.rule_repo
                        .record_daily_stats(rule.id, today, match_count, 0)
                        .await?;

                    // Store detection match for review
                    // Per-event rules store one match per event for consistent display
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

                    // Group events by entity and create separate signals for each
                    // This ensures each unique entity gets its own risk score update
                    let events_by_entity =
                        self.group_events_by_entity(rule.risk_entity_field.as_deref(), &results);

                    info!(
                        "Rule {} (LIVE mode) matched {} events across {} unique entities",
                        rule.name,
                        match_count,
                        events_by_entity.len()
                    );

                    // Log signal for each entity group
                    if let Some(ref logger) = self.finding_logger {
                        // Check if results have query-derived risk scores (from | risk command)
                        let has_query_scores = results
                            .first()
                            .map(|e| super::super::risk::ScoreCalculator::has_query_risk_score(e))
                            .unwrap_or(false);

                        if has_query_scores {
                            // Use query-derived scores - each event has its own score
                            for event in &results {
                                if let Some(risk_result) = self
                                    .score_calculator
                                    .calculate_from_query_result(event, global_weight)
                                {
                                    debug!(
                                        "Query-derived risk score for entity {} (field: {:?}): raw={}, weighted={}",
                                        risk_result.entity, risk_result.entity_field, risk_result.raw_score, risk_result.weighted_score
                                    );

                                    if let Err(e) = logger
                                        .log_detection_match(
                                            rule,
                                            &[event.clone()],
                                            false,
                                            risk_result,
                                        )
                                        .await
                                    {
                                        error!("Failed to log detection match signal: {}", e);
                                    }
                                }
                            }
                        } else {
                            // Use rule-derived scores - group by entity
                            for ((entity, field_name), entity_events) in events_by_entity {
                                let risk_result = self.score_calculator.calculate(
                                    rule.risk_score,
                                    rule.severity,
                                    Some(&field_name), // Use the field name from grouping
                                    &rule.risk_modifiers,
                                    &entity_events,
                                    global_weight,
                                );

                                // Override entity with the grouped entity value and field name
                                let risk_result = super::super::risk::RiskResult::new(
                                    risk_result.raw_score,
                                    risk_result.weighted_score,
                                    entity.clone(),
                                    Some(field_name.clone()),
                                    risk_result.factors,
                                );

                                debug!(
                                    "Rule-derived risk score for entity {} (field: {}): raw={}, weighted={}",
                                    entity, field_name, risk_result.raw_score, risk_result.weighted_score
                                );

                                if let Err(e) = logger
                                    .log_detection_match(rule, &entity_events, false, risk_result)
                                    .await
                                {
                                    error!(
                                        "Failed to log detection match signal for entity {}: {}",
                                        entity, e
                                    );
                                }
                            }
                        }
                    }
                }

                // No alert in live mode
                Ok(None)
            }
            RuleMode::Alerting => {
                // In alerting mode, update match_count and generate alerts
                self.rule_repo
                    .update_execution_stats(rule.id, match_count)
                    .await?;

                // Generate alert if there are matches
                if !results.is_empty() {
                    match rule.alert_mode {
                        AlertMode::Grouped => {
                            self.handle_grouped_alert(
                                rule,
                                &results,
                                match_count,
                                today,
                                global_weight,
                            )
                            .await
                        }
                        AlertMode::PerEvent => {
                            self.handle_per_event_alerts(
                                rule,
                                &results,
                                match_count,
                                today,
                                global_weight,
                            )
                            .await
                        }
                    }
                } else {
                    debug!("Rule {} had no matches", rule.name);
                    Ok(None)
                }
            }
            RuleMode::Paused => {
                // Paused rules should never reach here (caught earlier in execute_rule)
                warn!("Paused rule {} unexpectedly reached execution", rule.name);
                Ok(None)
            }
        }
    }

    /// Test a rule against historical data without creating an alert
    ///
    /// Uses SearchService to query logs (ClickHouse when DualPool is configured).
    /// This is useful for validating rule queries before enabling them.
    #[instrument(skip(self))]
    pub async fn test_rule(
        &self,
        query: &str,
        time_range: TimeRangeInput,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        // Validate the query
        self.validate_query(query)?;

        // Execute the query
        let request = SearchRequest {
            query: query.to_string(),
            time_range,
            limit: Some(self.config.max_events_per_alert),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
        };

        let response = self
            .search_service
            .search(request)
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))?;

        Ok(response.results)
    }
}
