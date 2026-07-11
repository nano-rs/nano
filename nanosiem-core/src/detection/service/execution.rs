// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Execution
//!
//! Execute detection rules against log data and generate alerts/signals.

use chrono::{Duration, Utc};
use metrics::{counter, histogram};
use tracing::{debug, info, instrument, warn};

use crate::detection::query_enrichment::inject_timestamp_bounds;
use crate::models::{Alert, AlertMode, DetectionRule, RuleMode};
use crate::query::{parse_query, PrettyPrint};
use crate::search::{SearchExecutionLimits, SearchRequest, TimeRangeInput};

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
        dataset: Option<String>,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        self.evaluate_window_with_limit(
            query,
            time_range,
            dataset,
            crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT,
        )
        .await
    }

    /// Evaluate one production-equivalent window with a caller-supplied result
    /// limit. Autonomous validation uses a deliberately small `cap + 1` limit
    /// so it can distinguish an exact result from a capped one without ever
    /// materializing the production 1M-row ceiling many times concurrently.
    pub(crate) async fn evaluate_window_with_limit(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        result_limit: usize,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        self.evaluate_window_with_options(query, time_range, dataset, result_limit, None, None)
            .await
    }

    /// Autonomous counterpart with an evaluator-owned query ID, no interactive
    /// count companion, and ClickHouse-enforced result row/byte ceilings.
    pub(crate) async fn evaluate_tuning_window(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        result_limit: usize,
        result_byte_limit: u64,
        query_id: String,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        let execution_limits = SearchExecutionLimits {
            max_result_rows: u64::try_from(result_limit).unwrap_or(u64::MAX),
            max_result_bytes: result_byte_limit,
        };
        self.evaluate_window_with_options(
            query,
            time_range,
            dataset,
            result_limit,
            Some(query_id),
            Some(execution_limits),
        )
        .await
    }

    async fn evaluate_window_with_options(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        result_limit: usize,
        request_id: Option<String>,
        execution_limits: Option<SearchExecutionLimits>,
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
            // Production passes the standard 1M safety cap here (audit D19).
            // Autonomous validation passes a smaller cap+1 and treats reaching
            // it as non-exact, routing the proposal to review.
            limit: Some(result_limit),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id,
            async_mode: false,
            priority: None,
            dataset,
        };

        let search_service = execution_limits.map_or_else(
            || self.search_service.clone(),
            |limits| self.search_service.clone().with_execution_limits(limits),
        );
        search_service
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
        let mut results = self
            .evaluate_window(&rule.query, time_range, rule.dataset.clone())
            .await?;

        // Audit D19: if a single window hit the 1M safety cap the rule is far too
        // broad — matches beyond 1M are still truncated, but now VISIBLY (a warn)
        // instead of silently at 100.
        if results.len() >= crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT {
            warn!(
                rule_id = %rule.id,
                "Rule {} hit the 1M result cap in a single window — the query is too broad; some matches are truncated",
                rule.name
            );
        }

        // Dedup namespace: Live bake-in and Alerting record/filter separately so
        // a rule promoted Live→Alerting isn't suppressed by bake-in records (D17).
        let matched_kind = super::helpers::MatchedEventKind::for_mode(rule.mode);

        // Filter out events already matched by this rule in this namespace. This
        // is READ-only; the surviving events are RECORDED as matched *after* the
        // alert/finding is durably created (audit D5), in the mode branch below.
        //
        // Audit D29: dedup runs for EVERY scheduled rule, not only those with an
        // explicit `lookback_minutes`. A lookback-NULL rule still overlaps the
        // previous window by the 5s ingestion-lag buffer, so without this its
        // boundary events re-matched every cycle and inflated match_count /
        // detection_matches.
        {
            let original_count = results.len();
            results = self
                .filter_already_matched_events(rule.id, matched_kind, &results)
                .await?;
            let filtered_count = original_count - results.len();
            if filtered_count > 0 {
                debug!(
                    "Filtered out {} already-matched events for rule {} (overlap deduplication)",
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

            // MTTD: find earliest event timestamp and measure time-to-detect.
            // Audit D23: use the shared event_field_time parser — the old inline
            // `parse_from_str(..., "%Y-%m-%d %H:%M:%S%.f")` targets DateTime<FixedOffset>
            // but the format carries no offset, so it ALWAYS errored (and the
            // RFC-3339 fallback can't parse the offset-less CH format either), so
            // MTTD never recorded for the normal CH timestamp format.
            let detection_time = Utc::now();
            let earliest_ts = results
                .iter()
                .filter_map(|e| Self::event_field_time(e, "timestamp"))
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

                    // Log per-entity live findings, deduped per (rule, entity,
                    // window) and stamped with the source event window so
                    // overlapping re-evaluations don't re-emit / re-inflate risk
                    // (NAN-1305).
                    let emitted = self.log_live_findings(rule, &results, global_weight).await;

                    // Record matched events AFTER live processing (audit D5), in
                    // the 'live' namespace (audit D17). A crash before here leaves
                    // them un-recorded so the next run re-evaluates them.
                    // Unconditional (audit D29): the 5s overlap dedups even
                    // lookback-NULL rules.
                    self.record_matched_events(rule.id, matched_kind, &results)
                        .await?;

                    info!(
                        "Rule {} (LIVE mode) matched {} events, emitted {} new findings",
                        rule.name, match_count, emitted
                    );
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
                    let alert = match rule.alert_mode {
                        AlertMode::Grouped => {
                            self.handle_grouped_alert(
                                rule,
                                &results,
                                match_count,
                                today,
                                global_weight,
                            )
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

                    // Record matched events only AFTER the alert path succeeds
                    // (audit D5), in the 'alert' namespace (audit D17). An error
                    // before here (propagated by `?`) leaves them un-recorded so
                    // the next run re-evaluates them instead of dropping the
                    // detection forever. Unconditional (audit D29): the 5s overlap
                    // dedups even lookback-NULL rules.
                    self.record_matched_events(rule.id, matched_kind, &results)
                        .await?;

                    Ok(alert)
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
}
