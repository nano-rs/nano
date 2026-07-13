// SPDX-License-Identifier: AGPL-3.0-or-later

//! Historical Analysis
//!
//! Historical analysis for false positive tuning and query validation.

use chrono::{DateTime, Duration, TimeZone, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::models::DetectionRule;
use crate::query::{parse_query, pre_aggregation_subquery, PrettyPrint};
use crate::search::{SearchRequest, TimeRangeInput};

use super::{
    DailyMatchCount, DetectionError, DetectionService, HistoricalAnalysisResult, TimeBucket,
    TuningReplayBudget, TuningWindowEvidence, TuningWindowPlan,
    AUTONOMOUS_TUNING_REPLAY_QUERY_COUNT, MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW,
    MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW, MAX_AUTONOMOUS_TUNING_TOTAL_SCAN_SECONDS,
    MAX_AUTONOMOUS_TUNING_WINDOWS,
};

/// Hard cap on the user-selected test range. Mirrors Google SecOps' "Run rule
/// against historical data" cap. Anything longer should use a saved search
/// rather than the interactive tester.
pub const MAX_TEST_RANGE_DAYS: i64 = 14;

/// Concurrency cap for stepped per-window evaluation against ClickHouse. Caps
/// the in-flight load a single test click can put on the database, regardless
/// of how many windows the rule's cadence produces over the user's range.
const STEPPED_TESTER_CONCURRENCY: usize = 16;

/// Autonomous validation is background work and must leave ClickHouse capacity
/// for live hunting and scheduled detections.
const AUTONOMOUS_TUNING_CONCURRENCY: usize = 2;

/// Lookback used when a rule has no `lookback_minutes` set. Matches the
/// scheduler's default in `DetectionServiceConfig`.
const DEFAULT_STEPPED_LOOKBACK_MINUTES: i64 = 15;

/// Defense-in-depth cap on the number of windows a single test can fan out
/// to. The 14-day range cap already bounds typical configurations
/// (`*/5 * * * *` × 14d = 4,032 windows, fits with margin), but a
/// pathological 1-minute cron rule against the full 14-day range would
/// produce 20,160 windows — combined with N concurrent users, that's enough
/// to ride the database into the ground. Reject those upfront with a clear
/// error so the user picks a shorter range.
const MAX_STEPPED_WINDOWS: usize = 5_000;

/// Cron expression assumed when a rule has no `schedule_cron` set. Matches the
/// most common detection schedule, and only kicks in for ad-hoc query tests
/// where there's no rule object yet. 5-field form; normalized to 6-field
/// before passing to the cron crate.
const DEFAULT_STEPPED_CRON: &str = "*/5 * * * *";

/// Bucket sizes the histogram can pick from, in seconds.
/// Sorted ascending; we pick the smallest size that keeps the bucket count below
/// `MAX_BUCKETS` so the API response stays sane regardless of window length.
const BUCKET_SIZES_SECS: &[u32] = &[
    60,      // 1m
    300,     // 5m
    900,     // 15m
    3600,    // 1h
    21_600,  // 6h
    86_400,  // 1d
    604_800, // 7d
];

const MAX_BUCKETS: i64 = 50;

/// Pick a bucket size based on the requested window length.
fn pick_bucket_size_seconds(window: Duration) -> u32 {
    let secs = window.num_seconds().max(1);
    for &size in BUCKET_SIZES_SECS {
        if secs / (size as i64) <= MAX_BUCKETS {
            return size;
        }
    }
    *BUCKET_SIZES_SECS.last().unwrap()
}

impl DetectionService {
    // ========================================================================
    // Historical Analysis (for false positive tuning)
    // ========================================================================

    /// Run historical analysis on a rule to check for false positives
    ///
    /// This method uses ClickHouse for historical queries when DualPool is configured (Requirement 6.5):
    /// - Queries log data from ClickHouse via SearchService
    /// - Generates timechart data from ClickHouse for trend analysis
    ///
    /// Default: looks back 7 days
    #[instrument(skip(self))]
    pub async fn analyze_historical(
        &self,
        rule_id: Uuid,
        days: Option<i64>,
    ) -> Result<HistoricalAnalysisResult, DetectionError> {
        let rule = self.get_rule(rule_id).await?;
        let days = days.unwrap_or(self.config.default_historical_days);

        let end = Utc::now();
        let start = end - Duration::days(days);
        let time_range = TimeRangeInput::new(start, end);

        info!(
            "Running historical analysis for rule {} over {} days",
            rule.name, days
        );

        let start_time = std::time::Instant::now();

        // Get total count and sample events
        let request = SearchRequest {
            query: rule.query.clone(),
            time_range: time_range.clone(),
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
            // NAN-1561: thread the rule's dataset so spans/metrics rules analyze
            // the right physical table.
            dataset: rule.dataset.clone(),
        };

        let response = self
            .search_service
            // SYSTEM caller: detection analysis must see ALL sources.
            .search(request, &crate::auth::ScopeSet::unrestricted())
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))?;

        let (matches_by_bucket, bucket_size_seconds) = self
            .compute_match_buckets(&rule.query, &time_range, rule.dataset.clone())
            .await;
        let matches_by_day = derive_daily_counts(&matches_by_bucket);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // NAN-831: normalize sample events through the canonical envelope so
        // the rule-editor test drawer renders aggregate-row labels the same
        // way the matches list does (NAN-830).
        let mut sample_events = response.results;
        for ev in &mut sample_events {
            crate::detection::normalize_match_event(ev);
        }
        // Audit D35: the sample is capped at `max_events_per_alert` for display.
        // While it isn't capped, its length IS the exact post-processing match
        // count — correct even for `| where count > N` threshold rules that
        // legitimately return few rows (so we must NOT substitute raw
        // pre-aggregation volume here). Only when the sample hits the cap do we
        // fall back to the uncapped SQL `total_count` so a high-volume rule isn't
        // frozen at exactly the cap (`min(len, 100)`); clamp so we never
        // under-report the sample.
        let cap = self.config.max_events_per_alert;
        let total_matches = if sample_events.len() < cap {
            sample_events.len() as u64
        } else {
            response.total_count.max(sample_events.len() as u64)
        };

        Ok(HistoricalAnalysisResult {
            rule_id: rule.id,
            rule_name: rule.name,
            time_range,
            // Uncapped match count (audit D35): exact sample length until the
            // display cap is hit, then the SQL total_count.
            total_matches,
            sample_events,
            matches_by_day,
            matches_by_bucket,
            bucket_size_seconds,
            execution_time_ms,
            // Single-search path: a query failure returns Err directly, so no
            // silent per-window swallowing to report (audit D3b).
            failed_windows: 0,
            error_sample: None,
        })
    }

    /// Run historical analysis using a query string (for testing before creating a rule)
    ///
    /// Uses ClickHouse for historical queries when DualPool is configured (Requirement 6.5).
    #[instrument(skip(self))]
    pub async fn analyze_query_historical(
        &self,
        query: &str,
        days: Option<i64>,
    ) -> Result<HistoricalAnalysisResult, DetectionError> {
        let days = days.unwrap_or(self.config.default_historical_days);
        let end = Utc::now();
        let start = end - Duration::days(days);
        let time_range = TimeRangeInput::new(start, end);

        self.analyze_query_with_time_range(query, time_range).await
    }

    /// Stepped historical analysis for a saved rule (NAN-741).
    ///
    /// Evaluates the rule's query the way the production scheduler would —
    /// once per cron tick within `[start, end]`, against the rule's lookback
    /// window — then aggregates per-window match counts into the
    /// `total_matches` and `matches_by_bucket` returned to the UI. This
    /// replaces the old single-shot aggregation that silently green-lit
    /// thresholds unreachable in any individual scheduled window (e.g.
    /// `where failures > 60` over a 15-min lookback).
    ///
    /// The per-window executor is `evaluate_window`, which is also called by
    /// `execute_rule` in production — so the test path cannot diverge from
    /// the scheduler path in query semantics.
    #[instrument(
        skip(self, rule),
        fields(rule_id = %rule.id, rule_name = %rule.name)
    )]
    pub async fn analyze_rule_stepped(
        &self,
        rule: &DetectionRule,
        time_range: TimeRangeInput,
    ) -> Result<HistoricalAnalysisResult, DetectionError> {
        validate_test_range(&time_range)?;
        self.validate_query(&rule.query)?;

        let lookback_minutes = rule
            .lookback_minutes
            .map(|m| m as i64)
            .unwrap_or(DEFAULT_STEPPED_LOOKBACK_MINUTES);
        let lookback = Duration::minutes(lookback_minutes);
        let cron_expr = rule
            .schedule_cron
            .as_deref()
            .unwrap_or(DEFAULT_STEPPED_CRON);

        let windows = enumerate_test_windows(&time_range, cron_expr, lookback)?;
        if windows.len() > MAX_STEPPED_WINDOWS {
            return Err(DetectionError::InvalidQuery(format!(
                "Selected range produces {} evaluation windows for this rule's \
                 cadence, which exceeds the {}-window cap. Pick a shorter range \
                 or use a coarser schedule.",
                windows.len(),
                MAX_STEPPED_WINDOWS,
            )));
        }
        let bucket_size_seconds = step_seconds(cron_expr).unwrap_or(0) as u32;

        info!(
            rule_id = %rule.id,
            rule_name = %rule.name,
            windows = windows.len(),
            cron = cron_expr,
            lookback_minutes = lookback_minutes,
            "Stepped rule test: evaluating {} windows", windows.len()
        );

        let result = self
            .run_stepped_windows(
                &rule.query,
                &windows,
                bucket_size_seconds,
                rule.dataset.clone(),
            )
            .await;

        Ok(HistoricalAnalysisResult {
            rule_id: rule.id,
            rule_name: rule.name.clone(),
            time_range,
            ..result
        })
    }

    /// Stepped historical analysis for an ad-hoc query (rule not yet saved).
    ///
    /// Same semantics as `analyze_rule_stepped` but with no `DetectionRule`
    /// to read schedule/lookback from — the caller passes them explicitly.
    /// Used by `POST /api/rules/test` from the rule editor before save.
    #[instrument(skip(self, query))]
    pub async fn analyze_query_stepped(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        schedule_cron: Option<&str>,
        lookback_minutes: Option<i64>,
        dataset: Option<String>,
    ) -> Result<HistoricalAnalysisResult, DetectionError> {
        validate_test_range(&time_range)?;
        self.validate_query(query)?;

        let lookback =
            Duration::minutes(lookback_minutes.unwrap_or(DEFAULT_STEPPED_LOOKBACK_MINUTES));
        let cron_expr = schedule_cron.unwrap_or(DEFAULT_STEPPED_CRON);

        let windows = enumerate_test_windows(&time_range, cron_expr, lookback)?;
        if windows.len() > MAX_STEPPED_WINDOWS {
            return Err(DetectionError::InvalidQuery(format!(
                "Selected range produces {} evaluation windows for this rule's \
                 cadence, which exceeds the {}-window cap. Pick a shorter range \
                 or use a coarser schedule.",
                windows.len(),
                MAX_STEPPED_WINDOWS,
            )));
        }
        let bucket_size_seconds = step_seconds(cron_expr).unwrap_or(0) as u32;

        info!(
            windows = windows.len(),
            cron = cron_expr,
            "Stepped ad-hoc query test: evaluating {} windows",
            windows.len()
        );

        let result = self
            .run_stepped_windows(query, &windows, bucket_size_seconds, dataset)
            .await;

        Ok(HistoricalAnalysisResult {
            rule_id: Uuid::nil(),
            rule_name: "Ad-hoc Query".to_string(),
            time_range,
            ..result
        })
    }

    /// Fan out across `windows` with bounded concurrency, collecting per-window
    /// match counts and a sample of matched events. Returns a partial
    /// `HistoricalAnalysisResult` with rule_id/rule_name/time_range left as
    /// defaults — callers fill those in.
    async fn run_stepped_windows(
        &self,
        query: &str,
        windows: &[TimeRangeInput],
        bucket_size_seconds: u32,
        dataset: Option<String>,
    ) -> HistoricalAnalysisResult {
        let start_time = std::time::Instant::now();
        let semaphore = Arc::new(Semaphore::new(STEPPED_TESTER_CONCURRENCY));
        let max_samples = self.config.max_events_per_alert;

        let mut futures = FuturesUnordered::new();
        for window in windows {
            let sem = semaphore.clone();
            let svc = self.clone();
            let q = query.to_string();
            let w = window.clone();
            // NAN-1561: thread the rule's dataset so a spans/metrics backtest
            // queries the right physical table instead of silently scanning logs.
            let ds = dataset.clone();
            futures.push(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .expect("stepped tester semaphore should not close");
                let result = svc.evaluate_window(&q, w.clone(), ds).await;
                (w, result)
            });
        }

        let mut total_matches: u64 = 0;
        let mut sample_events: Vec<serde_json::Value> = Vec::new();
        let mut buckets: Vec<TimeBucket> = Vec::with_capacity(windows.len());
        // Audit D3b: track window failures so the tester surfaces "N windows
        // errored" instead of silently reporting them as `count: 0` — which made
        // a rule that errors every cycle look like a healthy "0 matches" rule.
        let mut failed_windows: u32 = 0;
        let mut error_sample: Option<String> = None;

        while let Some((window, result)) = futures.next().await {
            // Use the tick time (window end) as bucket_start so the histogram
            // is anchored at the moment the rule "fired" — not the start of
            // its lookback window, which can extend before the user-selected
            // range.
            let bucket_start = window.end;
            match result {
                Ok(rows) => {
                    let count = rows.len() as u64;
                    total_matches += count;
                    buckets.push(TimeBucket {
                        bucket_start,
                        count,
                    });
                    for mut row in rows {
                        if sample_events.len() >= max_samples {
                            break;
                        }
                        // NAN-831: canonical envelope so the test drawer
                        // renders aggregate-row labels uniformly.
                        crate::detection::normalize_match_event(&mut row);
                        sample_events.push(row);
                    }
                }
                Err(e) => {
                    warn!(
                        "Stepped tester: window {}..{} failed: {}",
                        window.start, window.end, e
                    );
                    failed_windows += 1;
                    if error_sample.is_none() {
                        error_sample = Some(e.to_string());
                    }
                    buckets.push(TimeBucket {
                        bucket_start,
                        count: 0,
                    });
                }
            }
        }

        // FuturesUnordered yields in completion order — sort chronologically
        // so the sparkline renders in time order regardless of how queries
        // raced to finish.
        buckets.sort_by_key(|b| b.bucket_start);

        let matches_by_day = derive_daily_counts(&buckets);
        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        HistoricalAnalysisResult {
            rule_id: Uuid::nil(),
            rule_name: String::new(),
            time_range: TimeRangeInput::new(Utc::now(), Utc::now()),
            total_matches,
            sample_events,
            matches_by_day,
            matches_by_bucket: buckets,
            bucket_size_seconds,
            execution_time_ms,
            failed_windows,
            error_sample,
        }
    }

    /// Replay an identity-preserving query over a fixed set of production
    /// schedule/lookback windows for autonomous tuning validation.
    ///
    /// Counts are exact only when every window succeeds, no autonomous row or
    /// byte budget is reached, and every returned row carries the physical
    /// source `id`. Callers persist those conditions and fail closed otherwise.
    pub(crate) async fn evaluate_tuning_windows(
        &self,
        query: &str,
        windows: &[TimeRangeInput],
        dataset: Option<String>,
        budget: TuningReplayBudget,
        query_id_prefix: &str,
    ) -> TuningWindowEvidence {
        if budget.rows == 0 || budget.bytes == 0 {
            return TuningWindowEvidence {
                budget_exceeded: true,
                ..TuningWindowEvidence::default()
            };
        }

        let semaphore = Arc::new(Semaphore::new(AUTONOMOUS_TUNING_CONCURRENCY));
        let max_samples = self.config.max_events_per_alert;
        let mut futures = FuturesUnordered::new();
        let result_limit = usize::try_from(
            (MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW + 1).min(budget.rows.saturating_add(1)),
        )
        .expect("autonomous tuning row cap fits usize");
        let result_byte_limit = MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW.min(budget.bytes);
        let query_ids = tuning_replay_query_ids(query_id_prefix, windows.len());

        for (window, query_id) in windows.iter().zip(query_ids.iter().cloned()) {
            let sem = semaphore.clone();
            let service = self.clone();
            let query = query.to_string();
            let window = window.clone();
            let dataset = dataset.clone();
            futures.push(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .expect("stepped tuning semaphore should not close");
                service
                    .evaluate_tuning_window(
                        &query,
                        window,
                        dataset,
                        result_limit,
                        result_byte_limit,
                        query_id,
                    )
                    .await
            });
        }

        let mut source_ids = HashSet::new();
        let mut sample_events = Vec::new();
        let mut rows_examined = 0_u64;
        let mut bytes_examined = 0_u64;
        let mut failed_windows = 0_u32;
        let mut truncated_windows = 0_u32;
        let mut identity_errors = 0_u64;
        let mut budget_exceeded = false;
        let mut cancel_remaining = false;

        while let Some(result) = futures.next().await {
            match result {
                Ok(rows) => {
                    if autonomous_window_is_truncated(rows.len()) {
                        truncated_windows = truncated_windows.saturating_add(1);
                        cancel_remaining = true;
                        break;
                    }

                    let Some((next_rows_examined, next_bytes_examined)) =
                        replay_batch_usage(&rows, rows_examined, bytes_examined, budget)
                    else {
                        budget_exceeded = true;
                        cancel_remaining = true;
                        break;
                    };

                    rows_examined = next_rows_examined;
                    bytes_examined = next_bytes_examined;

                    for row in rows {
                        if sample_events.len() < max_samples {
                            sample_events.push(row.clone());
                        }

                        let source_id = row
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .and_then(|value| Uuid::parse_str(value).ok());
                        match source_id {
                            Some(id) => {
                                source_ids.insert(id);
                            }
                            None => identity_errors = identity_errors.saturating_add(1),
                        }
                    }
                    if identity_errors > 0 {
                        cancel_remaining = true;
                        break;
                    }
                }
                Err(error) => {
                    failed_windows = failed_windows.saturating_add(1);
                    warn!(error = %error, "Stepped tuning validation window failed");
                    cancel_remaining = true;
                    break;
                }
            }
        }

        if cancel_remaining {
            if let Err(error) = self.search_service.cancel_exact_queries(&query_ids).await {
                warn!(error = %error, "Failed to cancel remaining tuning replay queries");
            }
        }

        TuningWindowEvidence {
            total_matches: u64::try_from(source_ids.len()).unwrap_or(u64::MAX),
            source_ids,
            sample_events,
            rows_examined,
            bytes_examined,
            failed_windows,
            truncated_windows,
            identity_errors,
            budget_exceeded,
        }
    }

    /// Explicitly kill every possible query ID for one or more replay lanes.
    /// Used by the outer timeout, whose cancellation drops the replay future
    /// before its normal error cleanup can run.
    pub(crate) async fn cancel_tuning_replays(
        &self,
        query_id_prefixes: &[&str],
        window_count: usize,
    ) -> Result<bool, crate::search::SearchError> {
        let query_ids = query_id_prefixes
            .iter()
            .flat_map(|prefix| tuning_replay_query_ids(prefix, window_count))
            .collect::<Vec<_>>();
        self.search_service.cancel_exact_queries(&query_ids).await
    }

    /// Run historical analysis using a query string with explicit time range
    ///
    /// Uses ClickHouse for historical queries when DualPool is configured (Requirement 6.5).
    /// Generates timechart data from ClickHouse for trend analysis.
    #[instrument(skip(self))]
    pub async fn analyze_query_with_time_range(
        &self,
        query: &str,
        time_range: TimeRangeInput,
    ) -> Result<HistoricalAnalysisResult, DetectionError> {
        // Validate the query
        self.validate_query(query)?;

        info!(
            "Running historical analysis for query from {} to {}",
            time_range.start, time_range.end
        );

        let start_time = std::time::Instant::now();

        // Get total count and sample events
        let request = SearchRequest {
            query: query.to_string(),
            time_range: time_range.clone(),
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
            // KNOWN LIMITATION (NAN-1561): this ad-hoc query-string analysis path
            // has no DetectionRule and therefore no dataset — it always queries
            // logs. The saved-rule paths (analyze_historical / evaluate_window /
            // the stepped tester) thread the rule's dataset correctly. Spans/
            // metrics rules should be tested via the stepped tester, which is
            // dataset-aware.
            dataset: None,
        };

        let response = self
            .search_service
            // SYSTEM caller: detection analysis must see ALL sources.
            .search(request, &crate::auth::ScopeSet::unrestricted())
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))?;

        let (matches_by_bucket, bucket_size_seconds) =
            self.compute_match_buckets(query, &time_range, None).await;
        let matches_by_day = derive_daily_counts(&matches_by_bucket);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // NAN-831: canonical envelope (see analyze_rule_historical above).
        let mut sample_events = response.results;
        for ev in &mut sample_events {
            crate::detection::normalize_match_event(ev);
        }
        // Audit D35: the sample is capped at `max_events_per_alert` for display.
        // While it isn't capped, its length IS the exact post-processing match
        // count — correct even for `| where count > N` threshold rules that
        // legitimately return few rows (so we must NOT substitute raw
        // pre-aggregation volume here). Only when the sample hits the cap do we
        // fall back to the uncapped SQL `total_count` so a high-volume rule isn't
        // frozen at exactly the cap (`min(len, 100)`); clamp so we never
        // under-report the sample.
        let cap = self.config.max_events_per_alert;
        let total_matches = if sample_events.len() < cap {
            sample_events.len() as u64
        } else {
            response.total_count.max(sample_events.len() as u64)
        };

        Ok(HistoricalAnalysisResult {
            rule_id: Uuid::nil(), // No rule ID for ad-hoc query
            rule_name: "Ad-hoc Query".to_string(),
            time_range,
            // Uncapped match count (audit D35): exact sample length until the
            // display cap is hit, then the SQL total_count.
            total_matches,
            sample_events,
            matches_by_day,
            matches_by_bucket,
            bucket_size_seconds,
            execution_time_ms,
            // Single-search path: a query failure returns Err directly, so no
            // silent per-window swallowing to report (audit D3b).
            failed_windows: 0,
            error_sample: None,
        })
    }

    /// Compute match counts bucketed at a granularity that adapts to the window.
    ///
    /// For aggregated rules (`| stats`, `| chart`, `| timechart`, etc.) the
    /// counts come from the pre-aggregation filter, not the (collapsed)
    /// post-aggregation rows — otherwise the histogram would either error
    /// (UNKNOWN_IDENTIFIER from chaining `| timechart` after `| stats count by
    /// src_ip`) or only show a single bar.
    ///
    /// Returns `(buckets, bucket_size_seconds)`. On any failure (parse error,
    /// search error, etc.) returns `(vec![], 0)` so the endpoint still
    /// responds successfully with sample events.
    async fn compute_match_buckets(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        dataset: Option<String>,
    ) -> (Vec<TimeBucket>, u32) {
        let bucket_size = pick_bucket_size_seconds(time_range.end - time_range.start);

        // Parse the query so we can split off the pre-aggregation filter.
        let parsed = match parse_query(query) {
            Ok(q) => q,
            Err(e) => {
                debug!(
                    "Skipping match histogram: query failed to parse for bucketing: {}",
                    e
                );
                return (Vec::new(), 0);
            }
        };

        // For aggregated rules, base the histogram on the row stream feeding
        // the first aggregation. For raw-event rules, use the whole query.
        let base_filter = pre_aggregation_subquery(&parsed)
            .unwrap_or(&parsed)
            .pretty_print();

        let timechart_query = format!("{} | timechart span={}s count()", base_filter, bucket_size);
        // Cap at MAX_BUCKETS + a small slack for boundary buckets.
        let limit = (MAX_BUCKETS as usize) + 5;
        let buckets = self
            .fetch_bucket_counts(&timechart_query, time_range, limit, dataset)
            .await;
        (buckets, bucket_size)
    }

    /// Fetch bucket counts using a timechart query.
    async fn fetch_bucket_counts(
        &self,
        timechart_query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
        dataset: Option<String>,
    ) -> Vec<TimeBucket> {
        let request = SearchRequest {
            query: timechart_query.to_string(),
            time_range: time_range.clone(),
            limit: Some(limit),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            // NAN-1561: threaded from the caller's rule dataset (None for the
            // ad-hoc query path, which has no rule and therefore queries logs).
            dataset,
        };

        // SYSTEM caller: detection analysis must see ALL sources.
        match self
            .search_service
            .search(request, &crate::auth::ScopeSet::unrestricted())
            .await
        {
            Ok(response) => response
                .results
                .iter()
                .filter_map(|row| {
                    let bucket_start = row
                        .get("time_bucket")
                        .or_else(|| row.get("timestamp"))
                        .and_then(parse_bucket_timestamp)?;
                    let count = row
                        .get("count")
                        .and_then(|v| {
                            v.as_u64()
                                .or_else(|| v.as_i64().map(|n| n.max(0) as u64))
                                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                        })
                        .unwrap_or(0);
                    Some(TimeBucket {
                        bucket_start,
                        count,
                    })
                })
                .collect(),
            Err(e) => {
                warn!("Histogram query failed: {}", e);
                Vec::new()
            }
        }
    }
}

#[derive(Default)]
struct JsonByteCounter(u64);

impl Write for JsonByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(u64::try_from(buf.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| io::Error::other("serialized event size overflow"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_json_size(value: &serde_json::Value) -> Option<u64> {
    let mut counter = JsonByteCounter::default();
    serde_json::to_writer(&mut counter, value).ok()?;
    Some(counter.0)
}

fn replay_batch_usage(
    rows: &[serde_json::Value],
    rows_examined: u64,
    bytes_examined: u64,
    budget: TuningReplayBudget,
) -> Option<(u64, u64)> {
    let next_rows = rows_examined.checked_add(u64::try_from(rows.len()).ok()?)?;
    if next_rows > budget.rows {
        return None;
    }

    let batch_bytes = rows.iter().try_fold(0_u64, |total, row| {
        serialized_json_size(row)
            .and_then(|size| size.checked_add(1))
            .and_then(|size| total.checked_add(size))
    })?;
    if autonomous_window_bytes_exceeded(batch_bytes) {
        return None;
    }
    let next_bytes = bytes_examined.checked_add(batch_bytes)?;
    (next_bytes <= budget.bytes).then_some((next_rows, next_bytes))
}

fn autonomous_window_is_truncated(row_count: usize) -> bool {
    u64::try_from(row_count).unwrap_or(u64::MAX) > MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW
}

fn autonomous_window_bytes_exceeded(byte_count: u64) -> bool {
    byte_count > MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW
}

fn tuning_replay_query_ids(prefix: &str, window_count: usize) -> Vec<String> {
    (0..window_count)
        .map(|index| format!("{prefix}-{index}"))
        .collect()
}

/// Enumerate the cron-tick times in `[range.start, range.end]` and return one
/// `TimeRangeInput` per tick covering `[tick - lookback, tick]`. Mirrors what
/// the production scheduler would have evaluated at each tick within the
/// user-selected range.
///
/// Errors if the cron expression doesn't parse. Empty result is valid (e.g.
/// daily-cron rule tested against a 1-hour range that doesn't contain a tick).
pub fn enumerate_test_windows(
    range: &TimeRangeInput,
    schedule_cron: &str,
    lookback: Duration,
) -> Result<Vec<TimeRangeInput>, DetectionError> {
    let normalized = crate::detection::scheduler::normalize_cron_expression(schedule_cron);
    let schedule = cron::Schedule::from_str(&normalized)
        .map_err(|e| DetectionError::InvalidCronExpression(format!("{}: {}", schedule_cron, e)))?;

    // Audit D36: `Schedule::after` yields ticks strictly greater than its
    // argument, so a tick landing exactly on `range.start` — which the
    // production scheduler WOULD evaluate — was excluded. Probe from one second
    // earlier (cron ticks are second-granular) and drop anything before
    // `range.start`, so an on-boundary tick is included.
    // `checked_sub` guards a chrono-min underflow — unreachable in practice
    // (`validate_test_range` bounds live ranges to a 14-day window near now),
    // but falling back to `range.start` degrades gracefully to the old
    // strictly-after behavior rather than panicking.
    let probe = range
        .start
        .checked_sub_signed(Duration::seconds(1))
        .unwrap_or(range.start);
    let mut windows = Vec::new();
    for tick in schedule.after(&probe) {
        if tick < range.start {
            continue;
        }
        if tick > range.end {
            break;
        }
        // NOTE (audit D36, deferred): when `lookback > step` consecutive windows
        // overlap, so an event in the overlap is counted in multiple windows —
        // the stepped tester over-counts raw-event volume by ~lookback/step vs
        // production, which dedups matched events across cycles. De-duplicating
        // here means threading per-event ids through the concurrent evaluator
        // (memory-bound for high-volume rules); tracked on NAN-1716 as a
        // follow-up so the tester's per-window semantics aren't changed under a
        // rushed pass.
        windows.push(TimeRangeInput::new(tick - lookback, tick));
    }
    Ok(windows)
}

/// Build the exact production cadence/lookback windows used by autonomous
/// tuning validation while enforcing its tighter unattended-workload limits.
pub(crate) fn tuning_test_windows(
    range: &TimeRangeInput,
    schedule_cron: Option<&str>,
    lookback_minutes: Option<i64>,
) -> Result<TuningWindowPlan, DetectionError> {
    validate_test_range(range)?;
    let schedule_cron = schedule_cron.ok_or_else(|| {
        DetectionError::InvalidQuery(
            "Autonomous tuning validation requires the rule's production schedule".to_string(),
        )
    })?;
    let lookback_minutes = lookback_minutes.ok_or_else(|| {
        DetectionError::InvalidQuery(
            "Autonomous tuning validation requires the rule's explicit production lookback"
                .to_string(),
        )
    })?;
    if !(1..=10_080).contains(&lookback_minutes) {
        return Err(DetectionError::InvalidQuery(format!(
            "Autonomous tuning lookback must be between 1 and 10080 minutes (got {lookback_minutes})"
        )));
    }
    let windows =
        enumerate_test_windows(range, schedule_cron, Duration::minutes(lookback_minutes))?;
    if windows.len() > MAX_AUTONOMOUS_TUNING_WINDOWS {
        return Err(DetectionError::InvalidQuery(format!(
            "Autonomous tuning produces {} evaluation windows, exceeding the {}-window cap",
            windows.len(),
            MAX_AUTONOMOUS_TUNING_WINDOWS
        )));
    }
    let total_scan_seconds = windows
        .iter()
        .try_fold(0_i64, |total, window| {
            total.checked_add((window.end - window.start).num_seconds())
        })
        .and_then(|seconds| seconds.checked_mul(AUTONOMOUS_TUNING_REPLAY_QUERY_COUNT));
    if total_scan_seconds.is_none_or(|seconds| seconds > MAX_AUTONOMOUS_TUNING_TOTAL_SCAN_SECONDS) {
        return Err(DetectionError::InvalidQuery(format!(
            "Autonomous tuning scan exceeds the {}-second aggregate budget",
            MAX_AUTONOMOUS_TUNING_TOTAL_SCAN_SECONDS
        )));
    }
    Ok(TuningWindowPlan {
        schedule_cron: schedule_cron.to_string(),
        lookback_minutes,
        windows,
    })
}

/// Compute the step interval (in seconds) implied by a cron expression by
/// measuring the gap between two consecutive upcoming ticks. Approximate for
/// non-uniform schedules (`0 9-17 * * *`) but accurate for the typical
/// detection-rule shapes (`*/N * * * *`, `0 * * * *`, etc.). Used purely as
/// a histogram-granularity hint for the UI; correctness of the per-window
/// evaluation does not depend on it.
pub fn step_seconds(cron_expr: &str) -> Option<u64> {
    let normalized = crate::detection::scheduler::normalize_cron_expression(cron_expr);
    let schedule = cron::Schedule::from_str(&normalized).ok()?;
    let mut iter = schedule.upcoming(Utc).take(2);
    let a = iter.next()?;
    let b = iter.next()?;
    Some((b - a).num_seconds().max(0) as u64)
}

/// Validate that a test time range is well-formed and within the 14-day cap.
/// Returns `InvalidQuery` (which surfaces as a 400 to the caller) on
/// violation rather than `SearchError` so the UI can show it inline.
pub fn validate_test_range(range: &TimeRangeInput) -> Result<(), DetectionError> {
    if range.end <= range.start {
        return Err(DetectionError::InvalidQuery(
            "Test time range must have end > start".to_string(),
        ));
    }
    let span = range.end - range.start;
    if span > Duration::days(MAX_TEST_RANGE_DAYS) {
        return Err(DetectionError::InvalidQuery(format!(
            "Test range cannot exceed {} days (got {:.1} days)",
            MAX_TEST_RANGE_DAYS,
            span.num_seconds() as f64 / 86_400.0,
        )));
    }
    Ok(())
}

/// Parse a JSON value into a UTC timestamp. Accepts ISO-8601 strings and
/// Unix epoch seconds (numeric).
fn parse_bucket_timestamp(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    if let Some(s) = value.as_str() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Some(dt.with_timezone(&Utc));
        }
        // Try date-only fallback (existing daily-timechart shape).
        if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            if let Some(dt) = date.and_hms_opt(0, 0, 0) {
                return Some(Utc.from_utc_datetime(&dt));
            }
        }
        // Last-ditch: try "YYYY-MM-DD HH:MM:SS"
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
            return Some(Utc.from_utc_datetime(&dt));
        }
    }
    if let Some(secs) = value.as_i64() {
        return Utc.timestamp_opt(secs, 0).single();
    }
    None
}

/// Roll bucketed counts up to per-day totals for back-compat consumers.
fn derive_daily_counts(buckets: &[TimeBucket]) -> Vec<DailyMatchCount> {
    let mut by_day: BTreeMap<String, u64> = BTreeMap::new();
    for b in buckets {
        let date = b.bucket_start.format("%Y-%m-%d").to_string();
        *by_day.entry(date).or_default() += b.count;
    }
    by_day
        .into_iter()
        .map(|(date, count)| DailyMatchCount { date, count })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_minute_buckets_for_short_window() {
        // 30 min window → 1m buckets (30 ≤ 50).
        assert_eq!(pick_bucket_size_seconds(Duration::minutes(30)), 60);
    }

    #[test]
    fn picks_five_minute_buckets_for_one_to_four_hour_window() {
        // 1h would be 60 buckets at 1m → step up to 5m (12 buckets).
        assert_eq!(pick_bucket_size_seconds(Duration::hours(1)), 300);
        assert_eq!(pick_bucket_size_seconds(Duration::hours(4)), 300);
    }

    #[test]
    fn picks_fifteen_minute_buckets_for_quarter_day() {
        assert_eq!(pick_bucket_size_seconds(Duration::hours(12)), 900);
    }

    #[test]
    fn picks_hourly_buckets_for_one_day_window() {
        // 24h at 15m = 96 → step up to 1h (24 buckets).
        assert_eq!(pick_bucket_size_seconds(Duration::days(1)), 3600);
    }

    #[test]
    fn picks_six_hour_buckets_for_seven_day_window() {
        // 7d at 1h = 168 → step up to 6h (28 buckets).
        assert_eq!(pick_bucket_size_seconds(Duration::days(7)), 21_600);
    }

    #[test]
    fn picks_daily_buckets_for_thirty_day_window() {
        // 30d at 6h = 120 → step up to 1d (30 buckets).
        assert_eq!(pick_bucket_size_seconds(Duration::days(30)), 86_400);
    }

    #[test]
    fn parse_bucket_timestamp_rfc3339() {
        let v = serde_json::Value::String("2026-05-04T12:30:00Z".to_string());
        let dt = parse_bucket_timestamp(&v).unwrap();
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2026-05-04T12:30:00Z"
        );
    }

    #[test]
    fn parse_bucket_timestamp_date_only() {
        let v = serde_json::Value::String("2026-05-04".to_string());
        let dt = parse_bucket_timestamp(&v).unwrap();
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2026-05-04T00:00:00Z"
        );
    }

    #[test]
    fn step_seconds_for_every_5_minutes_5field() {
        // saturn's `windows_failed_login_threshold` cron — 5-field, normalized
        // by prepending "0 ". Step = 300s.
        assert_eq!(step_seconds("*/5 * * * *"), Some(300));
    }

    #[test]
    fn step_seconds_for_hourly() {
        assert_eq!(step_seconds("0 * * * *"), Some(3600));
    }

    #[test]
    fn step_seconds_for_every_5_minutes_6field() {
        // 6-field: explicit "0" seconds prefix.
        assert_eq!(step_seconds("0 */5 * * * *"), Some(300));
    }

    #[test]
    fn step_seconds_for_invalid_cron_returns_none() {
        assert_eq!(step_seconds("not a cron"), None);
        assert_eq!(step_seconds(""), None);
    }

    #[test]
    fn enumerate_test_windows_5min_step_15min_lookback() {
        // 1-hour range, every 5 min, 15-min lookback. Both the `12:00:00`
        // boundary tick (audit D36) and the `13:00:00` end tick are inclusive →
        // 13 windows. Each window ends at a tick and starts 15 min before. This
        // is what the saturn bug case (`windows_failed_login_threshold`) would
        // have evaluated.
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 5, 5, 13, 0, 0).unwrap();
        let range = TimeRangeInput::new(start, end);
        let windows = enumerate_test_windows(&range, "*/5 * * * *", Duration::minutes(15))
            .expect("valid cron");

        assert_eq!(
            windows.len(),
            13,
            "13 ticks in an inclusive 1h window at 5min cadence (12:00..=13:00)"
        );
        // First window ends exactly on the range start (the D36 boundary tick).
        assert_eq!(windows[0].end, start);
        // Window ends advance by 5 min each.
        for pair in windows.windows(2) {
            let delta = pair[1].end - pair[0].end;
            assert_eq!(delta, Duration::minutes(5));
        }
        // Each window's lookback span is 15 min.
        for w in &windows {
            assert_eq!(w.end - w.start, Duration::minutes(15));
        }
    }

    #[test]
    fn autonomous_tuning_windows_bind_production_schedule_and_lookback() {
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let end = start + Duration::hours(1);
        let range = TimeRangeInput::new(start, end);
        let plan = tuning_test_windows(&range, Some("*/15 * * * *"), Some(7)).unwrap();

        assert_eq!(plan.schedule_cron, "*/15 * * * *");
        assert_eq!(plan.lookback_minutes, 7);
        assert_eq!(plan.windows.len(), 5);
        assert!(plan
            .windows
            .iter()
            .all(|window| window.end - window.start == Duration::minutes(7)));
    }

    #[test]
    fn autonomous_tuning_windows_require_a_schedule_and_valid_lookback() {
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let range = TimeRangeInput::new(start, start + Duration::hours(1));

        assert!(tuning_test_windows(&range, None, Some(5)).is_err());
        assert!(tuning_test_windows(&range, Some("*/5 * * * *"), None).is_err());
        assert!(tuning_test_windows(&range, Some("*/5 * * * *"), Some(0)).is_err());
        assert!(tuning_test_windows(&range, Some("*/5 * * * *"), Some(10_081)).is_err());
    }

    #[test]
    fn autonomous_tuning_windows_enforce_fanout_and_scan_budgets() {
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let range = TimeRangeInput::new(start, start + Duration::hours(24));

        assert!(tuning_test_windows(&range, Some("* * * * *"), Some(15)).is_err());
        assert!(tuning_test_windows(&range, Some("0 * * * *"), Some(10_080)).is_err());
        assert!(tuning_test_windows(&range, Some("*/5 * * * *"), Some(20)).is_err());

        let admitted = tuning_test_windows(&range, Some("*/5 * * * *"), Some(15))
            .expect("bounded autonomous replay should be admitted");
        assert_eq!(admitted.windows.len(), 289);
    }

    #[test]
    fn autonomous_replay_batch_enforces_cumulative_row_and_byte_budgets() {
        let rows = vec![
            serde_json::json!({"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}),
            serde_json::json!({"id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}),
        ];
        let exact_bytes = rows
            .iter()
            .map(|row| serialized_json_size(row).unwrap() + 1)
            .sum::<u64>();

        assert_eq!(
            replay_batch_usage(
                &rows,
                0,
                0,
                TuningReplayBudget {
                    rows: 2,
                    bytes: exact_bytes,
                },
            ),
            Some((2, exact_bytes))
        );
        assert!(replay_batch_usage(
            &rows,
            1,
            0,
            TuningReplayBudget {
                rows: 2,
                bytes: u64::MAX,
            },
        )
        .is_none());
        assert!(replay_batch_usage(
            &rows,
            0,
            0,
            TuningReplayBudget {
                rows: u64::MAX,
                bytes: exact_bytes - 1,
            },
        )
        .is_none());
    }

    #[test]
    fn autonomous_replay_query_ids_are_owned_stable_and_unique() {
        let ids = tuning_replay_query_ids("tuning-proof-original", 3);
        assert_eq!(
            ids,
            vec![
                "tuning-proof-original-0",
                "tuning-proof-original-1",
                "tuning-proof-original-2",
            ]
        );
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            3
        );
        assert_eq!(
            AUTONOMOUS_TUNING_REPLAY_QUERY_COUNT, 2,
            "only original and proposed data lanes are admitted; bounded search suppresses count companions"
        );
    }

    #[test]
    fn autonomous_window_cap_plus_one_preserves_exact_boundary_counts() {
        let cap = usize::try_from(MAX_AUTONOMOUS_TUNING_ROWS_PER_WINDOW).unwrap();
        assert!(!autonomous_window_is_truncated(cap));
        assert!(autonomous_window_is_truncated(cap + 1));
        assert!(!autonomous_window_bytes_exceeded(
            MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW
        ));
        assert!(autonomous_window_bytes_exceeded(
            MAX_AUTONOMOUS_TUNING_BYTES_PER_WINDOW + 1
        ));
    }

    #[test]
    fn enumerate_test_windows_includes_boundary_start_tick() {
        // Audit D36: a tick landing exactly on `range.start` must be included —
        // `Schedule::after` alone (strictly-greater) dropped it. Here 12:00:00 is
        // both the range start and an hourly tick.
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 5, 5, 14, 0, 0).unwrap();
        let range = TimeRangeInput::new(start, end);
        let windows =
            enumerate_test_windows(&range, "0 * * * *", Duration::minutes(30)).expect("valid cron");
        // Inclusive on both ends: 12:00, 13:00, 14:00.
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0].end, start, "boundary start tick included");
        assert_eq!(windows[2].end, end);
    }

    #[test]
    fn enumerate_test_windows_offset_start_excludes_pre_start_tick() {
        // When the range start is NOT on a tick, the 1-second probe must not
        // pull in a tick before `range.start`.
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 30).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 5, 5, 12, 2, 0).unwrap();
        let range = TimeRangeInput::new(start, end);
        let windows =
            enumerate_test_windows(&range, "* * * * *", Duration::minutes(1)).expect("valid cron");
        // Only 12:01:00 and 12:02:00 fall in [12:00:30, 12:02:00]; 12:00:00 is
        // before the start and must be excluded.
        assert_eq!(windows.len(), 2);
        assert!(windows.iter().all(|w| w.end >= start && w.end <= end));
    }

    #[test]
    fn enumerate_test_windows_invalid_cron_errors() {
        let range = TimeRangeInput::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 5, 13, 0, 0).unwrap(),
        );
        let err = enumerate_test_windows(&range, "not a cron", Duration::minutes(15)).unwrap_err();
        assert!(matches!(err, DetectionError::InvalidCronExpression(_)));
    }

    #[test]
    fn enumerate_test_windows_one_minute_cron_full_range_overflows_cap() {
        // 1-min cron × 14 days = 20,160 windows — should produce more than the
        // MAX_STEPPED_WINDOWS cap. Verifies the enumerator itself produces the
        // expected count; the cap check lives in `analyze_rule_stepped`.
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 0, 0, 0).unwrap();
        let end = start + Duration::days(14);
        let range = TimeRangeInput::new(start, end);
        let windows =
            enumerate_test_windows(&range, "* * * * *", Duration::minutes(1)).expect("valid cron");
        assert!(
            windows.len() > MAX_STEPPED_WINDOWS,
            "1-min cron × 14d = {} windows; cap is {}",
            windows.len(),
            MAX_STEPPED_WINDOWS,
        );
    }

    #[test]
    fn enumerate_test_windows_empty_range_returns_zero_windows() {
        // Daily-cron rule tested against a 1-hour range with no tick inside it.
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 5, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 5, 5, 12, 35, 0).unwrap();
        let range = TimeRangeInput::new(start, end);
        let windows =
            enumerate_test_windows(&range, "0 0 * * *", Duration::hours(24)).expect("valid cron");
        assert!(
            windows.is_empty(),
            "no daily-midnight tick falls in 12:05–12:35"
        );
    }

    #[test]
    fn validate_test_range_accepts_within_cap() {
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        // Exactly 14 days: allowed.
        let r = TimeRangeInput::new(now - Duration::days(14), now);
        assert!(validate_test_range(&r).is_ok());
        // 1 hour: trivially allowed.
        let r = TimeRangeInput::new(now - Duration::hours(1), now);
        assert!(validate_test_range(&r).is_ok());
    }

    #[test]
    fn validate_test_range_rejects_over_cap() {
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        // 14 days + 1 minute: over cap.
        let r = TimeRangeInput::new(now - Duration::days(14) - Duration::minutes(1), now);
        let err = validate_test_range(&r).unwrap_err();
        match err {
            DetectionError::InvalidQuery(msg) => {
                assert!(msg.contains("14 days"), "error mentions cap: {}", msg);
            }
            other => panic!("expected InvalidQuery, got {:?}", other),
        }
    }

    #[test]
    fn validate_test_range_rejects_inverted_range() {
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let r = TimeRangeInput::new(now, now - Duration::hours(1));
        assert!(matches!(
            validate_test_range(&r),
            Err(DetectionError::InvalidQuery(_))
        ));
    }

    #[test]
    fn validate_test_range_rejects_zero_width() {
        let now = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let r = TimeRangeInput::new(now, now);
        assert!(matches!(
            validate_test_range(&r),
            Err(DetectionError::InvalidQuery(_))
        ));
    }

    #[test]
    fn derive_daily_rolls_up_buckets() {
        let buckets = vec![
            TimeBucket {
                bucket_start: Utc.with_ymd_and_hms(2026, 5, 4, 0, 0, 0).unwrap(),
                count: 3,
            },
            TimeBucket {
                bucket_start: Utc.with_ymd_and_hms(2026, 5, 4, 6, 0, 0).unwrap(),
                count: 5,
            },
            TimeBucket {
                bucket_start: Utc.with_ymd_and_hms(2026, 5, 5, 0, 0, 0).unwrap(),
                count: 2,
            },
        ];
        let daily = derive_daily_counts(&buckets);
        assert_eq!(daily.len(), 2);
        assert_eq!(daily[0].date, "2026-05-04");
        assert_eq!(daily[0].count, 8);
        assert_eq!(daily[1].date, "2026-05-05");
        assert_eq!(daily[1].count, 2);
    }
}
