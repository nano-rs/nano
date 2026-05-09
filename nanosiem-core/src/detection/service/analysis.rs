// SPDX-License-Identifier: AGPL-3.0-or-later

//! Historical Analysis
//!
//! Historical analysis for false positive tuning and query validation.

use chrono::{DateTime, Duration, TimeZone, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeMap;
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
};

/// Hard cap on the user-selected test range. Mirrors Google SecOps' "Run rule
/// against historical data" cap. Anything longer should use a saved search
/// rather than the interactive tester.
pub const MAX_TEST_RANGE_DAYS: i64 = 14;

/// Concurrency cap for stepped per-window evaluation against ClickHouse. Caps
/// the in-flight load a single test click can put on the database, regardless
/// of how many windows the rule's cadence produces over the user's range.
const STEPPED_TESTER_CONCURRENCY: usize = 16;

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
    60,        // 1m
    300,       // 5m
    900,       // 15m
    3600,      // 1h
    21_600,    // 6h
    86_400,    // 1d
    604_800,   // 7d
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
        };

        let response = self
            .search_service
            .search(request)
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))?;

        let (matches_by_bucket, bucket_size_seconds) =
            self.compute_match_buckets(&rule.query, &time_range).await;
        let matches_by_day = derive_daily_counts(&matches_by_bucket);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(HistoricalAnalysisResult {
            rule_id: rule.id,
            rule_name: rule.name,
            time_range,
            // Use actual result count after all post-processing (stats, where, etc.)
            // not total_count which is from SQL execution before in-memory processing
            total_matches: response.results.len() as u64,
            sample_events: response.results,
            matches_by_day,
            matches_by_bucket,
            bucket_size_seconds,
            execution_time_ms,
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
            .run_stepped_windows(&rule.query, &windows, bucket_size_seconds)
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
    ) -> Result<HistoricalAnalysisResult, DetectionError> {
        validate_test_range(&time_range)?;
        self.validate_query(query)?;

        let lookback = Duration::minutes(
            lookback_minutes.unwrap_or(DEFAULT_STEPPED_LOOKBACK_MINUTES),
        );
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
            "Stepped ad-hoc query test: evaluating {} windows", windows.len()
        );

        let result = self
            .run_stepped_windows(query, &windows, bucket_size_seconds)
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
            futures.push(async move {
                let _permit = sem
                    .acquire_owned()
                    .await
                    .expect("stepped tester semaphore should not close");
                let result = svc.evaluate_window(&q, w.clone()).await;
                (w, result)
            });
        }

        let mut total_matches: u64 = 0;
        let mut sample_events: Vec<serde_json::Value> = Vec::new();
        let mut buckets: Vec<TimeBucket> = Vec::with_capacity(windows.len());

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
                    for row in rows {
                        if sample_events.len() >= max_samples {
                            break;
                        }
                        sample_events.push(row);
                    }
                }
                Err(e) => {
                    warn!(
                        "Stepped tester: window {}..{} failed: {}",
                        window.start, window.end, e
                    );
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
        }
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
        };

        let response = self
            .search_service
            .search(request)
            .await
            .map_err(|e| DetectionError::SearchError(e.to_string()))?;

        let (matches_by_bucket, bucket_size_seconds) =
            self.compute_match_buckets(query, &time_range).await;
        let matches_by_day = derive_daily_counts(&matches_by_bucket);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(HistoricalAnalysisResult {
            rule_id: Uuid::nil(), // No rule ID for ad-hoc query
            rule_name: "Ad-hoc Query".to_string(),
            time_range,
            // Use actual result count after all post-processing (stats, where, etc.)
            // not total_count which is from SQL execution before in-memory processing
            total_matches: response.results.len() as u64,
            sample_events: response.results,
            matches_by_day,
            matches_by_bucket,
            bucket_size_seconds,
            execution_time_ms,
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

        let timechart_query = format!(
            "{} | timechart span={}s count()",
            base_filter, bucket_size
        );
        // Cap at MAX_BUCKETS + a small slack for boundary buckets.
        let limit = (MAX_BUCKETS as usize) + 5;
        let buckets = self
            .fetch_bucket_counts(&timechart_query, time_range, limit)
            .await;
        (buckets, bucket_size)
    }

    /// Fetch bucket counts using a timechart query.
    async fn fetch_bucket_counts(
        &self,
        timechart_query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
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
        };

        match self.search_service.search(request).await {
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
    let schedule = cron::Schedule::from_str(&normalized).map_err(|e| {
        DetectionError::InvalidCronExpression(format!("{}: {}", schedule_cron, e))
    })?;

    let mut windows = Vec::new();
    for tick in schedule.after(&range.start) {
        if tick > range.end {
            break;
        }
        windows.push(TimeRangeInput::new(tick - lookback, tick));
    }
    Ok(windows)
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
        assert_eq!(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(), "2026-05-04T12:30:00Z");
    }

    #[test]
    fn parse_bucket_timestamp_date_only() {
        let v = serde_json::Value::String("2026-05-04".to_string());
        let dt = parse_bucket_timestamp(&v).unwrap();
        assert_eq!(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(), "2026-05-04T00:00:00Z");
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
        // 1-hour range, every 5 min, 15-min lookback → 12 windows. Each window
        // ends at a tick and starts 15 min before. This is what the saturn
        // bug case (`windows_failed_login_threshold`) would have evaluated.
        let start = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 5, 5, 13, 0, 0).unwrap();
        let range = TimeRangeInput::new(start, end);
        let windows = enumerate_test_windows(&range, "*/5 * * * *", Duration::minutes(15))
            .expect("valid cron");

        assert_eq!(windows.len(), 12, "12 ticks in a 1h window at 5min cadence");
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
    fn enumerate_test_windows_invalid_cron_errors() {
        let range = TimeRangeInput::new(
            Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 5, 13, 0, 0).unwrap(),
        );
        let err =
            enumerate_test_windows(&range, "not a cron", Duration::minutes(15)).unwrap_err();
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
        let windows = enumerate_test_windows(&range, "* * * * *", Duration::minutes(1))
            .expect("valid cron");
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
