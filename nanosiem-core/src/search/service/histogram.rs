// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Generate histogram data for a piped query
    /// Extracts the base filter (before any pipe commands) and generates time buckets
    ///
    /// NAN-1428: `query_id` should be the derived `{request_id}-hist` id so
    /// the companion is killable by `KILL QUERY` alongside the data query.
    pub(crate) async fn generate_histogram(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        query_id: Option<&str>,
        dataset: crate::query::Dataset,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        // NAN-1798 P2: the risk dataset has no meaningful time axis at entity
        // grain (one row per entity; fixed trailing 24h/7d windows) — an empty
        // timeline, guarded HERE so every caller (core_search, streaming) is
        // covered without per-site checks.
        if dataset == crate::query::Dataset::Risk {
            return Ok(Vec::new());
        }

        // Extract base filter (everything before the first pipe command)
        let base_query = extract_base_query(query);

        // A leading-pipe query (e.g. `| stats count by src_ip`) has no base
        // filter, so `base_query` is empty. Mirror the main parser's `query()`,
        // which substitutes an implicit match-all wildcard for a leading `|`;
        // parsing the empty string instead would fail with "Empty query" and
        // silently drop the timeline (NAN-1179).
        let parsed = if base_query.is_empty() {
            Query::Search(crate::query::SearchExpr::Keyword("*".to_string()))
        } else {
            parse_query(base_query).map_err(|e| convert_parse_error(e))?
        };

        let tr = TimeRange::new(time_range.start, time_range.end);

        // Calculate appropriate bucket interval based on time range
        let duration_secs = (time_range.end - time_range.start).num_seconds();

        self.generate_clickhouse_histogram(&parsed, &tr, duration_secs, query_id, dataset)
            .await
    }

    /// Generation options for the histogram companion's base query.
    ///
    /// NAN-1635 (finding 2.2): the base must be an unbounded flat scan, like
    /// the raw-SQL histogram (`generate_clickhouse_histogram_for_time_range`).
    /// Default options baked `ORDER BY timestamp DESC LIMIT 1000000` into the
    /// base, which (a) made the sort semantically required — a forced top-1M
    /// sort on every broad search (Saturn: 2x wall, ~2750x memory) — and
    /// (b) silently truncated the timeline to the newest 1M events (17 buckets
    /// shown vs 289 real ones over a 21.77M-event day). `limit: None` still
    /// preserves user-semantic LIMITs (`| head` never reaches here — the base
    /// is pipe-stripped — but subsearch caps inside the base expression are
    /// emitted regardless, per the QueryOptions contract).
    pub(crate) fn histogram_base_options() -> crate::query::QueryOptions {
        crate::query::QueryOptions {
            use_cache: false,
            table_view: false,
            limit: None,
            unordered: true,
        }
    }

    /// Generate histogram for ClickHouse backend
    async fn generate_clickhouse_histogram(
        &self,
        query: &Query,
        time_range: &TimeRange,
        duration_secs: i64,
        query_id: Option<&str>,
        dataset: crate::query::Dataset,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        // Verify ClickHouse client is configured
        if self.ch_client.is_none() {
            return Err(SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            )));
        }

        // Generate base SQL for the search expression. NAN-1557: thread the
        // observability dataset so the timeline reads `otel_spans`/`otel_metrics`
        // (not `logs`) and buckets on the dataset's own time column (`start_time`
        // for spans). `Dataset::Logs` leaves the generator untouched (byte-identical).
        let base_gen = if dataset == crate::query::Dataset::Logs {
            self.ch_sql_generator.clone()
        } else {
            self.ch_sql_generator.clone().with_dataset(dataset)
        };
        let base_sql = base_gen
            .generate_with_options(query, time_range, &Self::histogram_base_options())
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // The histogram buckets the BASE query's output, which carries the
        // dataset's time column (spans → `start_time`).
        let tc = dataset.time_column();

        // Determine the time bucket function and interval based on duration
        // (finer granularity for short windows; NAN-5144 caps the count).
        let (time_bucket_func, interval_secs) = npl_histogram_bucket(duration_secs, tc);

        let histogram_sql = format!(
            r#"
            SELECT 
                {} as time_bucket,
                count(*) as count
            FROM ({}) as base_query
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
            "#,
            time_bucket_func, base_sql
        );

        debug!("ClickHouse histogram SQL: {}", histogram_sql);

        // Execute the query using dynamic JSON parsing
        let mut histogram = self
            .execute_clickhouse_histogram_query(&histogram_sql, query_id)
            .await?;

        // Fill in missing buckets with zero counts to show the complete time range
        histogram = Self::fill_histogram_gaps(histogram, time_range, interval_secs);

        Ok(histogram)
    }

    /// Execute a ClickHouse histogram query and parse results dynamically
    ///
    /// NAN-1428: carries the derived companion query_id (when given) and the
    /// resolved per-priority settings from the admission-controlled path, so
    /// the companion is cancellable and bounded like the data query.
    async fn execute_clickhouse_histogram_query(
        &self,
        sql: &str,
        query_id: Option<&str>,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let ch_client = self.ch_client.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        // Escape ? characters in string literals to prevent clickhouse-rs from
        // interpreting them as parameter placeholders (e.g., in regex patterns like (?i))
        let escaped_sql = escape_question_marks_in_strings(sql);

        // Use fetch_bytes with JSONEachRow format
        let mut cursor = execution::clickhouse_executor::with_query_options(
            ch_client.query(&escaped_sql),
            query_id,
            self.active_ch_settings.as_ref(),
        )
        .fetch_bytes("JSONEachRow")
        .map_err(|e| SearchError::DatabaseError(sqlx::Error::Protocol(e.to_string())))?;

        // Collect all bytes from the cursor.
        //
        // NAN-1429 (E5): must distinguish a stream Err from end-of-stream. The
        // old `while let Ok(Some(chunk))` treated a mid-stream ClickHouse error
        // (e.g. the execution-time cap firing on a full-range scan) as EOF, so
        // partial/empty buckets flowed into `fill_histogram_gaps`, which
        // zero-filled them into a confidently wrong all-zero timeline next to
        // real result rows. Same fix NAN-1160/1177 applied to count/field-stats.
        // Both histogram call sites wrap in match{Ok/Err→None}, so propagating
        // yields histogram:null plus a logged warning.
        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("Histogram query failed mid-stream: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        }

        // Parse JSONEachRow format
        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in ClickHouse response: {}",
                e
            )))
        })?;

        let histogram: Vec<HistogramBucket> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let json: serde_json::Value = serde_json::from_str(line).ok()?;
                let time_str = json.get("time_bucket")?.as_str()?;
                let count = json.get("count")?.as_u64()?;

                // Parse the timestamp - ClickHouse returns "YYYY-MM-DD HH:MM:SS" format
                let time = chrono::NaiveDateTime::parse_from_str(time_str, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc())?;

                Some(HistogramBucket { time, count })
            })
            .collect();

        Ok(histogram)
    }

    /// Test-only seam (NAN-1436): run the real nPL histogram path with
    /// explicitly forced per-query ClickHouse settings.
    ///
    /// `generate_histogram` is `pub(crate)` and `active_ch_settings` is only
    /// set by the admission-controlled path (whose per-priority settings are
    /// fixed), so the forced-error regression test for the NAN-1429 read-loop
    /// fix — which must drive `execute_clickhouse_histogram_query` into a real
    /// ClickHouse stream error — cannot reach this code through the public
    /// API. This wrapper is the smallest surface that exercises the actual
    /// fixed loop with a real cursor; it is not part of the supported API.
    #[doc(hidden)]
    pub async fn histogram_with_forced_ch_settings(
        &mut self,
        query: &str,
        time_range: &TimeRangeInput,
        settings: crate::search::admission::ClickHouseQuerySettings,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        self.active_ch_settings = Some(settings);
        self.generate_histogram(query, time_range, None, crate::query::Dataset::Logs)
            .await
    }

    /// Generate histogram for a time range (used for raw SQL queries)
    pub(crate) async fn generate_histogram_for_time_range(
        &self,
        time_range: &TimeRangeInput,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let duration_secs = (time_range.end - time_range.start).num_seconds();

        self.generate_clickhouse_histogram_for_time_range(time_range, duration_secs)
            .await
    }

    /// Generate histogram for ClickHouse for a time range
    async fn generate_clickhouse_histogram_for_time_range(
        &self,
        time_range: &TimeRangeInput,
        duration_secs: i64,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        // Verify ClickHouse client is configured
        if self.ch_client.is_none() {
            return Err(SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            )));
        }

        let (time_bucket_func, interval_secs) = raw_histogram_bucket(duration_secs);

        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let histogram_sql = format!(
            r#"
            SELECT
                {} as time_bucket,
                count(*) as count
            FROM {}
            WHERE {}
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
            "#,
            time_bucket_func,
            logs_table,
            // NAN-4280: the same half-open window as the search it charts.
            crate::sql_hygiene::half_open_time_bound(
                "timestamp",
                &crate::sql_hygiene::format_ch_bound_micros(&time_range.start),
                &crate::sql_hygiene::format_ch_bound_micros(&time_range.end),
            )
        );

        // Execute query and fill gaps
        let mut histogram = self
            .execute_clickhouse_histogram_query(&histogram_sql, None)
            .await?;

        // Convert TimeRangeInput to TimeRange for fill_histogram_gaps
        let tr = TimeRange {
            start: time_range.start,
            end: time_range.end,
        };
        histogram = Self::fill_histogram_gaps(histogram, &tr, interval_secs);

        Ok(histogram)
    }

    /// Fill in missing histogram buckets with zero counts to show complete time range
    /// This ensures the histogram spans the entire requested time range, not just where events exist.
    ///
    /// NAN-5144: never emits more than [`MAX_HISTOGRAM_BUCKETS`] buckets. The
    /// interval selection already keeps a window under that; this is the
    /// backstop so no caller can make the fill allocate without bound.
    pub(crate) fn fill_histogram_gaps(
        mut histogram: Vec<HistogramBucket>,
        time_range: &TimeRange,
        interval_secs: i64,
    ) -> Vec<HistogramBucket> {
        if interval_secs <= 0 {
            return histogram;
        }
        // Align start time to bucket boundary (floor to interval; euclidean so
        // a pre-1970 start still lands on a boundary instead of past it)
        let start_ts = time_range.start.timestamp();
        let aligned_start_ts = start_ts.div_euclid(interval_secs) * interval_secs;
        let aligned_start =
            chrono::DateTime::from_timestamp(aligned_start_ts, 0).unwrap_or(time_range.start);
        let step = chrono::Duration::seconds(interval_secs);

        // Build a map of bucket timestamp -> count for O(1) lookup
        let bucket_map: std::collections::HashMap<i64, u64> = histogram
            .drain(..)
            .map(|b| (b.time.timestamp(), b.count))
            .collect();

        let mut result = Vec::new();
        let mut current = aligned_start;

        // Iterate through the entire time range, filling gaps
        while current < time_range.end && result.len() < MAX_HISTOGRAM_BUCKETS {
            let count = bucket_map.get(&current.timestamp()).copied().unwrap_or(0);
            result.push(HistogramBucket {
                time: current,
                count,
            });
            current = current + step;
        }

        result
    }
}

/// Upper bound on histogram buckets for one search (NAN-5144). The finest
/// interval is kept for normal windows; longer windows coarsen so the
/// bucket count stays at or under this, in both the SQL and the gap-fill.
pub(crate) const MAX_HISTOGRAM_BUCKETS: usize = 10_000;

/// Coarser intervals a long window steps up to, smallest first: hour,
/// 6 hours, day, week, 30 days, 365 days.
const COARSE_INTERVALS_SECS: &[i64] = &[3_600, 21_600, 86_400, 604_800, 2_592_000, 31_536_000];

/// `base_secs` unless the window would need more than
/// [`MAX_HISTOGRAM_BUCKETS`] of them; then the smallest coarser interval
/// that fits (falling back to a whole number of days for anything longer).
pub(crate) fn capped_histogram_interval(duration_secs: i64, base_secs: i64) -> i64 {
    let max = MAX_HISTOGRAM_BUCKETS as i64;
    // Strictly under: an unaligned start adds one partial leading bucket.
    let fits = |interval: i64| duration_secs.max(0) / interval < max;
    if fits(base_secs) {
        return base_secs;
    }
    COARSE_INTERVALS_SECS
        .iter()
        .copied()
        .find(|&interval| interval > base_secs && fits(interval))
        .unwrap_or_else(|| {
            let days = duration_secs.max(0) / (max - 1) / 86_400 + 1;
            days * 86_400
        })
}

/// Bucket expression + interval for the nPL histogram companion.
pub(crate) fn npl_histogram_bucket(duration_secs: i64, tc: &str) -> (String, i64) {
    let (func, base) = match duration_secs {
        d if d <= 300 => (format!("toStartOfInterval({tc}, INTERVAL 5 SECOND)"), 5),
        d if d <= 900 => (format!("toStartOfInterval({tc}, INTERVAL 10 SECOND)"), 10),
        d if d <= 1800 => (format!("toStartOfInterval({tc}, INTERVAL 30 SECOND)"), 30),
        d if d <= 3600 => (format!("toStartOfMinute({tc})"), 60),
        d if d <= 7200 => (format!("toStartOfMinute({tc})"), 60),
        d if d <= 21600 => (format!("toStartOfFiveMinutes({tc})"), 300),
        d if d <= 43200 => (format!("toStartOfFiveMinutes({tc})"), 300),
        d if d <= 86400 => (format!("toStartOfFiveMinutes({tc})"), 300),
        d if d <= 172800 => (format!("toStartOfTenMinutes({tc})"), 600),
        d if d <= 604800 => (format!("toStartOfInterval({tc}, INTERVAL 30 MINUTE)"), 1800),
        _ => (format!("toStartOfHour({tc})"), 3600),
    };
    cap_bucket(duration_secs, tc, func, base)
}

/// Bucket expression + interval for the raw-SQL / field-stats histogram.
pub(crate) fn raw_histogram_bucket(duration_secs: i64) -> (String, i64) {
    let tc = "timestamp";
    let (func, base) = match duration_secs {
        d if d <= 300 => (format!("toStartOfInterval({tc}, INTERVAL 5 SECOND)"), 5),
        d if d <= 900 => (format!("toStartOfInterval({tc}, INTERVAL 10 SECOND)"), 10),
        d if d <= 1800 => (format!("toStartOfInterval({tc}, INTERVAL 30 SECOND)"), 30),
        d if d <= 3600 => (format!("toStartOfMinute({tc})"), 60),
        d if d <= 7200 => (format!("toStartOfMinute({tc})"), 60),
        d if d <= 21600 => (format!("toStartOfFiveMinutes({tc})"), 300),
        d if d <= 43200 => (format!("toStartOfTenMinutes({tc})"), 600),
        d if d <= 86400 => (format!("toStartOfFifteenMinutes({tc})"), 900),
        d if d <= 172800 => (format!("toStartOfInterval({tc}, INTERVAL 30 MINUTE)"), 1800),
        d if d <= 604800 => (format!("toStartOfHour({tc})"), 3600),
        _ => (format!("toStartOfDay({tc})"), 86400),
    };
    cap_bucket(duration_secs, tc, func, base)
}

/// Keep `func` when its interval fits the cap; otherwise bucket on the
/// capped interval by plain epoch-second division, the same floor the
/// gap-fill uses, rendered as a second-precision UTC DateTime so the bucket
/// keys parse and match exactly.
fn cap_bucket(duration_secs: i64, tc: &str, func: String, base: i64) -> (String, i64) {
    let interval = capped_histogram_interval(duration_secs, base);
    if interval == base {
        return (func, base);
    }
    (
        format!("toDateTime(intDiv(toUnixTimestamp({tc}), {interval}) * {interval}, 'UTC')"),
        interval,
    )
}
