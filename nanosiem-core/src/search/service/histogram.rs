// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// A search's timeline answered on its own (NAN-3093,
/// `POST /api/search/histogram`).
#[derive(Debug, Clone, Default)]
pub struct SearchHistogramResult {
    /// The same buckets the search response would carry in `histogram`.
    pub histogram: Vec<HistogramBucket>,
    /// The search's exact total when the timeline proves it (every base
    /// event is exactly one result row); `None` otherwise.
    pub total_count: Option<u64>,
}

impl SearchService {
    /// A request-local view that answers only the timeline of a search
    /// (see the `histogram_only` field).
    pub fn histogram_only(&self) -> Self {
        let mut view = self.clone();
        view.histogram_only = true;
        view
    }

    /// The histogram (and, when provable, the exact total) of one search,
    /// admission-gated like the other search companions (NAN-3093).
    ///
    /// The Search page used to receive the timeline inside the search
    /// response, so rows never painted before the histogram companion was
    /// back. Asking for it separately lets rows paint first. On the primary
    /// lake the view runs the full search preparation (scope, IOC and
    /// lookup resolution) and then only the histogram companion; any other
    /// backend answers from a one-row search, whose histogram is the same.
    pub async fn search_histogram_with_admission(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        dataset: Option<&str>,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        scope: &crate::auth::ScopeSet,
    ) -> Result<SearchHistogramResult, SearchError> {
        let mut view = self.histogram_only();
        let _permit = match self.required_admission_controller()? {
            Some(controller) => {
                let job_id = uuid::Uuid::now_v7().to_string();
                let permit = self
                    .acquire_auxiliary_search_admission(&controller, &job_id, user_id, priority)
                    .await
                    .map_err(SearchError::from)?;
                view.active_ch_settings = Some(view.ch_settings_for_priority(priority));
                Some(permit)
            }
            None => None,
        };
        let request = SearchRequest {
            query: query.to_string(),
            time_range: time_range.clone(),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: false,
            skip_field_stats: true,
            use_cache: true,
            table_view: true,
            // No request id: the rows search owns the caller's id (and its
            // cancel registration); this companion never replaces it.
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: dataset.map(str::to_string),
        };
        let response = view.search(request, scope).await?;
        Ok(SearchHistogramResult {
            total_count: (response.total_count_exact && response.histogram.is_some())
                .then_some(response.total_count),
            histogram: response.histogram.unwrap_or_default(),
        })
    }

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
        deny_source_types: &std::collections::BTreeSet<String>,
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

        if self.lake_query.mode == LakeQueryMode::Primary && dataset == crate::query::Dataset::Logs
        {
            return self
                .generate_lake_histogram(
                    base_query,
                    time_range,
                    duration_secs,
                    query_id,
                    deny_source_types,
                )
                .await;
        }

        self.generate_clickhouse_histogram(&parsed, &tr, duration_secs, query_id, dataset)
            .await
    }

    async fn generate_lake_histogram(
        &self,
        base_query: &str,
        time_range: &TimeRangeInput,
        duration_secs: i64,
        query_id: Option<&str>,
        deny_source_types: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let base_query = if base_query.is_empty() {
            "*"
        } else {
            base_query
        };
        // NAN-3163: the rollup decision is made on the base without the
        // caller's injected source-scope gate (the rollup request enforces the
        // same deny set itself); the raw timechart keeps the gated base.
        let rollup_base = lake_histogram_rollup_base(base_query, deny_source_types);
        let (span, interval_secs) =
            lake_histogram_span_for(self.active_profile.as_ref(), &rollup_base, duration_secs);
        let histogram_query_id = query_id
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}-hist", uuid::Uuid::now_v7()));
        let query = format!("{base_query} | timechart span={span} count() as count");
        let rollup_query = format!("{rollup_base} | timechart span={span} count() as count");
        if let Some(histogram) = self
            .query_lake_histogram_rollup(
                client,
                &rollup_query,
                time_range,
                interval_secs,
                &histogram_query_id,
                deny_source_types,
            )
            .await
        {
            return Ok(self.fill_histogram_gaps(
                merge_lake_histogram_rows(histogram),
                &TimeRange::new(time_range.start, time_range.end),
                interval_secs,
            ));
        }
        // The worker already applies the entity/text sidecars and count rollup
        // to a bounded full-range timechart. Splitting every range wider than
        // one hour into N independent requests multiplied compiler, planner,
        // HTTP, and chDB-session startup cost (a 24-hour selective histogram
        // measured ~6.5s as 24 requests vs ~0.4s as one request). Try the exact
        // full-range query first. Hour slices are only a safety fallback when
        // the worker explicitly rejects that plan on its byte budget.
        let histogram = match self
            .query_lake_histogram_range(
                client,
                &query,
                time_range.clone(),
                interval_secs,
                histogram_query_id.clone(),
                deny_source_types,
            )
            .await
        {
            Ok(histogram) => histogram,
            Err(error) if super::core_search::is_lake_scan_budget_rejection(&error) => {
                self.query_lake_histogram_adaptive(
                    client,
                    &query,
                    time_range,
                    interval_secs,
                    &histogram_query_id,
                    deny_source_types,
                )
                .await?
            }
            Err(error) => return Err(error),
        };
        let histogram = merge_lake_histogram_rows(histogram);
        Ok(self.fill_histogram_gaps(
            histogram,
            &TimeRange::new(time_range.start, time_range.end),
            interval_secs,
        ))
    }

    /// Serve the histogram from the exact count rollups when its base and
    /// span allow it (see [`super::core_search::lake_histogram_rollup_plan`]).
    /// `None` means "not eligible or not available": the caller runs the raw
    /// timechart exactly as before, so this never changes a result.
    async fn query_lake_histogram_rollup(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        query: &str,
        time_range: &TimeRangeInput,
        interval_secs: i64,
        histogram_query_id: &str,
        deny_source_types: &std::collections::BTreeSet<String>,
    ) -> Option<Vec<HistogramBucket>> {
        let parsed = super::core_search::lake_rollup_planning_query(
            self.active_profile.as_ref(),
            &parse_query(query).ok()?,
        );
        let plan = super::core_search::lake_histogram_rollup_plan(&parsed)?;
        // NAN-3153: a dotless host equality is sent as `host_eq` (the exact
        // FQDN-expanding form); anything the rollup cannot express scans.
        let predicate = super::core_search::lake_rollup_exact_predicate(
            self.active_profile.as_ref(),
            &plan.field,
            plan.predicate.as_ref(),
        )?;
        let duration_secs = (time_range.end - time_range.start).num_seconds();
        let bucket_limit = (duration_secs.max(0) / interval_secs + 2).clamp(1, 100_000) as usize;
        let rows = match client
            .count_aggregate(
                &format!("{histogram_query_id}-rollup"),
                &plan.field,
                false,
                predicate.as_ref(),
                Some(plan.bucket_span_us),
                "count",
                time_range,
                plan.source_filter.as_deref(),
                deny_source_types,
                bucket_limit,
            )
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::debug!(%error, "lake histogram rollup unavailable; using the raw timechart");
                return None;
            }
        };
        match parse_lake_histogram_rows(rows) {
            Ok(histogram) => Some(histogram),
            Err(error) => {
                tracing::warn!(%error, "lake histogram rollup rows were malformed; using the raw timechart");
                None
            }
        }
    }

    async fn query_lake_histogram_range(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        query: &str,
        range: TimeRangeInput,
        interval_secs: i64,
        query_id: String,
        deny_source_types: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let duration_secs = (range.end - range.start).num_seconds();
        let bucket_limit = (duration_secs.max(0) / interval_secs + 2).clamp(1, 100_000) as usize;
        let request = SearchRequest {
            query: query.to_string(),
            time_range: range,
            limit: Some(bucket_limit),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: Some(query_id.clone()),
            async_mode: false,
            priority: Some("interactive".to_string()),
            dataset: Some("logs".to_string()),
        };
        let response = client
            .search(&request, &query_id, None, deny_source_types)
            .await?;
        parse_lake_histogram_rows(response.results)
    }

    /// Retry an over-budget histogram by bisecting only the ranges that still
    /// exceed the physical scan fence. The previous fallback eagerly expanded
    /// every wide request into one-hour slices: a 40-day query that needed two
    /// halves became 960 HTTP/compiler/chDB sessions and could keep executing
    /// long after its caller disconnected. Adaptive bisection preserves exact
    /// buckets while making work proportional to the actual byte pressure.
    async fn query_lake_histogram_adaptive(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        query: &str,
        time_range: &TimeRangeInput,
        interval_secs: i64,
        histogram_query_id: &str,
        deny_source_types: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let Some((older, newer)) = split_lake_histogram_range(time_range) else {
            return Err(SearchError::ResourceExhausted("scan".to_string()));
        };
        let mut pending = vec![("r".to_string(), newer), ("l".to_string(), older)];
        let mut completed = 0_usize;
        let mut histogram = Vec::new();

        while let Some((path, range)) = pending.pop() {
            match self
                .query_lake_histogram_range(
                    client,
                    query,
                    range.clone(),
                    interval_secs,
                    format!("{histogram_query_id}-{path}"),
                    deny_source_types,
                )
                .await
            {
                Ok(mut buckets) => {
                    completed += 1;
                    histogram.append(&mut buckets);
                }
                Err(error) if super::core_search::is_lake_scan_budget_rejection(&error) => {
                    let Some((older, newer)) = split_lake_histogram_range(&range) else {
                        return Err(error);
                    };
                    if completed.saturating_add(pending.len()).saturating_add(2)
                        > LAKE_MAX_HISTOGRAM_CHUNKS
                    {
                        return Err(SearchError::ResourceExhausted("scan".to_string()));
                    }
                    // Stack order keeps the older half first; ordering is not
                    // required for correctness because equal buckets are merged
                    // below, but deterministic execution improves evidence.
                    pending.push((format!("{path}r"), newer));
                    pending.push((format!("{path}l"), older));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(histogram)
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
        // Use finer granularity for better visualization
        let (time_bucket_func, interval_secs) = match duration_secs {
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
        histogram = self.fill_histogram_gaps(histogram, time_range, interval_secs);

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
        let Some(retention_time_range) =
            self.retention_bound_input_range(time_range, chrono::Utc::now())?
        else {
            return Ok(Vec::new());
        };
        self.active_ch_settings = Some(settings);
        self.generate_histogram(
            query,
            &retention_time_range,
            None,
            crate::query::Dataset::Logs,
            &std::collections::BTreeSet::new(),
        )
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

        let (time_bucket_func, interval_secs) = match duration_secs {
            d if d <= 300 => (
                "toStartOfInterval(timestamp, INTERVAL 5 SECOND)".to_string(),
                5,
            ),
            d if d <= 900 => (
                "toStartOfInterval(timestamp, INTERVAL 10 SECOND)".to_string(),
                10,
            ),
            d if d <= 1800 => (
                "toStartOfInterval(timestamp, INTERVAL 30 SECOND)".to_string(),
                30,
            ),
            d if d <= 3600 => ("toStartOfMinute(timestamp)".to_string(), 60),
            d if d <= 7200 => ("toStartOfMinute(timestamp)".to_string(), 60),
            d if d <= 21600 => ("toStartOfFiveMinutes(timestamp)".to_string(), 300),
            d if d <= 43200 => ("toStartOfTenMinutes(timestamp)".to_string(), 600),
            d if d <= 86400 => ("toStartOfFifteenMinutes(timestamp)".to_string(), 900),
            d if d <= 172800 => (
                "toStartOfInterval(timestamp, INTERVAL 30 MINUTE)".to_string(),
                1800,
            ),
            d if d <= 604800 => ("toStartOfHour(timestamp)".to_string(), 3600),
            _ => ("toStartOfDay(timestamp)".to_string(), 86400),
        };

        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let histogram_sql = format!(
            r#"
            SELECT
                {} as time_bucket,
                count(*) as count
            FROM {}
            WHERE timestamp BETWEEN '{}' AND '{}'
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
            "#,
            time_bucket_func,
            logs_table,
            crate::sql_hygiene::format_ch_bound_micros(&time_range.start),
            crate::sql_hygiene::format_ch_bound_micros(&time_range.end)
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
        histogram = self.fill_histogram_gaps(histogram, &tr, interval_secs);

        Ok(histogram)
    }

    /// Fill in missing histogram buckets with zero counts to show complete time range
    /// This ensures the histogram spans the entire requested time range, not just where events exist
    fn fill_histogram_gaps(
        &self,
        mut histogram: Vec<HistogramBucket>,
        time_range: &TimeRange,
        interval_secs: i64,
    ) -> Vec<HistogramBucket> {
        // Align start time to bucket boundary (floor to interval)
        let start_ts = time_range.start.timestamp();
        let aligned_start_ts = (start_ts / interval_secs) * interval_secs;
        let aligned_start =
            chrono::DateTime::from_timestamp(aligned_start_ts, 0).unwrap_or(time_range.start);

        if histogram.is_empty() {
            // If no events at all, create empty buckets for the entire range
            let mut current = aligned_start;
            let mut result = Vec::new();

            while current < time_range.end {
                result.push(HistogramBucket {
                    time: current,
                    count: 0,
                });
                current = current + chrono::Duration::seconds(interval_secs);
            }

            return result;
        }

        // Build a map of bucket timestamp -> count for O(1) lookup
        let bucket_map: std::collections::HashMap<i64, u64> = histogram
            .drain(..)
            .map(|b| (b.time.timestamp(), b.count))
            .collect();

        let mut result = Vec::new();
        let mut current = aligned_start;

        // Iterate through the entire time range, filling gaps
        while current < time_range.end {
            let count = bucket_map.get(&current.timestamp()).copied().unwrap_or(0);
            result.push(HistogramBucket {
                time: current,
                count,
            });
            current = current + chrono::Duration::seconds(interval_secs);
        }

        result
    }
}

const LAKE_MAX_HISTOGRAM_CHUNKS: usize = 4_096;

fn split_lake_histogram_range(
    time_range: &TimeRangeInput,
) -> Option<(TimeRangeInput, TimeRangeInput)> {
    let width_us = (time_range.end - time_range.start).num_microseconds()?;
    if width_us < 2 {
        return None;
    }
    // NAN-4280: windows are half-open `[start, end)`, so the halves share
    // `newer_start` and an event on it lands in exactly one half.
    let newer_start = time_range.start + chrono::Duration::microseconds(width_us / 2);
    Some((
        TimeRangeInput {
            start: time_range.start,
            end: newer_start,
        },
        TimeRangeInput {
            start: newer_start,
            end: time_range.end,
        },
    ))
}

fn merge_lake_histogram_rows(histogram: Vec<HistogramBucket>) -> Vec<HistogramBucket> {
    let mut merged = std::collections::BTreeMap::<chrono::DateTime<chrono::Utc>, u64>::new();
    for bucket in histogram {
        *merged.entry(bucket.time).or_default() += bucket.count;
    }
    merged
        .into_iter()
        .map(|(time, count)| HistogramBucket { time, count })
        .collect()
}

/// The histogram base to plan the count-rollup route from (NAN-3163): the
/// base with the caller's injected lake source-scope gate for
/// `deny_source_types` removed, or the base unchanged when it carries no such
/// gate. Planning only: the rollup request carries `deny_source_types`, and
/// every executed timechart keeps the gated base.
fn lake_histogram_rollup_base(
    base_query: &str,
    deny_source_types: &std::collections::BTreeSet<String>,
) -> String {
    parse_query(base_query)
        .ok()
        .and_then(|parsed| {
            crate::search::query_processing::strip_lake_source_scope_gate(
                &parsed,
                deny_source_types,
            )
        })
        .map(|stripped| stripped.pretty_print())
        .unwrap_or_else(|| base_query.to_string())
}

/// Windows at least this long whose base is rollup-expressible get the
/// rollup bucket (5 min) as their histogram span: at least 12 bars.
const LAKE_HISTOGRAM_ROLLUP_SNAP_MIN_SECS: i64 = 3_600;

/// The histogram span for `base_query` over `duration_secs` (NAN-3093).
///
/// Below two hours the default span (1 min at 1 h) is finer than the parts'
/// 5-minute count rollups, so every 1 h search re-counted ~1M raw rows from
/// ~200 files for its timeline, and a selective pivot read ~650k rows to
/// bucket ~160 matches. When the base is fully rollup-expressible (`*`, a
/// source, a rollup field predicate, or a source AND such a predicate) and
/// the window is at least an hour, the timeline uses the rollup bucket
/// instead and is answered from the rollups (exact; only the ragged window
/// edges are scanned). Narrower windows keep their finer raw timeline.
fn lake_histogram_span_for(
    profile: &dyn crate::schema::SchemaProfile,
    base_query: &str,
    duration_secs: i64,
) -> (&'static str, i64) {
    let (span, interval_secs) = lake_histogram_span(duration_secs);
    if interval_secs >= LAKE_HISTOGRAM_ROLLUP_BUCKET_SECS
        || duration_secs < LAKE_HISTOGRAM_ROLLUP_SNAP_MIN_SECS
    {
        return (span, interval_secs);
    }
    let rollup_query = format!("{base_query} | timechart span=5m count() as count");
    let served_from_rollups = parse_query(&rollup_query)
        .ok()
        .and_then(|parsed| {
            super::core_search::lake_histogram_rollup_plan(
                &super::core_search::lake_rollup_planning_query(profile, &parsed),
            )
        })
        .is_some_and(|plan| {
            // Exactly what the worker's `count_aggregate` serves from the
            // rollup partials; any other field would be a raw scan anyway,
            // so it keeps its finer span.
            let Some(predicate) = super::core_search::lake_rollup_exact_predicate(
                profile,
                &plan.field,
                plan.predicate.as_ref(),
            ) else {
                return false;
            };
            crate::search::lake::lake_count_rollup_field_multi_value(&plan.field)
                    .is_some_and(|multi_value| {
                        !multi_value
                            || predicate.as_ref().is_some_and(|predicate| predicate.kind == "eq")
                    })
        });
    if served_from_rollups {
        ("5m", LAKE_HISTOGRAM_ROLLUP_BUCKET_SECS)
    } else {
        (span, interval_secs)
    }
}

/// The worker's count-rollup bucket (`COUNT_ROLLUP_BUCKET_US`), in seconds.
const LAKE_HISTOGRAM_ROLLUP_BUCKET_SECS: i64 = 300;

fn lake_histogram_span(duration_secs: i64) -> (&'static str, i64) {
    match duration_secs {
        d if d <= 300 => ("5s", 5),
        d if d <= 900 => ("10s", 10),
        d if d <= 1_800 => ("30s", 30),
        d if d <= 7_200 => ("1m", 60),
        d if d <= 86_400 => ("5m", 300),
        d if d <= 172_800 => ("10m", 600),
        d if d <= 604_800 => ("30m", 1_800),
        _ => ("1h", 3_600),
    }
}

fn parse_lake_histogram_rows(
    rows: Vec<serde_json::Value>,
) -> Result<Vec<HistogramBucket>, SearchError> {
    rows.into_iter()
        .map(|row| {
            let time = row
                .get("time_bucket")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| {
                    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                        .ok()
                        .map(|time| time.and_utc())
                        .or_else(|| {
                            chrono::DateTime::parse_from_rfc3339(value)
                                .ok()
                                .map(|time| time.with_timezone(&chrono::Utc))
                        })
                })
                .ok_or_else(|| {
                    SearchError::SqlValidationError(
                        "lake histogram worker returned an invalid time_bucket".to_string(),
                    )
                })?;
            let count = row
                .get("count")
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                })
                .ok_or_else(|| {
                    SearchError::SqlValidationError(
                        "lake histogram worker returned an invalid count".to_string(),
                    )
                })?;
            Ok(HistogramBucket { time, count })
        })
        .collect()
}

#[cfg(test)]
mod lake_histogram_tests {
    use super::*;

    #[test]
    fn span_keeps_interactive_ranges_bounded() {
        assert_eq!(lake_histogram_span(300), ("5s", 5));
        assert_eq!(lake_histogram_span(7_200), ("1m", 60));
        assert_eq!(lake_histogram_span(86_400), ("5m", 300));
        assert_eq!(lake_histogram_span(604_800), ("30m", 1_800));
        assert_eq!(lake_histogram_span(2_592_000), ("1h", 3_600));
    }

    /// NAN-3093: a rollup-expressible base over >= 1 h takes the rollup
    /// bucket so the timeline is answered from part rollups; anything else
    /// keeps its raw span.
    #[test]
    fn rollup_expressible_hour_windows_take_the_rollup_bucket() {
        let profile = crate::schema::OcsfProfile::new();
        let lake_histogram_span_for =
            |base: &str, secs: i64| super::lake_histogram_span_for(&profile, base, secs);
        for base in [
            "*",
            "metadata.log_source=windows_sysmon",
            "metadata.log_source=windows_sysmon src_endpoint.hostname=\"ws-1.corp.local\"",
            "src_endpoint.ip=\"10.0.0.1\"",
            // NAN-4168: enrichment leaves are plain columns, rollups included.
            "src_endpoint.location.country=\"US\"",
            "actor.user.name=\"alice\"",
            // NAN-3153: a dotless host equality also matches the host's
            // FQDNs; the rollup now evaluates exactly that (`host_eq`).
            "metadata.log_source=windows_sysmon src_endpoint.hostname=\"ws-1\"",
        ] {
            assert_eq!(lake_histogram_span_for(base, 3_600), ("5m", 300), "{base}");
            assert_eq!(lake_histogram_span_for(base, 7_200), ("5m", 300), "{base}");
            // Under an hour the finer raw timeline stays.
            assert_eq!(lake_histogram_span_for(base, 1_800), ("30s", 30), "{base}");
            assert_eq!(lake_histogram_span_for(base, 3_599), ("1m", 60), "{base}");
            // Wider windows are unchanged (already rollup buckets or coarser).
            assert_eq!(lake_histogram_span_for(base, 86_400), ("5m", 300), "{base}");
            assert_eq!(lake_histogram_span_for(base, 604_800), ("30m", 1_800), "{base}");
        }
        for base in [
            "powershell",
            "process.cmd_line=\"*whoami*\" OR user.name=\"x\"",
            "unmapped.custom_field=\"x\"",
            "enrichments.value!=\"x\"",
            // Negated dotless host equality has no exact rollup form.
            "metadata.log_source=windows_sysmon src_endpoint.hostname!=\"ws-1\"",
            // A CIDR literal is a range, not a value.
            "src_endpoint.ip=\"10.0.0.0/8\"",
        ] {
            assert_eq!(lake_histogram_span_for(base, 3_600), ("1m", 60), "{base}");
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3093: the histogram-only view runs the timeline alone — from the
    /// count rollups for a rollup-expressible hour — and never the rows query;
    /// its sum is the search's exact total.
    #[tokio::test]
    async fn histogram_only_view_answers_the_timeline_without_the_rows_query() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use chrono::DurationRound;
        let end = chrono::Utc::now().duration_trunc(chrono::Duration::hours(1)).unwrap();
        let start = end - chrono::Duration::hours(1);
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3093);
        let token = tempfile::tempdir().unwrap();
        let token_file = token.path().join("router.token");
        std::fs::write(&token_file, "histogram-only-router-token-1234567890").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let seen: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
        let recorded = seen.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/aggregate/count")))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                recorded.lock().unwrap().push(body.clone());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": body["tenant_id"],
                    "route": "count_aggregate", "source_mode": "parts",
                    "log_head": {"seq": 4, "sha256": "ab".repeat(32)},
                    "result": {"rows": [
                        {"time_bucket": start.to_rfc3339(), "count": 5},
                        {"time_bucket": (start + chrono::Duration::minutes(5)).to_rfc3339(), "count": 7}
                    ]}
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        ))
        .await
        .unwrap();
        let view = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &crate::search::LakeCellRoute {
                    tenant_id: tenant, assignment_generation: 1, part_log_writer_epoch: 1, worker_revision: 1,
                    assignment_fenced: true, cell_origin: server.uri(),
                    query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
                    router_token_file: token_file,
                },
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "metadata.log_source=windows_sysmon",
            "time_range": {"start": start, "end": end},
            "limit": 1
        }))
        .unwrap();
        let response = view
            .histogram_only()
            .search(request, &crate::auth::ScopeSet::default())
            .await
            .unwrap();
        assert!(response.results.is_empty(), "no rows are fetched");
        let histogram = response.histogram.expect("the timeline");
        assert_eq!(histogram.len(), 12, "five-minute buckets over the hour");
        assert_eq!(histogram.iter().map(|bucket| bucket.count).sum::<u64>(), 12);
        assert_eq!((response.total_count, response.total_count_exact), (12, true));
        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls[0]["group_field"], "metadata.log_source");
        assert_eq!(calls[0]["bucket_span_us"], 300_000_000);
    }

    #[cfg(feature = "enterprise")]
    /// A lean-cell tenant view whose query[T] is `server` (NAN-3163 tests).
    async fn nan3163_cell_view(
        server: &wiremock::MockServer,
        tenant: uuid::Uuid,
    ) -> (SearchService, tempfile::TempDir) {
        let token = tempfile::tempdir().unwrap();
        let token_file = token.path().join("router.token");
        std::fs::write(&token_file, "nan3163-router-token-1234567890abcdef").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let view = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &crate::search::LakeCellRoute {
                    tenant_id: tenant,
                    assignment_generation: 1,
                    part_log_writer_epoch: 1,
                    worker_revision: 1,
                    assignment_fenced: true,
                    cell_origin: server.uri(),
                    query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
                    router_token_file: token_file,
                },
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                std::sync::Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        (view, token)
    }

    /// Mount a recording `/v1/aggregate/count` answering `rows`, and a
    /// `/v1/query` that must never be called.
    async fn nan3163_mount_count_only(
        server: &wiremock::MockServer,
        tenant: uuid::Uuid,
        rows: serde_json::Value,
    ) -> std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let seen: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let recorded = seen.clone();
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/tenants/{tenant}/query/v1/aggregate/count"
            )))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                recorded.lock().unwrap().push(body.clone());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": body["tenant_id"],
                    "route": "count_aggregate", "source_mode": "parts",
                    "log_head": {"seq": 4, "sha256": "ab".repeat(32)},
                    "result": {"rows": rows.clone()}
                }))
            })
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(server)
            .await;
        seen
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3163: a caller without `audit:view` (deny set `{audit}`) gets the
    /// same rollup timeline as an unrestricted one; the deny set rides on the
    /// rollup request instead of hiding it.
    #[tokio::test]
    async fn scoped_histogram_is_answered_from_rollups_with_the_deny_set() {
        use chrono::DurationRound;
        let end = chrono::Utc::now()
            .duration_trunc(chrono::Duration::hours(1))
            .unwrap();
        let start = end - chrono::Duration::hours(1);
        let server = wiremock::MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3163);
        let seen = nan3163_mount_count_only(
            &server,
            tenant,
            serde_json::json!([{"time_bucket": start.to_rfc3339(), "count": 5}]),
        )
        .await;
        let (view, _token) = nan3163_cell_view(&server, tenant).await;
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": r#"device.hostname="ws-hr-132.corp.local""#,
            "time_range": {"start": start, "end": end},
            "limit": 1
        }))
        .unwrap();
        let scope = crate::auth::compose_viewer_scope(&crate::auth::ScopeSet::default(), false);
        let response = view.histogram_only().search(request, &scope).await.unwrap();
        let histogram = response.histogram.expect("the timeline");
        assert_eq!(
            histogram.len(),
            12,
            "five-minute rollup buckets over the hour"
        );
        assert_eq!(histogram.iter().map(|bucket| bucket.count).sum::<u64>(), 5);
        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(calls[0]["group_field"], "device.hostname");
        assert_eq!(
            calls[0]["predicate"],
            serde_json::json!({"kind": "eq", "values": ["ws-hr-132.corp.local"]})
        );
        assert_eq!(calls[0]["deny_source_types"], serde_json::json!(["audit"]));
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3163 (the live probe): a scoped `host | stats count by
    /// metadata.log_source` page is answered from the source-grouped rollups,
    /// carrying the deny set, and never runs the compiled page.
    #[tokio::test]
    async fn scoped_entity_pivot_page_is_answered_from_rollups_with_the_deny_set() {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::hours(24);
        let server = wiremock::MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3164);
        let seen = nan3163_mount_count_only(
            &server,
            tenant,
            serde_json::json!([
                {"metadata.log_source": "windows_sysmon", "count": 7},
                {"metadata.log_source": "windows_security", "count": 2}
            ]),
        )
        .await;
        let (view, _token) = nan3163_cell_view(&server, tenant).await;
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": r#"device.hostname="ws-hr-132.corp.local" | stats count by metadata.log_source"#,
            "time_range": {"start": start, "end": end},
            "limit": 100,
            "table_view": true,
            "skip_histogram": true,
            "skip_field_stats": true
        }))
        .unwrap();
        for scope in [
            crate::auth::compose_viewer_scope(&crate::auth::ScopeSet::default(), false),
            crate::auth::ScopeSet::from_denied(["windows_security".to_string()].into()),
        ] {
            seen.lock().unwrap().clear();
            let response = view.search(request.clone(), &scope).await.unwrap();
            assert_eq!(response.results.len(), 2, "{:?}", response.results);
            let calls = seen.lock().unwrap().clone();
            assert_eq!(calls.len(), 1, "{calls:?}");
            assert_eq!(calls[0]["group_field"], "device.hostname");
            assert_eq!(calls[0]["group_by_source"], true);
            assert_eq!(
                calls[0]["deny_source_types"],
                serde_json::json!(scope.deny_set().iter().collect::<Vec<_>>())
            );
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3166: a scoped caller's count-metrics search is answered from the
    /// exact count aggregates exactly like an unrestricted one's, every
    /// metric request carrying the caller's deny set, and never scans.
    #[tokio::test]
    async fn scoped_count_metrics_are_answered_from_rollups_with_the_deny_set() {
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::hours(24);
        let server = wiremock::MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3166);
        let seen = nan3163_mount_count_only(
            &server,
            tenant,
            serde_json::json!([{"internal": 3, "total": 5}]),
        )
        .await;
        let (view, _token) = nan3163_cell_view(&server, tenant).await;
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": r#"* | eval is_int = if(src_endpoint.ip != "", 1, 0) | stats sum(is_int) as internal, count() as total"#,
            "time_range": {"start": start, "end": end},
            "limit": 100,
            "table_view": true,
            "skip_histogram": true,
            "skip_field_stats": true
        }))
        .unwrap();
        for scope in [
            crate::auth::ScopeSet::default(),
            crate::auth::compose_viewer_scope(&crate::auth::ScopeSet::default(), false),
            crate::auth::ScopeSet::from_denied(["windows_security".to_string()].into()),
        ] {
            seen.lock().unwrap().clear();
            let response = view.search(request.clone(), &scope).await.unwrap();
            assert_eq!(response.results.len(), 1, "{:?}", response.results);
            assert_eq!(response.results[0]["internal"], 3);
            assert_eq!(response.results[0]["total"], 5);
            let calls = seen.lock().unwrap().clone();
            assert_eq!(calls.len(), 2, "{calls:?}");
            let mut fields = calls
                .iter()
                .map(|call| call["group_field"].as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            fields.sort();
            assert_eq!(fields, ["metadata.log_source", "src_endpoint.ip"]);
            for call in &calls {
                assert_eq!(
                    call["deny_source_types"],
                    serde_json::json!(scope.deny_set().iter().collect::<Vec<_>>()),
                    "{scope:?}"
                );
            }
        }
    }

    /// The timechart re-enters `search` for its inner fetches; in a debug
    /// build that nested future outgrows the 2 MiB test-thread stack.
    fn on_large_stack<F, Fut>(test: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()>,
    {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(test())
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3173 (the live probe): a scoped caller's 24 h
    /// `* | timechart span=1h count by metadata.log_source` is answered by
    /// ONE source-grouped, hour-bucketed count-rollup request carrying the
    /// deny set: no ranking scan, no selected-series scan, no OTHER scan.
    /// Every hour of the window (both ragged edges included) is a row, empty
    /// hours are zero, and `limit` folds the tail series into OTHER exactly.
    #[test]
    fn scoped_split_timechart_is_answered_from_one_rollup_request() {
        on_large_stack(|| async {
            use chrono::DurationRound;
            let end = chrono::Utc::now();
            let start = end - chrono::Duration::hours(24);
            let hour = chrono::Duration::hours(1);
            let first = start.duration_trunc(hour).unwrap();
            let last = end.duration_trunc(hour).unwrap();
            let server = wiremock::MockServer::start().await;
            let tenant = uuid::Uuid::from_u128(0x3173);
            let seen = nan3163_mount_count_only(
                &server,
                tenant,
                serde_json::json!([
                    {"time_bucket": first.to_rfc3339(), "metadata.log_source": "windows_sysmon", "count": 3},
                    {"time_bucket": first.to_rfc3339(), "metadata.log_source": "windows_security", "count": 1},
                    {"time_bucket": (first + hour * 12).to_rfc3339(), "metadata.log_source": "windows_sysmon", "count": 5},
                    {"time_bucket": last.to_rfc3339(), "metadata.log_source": "windows_security", "count": 2},
                    {"time_bucket": last.to_rfc3339(), "metadata.log_source": "zeek", "count": 4}
                ]),
            )
            .await;
            let (view, _token) = nan3163_cell_view(&server, tenant).await;
            let request = |query: &str| -> SearchRequest {
                serde_json::from_value(serde_json::json!({
                    "query": query,
                    "time_range": {"start": start, "end": end},
                    "limit": 100,
                    "skip_field_stats": true
                }))
                .unwrap()
            };
            let buckets = ((last - first).num_hours() + 1) as usize;
            assert_eq!(buckets, 25, "a 24 h window ending mid-hour spans 25 hours");
            for scope in [
                crate::auth::compose_viewer_scope(&crate::auth::ScopeSet::default(), false),
                crate::auth::ScopeSet::from_denied(["windows_security".to_string()].into()),
                crate::auth::ScopeSet::default(),
            ] {
                seen.lock().unwrap().clear();
                let response = view
                    .search(
                        request("* | timechart span=1h count by metadata.log_source"),
                        &scope,
                    )
                    .await
                    .unwrap();
                let calls = seen.lock().unwrap().clone();
                assert_eq!(calls.len(), 1, "{scope:?}: {calls:?}");
                assert_eq!(calls[0]["group_field"], "metadata.log_source");
                assert_eq!(calls[0]["group_results"], true);
                assert_eq!(calls[0]["bucket_span_us"], 3_600_000_000_i64);
                assert_eq!(
                    calls[0]["deny_source_types"],
                    serde_json::json!(scope.deny_set().iter().collect::<Vec<_>>())
                );
                let rows = &response.results;
                assert_eq!(rows.len(), buckets, "{rows:?}");
                assert_eq!(response.display_type, Some(DisplayType::Timechart));
                assert_eq!(rows[0]["windows_sysmon"], 3);
                assert_eq!(rows[0]["windows_security"], 1);
                assert_eq!(rows[0]["zeek"], 0);
                assert_eq!(rows[12]["windows_sysmon"], 5);
                assert_eq!(rows[5]["windows_sysmon"], 0, "empty hours are zero");
                assert_eq!(rows[buckets - 1]["zeek"], 4, "the open tail hour");
                assert_eq!(rows[buckets - 1]["windows_security"], 2);
                assert!(rows.iter().all(|row| row.get("OTHER").is_none()));
                let total: u64 = rows
                    .iter()
                    .flat_map(|row| ["windows_sysmon", "windows_security", "zeek"].map(|s| row[s].as_u64().unwrap()))
                    .sum();
                assert_eq!(total, 15);
            }

            // `limit` keeps the top series by total and folds the rest into OTHER.
            seen.lock().unwrap().clear();
            let scope = crate::auth::compose_viewer_scope(&crate::auth::ScopeSet::default(), false);
            let response = view
                .search(
                    request("* | timechart span=1h limit=2 count by metadata.log_source"),
                    &scope,
                )
                .await
                .unwrap();
            assert_eq!(seen.lock().unwrap().len(), 1);
            let rows = &response.results;
            assert_eq!(rows.len(), buckets);
            assert!(rows.iter().all(|row| row.get("windows_security").is_none()), "{rows:?}");
            assert_eq!(rows[0]["OTHER"], 1);
            assert_eq!(rows[buckets - 1]["OTHER"], 2);
            assert_eq!(rows[buckets - 1]["zeek"], 4);
            assert_eq!(rows[0]["windows_sysmon"], 3);

            // The entity pivot shape takes the source-grouped predicate rollup.
            seen.lock().unwrap().clear();
            view.search(
                request(r#"device.hostname="ws-hr-132.corp.local" | timechart span=1h count by metadata.log_source"#),
                &scope,
            )
            .await
            .unwrap();
            let calls = seen.lock().unwrap().clone();
            assert_eq!(calls.len(), 1, "{calls:?}");
            assert_eq!(calls[0]["group_field"], "device.hostname");
            assert_eq!(calls[0]["group_by_source"], true);
            assert_eq!(calls[0]["bucket_span_us"], 3_600_000_000_i64);
            assert_eq!(calls[0]["deny_source_types"], serde_json::json!(["audit"]));
        })
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3173: the unsplit `* | timechart span=1h count` of a scoped
    /// caller also reaches the rollup (its inner fetch used to carry the
    /// gate twice, which the planning strip could not see through).
    #[test]
    fn scoped_unsplit_timechart_is_answered_from_the_rollup() {
        on_large_stack(|| async {
            use chrono::DurationRound;
            let end = chrono::Utc::now();
            let start = end - chrono::Duration::hours(24);
            let first = start.duration_trunc(chrono::Duration::hours(1)).unwrap();
            let server = wiremock::MockServer::start().await;
            let tenant = uuid::Uuid::from_u128(0x3174);
            let seen = nan3163_mount_count_only(
                &server,
                tenant,
                serde_json::json!([{"time_bucket": first.to_rfc3339(), "count": 9}]),
            )
            .await;
            let (view, _token) = nan3163_cell_view(&server, tenant).await;
            let request: SearchRequest = serde_json::from_value(serde_json::json!({
                "query": "* | timechart span=1h count",
                "time_range": {"start": start, "end": end},
                "limit": 100,
                "skip_field_stats": true
            }))
            .unwrap();
            let scope = crate::auth::compose_viewer_scope(&crate::auth::ScopeSet::default(), false);
            let response = view.search(request, &scope).await.unwrap();
            let calls = seen.lock().unwrap().clone();
            assert_eq!(calls.len(), 1, "{calls:?}");
            assert_eq!(calls[0]["bucket_span_us"], 3_600_000_000_i64);
            assert_eq!(calls[0]["deny_source_types"], serde_json::json!(["audit"]));
            assert_eq!(response.results.len(), 25);
            assert_eq!(response.results[0]["count"], 9);
        })
    }

    /// NAN-3163: the histogram's rollup decision ignores the injected gate
    /// for the caller's own deny set, and only that gate.
    #[test]
    fn scoped_histogram_bases_keep_the_rollup_bucket() {
        let profile = crate::schema::OcsfProfile::new();
        let set = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<std::collections::BTreeSet<_>>()
        };
        for deny in [
            &["audit"][..],
            &["windows_sysmon"],
            &["audit", "conduit_proxy"],
        ] {
            for base in [
                "*",
                "metadata.log_source=windows_sysmon",
                "metadata.log_source=windows_sysmon src_endpoint.hostname=\"ws-1.corp.local\"",
                "src_endpoint.ip=\"10.0.0.1\"",
                "device.hostname=\"ws-hr-132.corp.local\"",
                "metadata.log_source=windows_sysmon src_endpoint.hostname=\"ws-1\"",
            ] {
                let gated = crate::search::query_processing::enforce_source_scope_with_field(
                    base,
                    &set(deny),
                    crate::search::query_processing::LAKE_SOURCE_FIELD,
                )
                .unwrap();
                assert_ne!(gated, base);
                let rollup_base = super::lake_histogram_rollup_base(&gated, &set(deny));
                assert_eq!(
                    super::lake_histogram_span_for(&profile, &rollup_base, 3_600),
                    ("5m", 300),
                    "{deny:?} {base}"
                );
                let plan = |base: &str| {
                    super::super::core_search::lake_histogram_rollup_plan(
                        &parse_query(&format!("{base} | timechart span=5m count() as count"))
                            .unwrap(),
                    )
                    .map(|plan| {
                        (
                            plan.field,
                            plan.predicate,
                            plan.source_filter,
                            plan.bucket_span_us,
                        )
                    })
                };
                assert!(plan(&rollup_base).is_some(), "{deny:?} {base}");
                assert_eq!(plan(&rollup_base), plan(base), "{deny:?} {base}");
                // Another deny set's gate is not stripped: that base still scans.
                assert_eq!(
                    super::lake_histogram_rollup_base(&gated, &set(&["other"])),
                    gated
                );
            }
            // Not rollup-expressible stays the raw timeline.
            let gated = crate::search::query_processing::enforce_source_scope_with_field(
                "powershell",
                &set(deny),
                crate::search::query_processing::LAKE_SOURCE_FIELD,
            )
            .unwrap();
            let rollup_base = super::lake_histogram_rollup_base(&gated, &set(deny));
            assert_eq!(
                super::lake_histogram_span_for(&profile, &rollup_base, 3_600),
                ("1m", 60)
            );
        }
    }

    #[test]
    fn worker_rows_decode_without_clickhouse_timestamp_types() {
        let rows = vec![
            serde_json::json!({"time_bucket": "2026-08-12 11:35:00", "count": 4856}),
            serde_json::json!({"time_bucket": "2026-08-12T11:40:00Z", "count": "12"}),
        ];
        let histogram = parse_lake_histogram_rows(rows).unwrap();
        assert_eq!(histogram.len(), 2);
        assert_eq!(histogram[0].time.to_rfc3339(), "2026-08-12T11:35:00+00:00");
        assert_eq!(histogram[0].count, 4_856);
        assert_eq!(histogram[1].count, 12);
        assert!(parse_lake_histogram_rows(vec![
            serde_json::json!({"time_bucket": "not-a-time", "count": 1})
        ])
        .is_err());
    }

    #[test]
    fn scan_budget_fallback_bisects_into_disjoint_ranges() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-08-12T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (older, newer) = split_lake_histogram_range(&TimeRangeInput { start, end }).unwrap();
        assert_eq!(older.start, start);
        assert_eq!(
            older
                .end
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "2026-08-12T06:00:00.000000Z"
        );
        assert_eq!(
            newer
                .start
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2026-08-12T06:00:00Z"
        );
        assert_eq!(newer.end, end);
        // NAN-4280: half-open halves share the split instant.
        assert_eq!(older.end, newer.start);
    }

    #[test]
    fn chunked_lake_histogram_merges_equal_bucket_counts() {
        let time = chrono::DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let merged = merge_lake_histogram_rows(vec![
            HistogramBucket { time, count: 7 },
            HistogramBucket { time, count: 5 },
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].count, 12);
    }
}
