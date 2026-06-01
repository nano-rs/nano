// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Generate histogram data for a piped query
    /// Extracts the base filter (before any pipe commands) and generates time buckets
    pub(crate) async fn generate_histogram(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
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

        self.generate_clickhouse_histogram(&parsed, &tr, duration_secs)
            .await
    }

    /// Generate histogram for ClickHouse backend
    async fn generate_clickhouse_histogram(
        &self,
        query: &Query,
        time_range: &TimeRange,
        duration_secs: i64,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        // Verify ClickHouse client is configured
        if self.ch_client.is_none() {
            return Err(SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            )));
        }

        // Generate base SQL for the search expression
        let base_sql = self
            .ch_sql_generator
            .generate(query, time_range)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Determine the time bucket function and interval based on duration
        // Use finer granularity for better visualization
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
            d if d <= 43200 => ("toStartOfFiveMinutes(timestamp)".to_string(), 300),
            d if d <= 86400 => ("toStartOfFiveMinutes(timestamp)".to_string(), 300),
            d if d <= 172800 => ("toStartOfTenMinutes(timestamp)".to_string(), 600),
            d if d <= 604800 => (
                "toStartOfInterval(timestamp, INTERVAL 30 MINUTE)".to_string(),
                1800,
            ),
            _ => ("toStartOfHour(timestamp)".to_string(), 3600),
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
            .execute_clickhouse_histogram_query(&histogram_sql)
            .await?;

        // Fill in missing buckets with zero counts to show the complete time range
        histogram = self.fill_histogram_gaps(histogram, time_range, interval_secs);

        Ok(histogram)
    }

    /// Execute a ClickHouse histogram query and parse results dynamically
    async fn execute_clickhouse_histogram_query(
        &self,
        sql: &str,
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
        let mut cursor = ch_client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| SearchError::DatabaseError(sqlx::Error::Protocol(e.to_string())))?;

        // Collect all bytes from the cursor
        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
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

        let histogram_sql = format!(
            r#"
            SELECT 
                {} as time_bucket,
                count(*) as count
            FROM logs
            WHERE timestamp BETWEEN '{}' AND '{}'
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
            "#,
            time_bucket_func,
            time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
            time_range.end.format("%Y-%m-%d %H:%M:%S%.6f")
        );

        // Execute query and fill gaps
        let mut histogram = self
            .execute_clickhouse_histogram_query(&histogram_sql)
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
