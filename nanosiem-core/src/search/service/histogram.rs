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

        // Parse the base query to generate SQL for histogram
        let parsed = parse_query(base_query).map_err(|e| convert_parse_error(e))?;

        let tr = TimeRange::new(time_range.start, time_range.end);

        // Calculate appropriate bucket interval based on time range
        let duration_secs = (time_range.end - time_range.start).num_seconds();
        let (trunc_unit, bucket_secs) = self.calculate_histogram_interval(duration_secs);

        match self.backend {
            SearchBackend::ClickHouse => {
                self.generate_clickhouse_histogram(&parsed, &tr, duration_secs)
                    .await
            }
            SearchBackend::PostgreSQL => {
                let base_sql = self
                    .pg_sql_generator
                    .generate(&parsed, &tr)
                    .map_err(|e| SearchError::SqlGenError(e.to_string()))?;
                self.generate_postgres_histogram(&base_sql, &tr, trunc_unit, bucket_secs)
                    .await
            }
        }
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

    /// Generate histogram for PostgreSQL backend
    async fn generate_postgres_histogram(
        &self,
        base_sql: &str,
        time_range: &TimeRange,
        trunc_unit: &str,
        bucket_secs: i64,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        // Generate histogram query with custom bucket sizes
        let histogram_sql = if bucket_secs == 60 || bucket_secs == 3600 || bucket_secs == 86400 {
            // Standard intervals - use date_trunc for efficiency
            format!(
                r#"
                SELECT 
                    date_trunc('{}', timestamp) as time_bucket,
                    COUNT(*) as count
                FROM ({}) as base_query
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
                "#,
                trunc_unit, base_sql
            )
        } else {
            // Custom intervals - use epoch-based bucketing
            format!(
                r#"
                SELECT 
                    to_timestamp(floor(extract(epoch from timestamp) / {}) * {}) as time_bucket,
                    COUNT(*) as count
                FROM ({}) as base_query
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
                "#,
                bucket_secs, bucket_secs, base_sql
            )
        };

        debug!("PostgreSQL histogram SQL: {}", histogram_sql);

        let rows = sqlx::query(&histogram_sql).fetch_all(&self.pg_pool).await?;

        let mut histogram: Vec<HistogramBucket> = rows
            .iter()
            .filter_map(|row| {
                let time: Option<chrono::DateTime<chrono::Utc>> = row.try_get("time_bucket").ok();
                let count: Option<i64> = row.try_get("count").ok();
                match (time, count) {
                    (Some(t), Some(c)) => Some(HistogramBucket {
                        time: t,
                        count: c as u64,
                    }),
                    _ => None,
                }
            })
            .collect();

        // Fill in missing buckets with zero counts
        histogram = self.fill_histogram_gaps(histogram, time_range, bucket_secs);

        Ok(histogram)
    }

    /// Generate histogram for a time range (used for raw SQL queries)
    pub(crate) async fn generate_histogram_for_time_range(
        &self,
        time_range: &TimeRangeInput,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let duration_secs = (time_range.end - time_range.start).num_seconds();
        let (trunc_unit, bucket_secs) = self.calculate_histogram_interval(duration_secs);

        match self.backend {
            SearchBackend::ClickHouse => {
                self.generate_clickhouse_histogram_for_time_range(time_range, duration_secs)
                    .await
            }
            SearchBackend::PostgreSQL => {
                self.generate_postgres_histogram_for_time_range(time_range, trunc_unit, bucket_secs)
                    .await
            }
        }
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

    /// Generate histogram for PostgreSQL for a time range
    async fn generate_postgres_histogram_for_time_range(
        &self,
        time_range: &TimeRangeInput,
        trunc_unit: &str,
        bucket_secs: i64,
    ) -> Result<Vec<HistogramBucket>, SearchError> {
        let histogram_sql = if bucket_secs == 60 || bucket_secs == 3600 || bucket_secs == 86400 {
            format!(
                r#"
                SELECT 
                    date_trunc('{}', timestamp) as time_bucket,
                    COUNT(*) as count
                FROM logs
                WHERE timestamp BETWEEN $1 AND $2
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
                "#,
                trunc_unit
            )
        } else {
            format!(
                r#"
                SELECT 
                    to_timestamp(floor(extract(epoch from timestamp) / {}) * {}) as time_bucket,
                    COUNT(*) as count
                FROM logs
                WHERE timestamp BETWEEN $1 AND $2
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
                "#,
                bucket_secs, bucket_secs
            )
        };

        let rows = sqlx::query(&histogram_sql)
            .bind(time_range.start)
            .bind(time_range.end)
            .fetch_all(&self.pg_pool)
            .await?;

        let mut histogram: Vec<HistogramBucket> = rows
            .iter()
            .filter_map(|row| {
                let time: Option<chrono::DateTime<chrono::Utc>> = row.try_get("time_bucket").ok();
                let count: Option<i64> = row.try_get("count").ok();
                match (time, count) {
                    (Some(t), Some(c)) => Some(HistogramBucket {
                        time: t,
                        count: c as u64,
                    }),
                    _ => None,
                }
            })
            .collect();

        // Fill in missing buckets with zero counts
        let tr = TimeRange {
            start: time_range.start,
            end: time_range.end,
        };
        histogram = self.fill_histogram_gaps(histogram, &tr, bucket_secs);

        Ok(histogram)
    }

    /// Calculate appropriate histogram interval based on time range duration
    /// Returns (interval_for_date_trunc, bucket_seconds) for flexible bucketing
    fn calculate_histogram_interval(&self, duration_secs: i64) -> (&'static str, i64) {
        match duration_secs {
            d if d <= 300 => ("second", 5), // <= 5 min: 5 second buckets (max 60)
            d if d <= 900 => ("second", 10), // <= 15 min: 10 second buckets (max 90)
            d if d <= 1800 => ("second", 30), // <= 30 min: 30 second buckets (max 60)
            d if d <= 3600 => ("minute", 60), // <= 1 hour: 1 minute buckets (max 60)
            d if d <= 7200 => ("minute", 60), // <= 2 hours: 1 minute buckets (max 120)
            d if d <= 21600 => ("minute", 300), // <= 6 hours: 5 minute buckets (max 72)
            d if d <= 43200 => ("minute", 300), // <= 12 hours: 5 minute buckets (max 144) - Changed from 10 to 5
            d if d <= 86400 => ("minute", 300), // <= 1 day: 5 minute buckets (max 288) - Changed from 15 to 5
            d if d <= 172800 => ("minute", 600), // <= 2 days: 10 minute buckets (max 288) - Changed from 30 to 10
            d if d <= 604800 => ("minute", 1800), // <= 1 week: 30 minute buckets (max 336) - Changed from 1 hour to 30 min
            d if d <= 2592000 => ("hour", 3600), // <= 30 days: 1 hour buckets - Changed from 1 day to 1 hour
            _ => ("hour", 3600), // > 30 days: 1 hour buckets - Changed from 1 day to 1 hour
        }
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
