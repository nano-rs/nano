// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3020: the two query[T] reads behind a lean tenant's ingest counters.
//!
//! * [`source_rollup`]: `POST /v1/aggregate/count` grouped by
//!   `metadata.log_source` per time bucket. The window is always whole
//!   rollup buckets, so query[T] answers it from the parts' signed rollup
//!   partials alone and never scans raw rows.
//! * [`live_parts`]: the `live_parts` block of `GET /v1/status`.
//!
//! Both go through the tenant-pinned cell route, exactly like search. The
//! caching, the conversion into the counter shape, and the policy on top
//! live in the hosted lean-ingest module.

use std::collections::BTreeSet;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};

use super::lake::LakeQueryClient;
pub use super::lake::LakeCellLiveParts;
use super::lake_cell::LakeCellRoute;
use super::{SearchError, TimeRangeInput};

/// The query[T] rollup bucket (`nanosiem-lake-worker` `COUNT_ROLLUP_BUCKET_US`).
pub const ROLLUP_BUCKET_SECS: i64 = 300;

/// The group field whose rollup column is the source label.
pub const SOURCE_GROUP_FIELD: &str = "metadata.log_source";

const COUNT_ALIAS: &str = "count";

/// One (bucket, source) row of the rollup read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRollupRow {
    pub bucket_start: DateTime<Utc>,
    /// `None` for rows without a `metadata.log_source`.
    pub source: Option<String>,
    pub events: u64,
}

fn client(route: &LakeCellRoute, timeout: Duration) -> Result<LakeQueryClient, SearchError> {
    LakeQueryClient::new_lake_cell(route, timeout).map_err(SearchError::ServiceUnavailable)
}

/// Per-source counts in `bucket_span` buckets over `[start, end_exclusive)`.
/// Both bounds must be whole rollup buckets (refused otherwise, so a caller
/// can never trigger a raw scan of a ragged edge).
pub async fn source_rollup(
    route: &LakeCellRoute,
    start: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
    bucket_span: Duration,
    max_groups: usize,
    timeout: Duration,
) -> Result<Vec<SourceRollupRow>, SearchError> {
    let span_secs = i64::try_from(bucket_span.as_secs()).unwrap_or(i64::MAX);
    if start >= end_exclusive
        || start.timestamp().rem_euclid(ROLLUP_BUCKET_SECS) != 0
        || end_exclusive.timestamp().rem_euclid(ROLLUP_BUCKET_SECS) != 0
        || start.timestamp_subsec_nanos() != 0
        || end_exclusive.timestamp_subsec_nanos() != 0
        || span_secs < ROLLUP_BUCKET_SECS
        || span_secs % ROLLUP_BUCKET_SECS != 0
    {
        return Err(SearchError::SqlValidationError(
            "lean ingest rollup window must be whole rollup buckets".to_string(),
        ));
    }
    // NAN-4280: `count_aggregate` takes the half-open window (it sends the
    // route's inclusive end itself).
    let range = TimeRangeInput::new(start, end_exclusive);
    let request_id = format!("lean-ingest-{}", uuid::Uuid::new_v4());
    let rows = client(route, timeout)?
        .count_aggregate(
            &request_id,
            SOURCE_GROUP_FIELD,
            true,
            None,
            Some(span_secs * 1_000_000),
            COUNT_ALIAS,
            &range,
            None,
            &BTreeSet::new(),
            max_groups,
        )
        .await?;
    rows.iter().map(parse_rollup_row).collect()
}

/// NAN-3662: one (5-minute bucket, source lane) row of query[T]'s
/// admission refusals, by refusal time. Value-free: a reason code and the
/// OCSF attribute path of the newest refusal in the cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRefusalRow {
    pub bucket_start: DateTime<Utc>,
    pub source: String,
    pub rows: u64,
    pub reason: String,
    pub field: Option<String>,
    pub last_at: DateTime<Utc>,
}

/// NAN-3662: query[T]'s refusals over a window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LakeCellRefusals {
    pub rows: Vec<SourceRefusalRow>,
    /// Every refusal from this time on is in `rows`; `None` while query[T]
    /// still reads the older log after a cold start.
    pub complete_since: Option<DateTime<Utc>>,
}

/// NAN-3662: rows refused at lean admission per source lane over
/// `[start, end_exclusive)`; `Ok(None)` from a cell that predates the read.
pub async fn source_refusals(
    route: &LakeCellRoute,
    start: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
    timeout: Duration,
) -> Result<Option<LakeCellRefusals>, SearchError> {
    let body = client(route, timeout)?
        .lake_cell_refusals(start.timestamp_millis(), end_exclusive.timestamp_millis())
        .await?;
    body.as_ref().map(parse_refusals).transpose()
}

/// Parse a `nano.lake-refusals.v1` answer.
pub fn parse_refusals(body: &serde_json::Value) -> Result<LakeCellRefusals, SearchError> {
    let invalid = || SearchError::SqlValidationError("lean refusal answer is malformed".to_string());
    if body.get("format").and_then(|v| v.as_str()) != Some("nano.lake-refusals.v1") {
        return Err(invalid());
    }
    let at = |ms: Option<i64>| ms.and_then(DateTime::<Utc>::from_timestamp_millis);
    let complete_since = match body.get("complete_since_ms") {
        None | Some(serde_json::Value::Null) => None,
        // i64::MIN (a full log) clamps to the earliest representable time.
        Some(v) => Some(at(v.as_i64()).unwrap_or(DateTime::<Utc>::MIN_UTC)),
    };
    let rows = body
        .get("rows")
        .and_then(|v| v.as_array())
        .ok_or_else(invalid)?
        .iter()
        .map(|row| {
            let text = |name: &str| row.get(name).and_then(|v| v.as_str()).map(str::to_string);
            Ok(SourceRefusalRow {
                bucket_start: at(row.get("bucket_start_ms").and_then(|v| v.as_i64())).ok_or_else(invalid)?,
                source: text("source").ok_or_else(invalid)?,
                rows: row.get("rows").and_then(|v| v.as_u64()).ok_or_else(invalid)?,
                reason: text("reason").ok_or_else(invalid)?,
                field: text("field"),
                last_at: at(row.get("last_at_ms").and_then(|v| v.as_i64())).ok_or_else(invalid)?,
            })
        })
        .collect::<Result<Vec<_>, SearchError>>()?;
    Ok(LakeCellRefusals { rows, complete_since })
}

/// query[T]'s live part totals; `None` from an image that predates them.
pub async fn live_parts(route: &LakeCellRoute, timeout: Duration) -> Result<Option<LakeCellLiveParts>, SearchError> {
    client(route, timeout)?.lake_cell_live_parts().await
}

/// The rollup's composite `(severity, class_name, metadata.log_source)`
/// field (`nanosiem-lake-worker` `DASHBOARD_BREAKDOWN_FIELD`): one read gives
/// every source's per-class counts.
pub const CLASS_BREAKDOWN_FIELD: &str = "__nano.dashboard_breakdown";

/// One (bucket, value[, source]) row of a segment rollup read (NAN-3207).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRollupRow {
    pub bucket_start: DateTime<Utc>,
    /// The counter label (`metadata.log_source`) when the read reports it;
    /// for a source-filtered read, the filter.
    pub source: Option<String>,
    /// The segment value; `None` for rows without one.
    pub value: Option<String>,
    pub events: u64,
}

fn whole_buckets(start: DateTime<Utc>, end_exclusive: DateTime<Utc>, bucket_span: Duration) -> Result<i64, SearchError> {
    let span_secs = i64::try_from(bucket_span.as_secs()).unwrap_or(i64::MAX);
    if start >= end_exclusive
        || start.timestamp().rem_euclid(ROLLUP_BUCKET_SECS) != 0
        || end_exclusive.timestamp().rem_euclid(ROLLUP_BUCKET_SECS) != 0
        || start.timestamp_subsec_nanos() != 0
        || end_exclusive.timestamp_subsec_nanos() != 0
        || span_secs < ROLLUP_BUCKET_SECS
        || span_secs % ROLLUP_BUCKET_SECS != 0
    {
        return Err(SearchError::SqlValidationError(
            "lean segment rollup window must be whole rollup buckets".to_string(),
        ));
    }
    Ok(span_secs)
}

/// NAN-3207: every source's per-`class_name` counts in `bucket_span`
/// buckets, from the composite rollup field alone (severity summed away).
pub async fn class_rollup(
    route: &LakeCellRoute,
    start: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
    bucket_span: Duration,
    max_groups: usize,
    timeout: Duration,
) -> Result<Vec<SegmentRollupRow>, SearchError> {
    let span_secs = whole_buckets(start, end_exclusive, bucket_span)?;
    let range = TimeRangeInput::new(start, end_exclusive);
    let request_id = format!("lean-segments-{}", uuid::Uuid::new_v4());
    let rows = client(route, timeout)?
        .count_aggregate(
            &request_id,
            CLASS_BREAKDOWN_FIELD,
            true,
            None,
            Some(span_secs * 1_000_000),
            COUNT_ALIAS,
            &range,
            None,
            &BTreeSet::new(),
            max_groups,
        )
        .await?;
    rows.iter().map(|row| parse_segment_row(row, "class_name", None)).collect()
}

#[allow(clippy::too_many_arguments)]
/// NAN-3207: one source label's per-value counts of one rollup field
/// (`cloud.region`, `metadata.product.name`, ...) in `bucket_span` buckets.
pub async fn field_rollup_for_source(
    route: &LakeCellRoute,
    field: &str,
    source_label: &str,
    start: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
    bucket_span: Duration,
    max_groups: usize,
    timeout: Duration,
) -> Result<Vec<SegmentRollupRow>, SearchError> {
    let span_secs = whole_buckets(start, end_exclusive, bucket_span)?;
    let range = TimeRangeInput::new(start, end_exclusive);
    let request_id = format!("lean-segments-{}", uuid::Uuid::new_v4());
    let rows = client(route, timeout)?
        .count_aggregate(
            &request_id,
            field,
            true,
            None,
            Some(span_secs * 1_000_000),
            COUNT_ALIAS,
            &range,
            Some(source_label),
            &BTreeSet::new(),
            max_groups,
        )
        .await?;
    rows.iter().map(|row| parse_segment_row(row, field, Some(source_label))).collect()
}

/// NAN-3762: events in `[start, end_exclusive)` whose `field` is present
/// (`is_not_null`), summed over whole-window buckets. Both bounds must be
/// whole rollup buckets, so a rollup field is answered from the parts'
/// rollup partials alone (enrichment leaves included: NAN-4168 fixes them at
/// ingest, so there is no read-time authority to apply).
pub async fn present_count(
    route: &LakeCellRoute,
    field: &str,
    start: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
    timeout: Duration,
) -> Result<u64, SearchError> {
    let span = end_exclusive - start;
    let span = Duration::from_secs(u64::try_from(span.num_seconds()).unwrap_or(0));
    let span_secs = whole_buckets(start, end_exclusive, span)?;
    let range = TimeRangeInput::new(start, end_exclusive);
    let request_id = format!("lean-coverage-{}", uuid::Uuid::new_v4());
    let predicate = super::lake::LakeCountPredicate { kind: "is_not_null", values: Vec::new() };
    let rows = client(route, timeout)?
        .count_aggregate(
            &request_id,
            field,
            false,
            Some(&predicate),
            Some(span_secs * 1_000_000),
            COUNT_ALIAS,
            &range,
            None,
            &BTreeSet::new(),
            // One bucket spans the window; the window may straddle two.
            4,
        )
        .await?;
    sum_counts(&rows)
}

/// Sum the `count` column of ungrouped count-route rows.
pub fn sum_counts(rows: &[serde_json::Value]) -> Result<u64, SearchError> {
    rows.iter().try_fold(0u64, |total, row| {
        let events = row
            .get(COUNT_ALIAS)
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .ok_or_else(|| SearchError::SqlValidationError("lean coverage count row is malformed".to_string()))?;
        Ok(total.saturating_add(events))
    })
}

/// One `{time_bucket, <value_field>[, metadata.log_source], count}` row.
/// Numbers and booleans are segment values in their JSON text form.
pub fn parse_segment_row(
    row: &serde_json::Value,
    value_field: &str,
    source_filter: Option<&str>,
) -> Result<SegmentRollupRow, SearchError> {
    let invalid = || SearchError::SqlValidationError("lean segment rollup row is malformed".to_string());
    let bucket = row.get("time_bucket").and_then(|v| v.as_str()).ok_or_else(invalid)?;
    let bucket_start = NaiveDateTime::parse_from_str(bucket, "%Y-%m-%d %H:%M:%S")
        .map_err(|_| invalid())?
        .and_utc();
    let text = |value: Option<&serde_json::Value>| -> Result<Option<String>, SearchError> {
        match value {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
            Some(v @ (serde_json::Value::Number(_) | serde_json::Value::Bool(_))) => Ok(Some(v.to_string())),
            Some(_) => Err(invalid()),
        }
    };
    let source = match source_filter {
        Some(label) => Some(label.to_string()),
        None => text(row.get(SOURCE_GROUP_FIELD))?,
    };
    let value = text(row.get(value_field))?;
    let events = row
        .get(COUNT_ALIAS)
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .ok_or_else(invalid)?;
    Ok(SegmentRollupRow { bucket_start, source, value, events })
}

/// One `{time_bucket, metadata.log_source, count}` row of the count route.
pub fn parse_rollup_row(row: &serde_json::Value) -> Result<SourceRollupRow, SearchError> {
    let invalid = || SearchError::SqlValidationError("lean ingest rollup row is malformed".to_string());
    let bucket = row.get("time_bucket").and_then(|v| v.as_str()).ok_or_else(invalid)?;
    let bucket_start = NaiveDateTime::parse_from_str(bucket, "%Y-%m-%d %H:%M:%S")
        .map_err(|_| invalid())?
        .and_utc();
    let source = match row.get(SOURCE_GROUP_FIELD) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        Some(_) => return Err(invalid()),
    };
    let events = row
        .get(COUNT_ALIAS)
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .ok_or_else(invalid)?;
    Ok(SourceRollupRow { bucket_start, source, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn coverage_counts_sum_every_bucket_and_refuse_malformed_rows() {
        let rows = vec![json!({"time_bucket": "2026-10-13 10:00:00", "count": 7}), json!({"count": "5"})];
        assert_eq!(sum_counts(&rows).unwrap(), 12);
        assert_eq!(sum_counts(&[]).unwrap(), 0);
        assert!(sum_counts(&[json!({"time_bucket": "2026-10-13 10:00:00"})]).is_err());
    }

    #[test]
    fn parses_count_route_rows() {
        let row = parse_rollup_row(&json!({
            "time_bucket": "2026-09-29 11:05:00", "metadata.log_source": "windows_sysmon", "count": 1234
        }))
        .unwrap();
        assert_eq!(row.bucket_start.to_rfc3339(), "2026-09-29T11:05:00+00:00");
        assert_eq!(row.source.as_deref(), Some("windows_sysmon"));
        assert_eq!(row.events, 1234);
        let unlabeled = parse_rollup_row(&json!({"time_bucket": "2026-09-29 11:05:00", "metadata.log_source": null, "count": "7"})).unwrap();
        assert_eq!((unlabeled.source, unlabeled.events), (None, 7));
        assert!(parse_rollup_row(&json!({"metadata.log_source": "x", "count": 1})).is_err());
        assert!(parse_rollup_row(&json!({"time_bucket": "2026-09-29 11:05:00", "metadata.log_source": 3, "count": 1})).is_err());
        assert!(parse_rollup_row(&json!({"time_bucket": "2026-09-29 11:05:00", "metadata.log_source": "x"})).is_err());
    }

    /// NAN-3662: the query[T] refusal answer (`parts::refusal_tally::RefusalRow`).
    #[test]
    fn parses_the_refusal_answer() {
        let answer = parse_refusals(&json!({
            "format": "nano.lake-refusals.v1", "bucket_secs": 300, "complete_since_ms": 1_791_700_000_000i64,
            "rows": [
                {"bucket_start_ms": 1_791_790_200_000i64, "source": "azure_monitor", "rows": 100,
                 "reason": "ocsf_constraint_failed", "field": "device", "last_at_ms": 1_791_790_201_000i64},
                {"bucket_start_ms": 1_791_790_200_000i64, "source": "default", "rows": 2, "reason": "admission_invalid", "last_at_ms": 1_791_790_202_000i64}
            ]
        }))
        .unwrap();
        assert_eq!(answer.rows.len(), 2);
        assert_eq!(answer.rows[0].field.as_deref(), Some("device"));
        assert_eq!(answer.rows[1].field, None);
        assert_eq!(answer.complete_since.unwrap().timestamp_millis(), 1_791_700_000_000);
        let full = parse_refusals(&json!({"format": "nano.lake-refusals.v1", "complete_since_ms": i64::MIN, "rows": []})).unwrap();
        assert_eq!(full.complete_since, Some(DateTime::<Utc>::MIN_UTC));
        let pending = parse_refusals(&json!({"format": "nano.lake-refusals.v1", "complete_since_ms": null, "rows": []})).unwrap();
        assert_eq!(pending.complete_since, None);
        assert!(parse_refusals(&json!({"format": "v2", "rows": []})).is_err());
        assert!(parse_refusals(&json!({"format": "nano.lake-refusals.v1", "rows": [{"source": "x"}]})).is_err());
    }

    #[test]
    fn parses_segment_rows_from_the_composite_and_filtered_reads() {
        let class = parse_segment_row(
            &json!({"time_bucket": "2026-10-07 10:00:00", "severity": "Informational", "class_name": "Authentication",
                    "metadata.log_source": "azure_signin", "count": 42}),
            "class_name",
            None,
        )
        .unwrap();
        assert_eq!(class.source.as_deref(), Some("azure_signin"));
        assert_eq!(class.value.as_deref(), Some("Authentication"));
        assert_eq!(class.events, 42);
        let region = parse_segment_row(
            &json!({"time_bucket": "2026-10-07 10:00:00", "cloud.region": "us-east-1", "count": "9"}),
            "cloud.region",
            Some("aws_cloudtrail"),
        )
        .unwrap();
        assert_eq!((region.source.as_deref(), region.value.as_deref(), region.events), (Some("aws_cloudtrail"), Some("us-east-1"), 9));
        let numeric = parse_segment_row(&json!({"time_bucket": "2026-10-07 10:00:00", "class_uid": 3002, "count": 1}), "class_uid", Some("x")).unwrap();
        assert_eq!(numeric.value.as_deref(), Some("3002"));
        assert!(parse_segment_row(&json!({"time_bucket": "2026-10-07 10:00:00", "cloud.region": ["a"], "count": 1}), "cloud.region", Some("x")).is_err());
        assert!(parse_segment_row(&json!({"cloud.region": "a", "count": 1}), "cloud.region", Some("x")).is_err());
    }
}
