// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `/v1/aggregate/count` contract shared by the generation reader and the
//! part query process (NAN-2869): request shape, window arithmetic, and the
//! exact merge of rollup and native count fragments. Keeping one merge is
//! what makes both paths return identical rows for identical fragments.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::native::NativeQueryOutput;
use crate::planner::{CountPredicate, DASHBOARD_BREAKDOWN_COMPONENTS, DASHBOARD_BREAKDOWN_FIELD};
use crate::rollup::COUNT_ROLLUP_BUCKET_US;

pub const MAX_COUNT_GROUPS: usize = 1_000_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountAggregateRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub group_field: String,
    #[serde(default = "default_true")]
    pub group_results: bool,
    #[serde(default)]
    pub predicate: Option<CountPredicate>,
    #[serde(default)]
    pub bucket_span_us: Option<i64>,
    pub count_alias: String,
    pub start: String,
    pub end: String,
    #[serde(default)]
    pub source_filter: Option<String>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: BTreeSet<String>,
    pub max_groups: usize,
    /// NAN-3153: group the rows matching `predicate` on `group_field` by
    /// their `metadata.log_source` (`F=v | stats count by metadata.log_source`).
    /// Excludes `group_results`; never on the source or dashboard field.
    #[serde(default)]
    pub group_by_source: bool,
}

/// The output column of a source-grouped count.
pub const SOURCE_GROUP_FIELD: &str = "metadata.log_source";

fn default_true() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum CountAggregateError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Internal(String),
}

/// The request's time window split into rollup-aligned full buckets and the
/// ragged edges a native scan must cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountWindow {
    pub start_us: i64,
    pub end_exclusive_us: i64,
    pub full_start_us: i64,
    pub full_end_us: i64,
}

impl CountAggregateRequest {
    /// Whether rows are grouped (by the field's value or by log source).
    pub fn grouped(&self) -> bool {
        self.group_results || self.group_by_source
    }

    /// The column the group key is reported under.
    pub fn output_group_field(&self) -> &str {
        if self.group_by_source {
            SOURCE_GROUP_FIELD
        } else {
            &self.group_field
        }
    }

    /// Bounds every reader applies (rollup coverage is checked by the caller).
    pub fn validate_shape(&self) -> Result<(), CountAggregateError> {
        if self.group_by_source
            && (self.group_results
                || self.group_field == SOURCE_GROUP_FIELD
                || self.group_field == DASHBOARD_BREAKDOWN_FIELD)
        {
            return Err(CountAggregateError::Invalid(
                "a source-grouped count needs an ungrouped non-source field".to_string(),
            ));
        }
        if self.group_field.len() > 512
            || self.count_alias.is_empty()
            || self.count_alias.len() > 512
            || self.count_alias.chars().any(char::is_control)
            || self.max_groups == 0
            || self.max_groups > MAX_COUNT_GROUPS
            || self
                .source_filter
                .as_ref()
                .is_some_and(|source| source.is_empty() || source.len() > 512 || source.chars().any(char::is_control))
            || self
                .deny_source_types
                .iter()
                .any(|source| source.is_empty() || source.len() > 512 || source.chars().any(char::is_control))
            || self.bucket_span_us.is_some_and(|span| {
                span < COUNT_ROLLUP_BUCKET_US || span % COUNT_ROLLUP_BUCKET_US != 0 || span > 31_622_400_000_000
            })
        {
            return Err(CountAggregateError::Invalid(
                "count aggregate violates its field, alias, group, or source-scope bound".to_string(),
            ));
        }
        Ok(())
    }

    pub fn window(&self) -> Result<CountWindow, CountAggregateError> {
        let start = DateTime::parse_from_rfc3339(&self.start)
            .map_err(|_| CountAggregateError::Invalid("count aggregate start is not RFC3339".to_string()))?
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339(&self.end)
            .map_err(|_| CountAggregateError::Invalid("count aggregate end is not RFC3339".to_string()))?
            .with_timezone(&Utc);
        if start > end || end - start > ChronoDuration::days(366) {
            return Err(CountAggregateError::Invalid(
                "count aggregate time range is reversed or exceeds 366 days".to_string(),
            ));
        }
        let start_us = start.timestamp_micros();
        let end_exclusive_us = end
            .timestamp_micros()
            .checked_add(1)
            .ok_or_else(|| CountAggregateError::Invalid("count aggregate end overflowed".to_string()))?;
        Ok(CountWindow {
            start_us,
            end_exclusive_us,
            full_start_us: ceil_to_bucket(start_us, COUNT_ROLLUP_BUCKET_US),
            full_end_us: end_exclusive_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US,
        })
    }
}

pub fn ceil_to_bucket(value: i64, width: i64) -> i64 {
    let floor = value.div_euclid(width) * width;
    if floor == value {
        value
    } else {
        floor.saturating_add(width)
    }
}

/// Merged rows plus engine counters.
#[derive(Debug, Clone)]
pub struct MergedCounts {
    pub rows: Vec<Value>,
    pub engine_seconds: f64,
    pub storage_rows: u64,
    pub storage_bytes: u64,
}

/// Merge every fragment's `(bucket_start_us?, value, events)` rows by
/// `(bucket, value)`, then shape and order the rows exactly as the reader's
/// `count_aggregate` route returns them.
pub fn merge_outputs(
    request: &CountAggregateRequest,
    outputs: Vec<NativeQueryOutput>,
) -> Result<MergedCounts, CountAggregateError> {
    let internal = |message: &str| CountAggregateError::Internal(message.to_string());
    let mut merged = std::collections::BTreeMap::<String, (Option<i64>, Value, u64)>::new();
    let mut engine_seconds = 0.0_f64;
    let mut storage_rows = 0_u64;
    let mut storage_bytes = 0_u64;
    for output in outputs {
        engine_seconds += output.elapsed.as_secs_f64();
        storage_rows = storage_rows.saturating_add(output.storage_rows_read);
        storage_bytes = storage_bytes.saturating_add(output.storage_bytes_read);
        for line in output.data.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            let row: Value = serde_json::from_slice(line)
                .map_err(|error| CountAggregateError::Internal(format!("native result JSON is invalid: {error}")))?;
            let value = normalize_count_group_value(request.output_group_field(), row.get("value").cloned().unwrap_or(Value::Null))?;
            let bucket = if request.bucket_span_us.is_some() {
                Some(
                    row.get("bucket_start_us")
                        .and_then(|value| value.as_i64().or_else(|| value.as_str().and_then(|value| value.parse().ok())))
                        .ok_or_else(|| internal("count aggregate fragment omitted its time bucket"))?,
                )
            } else {
                None
            };
            let count = row
                .get("events")
                .and_then(|value| value.as_u64().or_else(|| value.as_str().and_then(|value| value.parse().ok())))
                .ok_or_else(|| internal("count aggregate fragment omitted a UInt64 count"))?;
            let key = serde_json::to_string(&(bucket, &value)).map_err(|error| CountAggregateError::Internal(error.to_string()))?;
            let entry = merged.entry(key).or_insert((bucket, value, 0));
            entry.2 = entry.2.checked_add(count).ok_or_else(|| internal("count aggregate overflowed UInt64"))?;
        }
    }
    if !request.grouped() && request.bucket_span_us.is_none() && merged.is_empty() {
        merged.insert("[null,null]".to_string(), (None, Value::Null, 0));
    }
    if !request.grouped() && request.bucket_span_us.is_none() && merged.len() != 1 {
        return Err(internal("ungrouped count aggregate did not converge to one exact result"));
    }
    if merged.len() > request.max_groups {
        return Err(CountAggregateError::Invalid(format!(
            "count aggregate produced {} groups above the configured bound of {}",
            merged.len(),
            request.max_groups
        )));
    }
    let mut rows = merged
        .into_iter()
        .map(|(key, (bucket, value, count))| {
            let mut row = serde_json::Map::new();
            if let Some(bucket) = bucket {
                let bucket = DateTime::<Utc>::from_timestamp_micros(bucket)
                    .ok_or_else(|| internal("count aggregate produced an invalid time bucket"))?;
                row.insert("time_bucket".to_string(), Value::String(bucket.format("%Y-%m-%d %H:%M:%S").to_string()));
            }
            if request.group_by_source {
                row.insert(SOURCE_GROUP_FIELD.to_string(), value);
            } else if request.group_results {
                if request.group_field == DASHBOARD_BREAKDOWN_FIELD {
                    let encoded = value
                        .as_str()
                        .ok_or_else(|| internal("dashboard count rollup returned a non-string composite key"))?;
                    let components: Vec<Option<String>> =
                        serde_json::from_str(encoded).map_err(|error| CountAggregateError::Internal(error.to_string()))?;
                    if components.len() != DASHBOARD_BREAKDOWN_COMPONENTS.len() {
                        return Err(internal("dashboard count rollup returned an invalid composite key"));
                    }
                    for (field, value) in DASHBOARD_BREAKDOWN_COMPONENTS.iter().zip(components) {
                        row.insert((*field).to_string(), value.map_or(Value::Null, Value::String));
                    }
                } else {
                    row.insert(request.group_field.clone(), value);
                }
            }
            row.insert(request.count_alias.clone(), Value::from(count));
            Ok((key, count, Value::Object(row)))
        })
        .collect::<Result<Vec<_>, CountAggregateError>>()?;
    if request.bucket_span_us.is_some() {
        rows.sort_by(|left, right| left.0.cmp(&right.0));
    } else {
        rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    }
    Ok(MergedCounts {
        rows: rows.into_iter().map(|(_, _, row)| row).collect(),
        engine_seconds,
        storage_rows,
        storage_bytes,
    })
}

pub fn normalize_count_group_value(field: &str, value: Value) -> Result<Value, CountAggregateError> {
    if value.is_null() || field == DASHBOARD_BREAKDOWN_FIELD {
        return Ok(value);
    }
    if matches!(
        field,
        "class_uid"
            | "category_uid"
            | "activity_id"
            | "type_uid"
            | "severity_id"
            | "status_id"
            | "src_endpoint.port"
            | "dst_endpoint.port"
    ) {
        let number = value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
            .ok_or_else(|| CountAggregateError::Internal(format!("count aggregate returned a non-integer value for {field}")))?;
        return Ok(Value::from(number));
    }
    if field == "unmapped.threat_blocked" {
        let boolean = value.as_bool().or_else(|| {
            value.as_str().and_then(|value| match value {
                "true" | "1" => Some(true),
                "false" | "0" => Some(false),
                _ => None,
            })
        });
        return boolean
            .map(Value::Bool)
            .ok_or_else(|| CountAggregateError::Internal("count aggregate returned a non-boolean threat flag".to_string()));
    }
    match value {
        Value::String(_) => Ok(value),
        other => Ok(Value::String(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn request(group: bool, span: Option<i64>) -> CountAggregateRequest {
        CountAggregateRequest {
            request_id: "r".into(),
            tenant_id: "t".into(),
            group_field: "class_uid".into(),
            group_results: group,
            predicate: None,
            bucket_span_us: span,
            count_alias: "count".into(),
            start: "2026-09-24T00:00:00Z".into(),
            end: "2026-09-24T01:00:00Z".into(),
            source_filter: None,
            deny_source_types: BTreeSet::new(),
            max_groups: 10,
            group_by_source: false,
        }
    }

    fn output(lines: &str) -> NativeQueryOutput {
        NativeQueryOutput { data: lines.as_bytes().to_vec(), elapsed: Duration::from_millis(1), storage_rows_read: 1, storage_bytes_read: 2 }
    }

    #[test]
    fn fragments_merge_by_bucket_and_value_and_order_like_the_reader() {
        let merged = merge_outputs(
            &request(true, None),
            vec![
                output("{\"value\":\"1007\",\"events\":\"3\"}\n{\"value\":\"4001\",\"events\":5}\n"),
                output("{\"value\":1007,\"events\":4}\n"),
            ],
        )
        .unwrap();
        assert_eq!(merged.rows, vec![serde_json::json!({"class_uid":1007,"count":7}), serde_json::json!({"class_uid":4001,"count":5})]);
        assert_eq!(merged.storage_bytes, 4);
        let empty = merge_outputs(&request(false, None), vec![]).unwrap();
        assert_eq!(empty.rows, vec![serde_json::json!({"count":0})]);
        let window = request(false, None).window().unwrap();
        assert_eq!(window.full_start_us, window.start_us);
        assert_eq!(window.full_end_us, window.end_exclusive_us - 1);
        assert_eq!(ceil_to_bucket(1, 300), 300);
    }

    /// NAN-3153: a source-grouped count reports `metadata.log_source` keys
    /// (never the predicate field's), merges rollup and edge fragments by
    /// source, and keeps a NULL source as its own group.
    #[test]
    fn source_grouped_fragments_merge_by_source() {
        let mut request = request(false, None);
        request.group_field = "device.hostname".into();
        request.group_by_source = true;
        assert!(request.grouped());
        request.validate_shape().unwrap();
        let merged = merge_outputs(
            &request,
            vec![
                output("{\"value\":\"windows_sysmon\",\"events\":\"3\"}\n{\"value\":null,\"events\":1}\n"),
                output("{\"value\":\"windows_sysmon\",\"events\":4}\n{\"value\":\"edr\",\"events\":9}\n"),
            ],
        )
        .unwrap();
        assert_eq!(
            merged.rows,
            vec![
                serde_json::json!({"metadata.log_source":"edr","count":9}),
                serde_json::json!({"metadata.log_source":"windows_sysmon","count":7}),
                serde_json::json!({"metadata.log_source":null,"count":1}),
            ]
        );
        // Empty source-grouped answers are empty, not a synthetic zero row.
        assert!(merge_outputs(&request, vec![]).unwrap().rows.is_empty());
        for (group_results, field) in [(true, "device.hostname"), (false, "metadata.log_source"), (false, DASHBOARD_BREAKDOWN_FIELD)] {
            let mut bad = request.clone();
            bad.group_results = group_results;
            bad.group_field = field.into();
            assert!(bad.validate_shape().is_err(), "{group_results} {field}");
        }
    }
}
