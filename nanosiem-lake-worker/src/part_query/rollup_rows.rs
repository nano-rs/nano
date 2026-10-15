// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-part count-rollup answers, memoized (NAN-3093).
//!
//! `/v1/aggregate/count` answers its whole 5-minute buckets from the parts'
//! rollup partials. Each call re-read every partial of its window: ~150
//! files and ~18 MB for one live hour, 0.7–1.2 s of engine time, for every
//! search histogram, every field-sidebar click and the field's total. A part
//! and its rollup partial are immutable, so the rows one request shape
//! (field, grouping, predicate, source filter, deny set) selects from one
//! part never change. They are kept here per part, over the part's whole
//! time range; any window and any span is then merged from memory, and only
//! parts new since the last identical request are read. Retention, erasure
//! and merges retire parts and add new ones, so an answer is never served
//! for data that is no longer live (the caller only asks for live parts).
//!
//! Bounds: an entry holds at most [`MAX_ENTRY_ROWS`] rows (a larger answer
//! is used once and not kept) and the memo at most [`MAX_TOTAL_ROWS`].

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::count_aggregate::CountAggregateRequest;
use crate::parts::format::PartId;

/// Largest per-part answer kept.
pub const MAX_ENTRY_ROWS: usize = 20_000;
/// Rows the memo holds across all entries (≈100 B each with the value's
/// heap string, so ≈50 MB), well inside query[T]'s non-chDB headroom.
pub const MAX_TOTAL_ROWS: usize = 500_000;
/// Bound metadata even when many request shapes return no rows.
pub const MAX_ENTRIES: usize = 20_000;

/// One `(bucket, value)` count of one part.
#[derive(Debug, Clone, PartialEq)]
pub struct RollupRow {
    pub bucket_start_us: i64,
    pub value: Value,
    pub events: u64,
}

/// The request shape a part's answer depends on: everything but the window,
/// the span, the alias and the group bound, which are applied on read.
pub fn key(request: &CountAggregateRequest) -> Arc<str> {
    format!(
        "{}\u{1f}{}\u{1f}{:?}\u{1f}{:?}\u{1f}{:?}{}",
        request.group_field,
        request.group_results,
        request.predicate,
        request.source_filter,
        request.deny_source_types,
        // NAN-3153: source-grouped rows carry sources, not field values.
        if request.group_by_source { "\u{1f}by-source" } else { "" },
    )
    .into()
}

#[derive(Default)]
struct Inner {
    answers: HashMap<(Arc<str>, PartId), Arc<Vec<RollupRow>>>,
    order: VecDeque<(Arc<str>, PartId)>,
    rows: usize,
}

#[derive(Default)]
pub struct RollupRowsMemo {
    inner: Mutex<Inner>,
}

impl RollupRowsMemo {
    /// Reuse a grouped source summary for wildcard/source-equality histograms.
    /// Source filters refer to source_type, a distinct column. Deny sets are
    /// retained in the summary key, with the original SQL source-type fence.
    pub fn for_request(&self, request: &CountAggregateRequest, part: &PartId) -> Option<Arc<Vec<RollupRow>>> {
        if let Some(rows) = self.get(&key(request), part) {
            return Some(rows);
        }
        if request.group_field != "metadata.log_source" || request.source_filter.is_some() || request.group_by_source {
            return None;
        }
        let values = match &request.predicate {
            None => None,
            Some(predicate) if matches!(predicate.kind, crate::planner::CountPredicateKind::Eq)
                && predicate.values.len() == 1 => Some(&predicate.values),
            Some(predicate) if matches!(predicate.kind, crate::planner::CountPredicateKind::In)
                && !predicate.values.is_empty() => Some(&predicate.values),
            _ => return None,
        };
        // Restrict this optimization to ASCII predicates: leave the runtime's
        // Unicode normalization semantics to the existing SQL path.
        if values.is_some_and(|values| values.len() > 64 || values.iter().any(|value| {
            !value.is_ascii() || value.len() > 2_048 || value.chars().any(char::is_control)
        })) {
            return None;
        }
        let mut summary_request = source_summary_request(&request.tenant_id);
        summary_request.deny_source_types = request.deny_source_types.clone();
        let summary = self.get(&key(&summary_request), part)?;
        if values.is_none() { return Some(summary); }
        if values.is_some() && summary.iter().any(|row| row.value.as_str().is_none_or(|value| !value.is_ascii())) {
            return None;
        }
        let rows = summary.iter().filter(|row| {
            values.is_none_or(|values| row.value.as_str().is_some_and(|value| {
                values.iter().any(|expected| value.eq_ignore_ascii_case(expected))
            }))
        }).cloned().collect();
        Some(Arc::new(rows))
    }

    pub fn get(&self, key: &Arc<str>, part: &PartId) -> Option<Arc<Vec<RollupRow>>> {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.answers.get(&(key.clone(), part.clone())).cloned()
    }

    /// Keep `rows` as `part`'s answer to `key` (dropped when too large).
    pub fn insert(&self, key: Arc<str>, part: PartId, rows: Arc<Vec<RollupRow>>) {
        if rows.len() > MAX_ENTRY_ROWS {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let entry = (key, part);
        let added = rows.len();
        if let Some(previous) = inner.answers.insert(entry.clone(), rows) {
            inner.rows = inner.rows.saturating_sub(previous.len());
        } else {
            inner.order.push_back(entry);
        }
        inner.rows = inner.rows.saturating_add(added);
        while inner.rows > MAX_TOTAL_ROWS || inner.answers.len() > MAX_ENTRIES {
            let Some(evicted) = inner.order.pop_front() else { break };
            if let Some(rows) = inner.answers.remove(&evicted) {
                inner.rows = inner.rows.saturating_sub(rows.len());
            }
        }
    }
}

/// Canonical per-part source inventory warmed independently of caller shape.
pub(super) fn source_summary_request(tenant: &str) -> CountAggregateRequest {
    CountAggregateRequest {
        request_id: "source-summary-prewarm".into(), tenant_id: tenant.into(),
        group_field: "metadata.log_source".into(), group_results: true,
        predicate: None, bucket_span_us: None, count_alias: "count".into(),
        start: "1970-01-01T00:00:00Z".into(), end: "1970-01-01T00:00:00Z".into(),
        source_filter: None, deny_source_types: Default::default(),
        max_groups: crate::count_aggregate::MAX_COUNT_GROUPS,
        group_by_source: false,
    }
}

/// Sum per-part answers into `(bucket?, value) → events` over the
/// rollup-aligned window `[from_us, to_us)`, bucketed by `span_us` and
/// grouped by value only when `group_results`. The result is JSON lines in
/// the rollup SQL's own output shape, for [`crate::count_aggregate::merge_outputs`].
pub fn fold(
    answers: &[Arc<Vec<RollupRow>>],
    from_us: i64,
    to_us: i64,
    span_us: Option<i64>,
    group_results: bool,
) -> Vec<u8> {
    let mut sums: HashMap<(Option<i64>, String), (Value, u64)> = HashMap::new();
    for rows in answers {
        for row in rows.iter() {
            if row.bucket_start_us < from_us || row.bucket_start_us >= to_us {
                continue;
            }
            let bucket = span_us.map(|span| row.bucket_start_us.div_euclid(span) * span);
            let value = if group_results { row.value.clone() } else { Value::Null };
            let entry = sums.entry((bucket, value.to_string())).or_insert((value, 0));
            entry.1 = entry.1.saturating_add(row.events);
        }
    }
    let mut data = Vec::new();
    for ((bucket, _), (value, events)) in sums {
        let mut line = serde_json::Map::new();
        if let Some(bucket) = bucket {
            line.insert("bucket_start_us".to_string(), Value::from(bucket));
        }
        line.insert("value".to_string(), value);
        line.insert("events".to_string(), Value::from(events));
        serde_json::to_writer(&mut data, &Value::Object(line)).expect("JSON rows serialize");
        data.push(b'\n');
    }
    data
}

/// Decode one `plan_by_part` output line: `(part_path, row)`.
pub fn decode(line: &[u8]) -> Option<(String, RollupRow)> {
    let row: Value = serde_json::from_slice(line).ok()?;
    let integer = |value: &Value| value.as_i64().or_else(|| value.as_str().and_then(|value| value.parse().ok()));
    let path = row.get("part_path")?.as_str()?.to_string();
    let bucket_start_us = integer(row.get("bucket_start_us")?)?;
    let events = row
        .get("events")
        .and_then(|value| value.as_u64().or_else(|| value.as_str().and_then(|value| value.parse().ok())))?;
    Some((path, RollupRow { bucket_start_us, value: row.get("value").cloned().unwrap_or(Value::Null), events }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(bucket: i64, value: Value, events: u64) -> RollupRow {
        RollupRow { bucket_start_us: bucket, value, events }
    }

    fn lines(data: &[u8]) -> Vec<Value> {
        let mut rows = data
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        rows.sort_by_key(|row| row.to_string());
        rows
    }

    #[test]
    fn folds_parts_into_the_window_span_and_grouping() {
        const M5: i64 = 300_000_000;
        let a = Arc::new(vec![row(0, json!("h1"), 2), row(M5, json!("h1"), 3), row(2 * M5, json!("h2"), 5)]);
        let b = Arc::new(vec![row(M5, json!("h2"), 7), row(3 * M5, json!("h1"), 11)]);
        // Window [5m, 15m), grouped by value, one 10-minute span.
        let grouped = lines(&fold(&[a.clone(), b.clone()], M5, 3 * M5, Some(2 * M5), true));
        assert_eq!(
            grouped,
            vec![
                json!({"bucket_start_us": 0, "value": "h1", "events": 3}),
                json!({"bucket_start_us": 0, "value": "h2", "events": 7}),
                json!({"bucket_start_us": 2 * M5, "value": "h2", "events": 5}),
            ]
        );
        // Ungrouped total over the same window.
        assert_eq!(lines(&fold(&[a, b], M5, 3 * M5, None, false)), vec![json!({"value": null, "events": 15})]);
    }

    #[test]
    fn memo_keeps_answers_per_part_and_bounds_them() {
        let memo = RollupRowsMemo::default();
        let key: Arc<str> = "k".into();
        let part = PartId::new(1_790_000_000_000).unwrap();
        memo.insert(key.clone(), part.clone(), Arc::new(vec![row(0, Value::Null, 1)]));
        assert_eq!(memo.get(&key, &part).unwrap().len(), 1);
        assert!(memo.get(&"other".into(), &part).is_none());
        let huge = Arc::new(vec![row(0, Value::Null, 1); MAX_ENTRY_ROWS + 1]);
        let other = PartId::new(1_790_000_000_001).unwrap();
        memo.insert(key.clone(), other.clone(), huge);
        assert!(memo.get(&key, &other).is_none(), "an oversized answer is used once, never kept");
    }

    #[test]
    fn warmed_source_inventory_answers_new_windows_and_source_predicates() {
        use crate::planner::{CountPredicate, CountPredicateKind};
        let memo = RollupRowsMemo::default();
        let part = PartId::new(1_790_000_000_000).unwrap();
        let summary = source_summary_request("tenant");
        memo.insert(key(&summary), part.clone(), Arc::new(vec![
            row(0, json!("Windows_Sysmon"), 3),
            row(300_000_000, json!("windows_sysmon"), 5),
            row(300_000_000, json!("proxy"), 7),
        ]));
        let mut request = summary.clone();
        request.group_results = false;
        request.predicate = Some(CountPredicate { kind: CountPredicateKind::Eq, values: vec!["WINDOWS_SYSMON".into()] });
        let rows = memo.for_request(&request, &part).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(lines(&fold(&[rows], 300_000_000, 600_000_000, None, false)), vec![json!({"value":null,"events":5})]);
        request.predicate = Some(CountPredicate { kind: CountPredicateKind::In, values: vec!["proxy".into(), "windows_sysmon".into()] });
        assert_eq!(memo.for_request(&request, &part).unwrap().len(), 3);
        request.predicate = None;
        assert_eq!(memo.for_request(&request, &part).unwrap().len(), 3);
        // A merged/replaced part never inherits an old part's counts.
        assert!(memo.for_request(&request, &PartId::new(1_790_000_000_001).unwrap()).is_none());
    }

    #[test]
    fn source_summary_reuse_keeps_scope_fences_and_leaves_other_semantics_to_sql() {
        use crate::planner::{CountPredicate, CountPredicateKind};
        let memo = RollupRowsMemo::default();
        let part = PartId::new(1_790_000_000_000).unwrap();
        let mut summary = source_summary_request("tenant");
        memo.insert(key(&summary), part.clone(), Arc::new(vec![row(0, json!("audit"), 99)]));
        let mut request = summary.clone();
        request.group_results = false;
        request.deny_source_types.insert("audit".into());
        assert!(memo.for_request(&request, &part).is_none(), "unrestricted counts cannot satisfy restricted scope");
        summary.deny_source_types = request.deny_source_types.clone();
        memo.insert(key(&summary), part.clone(), Arc::new(vec![row(0, json!("proxy"), 2)]));
        assert_eq!(memo.for_request(&request, &part).unwrap()[0].events, 2);
        request.source_filter = Some("proxy".into());
        assert!(memo.for_request(&request, &part).is_none());
        request.source_filter = None;
        request.group_field = "device.hostname".into();
        assert!(memo.for_request(&request, &part).is_none());
        request.group_field = "metadata.log_source".into();
        request.predicate = Some(CountPredicate { kind: CountPredicateKind::Regex, values: vec![".*".into()] });
        assert!(memo.for_request(&request, &part).is_none());
        request.predicate = Some(CountPredicate { kind: CountPredicateKind::Eq, values: vec!["Ä".into()] });
        assert!(memo.for_request(&request, &part).is_none());
    }

    #[test]
    fn memo_bounds_empty_answers() {
        let memo = RollupRowsMemo::default();
        let part = PartId::new(1_790_000_000_000).unwrap();
        for index in 0..=MAX_ENTRIES {
            memo.insert(index.to_string().into(), part.clone(), Arc::new(Vec::new()));
        }
        assert!(memo.get(&"0".into(), &part).is_none());
        assert!(memo.get(&MAX_ENTRIES.to_string().into(), &part).is_some());
        let inner = memo.inner.lock().unwrap();
        assert_eq!(inner.answers.len(), MAX_ENTRIES);
        assert_eq!(inner.order.len(), MAX_ENTRIES);
    }

    #[test]
    fn decodes_quoted_64_bit_integers() {
        let (path, row) = decode(br#"{"part_path":"/c/a.parquet","bucket_start_us":"300000000","value":"x","events":"4"}"#).unwrap();
        assert_eq!(path, "/c/a.parquet");
        assert_eq!(row, RollupRow { bucket_start_us: 300_000_000, value: json!("x"), events: 4 });
        assert!(decode(br#"{"bucket_start_us":1,"events":1}"#).is_none());
    }
}
