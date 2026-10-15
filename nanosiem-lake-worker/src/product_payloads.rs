// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed product-view payloads shared by the gen1 job child and the lean
//! query[T] job path (NAN-3078), so both lanes publish byte-compatible
//! artifacts for the same task.

use serde_json::{json, Value};

pub fn row_string(row: &Value, path: &str) -> Option<String> {
    row.get(path).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

pub fn row_u64(row: &Value, path: &str) -> u64 {
    row.get(path)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or_default()
}

/// The exact-count Asset summary (`asset_v1`) response.
pub fn asset_summary_payload(summary: &[Value], sources: &[Value], users: &[Value]) -> Value {
    let row = summary.first();
    let total_count = row
        .map(|row| row_u64(row, "event_count"))
        .unwrap_or_default();
    let mut known = 0_u64;
    let mut event_kind = [
        ("FILE", "file_count"),
        ("PROCESS", "process_count"),
        ("AUTH_FAILURE", "auth_failure_count"),
        ("AUTH_SUCCESS", "auth_success_count"),
        ("NETWORK", "network_count"),
        ("DNS", "dns_count"),
        ("CLOUD_API", "cloud_api_count"),
    ]
    .into_iter()
    .filter_map(|(label, field)| {
        let count = row
            .map(|row| row_u64(row, field))
            .unwrap_or_default();
        known = known.saturating_add(count);
        (count > 0).then(|| json!([label, count]))
    })
    .collect::<Vec<_>>();
    let other = total_count.saturating_sub(known);
    if other > 0 {
        event_kind.push(json!(["OTHER", other]));
    }
    event_kind.sort_by(|left, right| {
        right
            .get(1)
            .and_then(Value::as_u64)
            .cmp(&left.get(1).and_then(Value::as_u64))
            .then_with(|| {
                left.get(0)
                    .and_then(Value::as_str)
                    .cmp(&right.get(0).and_then(Value::as_str))
            })
    });
    let ranked = |rows: &[Value], field: &str| {
        rows.iter()
            .filter_map(|row| {
                row_string(row, field)
                    .filter(|value| !value.is_empty())
                    .map(|value| json!([value, row_u64(row, "event_count")]))
            })
            .collect::<Vec<_>>()
    };
    json!({
        "events": [],
        "total_count": total_count,
        "total_count_exact": true,
        "facets": {
            "source_type": ranked(sources, "metadata.log_source"),
            "event_kind": event_kind,
            "user": ranked(users, "asset_user"),
        },
        "offset": 0,
        "limit": 1,
        "has_more": total_count > 0,
    })
}

