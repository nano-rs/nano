// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper utilities for expression evaluation and data conversion

use chrono::{DateTime, Utc};
use serde_json;
use std::cmp::Ordering;
use tracing::debug;

// Re-import ClickHouseLogReadRow from execution module for clickhouse_row_to_json
use super::super::execution::ClickHouseLogReadRow;

/// Parse a datetime string in either RFC3339 format or ClickHouse format
/// RFC3339: 2025-12-29T10:50:41.000000Z
/// ClickHouse: 2025-12-29 10:50:41.000000
pub fn parse_datetime_flexible(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC3339 first (ISO 8601 with timezone)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try ClickHouse format with microseconds: YYYY-MM-DD HH:MM:SS.ffffff
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    // Try ClickHouse format without microseconds: YYYY-MM-DD HH:MM:SS
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    // Try ISO 8601 without timezone: YYYY-MM-DDTHH:MM:SS
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    // Try ISO 8601 with microseconds but no timezone: YYYY-MM-DDTHH:MM:SS.ffffff
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    None
}

/// Compare two JSON values for sorting
pub fn compare_json_values(
    a: Option<&serde_json::Value>,
    b: Option<&serde_json::Value>,
) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => match (a, b) {
            (serde_json::Value::Number(a), serde_json::Value::Number(b)) => {
                let a_f = a.as_f64().unwrap_or(0.0);
                let b_f = b.as_f64().unwrap_or(0.0);
                a_f.partial_cmp(&b_f).unwrap_or(Ordering::Equal)
            }
            (serde_json::Value::String(a), serde_json::Value::String(b)) => a.cmp(b),
            (serde_json::Value::Bool(a), serde_json::Value::Bool(b)) => a.cmp(b),
            _ => Ordering::Equal,
        },
    }
}

// Canonical SQL-literal escapers live in `crate::sql_hygiene` (NAN-1616).
// Re-exported here so existing `evaluator::helpers::{escape_sql_string,
// escape_like_pattern}` import paths keep working.
pub(crate) use crate::sql_hygiene::{escape_like_pattern, escape_sql_string};

/// Strip empty/default values from a result JSON object to reduce response size.
/// Removes empty strings, zero numbers, empty arrays, and null values.
/// Core fields (id, timestamp, message, source_type) are always preserved.
pub fn strip_empty_values(obj: &mut serde_json::Map<String, serde_json::Value>) {
    const ALWAYS_KEEP: &[&str] = &[
        "id",
        "timestamp",
        "message",
        "source_type",
        "ingest_time",
        "metadata",
    ];

    obj.retain(|key, value| {
        if ALWAYS_KEEP.contains(&key.as_str()) {
            return true;
        }
        match value {
            serde_json::Value::Null => false,
            serde_json::Value::String(s) => !s.is_empty(),
            serde_json::Value::Number(_) => true,
            serde_json::Value::Array(a) => !a.is_empty(),
            serde_json::Value::Object(o) => !o.is_empty(),
            serde_json::Value::Bool(_) => true,
        }
    });
}

/// Merge the `ext` overflow object's fields into `obj`, each namespaced as
/// `ext.<key>`.
///
/// `ext` carries extended/overflow UDM fields that are NOT promoted columns.
/// Every ext field is surfaced under its `ext.<key>` name so that (a) it can
/// never collide with or overwrite a real promoted column, and (b) the
/// displayed field name IS the queryable nPL path (`ext.<key>` hits the JSON
/// column), so click-to-filter is correct. This mirrors how OCSF keeps overflow
/// fields under their `unmapped.<key>` prefix — in UDM land the raw `ext`
/// wrapper was hidden, but the per-field prefix is what makes each leaf
/// addressable.
///
/// NAN-1467: previously ext keys merged bare, namespacing only on collision
/// with an occupied column (NAN-1463) and otherwise filling a blank same-named
/// column. That made the displayed name diverge from the queryable path — an
/// `ext.user` shown as bare `user` queried the (empty) `user` column and
/// returned nothing. Always-namespacing removes that ambiguity. This is
/// display/result-shaping only; nPL `ext.<key>` querying is unaffected.
pub fn merge_ext_fields_into(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    ext_map: serde_json::Map<String, serde_json::Value>,
) {
    for (key, value) in ext_map {
        obj.insert(format!("ext.{key}"), value);
    }
}

/// Parse a row's `ext` field (a JSON string or already-parsed object) and
/// flatten each entry into `obj` under its `ext.<key>` name, then drop the raw
/// `ext` key. No-op when `ext` is absent, empty, or not an object.
pub fn flatten_ext_field_in_place(obj: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(ext_val) = obj.get("ext") else {
        return;
    };
    let ext_obj = if let Some(ext_str) = ext_val.as_str() {
        if !ext_str.is_empty() && ext_str != "{}" && ext_str != "null" {
            serde_json::from_str::<serde_json::Value>(ext_str).ok()
        } else {
            None
        }
    } else if ext_val.is_object() {
        Some(ext_val.clone())
    } else {
        None
    };
    if let Some(serde_json::Value::Object(ext_map)) = ext_obj {
        merge_ext_fields_into(obj, ext_map);
    }
    obj.remove("ext");
}

/// Convert timestamp fields in a JSON object to ISO 8601 format with Z suffix.
/// ClickHouse returns timestamps as "YYYY-MM-DD HH:MM:SS.ffffff" without timezone indicator.
/// This function converts them to "YYYY-MM-DDTHH:MM:SS.ffffffZ" so JavaScript clients
/// correctly interpret them as UTC.
pub fn convert_timestamps_to_iso8601(obj: &mut serde_json::Map<String, serde_json::Value>) {
    // List of known timestamp fields
    let timestamp_fields = [
        "timestamp",
        "ingest_time",
        "enrich_time",
        "created_at",
        "updated_at",
        "transaction_start",
        "transaction_end",
        "time_bucket",
        "first_seen",
        "last_seen",
    ];

    for field in &timestamp_fields {
        if let Some(value) = obj.get_mut(*field) {
            if let Some(ts_str) = value.as_str() {
                // Check if it's already in ISO 8601 format (has T and Z or timezone offset)
                if !ts_str.contains('T') || (!ts_str.ends_with('Z') && !ts_str.contains('+')) {
                    // Convert "YYYY-MM-DD HH:MM:SS.ffffff" to "YYYY-MM-DDTHH:MM:SS.ffffffZ"
                    let iso_str = ts_str.replace(' ', "T");
                    let iso_str = if iso_str.ends_with('Z') || iso_str.contains('+') {
                        iso_str
                    } else {
                        format!("{}Z", iso_str)
                    };
                    *value = serde_json::Value::String(iso_str);
                }
            }
        }
    }
}

/// Convert a ClickHouseLogReadRow to a JSON value
pub fn clickhouse_row_to_json(row: &ClickHouseLogReadRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();

    // Add all fields from the ClickHouseLogReadRow
    map.insert("id".to_string(), serde_json::Value::String(row.id.clone()));

    // Convert timestamp from microseconds to RFC3339
    let timestamp = DateTime::from_timestamp_micros(row.timestamp)
        .map(|dt| serde_json::Value::String(dt.to_rfc3339()))
        .unwrap_or(serde_json::Value::Null);
    map.insert("timestamp".to_string(), timestamp);

    map.insert(
        "message".to_string(),
        serde_json::Value::String(row.message.clone()),
    );
    map.insert(
        "source_type".to_string(),
        serde_json::Value::String(row.source_type.clone()),
    );

    // Parse metadata JSON string
    if !row.metadata.is_empty() {
        if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&row.metadata) {
            map.insert("metadata".to_string(), metadata);
        } else {
            map.insert(
                "metadata".to_string(),
                serde_json::Value::String(row.metadata.clone()),
            );
        }
    }

    // Entity fields
    if !row.src_ip.is_empty() {
        map.insert(
            "src_ip".to_string(),
            serde_json::Value::String(row.src_ip.clone()),
        );
    }
    if !row.dest_ip.is_empty() {
        map.insert(
            "dest_ip".to_string(),
            serde_json::Value::String(row.dest_ip.clone()),
        );
    }
    if !row.src_host.is_empty() {
        map.insert(
            "src_host".to_string(),
            serde_json::Value::String(row.src_host.clone()),
        );
    }
    if !row.dest_host.is_empty() {
        map.insert(
            "dest_host".to_string(),
            serde_json::Value::String(row.dest_host.clone()),
        );
    }

    // Network fields
    if row.src_port > 0 {
        map.insert(
            "src_port".to_string(),
            serde_json::Value::Number(row.src_port.into()),
        );
    }
    if row.dest_port > 0 {
        map.insert(
            "dest_port".to_string(),
            serde_json::Value::Number(row.dest_port.into()),
        );
    }
    if !row.protocol.is_empty() {
        map.insert(
            "protocol".to_string(),
            serde_json::Value::String(row.protocol.clone()),
        );
    }
    if row.bytes_in > 0 {
        map.insert(
            "bytes_in".to_string(),
            serde_json::Value::Number(row.bytes_in.into()),
        );
    }
    if row.bytes_out > 0 {
        map.insert(
            "bytes_out".to_string(),
            serde_json::Value::Number(row.bytes_out.into()),
        );
    }

    // User/Action fields
    if !row.user.is_empty() {
        map.insert(
            "user".to_string(),
            serde_json::Value::String(row.user.clone()),
        );
    }
    if !row.action.is_empty() {
        map.insert(
            "action".to_string(),
            serde_json::Value::String(row.action.clone()),
        );
    }
    if !row.status.is_empty() {
        map.insert(
            "status".to_string(),
            serde_json::Value::String(row.status.clone()),
        );
    }

    // Authentication fields
    if !row.auth_type.is_empty() {
        map.insert(
            "auth_type".to_string(),
            serde_json::Value::String(row.auth_type.clone()),
        );
    }
    if !row.auth_result.is_empty() {
        map.insert(
            "auth_result".to_string(),
            serde_json::Value::String(row.auth_result.clone()),
        );
    }
    if !row.session_id.is_empty() {
        map.insert(
            "session_id".to_string(),
            serde_json::Value::String(row.session_id.clone()),
        );
    }

    // Process fields
    if !row.process_name.is_empty() {
        map.insert(
            "process_name".to_string(),
            serde_json::Value::String(row.process_name.clone()),
        );
    }
    if row.process_id > 0 {
        map.insert(
            "process_id".to_string(),
            serde_json::Value::Number(row.process_id.into()),
        );
    }
    if !row.command_line.is_empty() {
        map.insert(
            "command_line".to_string(),
            serde_json::Value::String(row.command_line.clone()),
        );
    }
    if !row.parent_process_name.is_empty() {
        map.insert(
            "parent_process_name".to_string(),
            serde_json::Value::String(row.parent_process_name.clone()),
        );
    }
    if !row.parent_command_line.is_empty() {
        map.insert(
            "parent_command_line".to_string(),
            serde_json::Value::String(row.parent_command_line.clone()),
        );
    }

    // File fields
    if !row.file_path.is_empty() {
        map.insert(
            "file_path".to_string(),
            serde_json::Value::String(row.file_path.clone()),
        );
    }
    if !row.file_name.is_empty() {
        map.insert(
            "file_name".to_string(),
            serde_json::Value::String(row.file_name.clone()),
        );
    }
    if !row.file_hash.is_empty() {
        map.insert(
            "file_hash".to_string(),
            serde_json::Value::String(row.file_hash.clone()),
        );
    }
    if !row.file_action.is_empty() {
        map.insert(
            "file_action".to_string(),
            serde_json::Value::String(row.file_action.clone()),
        );
    }

    // HTTP fields
    if !row.user_agent.is_empty() {
        map.insert(
            "user_agent".to_string(),
            serde_json::Value::String(row.user_agent.clone()),
        );
    }

    // Enrichment fields (source)
    if !row.enriched_src_country.is_empty() {
        map.insert(
            "enriched_src_country".to_string(),
            serde_json::Value::String(row.enriched_src_country.clone()),
        );
    }
    if !row.enriched_src_country_code.is_empty() {
        map.insert(
            "enriched_src_country_code".to_string(),
            serde_json::Value::String(row.enriched_src_country_code.clone()),
        );
    }
    if !row.enriched_src_continent.is_empty() {
        map.insert(
            "enriched_src_continent".to_string(),
            serde_json::Value::String(row.enriched_src_continent.clone()),
        );
    }
    if !row.enriched_src_continent_code.is_empty() {
        map.insert(
            "enriched_src_continent_code".to_string(),
            serde_json::Value::String(row.enriched_src_continent_code.clone()),
        );
    }
    if !row.enriched_src_asn.is_empty() {
        map.insert(
            "enriched_src_asn".to_string(),
            serde_json::Value::String(row.enriched_src_asn.clone()),
        );
    }
    if !row.enriched_src_as_name.is_empty() {
        map.insert(
            "enriched_src_as_name".to_string(),
            serde_json::Value::String(row.enriched_src_as_name.clone()),
        );
    }
    if !row.enriched_src_as_domain.is_empty() {
        map.insert(
            "enriched_src_as_domain".to_string(),
            serde_json::Value::String(row.enriched_src_as_domain.clone()),
        );
    }

    // Enrichment fields (destination)
    if !row.enriched_dest_country.is_empty() {
        map.insert(
            "enriched_dest_country".to_string(),
            serde_json::Value::String(row.enriched_dest_country.clone()),
        );
    }
    if !row.enriched_dest_country_code.is_empty() {
        map.insert(
            "enriched_dest_country_code".to_string(),
            serde_json::Value::String(row.enriched_dest_country_code.clone()),
        );
    }
    if !row.enriched_dest_continent.is_empty() {
        map.insert(
            "enriched_dest_continent".to_string(),
            serde_json::Value::String(row.enriched_dest_continent.clone()),
        );
    }
    if !row.enriched_dest_continent_code.is_empty() {
        map.insert(
            "enriched_dest_continent_code".to_string(),
            serde_json::Value::String(row.enriched_dest_continent_code.clone()),
        );
    }
    if !row.enriched_dest_asn.is_empty() {
        map.insert(
            "enriched_dest_asn".to_string(),
            serde_json::Value::String(row.enriched_dest_asn.clone()),
        );
    }
    if !row.enriched_dest_as_name.is_empty() {
        map.insert(
            "enriched_dest_as_name".to_string(),
            serde_json::Value::String(row.enriched_dest_as_name.clone()),
        );
    }
    if !row.enriched_dest_as_domain.is_empty() {
        map.insert(
            "enriched_dest_as_domain".to_string(),
            serde_json::Value::String(row.enriched_dest_as_domain.clone()),
        );
    }

    // Processing timestamps
    let ingest_time = DateTime::from_timestamp_micros(row.ingest_time)
        .map(|dt| serde_json::Value::String(dt.to_rfc3339()))
        .unwrap_or(serde_json::Value::Null);
    map.insert("ingest_time".to_string(), ingest_time);

    if row.enrich_time > 0 {
        let enrich_dt = DateTime::from_timestamp_micros(row.enrich_time)
            .map(|dt| serde_json::Value::String(dt.to_rfc3339()))
            .unwrap_or(serde_json::Value::Null);
        map.insert("enrich_time".to_string(), enrich_dt);
    }

    // Parse ext JSON string and flatten fields into the result.
    // ext contains extended/overflow UDM fields that aren't in explicit columns.
    // NAN-1467: every ext field is surfaced as `ext.<key>` so the displayed name
    // is the queryable nPL path and can never clobber a promoted column.
    if !row.ext.is_empty() && row.ext != "{}" && row.ext != "null" {
        match serde_json::from_str::<serde_json::Value>(&row.ext) {
            Ok(serde_json::Value::Object(ext_map)) => {
                merge_ext_fields_into(&mut map, ext_map);
            }
            Ok(other) => {
                debug!("ext is not an object: {:?}", other);
            }
            Err(e) => {
                debug!("Failed to parse ext JSON: {} - Error: {}", row.ext, e);
            }
        }
    }

    serde_json::Value::Object(map)
}

#[cfg(test)]
mod ext_flatten_tests {
    use super::*;
    use serde_json::json;

    fn obj(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    // NAN-1467: every ext field is namespaced as `ext.<key>`. A key that shares
    // a name with a real promoted column can never overwrite it (the column
    // value is untouched and the ext value lands at `ext.<key>`).
    #[test]
    fn ext_collision_preserves_promoted_column() {
        let mut o = obj(json!({
            "category": "web_proxy",          // promoted column (event-class)
            "ext": { "category": "social_media", "cache_status": "hit" }
        }));
        flatten_ext_field_in_place(&mut o);

        assert_eq!(o["category"], json!("web_proxy"), "column was clobbered");
        assert_eq!(o["ext.category"], json!("social_media"), "ext value lost");
        assert_eq!(o["ext.cache_status"], json!("hit"), "non-colliding ext key dropped");
        assert!(!o.contains_key("ext"), "raw ext key should be removed");
    }

    // NAN-1467: even a blank same-named column is NOT filled in place — the ext
    // value is surfaced as `ext.<key>` so the displayed name matches the
    // queryable nPL path (filling the bare column would query the empty column
    // on click-to-filter and return nothing).
    #[test]
    fn ext_always_namespaces_not_fills_blank_column() {
        let mut o = obj(json!({ "user": "", "ext": { "user": "jdoe", "host": "ws1" } }));
        flatten_ext_field_in_place(&mut o);
        assert_eq!(o["ext.user"], json!("jdoe"), "ext value should land at ext.<key>");
        assert_eq!(o["user"], json!(""), "blank column should stay untouched");
        assert_eq!(o["ext.host"], json!("ws1"));
    }

    #[test]
    fn ext_string_form_is_parsed_and_flattened() {
        let mut o = obj(json!({ "ext": "{\"foo\":\"bar\"}" }));
        flatten_ext_field_in_place(&mut o);
        assert_eq!(o["ext.foo"], json!("bar"));
        assert!(!o.contains_key("ext"));
    }

    #[test]
    fn ext_empty_or_missing_is_noop() {
        for v in [json!({}), json!({ "ext": "{}" }), json!({ "ext": "null" }), json!({ "ext": "" })] {
            let mut o = obj(v);
            flatten_ext_field_in_place(&mut o);
            assert!(!o.contains_key("ext"));
        }
    }
}
