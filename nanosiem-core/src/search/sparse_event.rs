// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3245: the "full event" an analyst inspects is the event's POPULATED
//! fields, not the storage schema.
//!
//! A lean (lake cell) full-event read is a `SELECT *` over the tenant's OCSF
//! union schema, so every row comes back with every leaf of every OCSF object
//! the tenant has ever stored: `actor.process.file.name: null`,
//! `finding_info.analytic.*: null`, empty arrays, objects of nothing but
//! nulls. An apache_access event measured 395 leaves, 319 of them null or
//! empty. Those are physical sparsity of the columnar layout, not attributes
//! present on the event.
//!
//! [`sparse_full_event`] removes them, recursively:
//!
//! * `null` scalars are dropped;
//! * `""` strings are dropped. This matches the result list's compact JSON
//!   line (`buildEventRowLine`, which skips `null` and `""`), so the full
//!   event is that line's fields plus the extra detail, never fewer;
//! * empty arrays, and arrays whose every element pruned away, are dropped;
//! * objects that are empty after pruning are dropped;
//! * `0`, `false` and non-empty strings are kept: they are real values.
//!
//! Array elements that prune to nothing are removed from their array (the
//! same physical-sparsity rule the Iceberg reader applies).
//!
//! `raw_data` ([`PRESERVED_ROOTS`]) is the source's original record and is
//! returned verbatim, byte for byte, unless the whole root is `null`/`""`.
//!
//! NAN-3458: `unmapped`, `ext` and `enrichments` are NOT verbatim. On the
//! lake (lean Parquet parts and open-core Iceberg tables alike) they are
//! STRUCT columns whose members are the union of every key any file of the
//! tenant ever stored (`unmapped.winlog.event_data.*`, `unmapped.@timestamp`,
//! ...), so one conduit_proxy event came back with ~70 `unmapped` members,
//! all `null` except its own 4. That is the same physical sparsity as the
//! OCSF objects, so they get the same pruning. A member a source sent as
//! literal `null` is indistinguishable from padding once stored in a struct
//! column, and the compact result line never showed it either. A root that
//! is a JSON string (the dedicated ClickHouse `unmapped` blob) is a non-empty
//! string and is kept as is.
//!
//! Only full-event output is pruned (fetch-by-id and non-table-view raw-event
//! rows). Table-view list rows, projections and aggregates keep their shape:
//! a `null` there is a real column value.

use serde_json::Value;

/// Top-level roots whose content is returned exactly as stored. A flat
/// dotted key under one of them (`raw_data.foo`) is preserved too.
///
/// NAN-3458: only `raw_data`. `unmapped`, `ext` and `enrichments` are lake
/// struct columns padded with the union of every stored key, so they are
/// pruned like the rest of the event (see the module docs).
pub const PRESERVED_ROOTS: &[&str] = &["raw_data"];

fn is_preserved_root(key: &str) -> bool {
    PRESERVED_ROOTS.iter().any(|root| {
        key == *root
            || key
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// Prune one full-event row in place (see the module docs). A non-object row
/// is pruned as a value but never removed.
pub fn sparse_full_event(row: &mut Value) {
    match row {
        Value::Object(fields) => fields.retain(|key, value| {
            if is_preserved_root(key) {
                !is_absent_scalar(value)
            } else {
                prune_value(value)
            }
        }),
        other => {
            prune_value(other);
        }
    }
}

/// Prune every row of a full-event page.
pub fn sparse_full_event_rows(rows: &mut [Value]) {
    for row in rows {
        sparse_full_event(row);
    }
}

fn is_absent_scalar(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        _ => false,
    }
}

/// Prune `value` in place; `false` means the value is now empty and its
/// parent should drop it.
fn prune_value(value: &mut Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
        Value::Array(items) => {
            items.retain_mut(prune_value);
            !items.is_empty()
        }
        Value::Object(fields) => {
            fields.retain(|_, value| prune_value(value));
            !fields.is_empty()
        }
    }
}

/// Does `query` return FULL raw events (every stored field of each matching
/// event, no projection or aggregation)? Only filter / order / limit stages
/// keep that shape. Anything that projects, renames, computes or aggregates
/// returns rows whose `null`s are real column values, so it is never pruned.
/// An unparsable query is never treated as full-event.
pub fn query_returns_full_events(query: &str) -> bool {
    crate::query::parse_query(query)
        .map(|parsed| is_full_event_shape(&parsed))
        .unwrap_or(false)
}

fn is_full_event_shape(query: &crate::query::Query) -> bool {
    use crate::query::{Command, Query};
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            is_full_event_shape(source)
                && matches!(
                    command,
                    Command::Where { .. }
                        | Command::Sort { .. }
                        | Command::Head { .. }
                        | Command::Tail { .. }
                        | Command::Dedup { .. }
                        | Command::Reverse
                        | Command::Sample { .. }
                )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn leaves(value: &Value) -> usize {
        match value {
            Value::Object(fields) => fields.values().map(leaves).sum(),
            Value::Array(items) => items.iter().map(leaves).sum(),
            _ => 1,
        }
    }

    fn has_null_or_empty(value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::String(text) => text.is_empty(),
            Value::Array(items) => items.is_empty() || items.iter().any(has_null_or_empty),
            Value::Object(fields) => fields.is_empty() || fields.values().any(has_null_or_empty),
            _ => false,
        }
    }

    /// A null-heavy OCSF union-schema row, shaped like the lean apache_access
    /// event in NAN-3245.
    fn apache_union_row() -> Value {
        json!({
            "time": "2026-10-07T12:00:00.000000Z",
            "class_uid": 4002,
            "severity_id": 0,
            "status_id": 1,
            "is_alert": false,
            "message": null,
            "metadata": {
                "uid": "f1541890-0000-4000-8000-000000000001",
                "log_source": "apache_access",
                "original_time": "",
                "labels": [],
                "product": {"name": "Apache HTTP Server", "vendor_name": null, "feature": {"uid": null, "name": null}},
            },
            "actor": {"process": {"file": {"name": null, "path": null, "hashes": []}, "pid": null}, "user": {"name": null}},
            "finding_info": {"analytic": {"name": null, "uid": null, "type_id": null}, "attacks": []},
            "module": {"file": {"name": null, "size": null}},
            "http_request": {
                "http_method": "GET",
                "url": {"path": "/index.html", "query_string": "", "port": 0},
                "headers": [{"name": null, "value": null}],
            },
            "http_response": {"code": 200, "length": 0, "message": null},
            "src_endpoint": {"ip": "203.0.113.7", "port": null, "location": {"country": null, "city": null}},
            "observables": [
                {"name": "src_endpoint.ip", "type_id": 2, "value": "203.0.113.7", "reputation": null},
                {"name": null, "type_id": null, "value": null},
            ],
            "raw_data": "203.0.113.7 - - [07/Oct/2026:12:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 0",
            "ext": {"note": null, "empty": "", "list": []},
            "enrichments": [{"name": "geo", "value": null, "data": {"country": "", "asn": 64500}}],
            "unmapped": "{\"x\":null}",
        })
    }

    #[test]
    fn null_heavy_ocsf_row_comes_out_sparse() {
        let mut row = apache_union_row();
        let before = leaves(&row);
        sparse_full_event(&mut row);
        assert!(leaves(&row) < before);
        // Pruned union-schema objects disappear entirely.
        for gone in ["message", "actor", "finding_info", "module"] {
            assert!(row.get(gone).is_none(), "{gone} should collapse");
        }
        assert!(row.pointer("/metadata/labels").is_none());
        assert!(row.pointer("/metadata/original_time").is_none());
        assert!(row.pointer("/metadata/product/feature").is_none());
        assert!(row.pointer("/metadata/product/vendor_name").is_none());
        assert!(
            row.pointer("/http_request/headers").is_none(),
            "an array of all-null objects collapses"
        );
        assert!(
            row.pointer("/http_request/url/query_string").is_none(),
            "\"\" is dropped"
        );
        assert!(row.pointer("/src_endpoint/location").is_none());
        // An array keeps only its populated elements.
        assert_eq!(row["observables"].as_array().unwrap().len(), 1);
        assert_eq!(
            row["observables"][0],
            json!({"name": "src_endpoint.ip", "type_id": 2, "value": "203.0.113.7"})
        );
        // Outside the preserved roots, nothing null or empty remains.
        let mut outside = row.clone();
        for root in PRESERVED_ROOTS {
            outside.as_object_mut().unwrap().remove(*root);
        }
        assert!(!has_null_or_empty(&outside), "{outside}");
    }

    #[test]
    fn zero_false_and_populated_values_are_kept() {
        let mut row = apache_union_row();
        sparse_full_event(&mut row);
        assert_eq!(row["severity_id"], json!(0));
        assert_eq!(row["is_alert"], json!(false));
        assert_eq!(row["status_id"], json!(1));
        assert_eq!(row.pointer("/http_request/url/port"), Some(&json!(0)));
        assert_eq!(row.pointer("/http_response/length"), Some(&json!(0)));
        assert_eq!(row.pointer("/http_response/code"), Some(&json!(200)));
        assert_eq!(
            row.pointer("/http_request/http_method"),
            Some(&json!("GET"))
        );
        assert_eq!(
            row.pointer("/metadata/uid"),
            Some(&json!("f1541890-0000-4000-8000-000000000001"))
        );
        assert_eq!(
            row.pointer("/metadata/product/name"),
            Some(&json!("Apache HTTP Server"))
        );
        assert_eq!(row["time"], json!("2026-10-07T12:00:00.000000Z"));
    }

    #[test]
    fn raw_data_is_verbatim() {
        let original = apache_union_row();
        let mut row = original.clone();
        sparse_full_event(&mut row);
        assert_eq!(row["raw_data"], original["raw_data"]);
        // A flat dotted key under raw_data is preserved too; a look-alike
        // prefix is not; a null/"" root itself is still absent.
        let mut flat = json!({"raw_data.note": "", "raw_data.list": [], "raw_datum": null, "raw_data": null});
        sparse_full_event(&mut flat);
        assert_eq!(flat, json!({"raw_data.list": []}));
    }

    /// NAN-3458: the lake stores `unmapped`, `ext` and `enrichments` as
    /// struct columns padded with the union of every key the tenant ever
    /// stored. A conduit_proxy event read back with ~70 `unmapped` members,
    /// all null except its own 4.
    #[test]
    fn union_padded_unmapped_ext_and_enrichments_are_pruned() {
        let mut row = json!({
            "time": "2026-10-09T12:00:00.000000Z",
            "metadata": {"log_source": "conduit_proxy"},
            "unmapped": {
                "_timestamp": null, "foo": null, "event_id": null,
                "winlog.event_data.Image": null,
                "winlog": {"event_data": {"Image": null, "TargetFilename": null}, "channel": null},
                "tags": [], "empty": "",
                "bytes_out": "1824", "status": "200", "url": "https://a.example/login", "user": "alice",
                "retries": 0, "cached": false,
            },
            "ext": {"note": null, "kept": "x"},
            "ext.flat": null,
            "enrichments": [{"name": "geo", "value": null, "data": {"country": "CA", "asn": null}}, {"name": null}],
        });
        sparse_full_event(&mut row);
        assert_eq!(
            row,
            json!({
                "time": "2026-10-09T12:00:00.000000Z",
                "metadata": {"log_source": "conduit_proxy"},
                "unmapped": {
                    "bytes_out": "1824", "status": "200", "url": "https://a.example/login", "user": "alice",
                    "retries": 0, "cached": false,
                },
                "ext": {"kept": "x"},
                "enrichments": [{"name": "geo", "data": {"country": "CA"}}],
            })
        );
        // All-padding roots disappear; a JSON-string root (the dedicated
        // ClickHouse `unmapped` blob) is a value and is kept as is.
        let mut row = json!({"unmapped": {"foo": null, "winlog": {"channel": null}}, "ext": "{\"a\":null}"});
        sparse_full_event(&mut row);
        assert_eq!(row, json!({"ext": "{\"a\":null}"}));
    }

    #[test]
    fn nested_empties_collapse_bottom_up() {
        let mut row = json!({"a": {"b": {"c": {"d": null, "e": []}, "f": [{}, [], null, ""]}}, "keep": {"x": {"y": false}}});
        sparse_full_event(&mut row);
        assert_eq!(row, json!({"keep": {"x": {"y": false}}}));
    }

    #[test]
    fn only_filter_order_limit_queries_are_full_event() {
        for query in [
            "*",
            "status=500",
            "error | head 10",
            "error | sort -time | head 5",
            "error | where severity_id > 2",
            "error | dedup src_endpoint.ip | reverse",
        ] {
            assert!(query_returns_full_events(query), "{query}");
        }
        for query in [
            "error | stats count by src_endpoint.ip",
            "error | table time, src_endpoint.ip",
            "error | fields src_endpoint.ip",
            "error | eval x=1",
            "error | rename src_endpoint.ip as ip",
            "error | fillnull value=0",
            "error | timechart span=1h count",
            "error | top src_endpoint.ip",
        ] {
            assert!(!query_returns_full_events(query), "{query}");
        }
        assert!(
            !query_returns_full_events("error | |"),
            "unparsable is never pruned"
        );
    }
}
