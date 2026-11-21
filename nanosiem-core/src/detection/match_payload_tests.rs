// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5736: a `detection_matches` row stays bounded however many events a
//! run matched and however large they are.

use super::*;
use serde_json::json;

fn sysmon_event(i: usize, command_line_len: usize) -> Value {
    json!({
        "log_id": format!("log-{i}"),
        "timestamp": "2026-11-20T12:00:00Z",
        "source_type": "sysmon",
        "process_name": "cmd.exe",
        "command_line": "x".repeat(command_line_len),
        "user": format!("user{i}"),
    })
}

#[test]
fn small_payloads_are_stored_unchanged() {
    let events: Vec<Value> = (0..10).map(|i| sysmon_event(i, 50)).collect();
    let bounded = bound_match_events(&events);
    assert_eq!(bounded.events, events);
    assert!(!bounded.truncated());
}

#[test]
fn a_run_matching_700k_events_stores_a_bounded_row() {
    // The CT122 shape: one rule matching every Sysmon event.
    let events: Vec<Value> = (0..700_000).map(|i| sysmon_event(i, 200)).collect();
    let bounded = bound_match_events(&events);
    let stored = json_len(&Value::Array(bounded.events.clone()));
    assert!(stored <= MAX_MATCH_ROW_BYTES, "row is {stored} bytes");
    assert!(bounded.truncated());
    assert_eq!(bounded.dropped + bounded.events.len(), events.len());
    // Newest first: the kept events are the leading ones.
    assert_eq!(bounded.events[0], events[0]);
    assert_eq!(bounded.events.last(), events.get(bounded.events.len() - 1));
}

#[test]
fn an_oversized_event_has_its_long_values_cut_and_is_marked() {
    let events = vec![sysmon_event(0, 200_000)];
    let bounded = bound_match_events(&events);
    assert_eq!(bounded.events.len(), 1);
    assert_eq!(bounded.shrunk, 1);
    let event = &bounded.events[0];
    assert!(json_len(event) <= MAX_MATCH_EVENT_BYTES);
    assert!(event.get(TRUNCATED_MARKER).is_some());
    let cmd = event["command_line"].as_str().unwrap();
    assert!(cmd.ends_with("…[truncated]"));
    // Short fields are untouched.
    assert_eq!(event["process_name"], "cmd.exe");
    assert_eq!(event["log_id"], "log-0");
}

#[test]
fn an_event_too_large_even_cut_keeps_only_its_identity() {
    // Many medium fields: cutting each string to 4096 chars is not enough.
    let mut map = serde_json::Map::new();
    map.insert("log_id".into(), json!("log-big"));
    map.insert("timestamp".into(), json!("2026-11-20T12:00:00Z"));
    map.insert("source_type".into(), json!("sysmon"));
    for f in 0..100 {
        map.insert(format!("field_{f}"), json!("y".repeat(4000)));
    }
    let bounded = bound_match_events(&[Value::Object(map)]);
    let event = &bounded.events[0];
    assert!(json_len(event) <= MAX_MATCH_EVENT_BYTES);
    assert_eq!(event["log_id"], "log-big");
    assert_eq!(event["source_type"], "sysmon");
    assert!(event.get("field_0").is_none());
    assert!(event.get(TRUNCATED_MARKER).is_some());
}

#[test]
fn string_cut_respects_char_boundaries() {
    let mut v = json!("é".repeat(10));
    truncate_strings(&mut v, 3);
    assert_eq!(v, json!("ééé…[truncated]"));
}

#[test]
fn at_least_one_event_is_always_kept() {
    let events = vec![sysmon_event(0, 10)];
    let bounded = bound_match_events_with(&events, 1, 1 << 20);
    assert_eq!(bounded.events.len(), 1);
}

#[test]
fn json_len_matches_serialization() {
    let v = sysmon_event(7, 33);
    assert_eq!(json_len(&v), serde_json::to_vec(&v).unwrap().len());
}
