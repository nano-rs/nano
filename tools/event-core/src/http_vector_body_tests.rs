// SPDX-License-Identifier: AGPL-3.0-or-later

//! The HTTP (`/ingest`) lane body carries raw records, never the generator's
//! `{message, timestamp, source_type}` envelope — the lane hands each line to
//! the parser verbatim, so an envelope makes every parser fall back.

use super::vector_raw_body;
use crate::event::Event;

fn ev(source_type: &str, message: &str) -> Event {
    Event {
        message: message.to_string(),
        timestamp: "2026-11-11T01:30:00Z".to_string(),
        source_type: source_type.to_string(),
        display_label: String::new(),
    }
}

#[test]
fn json_records_go_as_ndjson_of_the_raw_record() {
    let a = ev("windows_sysmon", r#"{"event_id":1,"event_data":{"Image":"a.exe"}}"#);
    let b = ev("windows_sysmon", r#"{"event_id":3}"#);
    let (ct, body) = vector_raw_body(&[&a, &b]);
    assert_eq!(ct, "application/x-ndjson");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines, vec![a.message.as_str(), b.message.as_str()]);
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert!(first.get("message").is_none(), "no envelope: {body}");
    assert!(first.get("source_type").is_none(), "no envelope: {body}");
    assert_eq!(first["event_id"], 1);
}

#[test]
fn text_lines_go_as_text_plain_verbatim() {
    let line = r#"203.0.113.7 - - [11/Nov/2026:01:30:00 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.5.0""#;
    let a = ev("apache_access", line);
    let (ct, body) = vector_raw_body(&[&a, &a]);
    assert_eq!(ct, "text/plain");
    assert_eq!(body, format!("{line}\n{line}"));
}

#[test]
fn a_mixed_group_falls_back_to_text_plain() {
    let a = ev("x", r#"{"k":1}"#);
    let b = ev("x", "plain line");
    let (ct, _) = vector_raw_body(&[&a, &b]);
    assert_eq!(ct, "text/plain");
}

#[test]
fn json_arrays_and_scalars_are_not_ndjson_objects() {
    let a = ev("x", "[1,2]");
    assert_eq!(vector_raw_body(&[&a]).0, "text/plain");
}

#[test]
fn embedded_newlines_cannot_split_a_record() {
    let a = ev("x", "line one\nline two\r\n");
    let (_, body) = vector_raw_body(&[&a]);
    assert_eq!(body.lines().count(), 1, "{body:?}");
}
