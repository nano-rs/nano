// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical event envelope for `DetectionMatch.events` (NAN-830).
//!
//! Rules can produce events with *any* shape (raw log rows, `stats … by …`
//! aggregates with user-aliased columns, etc.), so the frontend can't reliably
//! infer "when did this happen" or "what to label it" from the raw JSON.
//!
//! `normalize_match_event` injects three system fields on every event before
//! serialization. The user's original fields are left untouched so the
//! expanded detail view still sees everything; we just also surface a
//! canonical envelope alongside:
//!
//! - `_match_event_time` — RFC 3339 timestamp string, best-effort
//! - `_match_event_label` — one-line human label (always present)
//! - `_match_kind` — `"raw"`, `"aggregate"`, or `"sequence"`
//!
//! The heuristics mirror what the frontend has accumulated across NAN-822 /
//! NAN-826 / NAN-829. Moving them server-side means future regressions get
//! fixed once, in one Rust function, instead of three TS files.

use serde_json::{Map, Value};

pub const MATCH_EVENT_TIME: &str = "_match_event_time";
pub const MATCH_EVENT_LABEL: &str = "_match_event_label";
pub const MATCH_KIND: &str = "_match_kind";

/// Inject canonical `_match_*` envelope fields on the event in-place. Only
/// operates on JSON objects; arrays / scalars are left untouched.
pub fn normalize_match_event(event: &mut Value) {
    let Some(obj) = event.as_object_mut() else {
        return;
    };
    let kind = pick_kind(obj);
    if let Some(t) = pick_time(obj) {
        obj.insert(MATCH_EVENT_TIME.into(), Value::String(t));
    }
    if let Some(label) = pick_label(obj, kind) {
        obj.insert(MATCH_EVENT_LABEL.into(), Value::String(label));
    }
    obj.insert(
        MATCH_KIND.into(),
        Value::String(match kind {
            Kind::Aggregate => "aggregate".into(),
            Kind::Sequence => "sequence".into(),
            Kind::Raw => "raw".into(),
        }),
    );
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Kind {
    Raw,
    Aggregate,
    Sequence,
}

/// Aggregate-row detection mirrors NAN-829's widened heuristic:
/// system-injected `_first_seen` / `_last_seen`, the user-aliased pair
/// `first_seen` + `last_seen` together, or the standalone `actions_attempted`
/// marker (which has no raw-event analog).
fn pick_kind(obj: &Map<String, Value>) -> Kind {
    if sequence_step_count(obj) >= 2
        || (sequence_step_count(obj) > 0
            && numeric_field(obj, "sequence_duration_seconds").is_some())
    {
        return Kind::Sequence;
    }
    if str_field(obj, "_first_seen").is_some() || str_field(obj, "_last_seen").is_some() {
        return Kind::Aggregate;
    }
    if str_field(obj, "first_seen").is_some() && str_field(obj, "last_seen").is_some() {
        return Kind::Aggregate;
    }
    if str_field(obj, "actions_attempted").is_some() {
        return Kind::Aggregate;
    }
    if obj
        .iter()
        .any(|(key, value)| value.as_f64().is_some() && is_aggregate_measure_name(key))
    {
        return Kind::Aggregate;
    }
    Kind::Raw
}

/// Event-time picker, mirrors NAN-822 (added `_last_seen` / `_first_seen` to
/// the canonical list) plus a loose-scan fallback for user-aliased columns.
/// `_nano_detected_at` stays excluded so the detection-engine timestamp
/// never masquerades as the event time.
fn pick_time(obj: &Map<String, Value>) -> Option<String> {
    for key in [
        "timestamp",
        "eventTime",
        "ingest_time",
        "_time",
        "_last_seen",
        "_first_seen",
        "last_seen",
        "first_seen",
    ] {
        if let Some(v) = str_field(obj, key) {
            return Some(v.to_string());
        }
    }
    // Loose scan — pick the latest-parsing timestamp-shaped string in any
    // non-`_`-prefixed field. Handles user-aliased windows like `bucket_end`.
    let mut best: Option<(i64, &str)> = None;
    for (k, v) in obj {
        if k.starts_with('_') {
            continue;
        }
        let Some(s) = v.as_str() else { continue };
        if !looks_like_timestamp(s) {
            continue;
        }
        // Lexicographic sort works for ISO 8601 / RFC 3339, which both
        // canonical and user-aliased fields use.
        match best {
            Some((_, prev)) if prev >= s => {}
            _ => best = Some((0, s)),
        }
    }
    best.map(|(_, s)| s.to_string())
}

/// Label picker. Raw events prefer the canonical action fields; aggregates
/// fall through to user-aliased summary strings, then count-based derivation,
/// then a generic `"stats aggregate"` so the cell is never empty.
fn pick_label(obj: &Map<String, Value>, kind: Kind) -> Option<String> {
    if kind == Kind::Sequence {
        return Some(sequence_label(obj));
    }

    for key in [
        "eventName",
        "event_type",
        "action",
        "event_id",
        "activity",
        "api.operation",
    ] {
        if let Some(v) = str_field(obj, key) {
            return Some(v.to_string());
        }
    }

    if kind == Kind::Aggregate {
        for key in [
            "actions_attempted",
            "action_summary",
            "top_action",
            "operations",
            "tools",
            "domains",
        ] {
            if let Some(v) = obj.get(key).and_then(compact_value) {
                return Some(v);
            }
        }
        if let Some(label) = aggregate_measure_label(obj) {
            return Some(label);
        }
        return Some("stats aggregate".into());
    }

    Some(semantic_raw_label(obj).unwrap_or_else(|| "Matched event".into()))
}

fn sequence_step_count(obj: &Map<String, Value>) -> usize {
    let mut steps = std::collections::BTreeSet::new();
    for (key, value) in obj {
        let Some(rest) = key.strip_prefix("step") else {
            continue;
        };
        let digits = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        if digits.is_empty() || !rest[digits.len()..].starts_with('_') || !meaningful(value) {
            continue;
        }
        if let Ok(step) = digits.parse::<usize>() {
            steps.insert(step);
        }
    }
    steps.len()
}

fn sequence_label(obj: &Map<String, Value>) -> String {
    let steps = sequence_step_count(obj);
    let base = if steps > 0 {
        format!("{steps}-step sequence")
    } else {
        "Sequence match".into()
    };
    match numeric_field(obj, "sequence_duration_seconds") {
        Some(seconds) if seconds.is_finite() && seconds >= 0.0 => {
            format!("{base} · {}", format_duration(seconds))
        }
        _ => base,
    }
}

fn format_duration(seconds: f64) -> String {
    if seconds < 120.0 {
        return format!("{}s", seconds.round() as u64);
    }
    let total = seconds.round() as u64;
    let minutes = total / 60;
    let remainder = total % 60;
    if remainder == 0 {
        format!("{minutes}m")
    } else {
        format!("{minutes}m {remainder}s")
    }
}

fn is_aggregate_measure_name(key: &str) -> bool {
    key == "count"
        || key.ends_with("_count")
        || key.starts_with("unique_")
        || matches!(
            key,
            "hits"
                | "failures"
                | "executions"
                | "logons"
                | "queries"
                | "beacons"
                | "recon_commands"
        )
}

fn aggregate_measure_label(obj: &Map<String, Value>) -> Option<String> {
    let mut best: Option<(f64, &str)> = None;
    for (k, v) in obj {
        if k.starts_with('_') {
            continue;
        }
        if !is_aggregate_measure_name(k) {
            continue;
        }
        let Some(n) = v.as_f64() else { continue };
        if !n.is_finite() {
            continue;
        }
        match best {
            Some((prev, _)) if prev >= n => {}
            _ => best = Some((n, k.as_str())),
        }
    }
    if let Some((n, key)) = best {
        return Some(format!("{} {}", format_count(n), key.replace('_', " ")));
    }
    None
}

fn semantic_raw_label(obj: &Map<String, Value>) -> Option<String> {
    if let Some(process) = first_str(obj, &["process_name", "process.name", "actor.process.name"]) {
        return Some(process.to_string());
    }

    let file_action = first_str(obj, &["file_action"]);
    let file = first_str(obj, &["file_name", "file.name", "file_path", "file.path"]);
    if file_action.is_some() || file.is_some() {
        return Some(match (file_action, file) {
            (Some(action), Some(path)) => format!("{action} · {}", basename(path)),
            (Some(action), None) => format!("{action} file"),
            (None, Some(path)) => format!("File · {}", basename(path)),
            (None, None) => unreachable!(),
        });
    }

    let auth_type = first_str(obj, &["auth_type", "authentication_method"]);
    // OCSF's generic `status` is only authentication-specific when an auth
    // method is also present. Treating a standalone status as auth would turn
    // ordinary "Success" process/network rows into "Success authentication".
    let auth_result = first_str(obj, &["auth_result"])
        .or_else(|| auth_type.and_then(|_| first_str(obj, &["status"])));
    if auth_result.is_some() || auth_type.is_some() {
        return Some(match (auth_result, auth_type) {
            (Some(result), Some(method)) => format!("{result} {method} authentication"),
            (Some(result), None) => format!("{result} authentication"),
            (None, Some(method)) => format!("{method} authentication"),
            (None, None) => unreachable!(),
        });
    }

    let method = first_str(obj, &["http_method", "http_request.http_method"]);
    let destination = first_str(
        obj,
        &[
            "dest_host",
            "http_request.url.hostname",
            "url",
            "http_request.url.url_string",
            "dest_ip",
        ],
    );
    if method.is_some() || destination.is_some() {
        return Some(match (method, destination) {
            (Some(method), Some(dest)) => format!("{method} · {}", truncate(dest, 72)),
            (Some(method), None) => format!("{method} request"),
            (None, Some(dest)) => format!("Connection · {}", truncate(dest, 72)),
            (None, None) => unreachable!(),
        });
    }

    if let Some(registry) = first_str(
        obj,
        &["registry_key_name", "registry_path", "registry_value_name"],
    ) {
        return Some(format!("Registry · {}", truncate(registry, 72)));
    }
    if let Some(subject) = first_str(obj, &["subject", "email.subject"]) {
        return Some(format!("Email · {}", truncate(subject, 72)));
    }
    if let Some(message) = first_str(obj, &["message", "signature", "alert_name"]) {
        return Some(truncate(message, 96));
    }
    first_str(obj, &["source_type"])
        .map(|source| format!("{} event", source.replace(['_', '-'], " ")))
}

fn first_str<'a>(obj: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| str_field(obj, key))
}

fn numeric_field(obj: &Map<String, Value>, key: &str) -> Option<f64> {
    obj.get(key).and_then(Value::as_f64)
}

fn meaningful(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

fn compact_value(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(truncate(s, 96)),
        Value::Array(values) => {
            let parts = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .take(3)
                .collect::<Vec<_>>();
            if parts.is_empty() {
                None
            } else {
                let suffix = if values.len() > parts.len() {
                    ", …"
                } else {
                    ""
                };
                Some(format!("{}{}", parts.join(", "), suffix))
            }
        }
        _ => None,
    }
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn str_field<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    let value = obj.get(key).or_else(|| {
        let mut parts = key.split('.');
        let first = parts.next()?;
        let mut value = obj.get(first)?;
        for part in parts {
            value = value.as_object()?.get(part)?;
        }
        Some(value)
    });
    value.and_then(|v| v.as_str()).and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(s)
        }
    })
}

/// `YYYY-MM-DD[T| ]HH:MM` shape gate — matches the frontend's
/// `ISO_TIMESTAMP_SHAPE` so plain numbers, year strings, and IPs/hostnames
/// don't reach the comparison.
fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 16 {
        return false;
    }
    b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4] == b'-'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
        && (b[10] == b'T' || b[10] == b' ')
        && b[11].is_ascii_digit()
        && b[12].is_ascii_digit()
        && b[13] == b':'
        && b[14].is_ascii_digit()
        && b[15].is_ascii_digit()
}

/// Render with thousands separators so "1582 denied count" reads as "1,582".
fn format_count(n: f64) -> String {
    let int = n.trunc() as i64;
    if (n - int as f64).abs() > f64::EPSILON {
        return format!("{:.2}", n);
    }
    let s = int.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if int < 0 {
        out.push('-');
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn normalize(v: Value) -> Value {
        let mut v = v;
        normalize_match_event(&mut v);
        v
    }

    fn field<'a>(v: &'a Value, key: &str) -> &'a str {
        v.get(key)
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("missing {}", key))
    }

    #[test]
    fn raw_cloudtrail_event_uses_canonical_fields() {
        let v = normalize(json!({
            "timestamp": "2026-05-16T18:00:14.000Z",
            "eventName": "ConsoleLogin",
            "src_ip": "10.0.0.1",
            "_nano_detected_at": "2026-05-16T18:00:15.000Z",
        }));
        assert_eq!(field(&v, MATCH_KIND), "raw");
        assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16T18:00:14.000Z");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "ConsoleLogin");
    }

    #[test]
    fn underscore_prefixed_aggregate_works() {
        let v = normalize(json!({
            "_first_seen": "2026-05-16 14:20:28.000000",
            "_last_seen": "2026-05-16 14:35:10.000000",
            "_nano_detected_at": "2026-05-16T14:35:20.000Z",
            "denied_count": 1582,
            "unique_actions": 110,
        }));
        assert_eq!(field(&v, MATCH_KIND), "aggregate");
        assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16 14:35:10.000000");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "1,582 denied count");
    }

    #[test]
    fn user_aliased_aggregate_works() {
        let v = normalize(json!({
            "first_seen": "2026-05-16T17:45:21.000000Z",
            "last_seen": "2026-05-16T18:00:14.000000Z",
            "_nano_detected_at": "2026-05-16T18:00:19.772Z",
            "actions_attempted": "getsecretvalue, deletesecurity, ...",
            "denied_count": 1000000,
            "unique_actions": 76,
        }));
        assert_eq!(field(&v, MATCH_KIND), "aggregate");
        assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16T18:00:14.000000Z");
        // actions_attempted wins over count-based derivation
        assert_eq!(
            field(&v, MATCH_EVENT_LABEL),
            "getsecretvalue, deletesecurity, ..."
        );
    }

    #[test]
    fn aggregate_with_only_counts_falls_back_to_largest() {
        let v = normalize(json!({
            "first_seen": "2026-05-16 14:20:28.000000",
            "last_seen": "2026-05-16 14:35:10.000000",
            "failure_count": 12,
            "success_count": 8,
        }));
        assert_eq!(field(&v, MATCH_KIND), "aggregate");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "12 failure count");
    }

    #[test]
    fn aggregate_with_only_actions_attempted() {
        let v = normalize(json!({
            "actions_attempted": "PutObject, DeleteObject",
        }));
        assert_eq!(field(&v, MATCH_KIND), "aggregate");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "PutObject, DeleteObject");
    }

    #[test]
    fn aggregate_with_no_summary_fields_uses_generic_fallback() {
        let v = normalize(json!({
            "first_seen": "2026-05-16 14:20:28.000000",
            "last_seen": "2026-05-16 14:35:10.000000",
            "user": "intern01",
        }));
        assert_eq!(field(&v, MATCH_KIND), "aggregate");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "stats aggregate");
    }

    #[test]
    fn sequence_row_gets_step_and_duration_summary() {
        let v = normalize(json!({
            "timestamp": "2026-07-24T15:00:00Z",
            "user": "alice",
            "step1_url": "https://search.example/",
            "step2_file_path": "C:\\Users\\alice\\Downloads\\search_term.zip",
            "step3_process_name": "wscript.exe",
            "step4_dest_host": "low-prevalence.example",
            "step5_process_name": "powershell.exe",
            "sequence_duration_seconds": 64,
            "risk_score": 95,
        }));
        assert_eq!(field(&v, MATCH_KIND), "sequence");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "5-step sequence · 64s");
    }

    #[test]
    fn malformed_negative_sequence_duration_is_omitted() {
        let v = normalize(json!({
            "step1_user": "alice",
            "step2_process_name": "powershell.exe",
            "sequence_duration_seconds": -42,
        }));
        assert_eq!(field(&v, MATCH_KIND), "sequence");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "2-step sequence");
    }

    #[test]
    fn aggregate_alias_without_time_markers_is_recognized() {
        let v = normalize(json!({
            "src_host": "WS-ENG-003",
            "hits": 12,
            "commands": ["whoami.exe", "net.exe"],
        }));
        assert_eq!(field(&v, MATCH_KIND), "aggregate");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "12 hits");
    }

    #[test]
    fn aggregate_array_summary_is_compact() {
        let v = normalize(json!({
            "first_seen": "2026-07-24T15:00:00Z",
            "last_seen": "2026-07-24T15:01:00Z",
            "operations": ["DeleteBucket", "DeleteObject", "StopLogging", "DeleteTrail"],
        }));
        assert_eq!(
            field(&v, MATCH_EVENT_LABEL),
            "DeleteBucket, DeleteObject, StopLogging, …"
        );
    }

    #[test]
    fn projected_process_row_uses_process_name() {
        let v = normalize(json!({
            "timestamp": "2026-07-24T15:00:00Z",
            "user": "alice",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc ...",
        }));
        assert_eq!(field(&v, MATCH_KIND), "raw");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "powershell.exe");
    }

    #[test]
    fn projected_file_row_uses_action_and_basename() {
        let v = normalize(json!({
            "file_action": "created",
            "file_path": "C:\\Users\\alice\\Downloads\\search_term.zip",
        }));
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "created · search_term.zip");
    }

    #[test]
    fn projected_auth_row_uses_result_and_type() {
        let v = normalize(json!({
            "auth_result": "failed",
            "auth_type": "RDP",
            "user": "alice",
        }));
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "failed RDP authentication");
    }

    #[test]
    fn nested_ocsf_network_row_gets_request_summary() {
        let v = normalize(json!({
            "http_request": {
                "http_method": "GET",
                "url": {
                    "hostname": "low-prevalence.example"
                }
            }
        }));
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "GET · low-prevalence.example");
    }

    #[test]
    fn source_type_is_the_last_data_driven_fallback() {
        let v = normalize(json!({
            "source_type": "windows_sysmon"
        }));
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "windows sysmon event");
    }

    #[test]
    fn empty_event_gets_non_empty_fallback() {
        let v = normalize(json!({}));
        assert_eq!(field(&v, MATCH_KIND), "raw");
        assert!(v.get(MATCH_EVENT_TIME).is_none());
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "Matched event");
    }

    #[test]
    fn nano_detected_at_does_not_become_event_time() {
        // No other timestamp fields — `_nano_detected_at` is excluded both
        // from the direct list and the loose scan (preserves NAN-739).
        let v = normalize(json!({
            "_nano_detected_at": "2026-05-16T18:00:19.000Z",
            "src_ip": "10.0.0.1",
            "eventName": "S3Read",
        }));
        assert!(v.get(MATCH_EVENT_TIME).is_none());
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "S3Read");
        assert_eq!(field(&v, MATCH_KIND), "raw");
    }

    #[test]
    fn loose_scan_picks_latest_user_aliased_time() {
        let v = normalize(json!({
            "bucket_start": "2026-05-16T10:00:00.000Z",
            "bucket_end":   "2026-05-16T11:00:00.000Z",
            "eventName": "Probe",
        }));
        assert_eq!(field(&v, MATCH_EVENT_TIME), "2026-05-16T11:00:00.000Z");
    }

    #[test]
    fn non_object_event_is_left_untouched() {
        let mut v = json!([1, 2, 3]);
        normalize_match_event(&mut v);
        assert_eq!(v, json!([1, 2, 3]));
    }

    #[test]
    fn single_last_seen_field_alone_does_not_trigger_aggregate() {
        // Some upstream agents emit a `last_seen` on raw events. We require
        // BOTH first_seen and last_seen together to call it an aggregate.
        let v = normalize(json!({
            "timestamp": "2026-05-16T18:00:14.000Z",
            "last_seen": "2026-05-16T18:00:14.000Z",
            "eventName": "GenericEvent",
        }));
        assert_eq!(field(&v, MATCH_KIND), "raw");
        assert_eq!(field(&v, MATCH_EVENT_LABEL), "GenericEvent");
    }

    #[test]
    fn format_count_renders_thousands() {
        assert_eq!(format_count(1582.0), "1,582");
        assert_eq!(format_count(1_000_000.0), "1,000,000");
        assert_eq!(format_count(42.0), "42");
        assert_eq!(format_count(0.0), "0");
    }
}
