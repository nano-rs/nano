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
//! - `_match_event_label` — one-line human label, best-effort
//! - `_match_kind` — `"raw"` or `"aggregate"`
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
            Kind::Raw => "raw".into(),
        }),
    );
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Kind {
    Raw,
    Aggregate,
}

/// Aggregate-row detection mirrors NAN-829's widened heuristic:
/// system-injected `_first_seen` / `_last_seen`, the user-aliased pair
/// `first_seen` + `last_seen` together, or the standalone `actions_attempted`
/// marker (which has no raw-event analog).
fn pick_kind(obj: &Map<String, Value>) -> Kind {
    if str_field(obj, "_first_seen").is_some() || str_field(obj, "_last_seen").is_some() {
        return Kind::Aggregate;
    }
    if str_field(obj, "first_seen").is_some() && str_field(obj, "last_seen").is_some() {
        return Kind::Aggregate;
    }
    if str_field(obj, "actions_attempted").is_some() {
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
    for key in ["eventName", "event_type", "action", "event_id"] {
        if let Some(v) = str_field(obj, key) {
            return Some(v.to_string());
        }
    }
    if kind != Kind::Aggregate {
        return None;
    }
    for key in ["actions_attempted", "action_summary", "top_action"] {
        if let Some(v) = str_field(obj, key) {
            return Some(v.to_string());
        }
    }
    // Largest `*_count` numeric field, labeled with its column name.
    let mut best: Option<(f64, &str)> = None;
    for (k, v) in obj {
        if k.starts_with('_') {
            continue;
        }
        if !(k == "count" || k.ends_with("_count")) {
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
        return Some(format!(
            "{} {}",
            format_count(n),
            key.replace('_', " ")
        ));
    }
    Some("stats aggregate".into())
}

fn str_field<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(|v| v.as_str()).and_then(|s| {
        let t = s.trim();
        if t.is_empty() { None } else { Some(s) }
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
    fn empty_event_gets_kind_only() {
        let v = normalize(json!({}));
        assert_eq!(field(&v, MATCH_KIND), "raw");
        assert!(v.get(MATCH_EVENT_TIME).is_none());
        assert!(v.get(MATCH_EVENT_LABEL).is_none());
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
