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
//! - `_match_entity` / `_match_entity_type` — the row's subject, when one
//!   resolves (NAN-2341)
//!
//! The heuristics mirror what the frontend has accumulated across NAN-822 /
//! NAN-826 / NAN-829. Moving them server-side means future regressions get
//! fixed once, in one Rust function, instead of three TS files.

use serde_json::{Map, Value};

pub const MATCH_EVENT_TIME: &str = "_match_event_time";
pub const MATCH_EVENT_LABEL: &str = "_match_event_label";
pub const MATCH_KIND: &str = "_match_kind";
pub const MATCH_ENTITY: &str = "_match_entity";
pub const MATCH_ENTITY_TYPE: &str = "_match_entity_type";

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
    if let Some((entity, entity_type)) = pick_entity(obj) {
        obj.insert(MATCH_ENTITY.into(), Value::String(entity));
        obj.insert(MATCH_ENTITY_TYPE.into(), Value::String(entity_type));
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

/// Entity picker (NAN-2341) — the subject a match fired against, as
/// `(value, type)`. Returns `None` when the row carries no recognisable
/// subject, so `_match_entity` is absent rather than `"unknown"`.
///
/// Precedence mirrors the frontend's `extractEntity` (identity before network
/// identifier) so injecting the envelope can't reshuffle what an existing
/// match already displays. The one addition ahead of it: an EXPLICIT
/// `entity` / `entity_type` pair. Derived datasets project exactly that pair —
/// `dataset=risk` rows are `entity`, `entity_type`, `score_24h`, … and carry
/// no UDM/OCSF column at all, which is why risk-notable matches used to render
/// as `unknown`.
///
/// The value is emitted RAW. Display shortening (an ARN down to its last
/// segment, say) stays a frontend concern — this is the identifier a pivot
/// query has to filter on.
fn pick_entity(obj: &Map<String, Value>) -> Option<(String, String)> {
    if let Some(entity) = str_field(obj, "entity") {
        let declared = str_field(obj, "entity_type")
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty());
        let ty = declared.unwrap_or_else(|| entity_type_from_value(entity).to_string());
        return Some((entity.to_string(), ty));
    }

    if let Some(arn) = str_field(obj, "user_identity.arn") {
        // `assumed-role/` counts: an STS session ARN
        // (`arn:aws:sts::…:assumed-role/Role/session`) never contains `:role/`.
        let ty = if arn.contains(":role/") || arn.contains(":assumed-role/") {
            "role"
        } else {
            "user"
        };
        return Some((arn.to_string(), ty.to_string()));
    }

    for (keys, ty) in [
        (&["user", "actor.user.name", "user.name"][..], "user"),
        (
            &[
                "src_host",
                "hostname",
                "dest_host",
                "device.hostname",
                "src_endpoint.hostname",
                "dst_endpoint.hostname",
            ][..],
            "hostname",
        ),
        (
            &[
                "src_ip",
                "dest_ip",
                "src_endpoint.ip",
                "dst_endpoint.ip",
            ][..],
            "ip",
        ),
    ] {
        if let Some(value) = first_str(obj, keys) {
            return Some((value.to_string(), ty.to_string()));
        }
    }

    None
}

/// Value-shape entity typing, for an explicit `entity` with no `entity_type`.
/// Same vocabulary as `FindingEvent::infer_entity_type_from_value`, but the
/// `@` test runs BEFORE the dotted-hostname test — `dan@corp.local` contains a
/// dot too, and it is an email, not a host.
fn entity_type_from_value(entity: &str) -> &'static str {
    if entity.parse::<std::net::IpAddr>().is_ok() {
        return "ip";
    }
    if entity.contains('@') {
        return "email";
    }
    if entity.len() >= 32 && entity.chars().all(|c| c.is_ascii_hexdigit()) {
        return "hash";
    }
    if entity.contains('.') && !entity.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return "hostname";
    }
    "user"
}

/// Risk-dataset row label (NAN-2341) — `dataset=risk` projects one row per
/// scored entity (`entity`, `score_24h`, `score_7d`, `last_rule_name`, …) with
/// none of the action/file/auth fields `semantic_raw_label` reads, so these
/// rows all fell through to the generic `"Matched event"`. Lead with the
/// window that actually carries the score, then name the rule that last
/// contributed to it.
fn risk_row_label(obj: &Map<String, Value>) -> Option<String> {
    if str_field(obj, "entity").is_none() {
        return None;
    }
    let (score, window) = [("score_24h", "24h"), ("score_7d", "7d")]
        .iter()
        .find_map(|(key, window)| {
            numeric_field(obj, key)
                .filter(|n| n.is_finite())
                .map(|n| (n, *window))
        })?;
    let label = format!("risk {} ({window})", format_count(score));
    match str_field(obj, "last_rule_name") {
        Some(rule) => Some(format!("{label} · {}", truncate(rule, 72))),
        None => Some(label),
    }
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
    if let Some(risk) = risk_row_label(obj) {
        return Some(risk);
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
#[path = "event_envelope_tests.rs"]
mod event_envelope_tests;
