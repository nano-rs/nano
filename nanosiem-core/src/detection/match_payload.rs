// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5736: bound what one `detection_matches` row stores.
//!
//! A grouped match stored EVERY matched event in one jsonb value. With a rule
//! matching every Sysmon event the rows reached 2.8 MB and PostgreSQL (512 MiB
//! on a small install) was OOM-killed while inserting them. A row now keeps
//! events, newest first, until [`MAX_MATCH_ROW_BYTES`] of serialized JSON; one
//! event larger than [`MAX_MATCH_EVENT_BYTES`] has its long strings cut, and
//! if it is still too large only its identifying fields are kept. The row's
//! `event_count` stays the true number of matched events, so a row whose
//! stored array is shorter than `event_count` reads as truncated, and every
//! event cut down is marked with [`TRUNCATED_MARKER`].

use serde_json::Value;

/// Budget of one `detection_matches.matched_events` value, measured as
/// compact JSON (PostgreSQL renders jsonb as text a few percent larger).
pub const MAX_MATCH_ROW_BYTES: usize = 512 * 1024;

/// Serialized-JSON budget of one stored event.
pub const MAX_MATCH_EVENT_BYTES: usize = 64 * 1024;

/// Longest string value kept in an oversized event (characters).
pub const MAX_MATCH_STRING_CHARS: usize = 4096;

/// Set (to the reason) on an event the row stores cut down.
pub const TRUNCATED_MARKER: &str = "_nano_truncated";

/// Fields kept when an event is too large even with its strings cut.
const IDENTITY_FIELDS: &[&str] = &[
    "log_id",
    "id",
    "timestamp",
    "time",
    "source_type",
    "class_uid",
    "_nano_detected_at",
    "_nano_source_types",
];

/// The bounded payload for one `detection_matches` row.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundedMatchPayload {
    pub events: Vec<Value>,
    /// Events left out to stay within [`MAX_MATCH_ROW_BYTES`].
    pub dropped: usize,
    /// Stored events that were cut down.
    pub shrunk: usize,
}

impl BoundedMatchPayload {
    pub fn truncated(&self) -> bool {
        self.dropped > 0 || self.shrunk > 0
    }
}

/// Serialized JSON length of `value`, without building the string.
pub fn json_len(value: &Value) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

/// Keep `events` (newest first) within the row budget. Always keeps at least
/// one event when there is one.
pub fn bound_match_events(events: &[Value]) -> BoundedMatchPayload {
    bound_match_events_with(events, MAX_MATCH_ROW_BYTES, MAX_MATCH_EVENT_BYTES)
}

pub(crate) fn bound_match_events_with(
    events: &[Value],
    row_budget: usize,
    event_budget: usize,
) -> BoundedMatchPayload {
    let mut kept = Vec::new();
    let mut used = 2usize; // `[` `]`
    let mut shrunk = 0usize;
    for event in events {
        let (event, was_shrunk) = bound_event(event, event_budget);
        let len = json_len(&event) + usize::from(!kept.is_empty());
        if !kept.is_empty() && used + len > row_budget {
            break;
        }
        used += len;
        shrunk += usize::from(was_shrunk);
        kept.push(event);
    }
    BoundedMatchPayload { dropped: events.len() - kept.len(), events: kept, shrunk }
}

/// One event within `budget` serialized bytes: unchanged when it fits; else
/// with its strings cut to [`MAX_MATCH_STRING_CHARS`]; else only its identity
/// fields. Returns whether it was cut down.
fn bound_event(event: &Value, budget: usize) -> (Value, bool) {
    if json_len(event) <= budget {
        return (event.clone(), false);
    }
    let mut cut = event.clone();
    truncate_strings(&mut cut, MAX_MATCH_STRING_CHARS);
    if let Value::Object(map) = &mut cut {
        map.insert(
            TRUNCATED_MARKER.to_string(),
            Value::String(format!("event exceeded {budget} bytes; long values were cut")),
        );
    }
    if json_len(&cut) <= budget {
        return (cut, true);
    }
    let mut stub = serde_json::Map::new();
    if let Value::Object(map) = event {
        for field in IDENTITY_FIELDS {
            if let Some(value) = map.get(*field) {
                let mut value = value.clone();
                truncate_strings(&mut value, 256);
                stub.insert((*field).to_string(), value);
            }
        }
    }
    stub.insert(
        TRUNCATED_MARKER.to_string(),
        Value::String(format!(
            "event exceeded {budget} bytes; only its identifying fields are stored (open it in search for the full event)"
        )),
    );
    (Value::Object(stub), true)
}

fn truncate_strings(value: &mut Value, max_chars: usize) {
    match value {
        Value::String(s) => {
            if let Some((idx, _)) = s.char_indices().nth(max_chars) {
                s.truncate(idx);
                s.push_str("…[truncated]");
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| truncate_strings(v, max_chars)),
        Value::Object(map) => map.values_mut().for_each(|v| truncate_strings(v, max_chars)),
        _ => {}
    }
}

#[cfg(test)]
#[path = "match_payload_tests.rs"]
mod tests;
