// SPDX-License-Identifier: AGPL-3.0-or-later

//! Make event-derived values storable in PostgreSQL `text` and `jsonb`.
//!
//! PostgreSQL cannot store U+0000: a `text`/`varchar`/`text[]` bind fails with
//! SQLSTATE 22021 and a `jsonb` bind with 22P05 ("unsupported Unicode escape
//! sequence"). ClickHouse stores the code point without complaint and
//! serde_json decodes a JSON `\u0000` escape to a literal NUL, so any value an
//! upstream application logged with `json.dumps` can carry one. Every write of
//! ClickHouse-derived data (matched events, entity values, evidence) into
//! PostgreSQL must go through this module first.
//!
//! **Replace, don't strip.** U+0000 becomes U+FFFD (REPLACEMENT CHARACTER).
//! Stripping would merge distinct values (`"admin\0x"` and `"adminx"`) into
//! one in alert evidence; the replacement keeps the value visibly altered,
//! distinct, and keeps character positions. The raw event in ClickHouse is untouched, so the
//! forensic copy stays byte-faithful.
//!
//! **Invalid UTF-8.** A Rust `String` (and so every `serde_json::Value`
//! string) is valid UTF-8 by construction, and serde_json rejects lone
//! surrogate escapes. Only byte sources can carry invalid sequences;
//! [`pg_safe_bytes`] decodes those lossily (also to U+FFFD) before the NUL
//! pass.
//!
//! Object keys are sanitized as well as values, at every depth.
//!
//! **Not at ingest.** Ingest (Vector/VRL) deliberately stores the value as
//! received: ClickHouse handles U+0000, the stored event is the forensic
//! record, and searches must be able to find the exact bytes a source sent.
//! The constraint is PostgreSQL's, so it is applied at the PostgreSQL write
//! boundary only.

use std::borrow::Cow;

use serde_json::{Map, Value};

/// What U+0000 is replaced with before a PostgreSQL write.
pub const PG_NUL_REPLACEMENT: char = '\u{FFFD}';

/// Whether `s` can be bound to a PostgreSQL text or jsonb value as-is.
#[inline]
pub fn is_pg_safe_str(s: &str) -> bool {
    !s.as_bytes().contains(&0)
}

/// `s` with every U+0000 replaced by [`PG_NUL_REPLACEMENT`]. Borrows when
/// there is nothing to replace.
pub fn pg_safe_str(s: &str) -> Cow<'_, str> {
    if is_pg_safe_str(s) {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(s.replace('\0', "\u{FFFD}"))
    }
}

/// Owned form of [`pg_safe_str`]; reuses the allocation when nothing changes.
pub fn pg_safe_string(s: String) -> String {
    if is_pg_safe_str(&s) {
        s
    } else {
        s.replace('\0', "\u{FFFD}")
    }
}

/// A PostgreSQL-safe `text[]` bind: borrowed when every element is already
/// safe, otherwise a sanitized copy.
pub fn pg_safe_strings(values: &[String]) -> Cow<'_, [String]> {
    if values.iter().all(|v| is_pg_safe_str(v)) {
        Cow::Borrowed(values)
    } else {
        Cow::Owned(values.iter().map(|v| pg_safe_str(v).into_owned()).collect())
    }
}

/// Error / diagnostic text for PostgreSQL, logs and health findings.
///
/// ClickHouse and PostgreSQL error messages can quote the offending row, so
/// they carry raw event bytes. Besides U+0000 (which PostgreSQL rejects, and
/// which would make the very write that records the failure fail too), line
/// breaks become spaces and other control characters (ESC, ...) become
/// U+FFFD, so a stored or logged error is one inert line.
pub fn pg_safe_error_text(message: &str) -> String {
    message
        .chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => PG_NUL_REPLACEMENT,
            c => c,
        })
        .collect()
}

/// Text accepted by [`pg_safe_error_bind`].
pub trait PgSafeErrorText {
    type Output;
    fn into_pg_safe_error_text(self) -> Self::Output;
}
impl PgSafeErrorText for &str {
    type Output = String;
    fn into_pg_safe_error_text(self) -> String {
        pg_safe_error_text(self)
    }
}
impl PgSafeErrorText for &String {
    type Output = String;
    fn into_pg_safe_error_text(self) -> String {
        pg_safe_error_text(self)
    }
}
impl PgSafeErrorText for String {
    type Output = String;
    fn into_pg_safe_error_text(self) -> String {
        pg_safe_error_text(&self)
    }
}
impl PgSafeErrorText for Option<&str> {
    type Output = Option<String>;
    fn into_pg_safe_error_text(self) -> Option<String> {
        self.map(pg_safe_error_text)
    }
}
impl PgSafeErrorText for Option<String> {
    type Output = Option<String>;
    fn into_pg_safe_error_text(self) -> Option<String> {
        self.as_deref().map(pg_safe_error_text)
    }
}
impl PgSafeErrorText for &Option<String> {
    type Output = Option<String>;
    fn into_pg_safe_error_text(self) -> Option<String> {
        self.as_deref().map(pg_safe_error_text)
    }
}

/// [`pg_safe_error_text`] for an error-message bind of any common string
/// shape (`&str`, `String`, `Option<…>`).
pub fn pg_safe_error_bind<T: PgSafeErrorText>(value: T) -> T::Output {
    value.into_pg_safe_error_text()
}

/// Decode bytes for a PostgreSQL text write: invalid UTF-8 sequences and
/// U+0000 both become U+FFFD.
pub fn pg_safe_bytes(bytes: &[u8]) -> String {
    pg_safe_string(String::from_utf8_lossy(bytes).into_owned())
}

/// Sanitize a JSON value in place for a PostgreSQL `jsonb` (or `text`) write:
/// every string value and every object key, at any depth. Returns whether
/// anything was replaced.
pub fn sanitize_json_for_pg(value: &mut Value) -> bool {
    match value {
        Value::String(s) => {
            if is_pg_safe_str(s) {
                false
            } else {
                *s = s.replace('\0', "\u{FFFD}");
                true
            }
        }
        Value::Array(items) => {
            let mut changed = false;
            for item in items.iter_mut() {
                changed |= sanitize_json_for_pg(item);
            }
            changed
        }
        Value::Object(map) => sanitize_object(map),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn sanitize_object(map: &mut Map<String, Value>) -> bool {
    let mut changed = false;
    if map.keys().any(|k| !is_pg_safe_str(k)) {
        // Rebuild so keys keep their order; a sanitized key that collides
        // with an existing one gets another U+FFFD rather than silently
        // overwriting that field.
        let old = std::mem::take(map);
        for (key, mut child) in old {
            changed |= sanitize_json_for_pg(&mut child);
            let mut key = if is_pg_safe_str(&key) {
                key
            } else {
                changed = true;
                key.replace('\0', "\u{FFFD}")
            };
            while map.contains_key(&key) {
                key.push(PG_NUL_REPLACEMENT);
            }
            map.insert(key, child);
        }
    } else {
        for child in map.values_mut() {
            changed |= sanitize_json_for_pg(child);
        }
    }
    changed
}

/// Sanitize a batch of events in place; returns how many events changed.
pub fn sanitize_events_for_pg(events: &mut [Value]) -> usize {
    events
        .iter_mut()
        .map(|event| usize::from(sanitize_json_for_pg(event)))
        .sum()
}

/// A PostgreSQL-safe view of `value`: borrowed when it is already safe,
/// otherwise a sanitized clone. For bind sites that only hold a reference.
pub fn pg_safe_json(value: &Value) -> Cow<'_, Value> {
    if json_is_pg_safe(value) {
        Cow::Borrowed(value)
    } else {
        let mut owned = value.clone();
        sanitize_json_for_pg(&mut owned);
        Cow::Owned(owned)
    }
}

/// Whether `value` (keys and strings, at any depth) can be written as-is.
pub fn json_is_pg_safe(value: &Value) -> bool {
    match value {
        Value::String(s) => is_pg_safe_str(s),
        Value::Array(items) => items.iter().all(json_is_pg_safe),
        Value::Object(map) => map
            .iter()
            .all(|(k, v)| is_pg_safe_str(k) && json_is_pg_safe(v)),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

#[cfg(test)]
#[path = "pg_text_tests.rs"]
mod tests;
