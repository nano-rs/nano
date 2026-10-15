// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ingest-edge support for the injector (NAN-2705).
//!
//! A tenant's ingest edge takes HEC (`Authorization: Splunk <token>`) and
//! HTTPS JSON (`Authorization: Bearer <token>`, `Idempotency-Key` required).
//! Its ingest credentials are per source: a token is bound to exactly one source slug,
//! and an event that declares another source is refused (403). A scenario that
//! mixes sources (Sysmon + Windows Security + proxy) therefore needs one token
//! per source, so a token file maps `source_type=token`.
//!
//! This module holds the pure parts: the token file grammar, per-run marker
//! tagging, and the per-source transport routing. Tokens never appear in an
//! error message or in `Debug` output.

use std::collections::BTreeMap;
use std::fmt;

use event_core::event::Event;
use event_core::http::Transport;

/// JSON key the marker is written under in JSON-shaped raw messages. The
/// tenant parsers keep the raw message as OCSF `raw_data` and fold unconsumed
/// source keys into `unmapped`, so the marker is searchable as a keyword and
/// never touches a field a detection rule matches on.
pub const MARKER_KEY: &str = "nano_e2e_marker";

/// Ingest tokens read from `--token-file`.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct TokenMap {
    /// A bare token: used for every source without its own line.
    pub default: Option<String>,
    /// `source_type=token` lines.
    pub by_source: BTreeMap<String, String>,
}

impl fmt::Debug for TokenMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenMap")
            .field("default", &self.default.as_ref().map(|_| "[REDACTED]"))
            .field("sources", &self.by_source.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
impl TokenMap {
    pub fn token_for(&self, source_type: &str) -> Option<&str> {
        self.by_source
            .get(source_type)
            .or(self.default.as_ref())
            .map(String::as_str)
    }
}

/// `^[a-z0-9][a-z0-9_-]{0,99}$`, the SIEM's source slug grammar.
pub fn is_source_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 100
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

fn is_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_whitespace)
}

/// Parse a token file: blank lines and `#` comments are ignored; a line is
/// either `source_type=token` or one bare token (at most one bare line).
/// Errors name the line number only.
pub fn parse_token_file(text: &str) -> Result<TokenMap, String> {
    let mut map = TokenMap::default();
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once('=') {
            Some((slug, token)) if is_source_slug(slug.trim()) => {
                let (slug, token) = (slug.trim(), token.trim());
                if !is_token(token) {
                    return Err(format!("token file line {line_no}: empty or malformed token for {slug}"));
                }
                if map.by_source.insert(slug.to_string(), token.to_string()).is_some() {
                    return Err(format!("token file line {line_no}: {slug} is listed twice"));
                }
            }
            _ => {
                // A bare token may itself contain '=' (base64 padding), so a
                // line whose left side is not a slug is a bare token.
                if !is_token(line) {
                    return Err(format!("token file line {line_no}: malformed token"));
                }
                if map.default.replace(line.to_string()).is_some() {
                    return Err(format!("token file line {line_no}: more than one bare token"));
                }
            }
        }
    }
    if map.default.is_none() && map.by_source.is_empty() {
        return Err("token file holds no token".into());
    }
    Ok(map)
}

/// `[A-Za-z0-9]{8,64}`: a marker is one search keyword (no separators, so a
/// whole-word keyword search finds it inside the raw JSON).
pub fn parse_marker(value: &str) -> Result<String, String> {
    let value = value.trim();
    if (8..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Ok(value.to_string())
    } else {
        Err("marker must be 8-64 ASCII letters or digits".into())
    }
}

/// `[A-Za-z0-9][A-Za-z0-9-]{0,39}`: a NetBIOS-ish host label.
pub fn parse_host_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if !bytes.is_empty()
        && bytes.len() <= 40
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    {
        Ok(value.to_string())
    } else {
        Err("host name must be 1-40 letters, digits or '-' (starting with a letter or digit)".into())
    }
}

/// Stamp the run marker on one event. A JSON-object message gets a top-level
/// `nano_e2e_marker` key; any other message gets ` nano_e2e_marker=<marker>`
/// appended.
pub fn tag_event(event: &mut Event, marker: &str) {
    if let Ok(serde_json::Value::Object(mut object)) =
        serde_json::from_str::<serde_json::Value>(&event.message)
    {
        object.insert(MARKER_KEY.into(), serde_json::Value::String(marker.into()));
        event.message = serde_json::Value::Object(object).to_string();
    } else {
        event.message = format!("{} {MARKER_KEY}={marker}", event.message);
    }
}

/// Where the injector sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkKind {
    /// Raw Vector HTTP (local stacks): `--vector`, optional `--token`.
    Vector,
    /// HEC: `--hec-url`.
    Hec,
    /// HTTPS JSON: `--https-url` (NDJSON, Bearer, Idempotency-Key).
    Https,
}

impl SinkKind {
    pub fn label(self) -> &'static str {
        match self {
            SinkKind::Vector => "vector",
            SinkKind::Hec => "hec",
            SinkKind::Https => "https",
        }
    }
}

/// One transport per source (ingest credentials are per source), plus an
/// optional fallback for a bare token or the local Vector sink.
pub struct SinkRouter {
    by_source: BTreeMap<String, Transport>,
    fallback: Option<Transport>,
}

impl SinkRouter {
    pub fn build(kind: SinkKind, url: &str, tokens: Option<&TokenMap>, idempotency_prefix: &str) -> Self {
        let make = |token: Option<String>| match kind {
            SinkKind::Hec => Transport::new_hec(url.to_string(), token),
            SinkKind::Https => Transport::Vector {
                url: url.to_string(),
                token,
                idempotency_key_prefix: Some(idempotency_prefix.to_string()),
            },
            SinkKind::Vector => Transport::Vector {
                url: url.to_string(),
                token,
                idempotency_key_prefix: None,
            },
        };
        let by_source = tokens
            .map(|t| {
                t.by_source
                    .iter()
                    .map(|(slug, token)| (slug.clone(), make(Some(token.clone()))))
                    .collect()
            })
            .unwrap_or_default();
        let fallback = match (kind, tokens) {
            (_, Some(t)) if t.default.is_some() => Some(make(t.default.clone())),
            // Local Vector without a token file keeps its historical wire shape.
            (SinkKind::Vector, None) => Some(make(None)),
            _ => None,
        };
        Self { by_source, fallback }
    }

    pub fn for_source(&self, source_type: &str) -> Option<&Transport> {
        self.by_source.get(source_type).or(self.fallback.as_ref())
    }

    /// Sources in `wanted` that have no transport (no token).
    pub fn missing<'a>(&self, wanted: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        let mut missing: Vec<String> = wanted
            .into_iter()
            .filter(|s| self.for_source(s).is_none())
            .map(str::to_string)
            .collect();
        missing.sort();
        missing.dedup();
        missing
    }
}

/// Split a step's events by `source_type`, keeping first-seen order.
pub fn group_by_source(events: &[Event]) -> Vec<(String, Vec<Event>)> {
    let mut groups: Vec<(String, Vec<Event>)> = Vec::new();
    for event in events {
        match groups.iter_mut().find(|(s, _)| *s == event.source_type) {
            Some((_, list)) => list.push(event.clone()),
            None => groups.push((event.source_type.clone(), vec![event.clone()])),
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(source_type: &str, message: &str) -> Event {
        Event {
            message: message.into(),
            timestamp: "2026-09-23T00:00:00Z".into(),
            source_type: source_type.into(),
            display_label: String::new(),
        }
    }

    #[test]
    fn token_file_accepts_bare_and_per_source_tokens() {
        let map = parse_token_file("# e2e\nwindows_sysmon=AAAA_bbbb-1\n\nconduit_proxy = CCCC\nZmFsbGJhY2s=\n").unwrap();
        assert_eq!(map.token_for("windows_sysmon"), Some("AAAA_bbbb-1"));
        assert_eq!(map.token_for("conduit_proxy"), Some("CCCC"));
        // The bare line (with base64 padding) is the fallback.
        assert_eq!(map.token_for("windows_event"), Some("ZmFsbGJhY2s="));
    }

    #[test]
    fn token_file_errors_never_echo_a_token() {
        for (text, needle) in [
            ("", "no token"),
            ("abc def", "malformed"),
            ("tok1\ntok2", "more than one bare"),
            ("windows_sysmon=\n", "empty or malformed"),
            ("windows_sysmon=secret1\nwindows_sysmon=secret2", "listed twice"),
        ] {
            let err = parse_token_file(text).unwrap_err();
            assert!(err.contains(needle), "{text:?} → {err}");
            for secret in ["secret1", "secret2", "tok1", "tok2", "abc"] {
                assert!(!err.contains(secret), "error echoes a token: {err}");
            }
        }
        let debug = format!("{:?}", parse_token_file("windows_sysmon=hunter22\nbare-token").unwrap());
        assert!(!debug.contains("hunter22") && !debug.contains("bare-token"), "{debug}");
    }

    #[test]
    fn marker_and_host_grammar() {
        assert_eq!(parse_marker(" nanoe2e0a1b2c3d ").unwrap(), "nanoe2e0a1b2c3d");
        for bad in ["short", "has_underscore1", "has-dash-12345", &"x".repeat(65)] {
            assert!(parse_marker(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_host_name("E2E-a1b2-QUICK").unwrap(), "E2E-a1b2-QUICK");
        for bad in ["", "-lead", "has.dot", "sp ace", &"h".repeat(41)] {
            assert!(parse_host_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tagging_adds_a_json_key_or_appends_a_pair() {
        let mut json = event("windows_sysmon", r#"{"event_id":1,"event_data":{"CommandLine":"whoami /all"}}"#);
        tag_event(&mut json, "nanoe2eabc123");
        let value: serde_json::Value = serde_json::from_str(&json.message).unwrap();
        assert_eq!(value[MARKER_KEY], "nanoe2eabc123");
        assert_eq!(value["event_data"]["CommandLine"], "whoami /all", "rule-visible fields are untouched");

        let mut line = event("apache_access", r#"10.0.0.1 - - [23/Sep/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1"#);
        tag_event(&mut line, "nanoe2eabc123");
        assert!(line.message.ends_with(" nano_e2e_marker=nanoe2eabc123"));
    }

    #[test]
    fn router_picks_the_per_source_token_and_reports_missing_sources() {
        let tokens = parse_token_file("windows_sysmon=AAAA\nconduit_proxy=BBBB").unwrap();
        let router = SinkRouter::build(SinkKind::Hec, "https://t.example/services/collector/event", Some(&tokens), "p");
        assert!(matches!(router.for_source("windows_sysmon"), Some(Transport::Hec { token: Some(t), .. }) if t == "AAAA"));
        assert!(router.for_source("windows_event").is_none());
        assert_eq!(router.missing(["windows_event", "windows_sysmon", "windows_event"]), vec!["windows_event"]);

        let https = SinkRouter::build(SinkKind::Https, "https://t.example/ingest", Some(&tokens), "injector-run1");
        assert!(matches!(
            https.for_source("conduit_proxy"),
            Some(Transport::Vector { token: Some(t), idempotency_key_prefix: Some(p), .. }) if t == "BBBB" && p == "injector-run1"
        ));

        let local = SinkRouter::build(SinkKind::Vector, "http://localhost:8080", None, "unused");
        assert!(matches!(local.for_source("anything"), Some(Transport::Vector { token: None, idempotency_key_prefix: None, .. })));
    }

    #[test]
    fn grouping_keeps_order_and_splits_sources() {
        let events = vec![event("a", "1"), event("b", "2"), event("a", "3")];
        let groups = group_by_source(&events);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, "a");
        assert_eq!(groups[0].1.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(), ["1", "3"]);
        assert_eq!(groups[1].0, "b");
    }
}
