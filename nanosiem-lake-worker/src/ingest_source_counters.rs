// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-source ingestion counters for the hosted-shared lake (NAN-2361 wave 5,
//! default-source attribution in wave 8).
//!
//! The tenant's Bronze publisher is the only lake stage that sees every
//! admitted row together with the source the edge authorized it under: the
//! source-bound parser stamps the route's `source_slug` into
//! `metadata.log_source` (Vector `%source_type`) and flags rows the parser
//! could not read with `metadata.parse_failure` / `metadata.parse_error`.
//! This module folds one staged batch into one counter per (source,
//! protocol) and records it through
//! `nano_shared.record_lake_ingest_source_counters` (migration 9000720,
//! protocol-aware since 9000920) inside the publisher's acknowledgement
//! transaction, so the counters are exactly-once with the tail publication
//! they describe.
//!
//! # The default-source contract (wave 8)
//!
//! A conventional (non-source-mode) tenant ingests through one
//! `ingest-token`; its parser cell stamps `metadata.log_source` with whatever
//! the sender declared (a HEC `sourcetype`, an `X-Source-Type` header) or
//! `unknown` when it declared nothing. Those rows used to fold into an
//! `unknown` bucket that no registry entry answers for, so the tenant's Log
//! Sources page and the portal's consumption read showed nothing. Now:
//!
//! * a row whose `metadata.log_source` is absent, empty, `unknown`, or not in
//!   the route-slug alphabet is attributed to [`DEFAULT_SOURCE`] (`default`);
//!   a row with a valid stamped slug keeps its own counter, unchanged;
//! * every counter carries the `protocol` the row came in on, read from
//!   `metadata.ingress_transport` (stamped by the Vector lake sink from the
//!   `%ingress_transport` event metadata each ingress lane sets:
//!   `nano_https`, `hec`, `otlp`, `vector`) and mapped onto the ingest-route
//!   protocol vocabulary (`nano_https` / `hec` / `otlp_http` / `vector`);
//! * a row that records no transport is attributed to [`DEFAULT_PROTOCOL`]
//!   (`hec`): the conventional ingest path's senders are Splunk-HEC
//!   forwarders re-pointed at the tenant hostname, and rows without the hint
//!   were produced by a cell rendered before the stamp existed. This is a
//!   documented assumption, not an observation — the counter row says `hec`
//!   even when the sender used another lane.
//!
//! # Per-credential attribution (NAN-2598)
//!
//! A v2 (collector-capable) Worker attributes every durable handoff to the
//! ingest credential that sent it, and the cell's Vector stamps it as
//! `metadata.nano_credential_id`. The fold adds it to the counter key, so a
//! collector credential's sources and a source credential's one source are
//! counted per credential (9001980). Rows without a well-formed UUID there
//! are unattributed (`credential_id` omitted, NULL in the control DB); the
//! control DB also drops any id that is not one of the tenant's credentials.
//!
//! # Per-parser-bundle attribution (NAN-2645)
//!
//! The collector-capable platform base's lake prepare stamps the parser
//! bundle the cell was started with as `metadata.nano_parser_bundle_sha256`
//! (the Container's `VECTOR_CONFIG_GZIP_SHA256`: the same pinned sha256 the
//! Worker verified the bundle bytes against). The fold adds it to the counter
//! key, so during a parser-bundle roll the rows the PENDING bundle parsed are
//! counted apart from the active bundle's (`parser-rollouts:landing`). The
//! first non-empty `parse_error` of each counter is kept as a bounded,
//! single-line sample. Unstamped rows (a v1 base, a cell started before the
//! stamp) omit the key; the control DB also drops a sha that is not one of
//! the tenant's registered bundles.
//!
//! `bytes` is the size of the normalized OCSF JSON of each row (what the lake
//! stores), not the wire bytes the edge received; the edge does not attribute
//! bytes per source and this is the honest measurable quantity here.
//!
//! # Refused rows (NAN-3680)
//!
//! A row strict OCSF admission refuses never reaches the lake, so it used to
//! appear nowhere a tenant can look: one error log line and a batch total.
//! Admission now reads the same four keys from the refused row (best-effort,
//! value-free: [`SourceKey::of`]) and folds it into [`RefusedSources`]. Those
//! counters carry `events = 0`, `bytes = 0`, `refused_events = n` and a
//! [`RefusalSample`] built only from the refusal's reason code and OCSF
//! attribute path, never a row value. The publisher records them in the same
//! acknowledgement transaction as the publication they belong to, under a
//! publication id derived from it ([`refusal_publication_id`]), so they are
//! exactly-once with it and an older control DB that refuses a zero-event
//! entry never costs the admitted counters. A row too broken to read is
//! attributed to [`DEFAULT_SOURCE`] on [`DEFAULT_PROTOCOL`].

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use std::collections::BTreeMap;

use crate::bronze::RowRefusal;
use crate::iceberg::{EventKind, EventRow};

/// Rows the edge did not bind to a named source are attributed to this slug:
/// the tenant's one implicit source on the conventional ingest path.
pub const DEFAULT_SOURCE: &str = "default";
/// Protocol recorded for rows that carry no `metadata.ingress_transport`.
pub const DEFAULT_PROTOCOL: &str = "hec";
/// The OCSF metadata attribute the Vector lake sink stamps with the ingress
/// lane a row arrived on (a nano extension, like `metadata.log_source`).
pub const INGRESS_TRANSPORT_FIELD: &str = "ingress_transport";
const MAX_SOURCES_PER_PUBLICATION: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCounter {
    pub source_slug: String,
    /// Ingest-route protocol vocabulary: `nano_https`, `hec`, `otlp_http`, `vector`.
    pub protocol: String,
    /// NAN-2598: the ingest credential the rows were attributed to
    /// (`metadata.nano_credential_id`, a lowercase UUID); absent when the
    /// row carries none (conventional path, OTLP spans/metrics, a v1 Worker).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// NAN-2645: the parser bundle the row was parsed by
    /// (`metadata.nano_parser_bundle_sha256`, lowercase hex); absent when the
    /// cell's base does not stamp it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_bundle_sha256: Option<String>,
    /// NAN-2645: the first parse error seen for this counter in the batch,
    /// single line, at most [`MAX_PARSE_ERROR_SAMPLE_CHARS`] characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_parse_error: Option<String>,
    pub events: u64,
    pub bytes: u64,
    pub parse_failures: u64,
    /// NAN-3680: rows strict admission refused (never in `events`/`bytes`).
    /// Omitted when zero, so an admitted-rows payload is byte-identical to
    /// what every earlier control DB accepts.
    #[serde(skip_serializing_if = "is_zero")]
    pub refused_events: u64,
    /// NAN-3680: the first refusal of this counter: reason code and OCSF
    /// attribute path only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_refusal: Option<RefusalSample>,
    pub first_event_at: DateTime<Utc>,
    pub last_event_at: DateTime<Utc>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// NAN-3680: why rows of one counter were refused, free of row content: the
/// stable reason code (`ocsf_constraint_failed`, `time_invalid`, ...) and,
/// when known, the OCSF attribute path it concerns (`device`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusalSample {
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl From<&RowRefusal> for RefusalSample {
    fn from(refusal: &RowRefusal) -> Self {
        Self { reason: refusal.reason.to_string(), field: refusal.field.clone() }
    }
}

/// The counter key of one row: (source, protocol, credential, parser
/// bundle), read with the fold's rules. Field order is the fold's sort order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey {
    pub source_slug: String,
    pub protocol: String,
    pub credential_id: Option<String>,
    pub parser_bundle_sha256: Option<String>,
}

impl SourceKey {
    /// The key of `event`, read value-free from its `metadata`. Anything
    /// unreadable falls back exactly like the fold: `default` / `hec` /
    /// unattributed / unstamped.
    pub fn of(event: &Value) -> Self {
        Self {
            source_slug: source_slug(event),
            protocol: protocol(event),
            credential_id: credential_id(event),
            parser_bundle_sha256: parser_bundle_sha256(event),
        }
    }

    /// A row too broken to read any key (an undecodable Bronze row).
    pub fn unreadable() -> Self {
        Self::of(&Value::Null)
    }
}

/// The refusal attribution of one row: its key and, when readable, its time.
pub fn refusal_attribution(event: &Value) -> (SourceKey, Option<DateTime<Utc>>) {
    (SourceKey::of(event), event_time(event))
}

/// Rows of one counter key that admission refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedSource {
    pub rows: u64,
    /// The first refusal seen for this key.
    pub first: RefusalSample,
    pub first_at: Option<DateTime<Utc>>,
    pub last_at: Option<DateTime<Utc>>,
}

/// NAN-3680: refused rows per counter key, deterministic by key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefusedSources(BTreeMap<SourceKey, RefusedSource>);

impl RefusedSources {
    pub fn note(&mut self, key: SourceKey, refusal: &RowRefusal, at: Option<DateTime<Utc>>) {
        let entry = self.0.entry(key).or_insert_with(|| RefusedSource {
            rows: 0,
            first: RefusalSample::from(refusal),
            first_at: None,
            last_at: None,
        });
        entry.rows += 1;
        if let Some(at) = at {
            entry.first_at = Some(entry.first_at.map_or(at, |first| first.min(at)));
            entry.last_at = Some(entry.last_at.map_or(at, |last| last.max(at)));
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn total(&self) -> u64 {
        self.0.values().map(|source| source.rows).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SourceKey, &RefusedSource)> {
        self.0.iter()
    }

    /// Add `other`'s rows; the first refusal of a key already present wins.
    pub fn merge(&mut self, other: &RefusedSources) {
        for (key, source) in &other.0 {
            match self.0.get_mut(key) {
                Some(entry) => {
                    entry.rows += source.rows;
                    entry.first_at = [entry.first_at, source.first_at].into_iter().flatten().min();
                    entry.last_at = [entry.last_at, source.last_at].into_iter().flatten().max();
                }
                None => {
                    self.0.insert(key.clone(), source.clone());
                }
            }
        }
    }

    /// One warn line per source with refused rows, value-free: the counter
    /// key, the count and the first refusal (reason code + attribute path).
    pub fn log(&self, stage: &'static str) {
        for (key, source) in &self.0 {
            tracing::warn!(
                stage,
                source_slug = %key.source_slug,
                protocol = %key.protocol,
                credential_id = key.credential_id.as_deref().unwrap_or(""),
                refused_rows = source.rows,
                first_row_reason = %source.first.reason,
                first_row_field = source.first.field.as_deref().unwrap_or(""),
                "rows refused by strict OCSF admission, by source"
            );
        }
    }

    /// The refused-only counters to record: `events = 0`, `bytes = 0`,
    /// `refused_events = rows`. A row without a readable time is placed at
    /// `now` (the control DB ignores the times of a zero-event entry).
    pub fn counters(&self, now: DateTime<Utc>) -> Vec<SourceCounter> {
        self.0
            .iter()
            .map(|(key, source)| SourceCounter {
                source_slug: key.source_slug.clone(),
                protocol: key.protocol.clone(),
                credential_id: key.credential_id.clone(),
                parser_bundle_sha256: key.parser_bundle_sha256.clone(),
                sample_parse_error: None,
                events: 0,
                bytes: 0,
                parse_failures: 0,
                refused_events: source.rows,
                sample_refusal: Some(source.first.clone()),
                first_event_at: source.first_at.unwrap_or(now),
                last_event_at: source.last_at.unwrap_or(now),
            })
            .collect()
    }
}

/// The publication id the refused-row counters of one acknowledgement are
/// recorded under: derived from the acknowledgement's own identity (`anchor`:
/// a tail publication id, a replay receipt, an exact rejected object), so a
/// retry of the same acknowledgement is exactly-once and the two calls never
/// claim the same id.
pub fn refusal_publication_id(kind: &str, anchor: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nano/ingest-source-refusals/v1\0");
    digest.update(kind.as_bytes());
    digest.update([0]);
    digest.update(anchor.as_bytes());
    hex::encode(digest.finalize())
}

fn source_slug(event: &Value) -> String {
    let raw = event
        .get("metadata")
        .and_then(|m| m.get("log_source"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SOURCE)
        .to_ascii_lowercase();
    // Same alphabet the route registry enforces; anything else (and the
    // `unknown` sentinel the parser cell stamps when the sender declared no
    // source) is the tenant's default source rather than a failed
    // publication.
    let valid = raw != "unknown"
        && raw.len() <= 100
        && raw
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'));
    if valid {
        raw
    } else {
        DEFAULT_SOURCE.to_string()
    }
}

/// Map the row's ingress lane onto the ingest-route protocol vocabulary.
/// Unknown or absent hints fall back to [`DEFAULT_PROTOCOL`] (see the module
/// documentation for why that is `hec`).
fn protocol(event: &Value) -> String {
    let hint = event
        .get("metadata")
        .and_then(|m| m.get(INGRESS_TRANSPORT_FIELD))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    match hint.as_str() {
        "nano_https" | "http" | "https" => "nano_https",
        "hec" | "splunk_hec" => "hec",
        "otlp" | "otlp_http" => "otlp_http",
        "vector" | "vector_native" => "vector",
        _ => DEFAULT_PROTOCOL,
    }
    .to_string()
}

/// The OCSF metadata attribute the cell's Vector stamps with the Worker's
/// credential attribution (NAN-2596, design §2.4).
pub const CREDENTIAL_ID_FIELD: &str = crate::iceberg::METADATA_CREDENTIAL_ID;

/// `metadata.nano_credential_id` as a canonical lowercase UUID, or `None`.
/// Anything else is unattributed, never a new counter bucket per value.
fn credential_id(event: &Value) -> Option<String> {
    let text = event
        .get("metadata")
        .and_then(|m| m.get(CREDENTIAL_ID_FIELD))
        .and_then(Value::as_str)?
        .trim();
    let parsed = uuid::Uuid::parse_str(text).ok()?;
    // Only the hyphenated 36-character form the Worker stamps.
    (text.len() == 36).then(|| parsed.hyphenated().to_string())
}

/// The OCSF metadata attribute the platform lake prepare stamps with the
/// cell's parser bundle sha256 (NAN-2645).
pub const PARSER_BUNDLE_FIELD: &str = crate::iceberg::METADATA_PARSER_BUNDLE_SHA256;
/// Bound of one parse error sample (the control DB column's own bound).
pub const MAX_PARSE_ERROR_SAMPLE_CHARS: usize = 256;

/// `metadata.nano_parser_bundle_sha256` as lowercase hex, or `None`.
fn parser_bundle_sha256(event: &Value) -> Option<String> {
    let text = event
        .get("metadata")
        .and_then(|m| m.get(PARSER_BUNDLE_FIELD))
        .and_then(Value::as_str)?
        .trim();
    (text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())).then(|| text.to_ascii_lowercase())
}

/// The row's parse error message as one bounded line, or `None`.
fn parse_error_sample(event: &Value) -> Option<String> {
    let message = [
        event.get("metadata").and_then(|m| m.get("parse_error")),
        event.get("unmapped").and_then(|u| u.get("parse_error")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(str::trim)
    .find(|s| !s.is_empty())?;
    let line: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_PARSE_ERROR_SAMPLE_CHARS)
        .collect();
    Some(line)
}

fn parse_failed(event: &Value) -> bool {
    let metadata = event.get("metadata");
    metadata
        .and_then(|m| m.get("parse_failure"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || metadata
            .and_then(|m| m.get("parse_error"))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        || event
            .get("unmapped")
            .and_then(|u| u.get("parse_error"))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
}

fn event_time(event: &Value) -> Option<DateTime<Utc>> {
    let value = event.get("time")?;
    if let Some(millis) = value.as_i64() {
        return DateTime::from_timestamp_millis(millis);
    }
    let text = value.as_str()?;
    DateTime::parse_from_rfc3339(text)
        .or_else(|_| DateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f%:z"))
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Fold admitted rows into one counter per (source, protocol, credential,
/// parser bundle), deterministic by slug, protocol, credential (unattributed
/// first), then bundle (unstamped first).
pub fn fold_source_counters(rows: &[EventRow], now: DateTime<Utc>) -> Vec<SourceCounter> {
    let mut by_source: BTreeMap<SourceKey, SourceCounter> = BTreeMap::new();
    // Only source events are tenant ingestion; signals and platform audit
    // rows that may share an acknowledgement path never inflate the counters.
    for row in rows.iter().filter(|row| row.event_kind == EventKind::Source) {
        let event = &row.ocsf_event;
        let key = SourceKey::of(event);
        let bytes = serde_json::to_vec(event).map(|v| v.len() as u64).unwrap_or(0);
        let failed = parse_failed(event);
        let at = event_time(event).unwrap_or(now);
        let entry = by_source.entry(key.clone()).or_insert_with(|| SourceCounter {
            source_slug: key.source_slug,
            protocol: key.protocol,
            credential_id: key.credential_id,
            parser_bundle_sha256: key.parser_bundle_sha256,
            sample_parse_error: None,
            events: 0,
            bytes: 0,
            parse_failures: 0,
            refused_events: 0,
            sample_refusal: None,
            first_event_at: at,
            last_event_at: at,
        });
        entry.events += 1;
        entry.bytes = entry.bytes.saturating_add(bytes);
        if failed {
            entry.parse_failures += 1;
        }
        if entry.sample_parse_error.is_none() {
            entry.sample_parse_error = parse_error_sample(event);
        }
        if at < entry.first_event_at {
            entry.first_event_at = at;
        }
        if at > entry.last_event_at {
            entry.last_event_at = at;
        }
    }
    by_source.into_values().collect()
}

/// Record the counters for one exact tail publication. Idempotent on the
/// database side (a replayed publication id touches nothing).
pub async fn record_source_counters(
    database: &mut PgConnection,
    tail_publication_id: &str,
    counters: &[SourceCounter],
) -> Result<i32> {
    if tail_publication_id.len() != 64 || !tail_publication_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("ingest source counters need the exact tail publication id");
    }
    if counters.is_empty() {
        return Ok(0);
    }
    if counters.len() > MAX_SOURCES_PER_PUBLICATION {
        bail!("ingest source counters exceed the per-publication source bound");
    }
    let payload = serde_json::to_value(counters).context("encode ingest source counters")?;
    sqlx::query_scalar::<_, i32>(
        "SELECT nano_shared.record_lake_ingest_source_counters($1, $2::jsonb)",
    )
    .bind(tail_publication_id)
    .bind(payload)
    .fetch_one(database)
    .await
    .context("record per-source ingest counters")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(event: Value) -> EventRow {
        EventRow {
            event_uid: "uid".into(),
            event_kind: EventKind::Source,
            ocsf_event: event,
        }
    }

    #[test]
    fn folds_rows_per_source_with_failures_and_bounds() {
        let now = DateTime::parse_from_rfc3339("2026-09-17T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let rows = vec![
            row(json!({"time": 1_758_000_000_000i64, "metadata": {"log_source": "Apache_Access", "ingress_transport": "hec"}})),
            row(json!({"time": 1_758_000_060_000i64, "metadata": {"log_source": "apache_access", "ingress_transport": "hec", "parse_failure": true}})),
            row(json!({"time": "2026-09-17T09:00:00Z", "metadata": {"log_source": "windows_security", "ingress_transport": "hec"}})),
            row(json!({"metadata": {}})),
            row(json!({"metadata": {"log_source": "Bad Slug!"}})),
            EventRow { event_uid: "sig".into(), event_kind: EventKind::Signal, ocsf_event: json!({"metadata": {"log_source": "apache_access"}}) },
        ];
        let counters = fold_source_counters(&rows, now);
        assert_eq!(counters.len(), 3);
        let apache = &counters[0];
        assert_eq!(apache.source_slug, "apache_access");
        assert_eq!(apache.protocol, "hec");
        assert_eq!(apache.events, 2);
        assert_eq!(apache.parse_failures, 1);
        assert!(apache.bytes > 0);
        assert_eq!(apache.first_event_at.timestamp_millis(), 1_758_000_000_000);
        assert_eq!(apache.last_event_at.timestamp_millis(), 1_758_000_060_000);
        let default = &counters[1];
        assert_eq!(default.source_slug, DEFAULT_SOURCE);
        assert_eq!(default.protocol, DEFAULT_PROTOCOL);
        assert_eq!(default.events, 2);
        assert_eq!(default.first_event_at, now);
        assert_eq!(counters[2].source_slug, "windows_security");
    }

    #[test]
    fn conventional_rows_fold_into_the_default_source_per_transport() {
        let now = DateTime::parse_from_rfc3339("2026-09-17T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let rows = vec![
            // The parser cell's sentinel for "the sender declared no source".
            row(json!({"metadata": {"log_source": "unknown", "ingress_transport": "hec"}})),
            row(json!({"metadata": {"log_source": "UNKNOWN", "ingress_transport": "hec", "parse_error": "boom"}})),
            row(json!({"metadata": {"log_source": "", "ingress_transport": "otlp"}})),
            row(json!({"metadata": {"ingress_transport": "nano_https"}})),
            row(json!({"metadata": {"ingress_transport": "vector_native"}})),
            // No transport hint at all: the documented conventional default.
            row(json!({"metadata": {}})),
            // A stamped source on a conventional cell keeps its own counter.
            row(json!({"metadata": {"log_source": "syslog", "ingress_transport": "hec"}})),
            // An unknown hint never invents a protocol outside the vocabulary.
            row(json!({"metadata": {"log_source": "syslog", "ingress_transport": "carrier_pigeon"}})),
        ];
        let counters = fold_source_counters(&rows, now);
        let keys: Vec<(&str, &str, u64, u64)> = counters
            .iter()
            .map(|c| (c.source_slug.as_str(), c.protocol.as_str(), c.events, c.parse_failures))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("default", "hec", 3, 1),
                ("default", "nano_https", 1, 0),
                ("default", "otlp_http", 1, 0),
                ("default", "vector", 1, 0),
                ("syslog", "hec", 2, 0),
            ]
        );
        let payload = serde_json::to_value(&counters).unwrap();
        assert_eq!(payload[0]["protocol"], "hec");
        assert_eq!(payload[0]["source_slug"], "default");
    }

    #[test]
    fn parse_failure_is_detected_from_every_stamp_location() {
        assert!(parse_failed(&json!({"metadata": {"parse_error": "boom"}})));
        assert!(parse_failed(&json!({"unmapped": {"parse_error": "boom"}})));
        assert!(!parse_failed(&json!({"metadata": {"parse_error": ""}})));
        assert!(!parse_failed(&json!({"metadata": {"log_source": "x"}})));
    }

    #[test]
    fn counters_are_keyed_by_the_stamped_credential() {
        let now = DateTime::parse_from_rfc3339("2026-09-23T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let a = "7d0b5c2e-4f1a-4c3e-9a6b-1e2f3a4b5c6d";
        let b = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let rows = vec![
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_credential_id": a}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_credential_id": a.to_uppercase()}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_credential_id": b, "parse_failure": true}})),
            // Unattributed: absent, empty, or not a UUID (never a new bucket per garbage value).
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec"}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_credential_id": ""}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_credential_id": "not-a-uuid"}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_credential_id": 7}})),
            // A collector's undeclared events: `unknown` folds into default, credential kept.
            row(json!({"metadata": {"log_source": "unknown", "ingress_transport": "hec", "nano_credential_id": a}})),
        ];
        let counters = fold_source_counters(&rows, now);
        let keys: Vec<(&str, Option<&str>, u64, u64)> = counters
            .iter()
            .map(|c| (c.source_slug.as_str(), c.credential_id.as_deref(), c.events, c.parse_failures))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("apache_access", None, 4, 0),
                ("apache_access", Some(b), 1, 1),
                ("apache_access", Some(a), 2, 0),
                ("default", Some(a), 1, 0),
            ]
        );
        let payload = serde_json::to_value(&counters).unwrap();
        assert!(payload[0].get("credential_id").is_none(), "unattributed entries omit the key");
        assert_eq!(payload[2]["credential_id"], a);
    }

    /// NAN-2645: the cell's platform lake prepare stamps the parser bundle it
    /// was started with (`metadata.nano_parser_bundle_sha256`, from the
    /// Container's `VECTOR_CONFIG_GZIP_SHA256`), so a roll's landing check
    /// counts exactly the rows its pending bundle parsed.
    #[test]
    fn counters_are_keyed_by_the_stamped_parser_bundle() {
        let now = DateTime::parse_from_rfc3339("2026-09-23T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let active = "a".repeat(64);
        let pending = "b".repeat(64);
        let rows = vec![
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_parser_bundle_sha256": active}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_parser_bundle_sha256": pending}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_parser_bundle_sha256": pending.to_uppercase(),
                "parse_failure": true, "parse_error": "function call error for \"parse_json\" at (0:20): unable to parse json"}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_parser_bundle_sha256": pending,
                "parse_error": "second error"}})),
            // Unstamped (a v1 base, or a cell started before the stamp): no bundle key, never a bucket per garbage value.
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec"}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_parser_bundle_sha256": "not-a-sha"}})),
            row(json!({"metadata": {"log_source": "apache_access", "ingress_transport": "hec", "nano_parser_bundle_sha256": 7}})),
        ];
        let counters = fold_source_counters(&rows, now);
        let keys: Vec<(Option<&str>, u64, u64)> = counters
            .iter()
            .map(|c| (c.parser_bundle_sha256.as_deref(), c.events, c.parse_failures))
            .collect();
        assert_eq!(keys, vec![(None, 3, 0), (Some(active.as_str()), 1, 0), (Some(pending.as_str()), 3, 2)]);
        // One bounded parse error sample per counter: the first seen in the batch.
        let sample = counters[2].sample_parse_error.as_deref().unwrap();
        assert!(sample.starts_with("function call error"), "{sample}");
        assert!(counters[0].sample_parse_error.is_none());
        let payload = serde_json::to_value(&counters).unwrap();
        assert!(payload[0].get("parser_bundle_sha256").is_none(), "unstamped entries omit the key");
        assert!(payload[0].get("sample_parse_error").is_none());
        assert_eq!(payload[2]["parser_bundle_sha256"], pending);
    }

    #[test]
    fn parse_error_samples_are_bounded_and_single_line() {
        let long = format!("line one\nline two {}", "x".repeat(1000));
        let sample = parse_error_sample(&json!({"metadata": {"parse_error": long}})).unwrap();
        assert!(sample.chars().count() <= MAX_PARSE_ERROR_SAMPLE_CHARS);
        assert!(!sample.contains('\n'));
        assert_eq!(parse_error_sample(&json!({"unmapped": {"parse_error": "boom"}})).as_deref(), Some("boom"));
        assert_eq!(parse_error_sample(&json!({"metadata": {"parse_failure": true}})), None);
        assert_eq!(parse_error_sample(&json!({"metadata": {"parse_error": "   "}})), None);
    }

    /// NAN-3680: refused rows fold per counter key with the fold's own
    /// attribution rules, carry no events or bytes, and keep only a
    /// value-free sample (reason code + OCSF attribute path).
    #[test]
    fn refused_rows_fold_per_source_without_events_or_values() {
        let now = DateTime::parse_from_rfc3339("2026-10-12T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let credential = "7d0b5c2e-4f1a-4c3e-9a6b-1e2f3a4b5c6d";
        let device = RowRefusal::new("ocsf_constraint_failed", Some("device"));
        let time = RowRefusal::new("time_invalid", Some("time"));
        let entra = json!({"time": 1_791_790_000_000i64, "metadata": {"log_source": "Azure_Monitor",
            "ingress_transport": "hec", "nano_credential_id": credential}, "user": {"name": "secret@corp.example"}});
        let mut refused = RefusedSources::default();
        let (key, at) = refusal_attribution(&entra);
        refused.note(key.clone(), &device, at);
        refused.note(key, &time, Some(now));
        // Unreadable rows (and garbage slugs) are the tenant's default source.
        refused.note(SourceKey::unreadable(), &RowRefusal::new("row_decode_failed", None), None);
        let (garbage, _) = refusal_attribution(&json!({"metadata": {"log_source": "Bad Slug!"}}));
        assert_eq!(garbage, SourceKey::unreadable());
        refused.note(garbage, &RowRefusal::new("uid_missing", Some("metadata.uid")), None);
        assert_eq!(refused.total(), 4);

        let counters = refused.counters(now);
        let keys: Vec<(&str, &str, Option<&str>, u64, u64)> = counters
            .iter()
            .map(|c| (c.source_slug.as_str(), c.protocol.as_str(), c.credential_id.as_deref(), c.events, c.refused_events))
            .collect();
        assert_eq!(
            keys,
            vec![("azure_monitor", "hec", Some(credential), 0, 2), ("default", "hec", None, 0, 2)]
        );
        let azure = &counters[0];
        assert_eq!(azure.bytes, 0);
        assert_eq!(azure.parse_failures, 0);
        assert_eq!(
            azure.sample_refusal,
            Some(RefusalSample { reason: "ocsf_constraint_failed".into(), field: Some("device".into()) }),
            "the first refusal is the sample"
        );
        assert_eq!(azure.first_event_at.timestamp_millis(), 1_791_790_000_000);
        assert_eq!(azure.last_event_at, now);
        assert_eq!(counters[1].first_event_at, now, "no readable time: recorded at now");
        assert_eq!(
            counters[1].sample_refusal,
            Some(RefusalSample { reason: "row_decode_failed".into(), field: None })
        );

        let payload = serde_json::to_value(&counters).unwrap();
        assert_eq!(payload[0]["refused_events"], 2);
        assert_eq!(payload[0]["events"], 0);
        assert_eq!(payload[0]["sample_refusal"], json!({"reason": "ocsf_constraint_failed", "field": "device"}));
        assert_eq!(payload[1]["sample_refusal"], json!({"reason": "row_decode_failed"}));
        let text = payload.to_string();
        assert!(!text.contains("secret@corp.example"), "no row value may leave admission: {text}");
    }

    /// Admitted-row payloads stay byte-identical to the pre-NAN-3680 shape:
    /// an older control DB never sees the new keys from the main call.
    #[test]
    fn admitted_counters_omit_the_refusal_keys() {
        let now = Utc::now();
        let counters = fold_source_counters(&[row(json!({"metadata": {"log_source": "syslog"}}))], now);
        let payload = serde_json::to_value(&counters).unwrap();
        assert!(payload[0].get("refused_events").is_none());
        assert!(payload[0].get("sample_refusal").is_none());
    }

    #[test]
    fn merged_refusals_add_rows_and_keep_the_first_sample() {
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        let key = SourceKey::of(&json!({"metadata": {"log_source": "azure_monitor"}}));
        let mut left = RefusedSources::default();
        left.note(key.clone(), &RowRefusal::new("ocsf_constraint_failed", Some("device")), Some(at("2026-10-12T09:00:00Z")));
        let mut right = RefusedSources::default();
        right.note(key.clone(), &RowRefusal::new("time_invalid", Some("time")), Some(at("2026-10-12T08:00:00Z")));
        right.note(SourceKey::unreadable(), &RowRefusal::new("unclassified", None), None);
        left.merge(&right);
        assert_eq!(left.total(), 3);
        let (_, merged) = left.iter().find(|(k, _)| **k == key).unwrap();
        assert_eq!(merged.rows, 2);
        assert_eq!(merged.first.reason, "ocsf_constraint_failed");
        assert_eq!(merged.first_at, Some(at("2026-10-12T08:00:00Z")));
        assert_eq!(merged.last_at, Some(at("2026-10-12T09:00:00Z")));
    }

    #[test]
    fn refusal_publication_ids_are_deterministic_and_distinct() {
        let tail = "a".repeat(64);
        let id = refusal_publication_id("tail", &tail);
        assert_eq!(id, refusal_publication_id("tail", &tail));
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_ne!(id, tail);
        assert_ne!(id, refusal_publication_id("replay", &tail));
    }
}
