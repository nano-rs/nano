//! HTTP send functions for the ingestion transports log-blaster supports.
//!
//! Two wire formats:
//!
//! - **Vector** (`Transport::Vector`) — Vector's `http` source: NDJSON body,
//!   `X-Source-Type` header per group, Bearer auth. Events are grouped by
//!   `source_type` because the header is per-request.
//! - **HEC** (`Transport::Hec`) — Splunk HEC `/services/collector/event`:
//!   line-delimited JSON envelopes with `sourcetype` in-band, Splunk auth
//!   (`Authorization: Splunk <token>`). No grouping — each envelope carries
//!   its own sourcetype, which the OOTB `hec_normalize` transform maps to
//!   `source_type`.

use anyhow::Result;
use chrono::DateTime;
use reqwest::Client;
use serde::Serialize;
use tokio::time::Duration as TokioDuration;
use tracing::warn;

use crate::event::Event;

/// Where to send events. Built once at startup; passed by reference through
/// the send call chain so the wire format never gets re-derived per call.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Vector HTTP source. `url` already includes any path suffix (e.g.
    /// `/ingest` for dev stacks); we POST directly to it.
    Vector {
        url: String,
        token: Option<String>,
    },
    /// Splunk HEC. `url` includes the `/services/collector/event` suffix —
    /// callers (log-blaster's CLI parsing) are responsible for appending
    /// it, mirroring the dev-mode `/ingest` convention for Vector.
    ///
    /// `channel` is a per-process UUID sent as the
    /// `X-Splunk-Request-Channel` header on every POST. Required when the
    /// receiving HEC source has `acknowledgements.enabled = true` (which
    /// nano's OOTB `02-hec-source.toml` does — NAN-919). We don't poll
    /// `/services/collector/ack`: Splunk's spec lets senders skip ack
    /// polling, the channel just has to be present.
    Hec {
        url: String,
        token: Option<String>,
        channel: String,
    },
}

impl Transport {
    /// Build an HEC transport with a fresh per-process channel UUID. The
    /// channel is required by Splunk HEC sources with ACK enabled (see
    /// `Transport::Hec` docs); callers don't need to think about it.
    /// Uses uuid v7 (the workspace's enabled feature) — Splunk just wants a
    /// well-formed UUID, the version is irrelevant on the wire.
    pub fn new_hec(url: String, token: Option<String>) -> Self {
        let channel = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string();
        Self::Hec {
            url,
            token,
            channel,
        }
    }

    fn url(&self) -> &str {
        match self {
            Transport::Vector { url, .. } => url,
            Transport::Hec { url, .. } => url,
        }
    }

    fn token(&self) -> Option<&str> {
        match self {
            Transport::Vector { token, .. } => token.as_deref(),
            Transport::Hec { token, .. } => token.as_deref(),
        }
    }

    /// Short human label for log lines.
    pub fn kind(&self) -> &'static str {
        match self {
            Transport::Vector { .. } => "vector",
            Transport::Hec { .. } => "hec",
        }
    }
}

/// Send a single event over the configured transport.
pub async fn send_event(client: &Client, transport: &Transport, event: &Event) -> Result<()> {
    match transport {
        Transport::Vector { .. } => send_event_vector(client, transport, event).await,
        Transport::Hec { .. } => send_event_hec(client, transport, event).await,
    }
}

/// Send a batch with per-group retry. Vector groups by source_type; HEC
/// sends a single line-delimited stream (sourcetype is in-band).
pub async fn send_batch_with_retry(
    client: &Client,
    transport: &Transport,
    events: &[Event],
    max_retries: u32,
) -> Result<()> {
    match transport {
        Transport::Vector { .. } => {
            send_batch_vector_with_retry(client, transport, events, max_retries).await
        }
        Transport::Hec { .. } => {
            send_batch_hec_with_retry(client, transport, events, max_retries).await
        }
    }
}

// ---------------------------------------------------------------------------
// Vector transport (NDJSON + X-Source-Type + Bearer)
// ---------------------------------------------------------------------------

async fn send_event_vector(client: &Client, transport: &Transport, event: &Event) -> Result<()> {
    let mut req = client
        .post(transport.url())
        .header("Content-Type", "application/json")
        .header("X-Source-Type", &event.source_type)
        .json(event);
    if let Some(t) = transport.token() {
        req = req.bearer_auth(t);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

async fn send_ndjson_group(
    client: &Client,
    transport: &Transport,
    source_type: &str,
    events: &[&Event],
) -> Result<()> {
    let body: String = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    let mut req = client
        .post(transport.url())
        .header("Content-Type", "application/x-ndjson")
        .header("X-Source-Type", source_type)
        .body(body);

    if let Some(t) = transport.token() {
        req = req.bearer_auth(t);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

async fn send_ndjson_group_with_retry(
    client: &Client,
    transport: &Transport,
    source_type: &str,
    events: &[&Event],
    max_retries: u32,
) -> Result<()> {
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff = TokioDuration::from_millis(500 * 2u64.pow(attempt - 1));
            warn!(
                "[{}] Retry {}/{} after {:?}",
                source_type, attempt, max_retries, backoff
            );
            tokio::time::sleep(backoff).await;
        }
        match send_ndjson_group(client, transport, source_type, events).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

async fn send_batch_vector_with_retry(
    client: &Client,
    transport: &Transport,
    events: &[Event],
    max_retries: u32,
) -> Result<()> {
    let mut grouped: std::collections::HashMap<&str, Vec<&Event>> =
        std::collections::HashMap::new();
    for event in events {
        grouped.entry(&event.source_type).or_default().push(event);
    }

    for (source_type, group) in &grouped {
        send_ndjson_group_with_retry(client, transport, source_type, group, max_retries).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HEC transport (line-delimited JSON envelopes + Splunk auth)
// ---------------------------------------------------------------------------

/// HEC wire envelope. Mirrors Splunk's documented schema for the
/// `/services/collector/event` endpoint. The OOTB `hec_normalize` transform
/// (`config/vector/02-hec-source.toml`) reads `.sourcetype` and `.event`,
/// then writes `.source_type` and `.message` for the rest of the pipeline.
#[derive(Debug, Serialize)]
struct HecEnvelope<'a> {
    /// Epoch seconds (float). Vector accepts both seconds and milliseconds;
    /// we always emit seconds-as-float to match Splunk's own forwarders.
    time: f64,
    sourcetype: &'a str,
    /// The raw log payload. We pass the message as a string — hec_normalize
    /// handles the `is_string(.event)` branch and lifts it into `.message`.
    event: &'a str,
}

impl<'a> HecEnvelope<'a> {
    fn from_event(event: &'a Event) -> Self {
        Self {
            time: event_epoch_seconds(event),
            sourcetype: &event.source_type,
            event: &event.message,
        }
    }
}

/// Parse the event's ISO-8601 timestamp into epoch seconds. Falls back to
/// 0.0 on malformed input — Vector's splunk_hec source will then stamp the
/// arrival time, which is fine for a load-generator. We don't want to bail
/// on a single bad parse.
fn event_epoch_seconds(event: &Event) -> f64 {
    DateTime::parse_from_rfc3339(&event.timestamp)
        .map(|t| t.timestamp() as f64 + (t.timestamp_subsec_micros() as f64 / 1_000_000.0))
        .unwrap_or(0.0)
}

/// Serialise events as a line-delimited HEC envelope stream. Splunk's HEC
/// accepts either newline-separated or whitespace-separated JSON objects;
/// Vector's `splunk_hec` source accepts both. We use newlines for log
/// readability when debugging with `curl -v`.
fn hec_body(events: &[&Event]) -> String {
    events
        .iter()
        .map(|e| serde_json::to_string(&HecEnvelope::from_event(e)).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns the HEC channel UUID for ack-required sources. Panics if called
/// on a non-HEC transport — `send_event` dispatches on the variant before
/// calling these helpers, so the variant is known here.
fn hec_channel(transport: &Transport) -> &str {
    match transport {
        Transport::Hec { channel, .. } => channel,
        Transport::Vector { .. } => unreachable!("hec_channel called on Vector transport"),
    }
}

async fn send_event_hec(client: &Client, transport: &Transport, event: &Event) -> Result<()> {
    let body = serde_json::to_string(&HecEnvelope::from_event(event)).unwrap();
    let mut req = client
        .post(transport.url())
        .header("Content-Type", "application/json")
        .header("X-Splunk-Request-Channel", hec_channel(transport))
        .body(body);
    if let Some(t) = transport.token() {
        req = req.header("Authorization", format!("Splunk {t}"));
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

async fn send_hec_batch(
    client: &Client,
    transport: &Transport,
    events: &[&Event],
) -> Result<()> {
    let body = hec_body(events);
    let mut req = client
        .post(transport.url())
        .header("Content-Type", "application/json")
        .header("X-Splunk-Request-Channel", hec_channel(transport))
        .body(body);
    if let Some(t) = transport.token() {
        req = req.header("Authorization", format!("Splunk {t}"));
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

async fn send_batch_hec_with_retry(
    client: &Client,
    transport: &Transport,
    events: &[Event],
    max_retries: u32,
) -> Result<()> {
    let refs: Vec<&Event> = events.iter().collect();
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff = TokioDuration::from_millis(500 * 2u64.pow(attempt - 1));
            warn!("[hec] Retry {}/{} after {:?}", attempt, max_retries, backoff);
            tokio::time::sleep(backoff).await;
        }
        match send_hec_batch(client, transport, &refs).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_event(source_type: &str, message: &str, timestamp: &str) -> Event {
        Event {
            message: message.to_string(),
            timestamp: timestamp.to_string(),
            source_type: source_type.to_string(),
            display_label: String::new(),
        }
    }

    /// HEC envelope must carry `time`, `sourcetype`, `event` exactly —
    /// hec_normalize reads `.sourcetype` and `.event`, then routing rules
    /// match on the resulting `source_type`.
    #[test]
    fn hec_envelope_shape() {
        let event = fake_event(
            "windows_sysmon",
            r#"{"EventID":1}"#,
            "2026-05-20T11:30:00.250000Z",
        );
        let env = HecEnvelope::from_event(&event);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();

        assert_eq!(json["sourcetype"], "windows_sysmon");
        assert_eq!(json["event"], r#"{"EventID":1}"#);
        // 2026-05-20T11:30:00.25Z → 1779276600.25 epoch seconds.
        let t = json["time"].as_f64().expect("time must be number");
        assert!(
            (t - 1779276600.25).abs() < 0.01,
            "expected ~1779276600.25, got {t}",
        );
    }

    /// Batch body is newline-delimited JSON objects (NOT a JSON array,
    /// NOT comma-separated). Vector's splunk_hec source parses this stream.
    #[test]
    fn hec_body_is_newline_delimited_envelopes() {
        let a = fake_event("sysmon", "msg-a", "2026-05-20T11:30:00Z");
        let b = fake_event("apache_http_server", "msg-b", "2026-05-20T11:30:01Z");
        let refs: Vec<&Event> = vec![&a, &b];
        let body = hec_body(&refs);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 lines, got: {body}");
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["sourcetype"], "sysmon");
        assert_eq!(second["sourcetype"], "apache_http_server");
        // No JSON-array wrapping.
        assert!(!body.starts_with('['), "body must not be wrapped in []: {body}");
    }

    /// Malformed timestamp must not panic — fall back to 0.0 so the HEC
    /// source stamps arrival time. log-blaster runs for hours; a single
    /// bad parse can't bring it down.
    #[test]
    fn hec_envelope_falls_back_on_bad_timestamp() {
        let event = fake_event("sysmon", "msg", "not-a-timestamp");
        let env = HecEnvelope::from_event(&event);
        assert_eq!(env.time, 0.0);
    }

    #[test]
    fn transport_kind_label() {
        let v = Transport::Vector {
            url: "http://x".into(),
            token: None,
        };
        let h = Transport::Hec {
            url: "http://x:8088/services/collector/event".into(),
            token: None,
            channel: "00000000-0000-0000-0000-000000000000".into(),
        };
        assert_eq!(v.kind(), "vector");
        assert_eq!(h.kind(), "hec");
    }

    /// NAN-919: HEC sources with `acknowledgements.enabled = true` (nano's
    /// OOTB `02-hec-source.toml`) reject POSTs without the channel header
    /// with 400. The helper must extract the channel; missing it would be
    /// a programmer error since `send_event` dispatches on the variant.
    #[test]
    fn hec_channel_extracts_the_uuid() {
        let h = Transport::Hec {
            url: "http://x".into(),
            token: None,
            channel: "deadbeef-0000-0000-0000-000000000000".into(),
        };
        assert_eq!(hec_channel(&h), "deadbeef-0000-0000-0000-000000000000");
    }

    #[test]
    #[should_panic(expected = "hec_channel called on Vector transport")]
    fn hec_channel_panics_on_vector_transport() {
        let v = Transport::Vector {
            url: "http://x".into(),
            token: None,
        };
        let _ = hec_channel(&v);
    }
}
