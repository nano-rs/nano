// SPDX-License-Identifier: AGPL-3.0-or-later
//! Live tap of a log source's Vector input (NAN-4919, open core).
//!
//! Vector 0.61 serves its observability API over gRPC only, and NAN-4918 binds
//! it to loopback inside the Vector container. nano-api therefore never talks
//! to it directly. A **tap relay** (`nanosiem-api --vector-tap-relay`) runs in
//! the Vector container's network namespace (compose `network_mode:
//! service:vector`, a sidecar in the k8s pod) and is the only client of
//! `127.0.0.1:8686`. It exposes one authenticated, bounded operation: capture
//! up to N events entering ONE named component for at most 60 s. nano-api
//! calls it with a shared bearer token, applies source RBAC, redaction and
//! audit, and returns the capture; nothing is persisted.
//!
//! This module holds the shared bounds and request types, the minimal
//! protobuf messages of `vector.observability.v1.StreamOutputEvents`
//! (hand-declared: only the fields read here exist, so event SECRETS — the HEC
//! token among them — are never even decoded), and the gRPC client.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};

pub const DEFAULT_SECONDS: u64 = 30;
pub const MAX_SECONDS: u64 = 60;
pub const DEFAULT_EVENTS: usize = 100;
pub const MAX_EVENTS: usize = 1000;
/// Larger events are dropped from the capture (counted, never truncated).
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
/// Whole-capture byte ceiling (1,000 × 64 KiB would be 64 MiB).
pub const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
/// Vector's per-interval sampling, so a busy source cannot flood the relay.
pub const SAMPLE_INTERVAL_MS: i32 = 500;
pub const SAMPLE_LIMIT_PER_INTERVAL: i32 = 50;

/// nano-api → relay: the relay's base URL (e.g. `http://vector:8687`).
pub const RELAY_URL_ENV: &str = "NANO_VECTOR_TAP_URL";
/// Comma-separated relay URLs for role-split/multi-ingest deployments. The API
/// fans one bounded request to every relay and merges the captures.
pub const RELAY_URLS_ENV: &str = "NANO_VECTOR_TAP_URLS";
/// Shared secret between nano-api and the relay (never given to Vector).
pub const RELAY_TOKEN_ENV: &str = "NANO_VECTOR_TAP_TOKEN";
/// The relay's listen address inside the Vector network namespace.
pub const RELAY_LISTEN_ENV: &str = "NANO_VECTOR_TAP_LISTEN";
pub const DEFAULT_RELAY_LISTEN: &str = "0.0.0.0:8687";
/// The relay's view of the loopback-only Vector API.
pub const VECTOR_API_ENV: &str = "NANO_VECTOR_API_URL";
pub const DEFAULT_VECTOR_API: &str = "http://127.0.0.1:8686";
/// Shortest accepted shared token.
pub const MIN_TOKEN_BYTES: usize = 32;

/// One capture the relay performs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TapRequest {
    /// The component whose INPUT is captured (`<source>_parse`). One exact
    /// id: no glob characters, so a caller can never widen the tap.
    pub component: String,
    pub seconds: u64,
    pub max_events: usize,
}

impl TapRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.component.is_empty()
            || self.component.len() > 256
            || !self
                .component
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err("Tap one generated component id".into());
        }
        if !(1..=MAX_SECONDS).contains(&self.seconds) {
            return Err(format!("A tap lasts 1–{MAX_SECONDS} seconds"));
        }
        if !(1..=MAX_EVENTS).contains(&self.max_events) {
            return Err(format!("A tap captures 1–{MAX_EVENTS} events"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TapEvent {
    /// The event as it enters the pipeline (the log value only).
    #[schema(value_type = Object)]
    pub event: Value,
    /// Its input identity (`push:<credential id>`) when ingress stamped one.
    pub input: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TapCapture {
    pub events: Vec<TapEvent>,
    /// Events skipped because one exceeded 64 KiB or the capture byte cap.
    pub dropped_oversize: usize,
    /// Why the capture ended: `deadline`, `max_events`, `max_bytes`,
    /// `stream_closed`.
    pub ended: String,
}

// --- vector.observability.v1 (subset) ---------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct StreamOutputEventsRequest {
    #[prost(string, repeated, tag = "1")]
    outputs_patterns: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    inputs_patterns: Vec<String>,
    #[prost(int32, tag = "3")]
    limit: i32,
    #[prost(int32, tag = "4")]
    interval_ms: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct StreamOutputEventsResponse {
    #[prost(oneof = "response::Event", tags = "1, 2")]
    event: Option<response::Event>,
}

mod response {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Event {
        #[prost(message, tag = "1")]
        Tapped(super::TappedEvent),
        #[prost(message, tag = "2")]
        Notification(super::EventNotification),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct TappedEvent {
    #[prost(string, tag = "1")]
    component_id: String,
    #[prost(message, optional, tag = "4")]
    event: Option<EventWrapper>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EventNotification {
    #[prost(string, tag = "1")]
    message: String,
}

/// `event.EventWrapper`: only the Log arm is declared; metrics/traces are
/// skipped as unknown fields.
#[derive(Clone, PartialEq, prost::Message)]
struct EventWrapper {
    #[prost(message, optional, tag = "1")]
    log: Option<Log>,
}

/// `event.Log`. Vector encodes an OBJECT root in the (deprecated) `fields`
/// map and leaves `value` unset; any other root goes in `value`.
#[derive(Clone, PartialEq, prost::Message)]
struct Log {
    #[prost(map = "string, message", tag = "1")]
    fields: std::collections::HashMap<String, PValue>,
    #[prost(message, optional, tag = "2")]
    value: Option<PValue>,
    #[prost(message, optional, tag = "4")]
    metadata_full: Option<Metadata>,
}

/// `event.Metadata` with ONLY its value map: `secrets` (tag 6) is
/// deliberately undeclared and therefore never decoded.
#[derive(Clone, PartialEq, prost::Message)]
struct Metadata {
    #[prost(message, optional, tag = "1")]
    value: Option<PValue>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PValue {
    #[prost(oneof = "kind::Kind", tags = "1, 2, 4, 5, 6, 7, 8, 9")]
    kind: Option<kind::Kind>,
}

mod kind {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(bytes, tag = "1")]
        RawBytes(Vec<u8>),
        #[prost(message, tag = "2")]
        Timestamp(super::PTimestamp),
        #[prost(int64, tag = "4")]
        Integer(i64),
        #[prost(double, tag = "5")]
        Float(f64),
        #[prost(bool, tag = "6")]
        Boolean(bool),
        #[prost(message, tag = "7")]
        Map(super::ValueMap),
        #[prost(message, tag = "8")]
        Array(super::ValueArray),
        #[prost(int32, tag = "9")]
        Null(i32),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct PTimestamp {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ValueMap {
    #[prost(map = "string, message", tag = "1")]
    fields: std::collections::HashMap<String, PValue>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ValueArray {
    #[prost(message, repeated, tag = "1")]
    items: Vec<PValue>,
}

fn to_json(value: PValue) -> Value {
    use kind::Kind;
    match value.kind {
        None | Some(Kind::Null(_)) => Value::Null,
        Some(Kind::RawBytes(bytes)) => Value::String(String::from_utf8_lossy(&bytes).into_owned()),
        Some(Kind::Timestamp(ts)) => {
            chrono::DateTime::from_timestamp(ts.seconds, ts.nanos.max(0) as u32)
                .map(|t| Value::String(t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)))
                .unwrap_or(Value::Null)
        }
        Some(Kind::Integer(i)) => Value::from(i),
        Some(Kind::Float(f)) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
        Some(Kind::Boolean(b)) => Value::Bool(b),
        Some(Kind::Map(map)) => Value::Object(
            map.fields
                .into_iter()
                .map(|(k, v)| (k, to_json(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Some(Kind::Array(array)) => Value::Array(array.items.into_iter().map(to_json).collect()),
    }
}

/// The input identity a tapped event's metadata carries, if any.
fn input_of(metadata: Option<Metadata>) -> Option<String> {
    let value = to_json(metadata?.value?);
    let stamp = value.get(super::input::METADATA)?.as_str()?;
    super::input::of_stamp(stamp)
}

/// Encode one gRPC message frame (uncompressed).
fn frame(message: &impl prost::Message) -> Vec<u8> {
    let body = message.encode_to_vec();
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(0);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Largest gRPC message accepted from Vector (one tapped event).
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Capture from Vector's loopback gRPC API. Runs in the relay only.
pub async fn capture(vector_api: &str, request: &TapRequest) -> Result<TapCapture, String> {
    use futures::StreamExt;
    request.validate()?;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .connect_timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let body = frame(&StreamOutputEventsRequest {
        outputs_patterns: vec![],
        inputs_patterns: vec![request.component.clone()],
        limit: SAMPLE_LIMIT_PER_INTERVAL,
        interval_ms: SAMPLE_INTERVAL_MS,
    });
    let url = format!(
        "{}/vector.observability.v1.ObservabilityService/StreamOutputEvents",
        vector_api.trim_end_matches('/')
    );
    let deadline = Instant::now() + Duration::from_secs(request.seconds);
    let response = tokio::time::timeout_at(
        deadline.into(),
        client
            .post(url)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(body)
            .send(),
    )
    .await
    .map_err(|_| "Vector API did not answer before the deadline".to_string())?
    .map_err(|_| "Vector API is unreachable".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Vector API refused the tap ({})",
            response.status()
        ));
    }
    if let Some(status) = response.headers().get("grpc-status") {
        if status != "0" {
            return Err("Vector API refused the tap".into());
        }
    }
    let mut stream = response.bytes_stream();
    let mut buffer: Vec<u8> = Vec::new();
    let mut capture = TapCapture {
        ended: "deadline".into(),
        ..Default::default()
    };
    let mut bytes = 0usize;
    'outer: loop {
        let chunk = match tokio::time::timeout_at(deadline.into(), stream.next()).await {
            Err(_) => break,
            Ok(None) => {
                capture.ended = "stream_closed".into();
                break;
            }
            Ok(Some(Err(_))) => {
                capture.ended = "stream_closed".into();
                break;
            }
            Ok(Some(Ok(chunk))) => chunk,
        };
        buffer.extend_from_slice(&chunk);
        while buffer.len() >= 5 {
            if buffer[0] != 0 {
                return Err("Compressed tap frames are not supported".into());
            }
            let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
            if len > MAX_FRAME_BYTES {
                return Err("Tap frame exceeds the inspection bound".into());
            }
            if buffer.len() < 5 + len {
                break;
            }
            let message: Vec<u8> = buffer.drain(..5 + len).skip(5).collect();
            let Ok(decoded) =
                <StreamOutputEventsResponse as prost::Message>::decode(message.as_slice())
            else {
                return Err("Invalid tap frame".into());
            };
            let Some(response::Event::Tapped(tapped)) = decoded.event else {
                continue;
            };
            let Some(log) = tapped.event.and_then(|e| e.log) else {
                continue;
            };
            let event = match log.value {
                Some(value) => to_json(value),
                None => to_json(PValue {
                    kind: Some(kind::Kind::Map(ValueMap { fields: log.fields })),
                }),
            };
            let size = serde_json::to_vec(&event)
                .map(|v| v.len())
                .unwrap_or(usize::MAX);
            if size > MAX_EVENT_BYTES || bytes + size > MAX_CAPTURE_BYTES {
                capture.dropped_oversize += 1;
                if bytes + MAX_EVENT_BYTES > MAX_CAPTURE_BYTES {
                    capture.ended = "max_bytes".into();
                    break 'outer;
                }
                continue;
            }
            bytes += size;
            capture.events.push(TapEvent {
                event,
                input: input_of(log.metadata_full),
            });
            if capture.events.len() >= request.max_events {
                capture.ended = "max_events".into();
                break 'outer;
            }
        }
    }
    Ok(capture)
}

/// Most bytes nano-api reads from a relay response: the capture cap plus
/// generous JSON/identity overhead. Anything larger is refused unread.
pub const MAX_RELAY_RESPONSE_BYTES: usize = MAX_CAPTURE_BYTES + 2 * 1024 * 1024;

/// Read and check a relay response in nano-api WITHOUT trusting the relay's
/// own bounds: the body is read incrementally up to
/// [`MAX_RELAY_RESPONSE_BYTES`], then the event count, each event's size and
/// the capture total are re-checked after decoding.
pub async fn read_relay_capture(
    mut response: reqwest::Response,
    max_events: usize,
) -> Result<TapCapture, String> {
    if response
        .content_length()
        .is_some_and(|len| len as usize > MAX_RELAY_RESPONSE_BYTES)
    {
        return Err("Live tap response exceeds its bound".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Invalid live tap response".to_string())?
    {
        if body.len() + chunk.len() > MAX_RELAY_RESPONSE_BYTES {
            return Err("Live tap response exceeds its bound".into());
        }
        body.extend_from_slice(&chunk);
    }
    decode_relay_capture(&body, max_events)
}

/// Decode and re-validate a relay capture body (see [`read_relay_capture`]).
pub fn decode_relay_capture(body: &[u8], max_events: usize) -> Result<TapCapture, String> {
    if body.len() > MAX_RELAY_RESPONSE_BYTES {
        return Err("Live tap response exceeds its bound".into());
    }
    let capture: TapCapture =
        serde_json::from_slice(body).map_err(|_| "Invalid live tap response".to_string())?;
    if capture.events.len() > max_events.min(MAX_EVENTS) {
        return Err("Live tap response exceeds its event bound".into());
    }
    let mut total = 0usize;
    for item in &capture.events {
        let size = serde_json::to_vec(&item.event)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if size > MAX_EVENT_BYTES {
            return Err("Live tap response exceeds its per-event bound".into());
        }
        total += size;
    }
    if total > MAX_CAPTURE_BYTES {
        return Err("Live tap response exceeds its capture bound".into());
    }
    Ok(capture)
}

/// Constant-time comparison of the relay bearer token.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    use sha2::Digest;
    let a = sha2::Sha256::digest(expected.as_bytes());
    let b = sha2::Sha256::digest(presented.as_bytes());
    expected.len() >= MIN_TOKEN_BYTES
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
#[path = "tap_tests.rs"]
mod tests;

/// The credential field names the platform redaction (NAN-4038,
/// `credential_field_redaction_vrl!`) removes; a test keeps the two in sync.
pub const CREDENTIAL_FIELD_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-webhook-secret",
    "cookie",
    "set-cookie",
];

/// Remove credential-named fields (case-insensitive) at ANY depth, through
/// objects AND arrays, before captured events leave the API. The storage
/// lanes' VRL redactor leaves arrays whole (they reach storage as encoded
/// values); a live tap returns the raw nested structure, so it must descend
/// into arrays too (a batched `records[].headers.Authorization`).
pub fn redact(capture: &mut TapCapture) -> Result<(), String> {
    fn walk(value: &mut Value, depth: usize) {
        if depth > 128 {
            // Bounded by the 64 KiB event cap; refuse to return anything
            // deeper than the walk covers.
            *value = serde_json::json!("[withheld: nesting too deep to redact]");
            return;
        }
        match value {
            Value::Object(map) => {
                map.retain(|key, _| {
                    !CREDENTIAL_FIELD_NAMES.contains(&key.to_ascii_lowercase().as_str())
                });
                for child in map.values_mut() {
                    walk(child, depth + 1);
                }
            }
            Value::Array(items) => {
                for child in items {
                    walk(child, depth + 1);
                }
            }
            _ => {}
        }
    }
    for item in &mut capture.events {
        walk(&mut item.event, 0);
    }
    Ok(())
}
