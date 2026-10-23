// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded OTLP/HTTP trace export for service operations. Export only static
//! span names, timing and a typed allowlist; never queries, tokens or event data.
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::{AnyValue, KeyValue, any_value::Value},
    resource::v1::Resource,
    trace::v1::{ResourceSpans, ScopeSpans, Span, Status},
};
use prost::Message;
use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

static BROWSER_SPANS: OnceLock<mpsc::Sender<Span>> = OnceLock::new();

pub struct OtlpTraceLayer {
    tx: Option<mpsc::Sender<Span>>,
    stdout_service: Option<String>,
    sample_every: u64,
    next: AtomicU64,
}

#[derive(Clone)]
struct TraceContext {
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
    sampled: bool,
    start: u64,
    error: bool,
    attributes: Vec<KeyValue>,
}

// Only these typed fields can leave the process. Debug/display values are
// deliberately ignored: formatting an arbitrary value could expose payloads.
#[derive(Default)]
struct SafeFields(Vec<KeyValue>);
impl SafeFields {
    fn set(&mut self, key: &str, value: Value) {
        self.0.retain(|entry| entry.key != key);
        self.0.push(KeyValue { key: key.to_owned(), value: Some(AnyValue { value: Some(value) }) });
    }
}
impl tracing::field::Visit for SafeFields {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if matches!(field.name(), "db.response.rows" | "db.response.bytes") {
            if let Ok(value) = i64::try_from(value) { self.set(field.name(), Value::IntValue(value)); }
        } else if field.name() == "http.response.status_code" && (100..=599).contains(&value) {
            self.set(field.name(), Value::IntValue(value as i64));
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        // Host only, never a URL, userinfo, path, query string or arbitrary text.
        if field.name() == "server.address" && !value.is_empty() && value.len() <= 253
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')) {
            self.set(field.name(), Value::StringValue(value.to_owned()));
        }
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

impl OtlpTraceLayer {
    #[cfg(test)]
    pub(crate) fn capture_for_test(sample_every: u64) -> (Self, mpsc::Receiver<Span>) {
        let (tx, rx) = mpsc::channel(64);
        (Self { tx: Some(tx), stdout_service: None, sample_every, next: AtomicU64::new(0) }, rx)
    }

    pub fn from_env(service: &str) -> Option<Self> {
        if std::env::var("NANO_OTLP_TRACE_STDOUT").as_deref() == Ok("1") {
            return Some(Self {
                tx: None,
                stdout_service: Some(service.to_owned()),
                sample_every: 10,
                next: AtomicU64::new(0),
            });
        }
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").ok()?;
        let url = reqwest::Url::parse(&endpoint).ok()?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            eprintln!("OTLP trace export disabled: invalid endpoint");
            return None;
        }
        let token = match std::env::var("NANO_OTLP_TRACE_TOKEN_FILE") {
            Ok(path) => match std::fs::read_to_string(path) {
                Ok(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
                _ => {
                    eprintln!("OTLP trace export disabled: credential file unavailable");
                    return None;
                }
            },
            Err(_) => None,
        };
        let sample_every = std::env::var("NANO_OTLP_TRACE_SAMPLE_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| (1..=1_000_000).contains(v))
            .unwrap_or(10);
        let (tx, rx) = mpsc::channel(1024);
        if service == "nanosiem-api"
            && std::env::var("NANO_BROWSER_TELEMETRY_ENABLED").as_deref() == Ok("1")
        {
            let (browser_tx, browser_rx) = mpsc::channel(1024);
            if BROWSER_SPANS.set(browser_tx).is_ok() {
                tokio::spawn(export(
                    browser_rx,
                    url.clone(),
                    token.clone(),
                    "nano-web".into(),
                ));
            }
        }
        tokio::spawn(export(rx, url, token, service.to_owned()));
        Some(Self {
            tx: Some(tx),
            stdout_service: None,
            sample_every,
            next: AtomicU64::new(0),
        })
    }
}

impl<S> Layer<S> for OtlpTraceLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        // The process-lifetime log identity span is not a request or operation.
        if attrs.metadata().name() == "service" {
            return;
        }
        let Some(span) = ctx.span(id) else {
            return;
        };
        let parent = span
            .parent()
            .and_then(|p| p.extensions().get::<TraceContext>().cloned());
        let (trace_id, sampled) = parent.map(|p| (p.trace_id, p.sampled)).unwrap_or_else(|| {
            (
                uuid::Uuid::now_v7().as_bytes().to_vec(),
                self.next.fetch_add(1, Ordering::Relaxed) % self.sample_every == 0,
            )
        });
        let span_id = uuid::Uuid::now_v7().as_bytes()[8..].to_vec();
        span.extensions_mut().insert(TraceContext {
            trace_id,
            span_id,
            sampled,
            start: now_ns(),
            error: false,
            attributes: {
                let mut fields = SafeFields::default();
                attrs.record(&mut fields);
                fields.0
            },
        });
    }

    fn on_record(&self, id: &tracing::span::Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(state) = span.extensions_mut().get_mut::<TraceContext>() {
                let mut fields = SafeFields(std::mem::take(&mut state.attributes));
                values.record(&mut fields);
                state.attributes = fields.0;
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        if let Some(span) = ctx.event_span(event) {
            if let Some(state) = span.extensions_mut().get_mut::<TraceContext>() {
                state.error = true;
            }
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let exts = span.extensions();
        let Some(state) = exts.get::<TraceContext>() else {
            return;
        };
        if !state.sampled {
            return;
        }
        let parent_span_id = span
            .parent()
            .and_then(|p| {
                p.extensions()
                    .get::<TraceContext>()
                    .map(|p| p.span_id.clone())
            })
            .unwrap_or_default();
        let wire = Span {
            trace_id: state.trace_id.clone(),
            span_id: state.span_id.clone(),
            parent_span_id,
            name: span.metadata().name().to_owned(),
            attributes: state.attributes.clone(),
            kind: 1,
            start_time_unix_nano: state.start,
            end_time_unix_nano: now_ns(),
            status: Some(Status {
                code: if state.error { 2 } else { 0 },
                message: String::new(),
            }),
            ..Default::default()
        };
        if let Some(tx) = self.tx.as_ref() {
            let _ = tx.try_send(wire);
        } else if let Some(service) = self.stdout_service.as_ref() {
            // Sandboxed cell children have no network. Their existing bounded
            // stdout pipe is collected by the region shipper; no jail is widened.
            let _ = writeln!(
                std::io::stdout().lock(), "{}",
                serde_json::json!({"nano_otel_span": {
                "traceId": hex::encode(&wire.trace_id), "spanId": hex::encode(&wire.span_id),
                "parentSpanId": hex::encode(&wire.parent_span_id), "name": wire.name,
                "kind": wire.kind, "startTimeUnixNano": wire.start_time_unix_nano.to_string(),
                "endTimeUnixNano": wire.end_time_unix_nano.to_string(),
                "status": {"code": wire.status.as_ref().map(|s| s.code).unwrap_or(0)}
            }, "service_name": service})
            );
        }
    }
}

/// Called only after the API validates a fixed page category and duration.
pub(super) fn record_browser_pageview(page: &'static str, duration_ms: u32) {
    let Some(tx) = BROWSER_SPANS.get() else {
        return;
    };
    let end = now_ns();
    let _ = tx.try_send(Span {
        trace_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
        span_id: uuid::Uuid::now_v7().as_bytes()[8..].to_vec(),
        name: "pageview".into(),
        kind: 1,
        start_time_unix_nano: end.saturating_sub(u64::from(duration_ms) * 1_000_000),
        end_time_unix_nano: end,
        attributes: vec![KeyValue {
            key: "page.url".into(),
            value: Some(AnyValue {
                value: Some(Value::StringValue(page.into())),
            }),
        }],
        ..Default::default()
    });
}

fn batch(service: &str, spans: Vec<Span>) -> Vec<u8> {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".into(),
                    value: Some(AnyValue {
                        value: Some(Value::StringValue(service.into())),
                    }),
                }],
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                spans,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
    .encode_to_vec()
}

async fn export(
    mut rx: mpsc::Receiver<Span>,
    url: reqwest::Url,
    token: Option<String>,
    service: String,
) {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return;
    };
    let mut pending = Vec::with_capacity(100);
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let (closed, elapsed) = tokio::select! {
            next = rx.recv() => match next { Some(span) => { pending.push(span); (false, false) }, None => (true, false) },
            _ = tick.tick() => (false, true),
        };
        if !pending.is_empty() && (closed || elapsed || pending.len() >= 100) {
            let body = batch(&service, std::mem::take(&mut pending));
            // Bounded retries; never backpressure request handlers or print credentials.
            for attempt in 0..3 {
                let mut request = client
                    .post(url.clone())
                    .header("content-type", "application/x-protobuf")
                    .body(body.clone());
                if let Some(token) = token.as_ref() {
                    request = request.bearer_auth(token);
                }
                match request.send().await {
                    Ok(response) if response.status().is_success() => break,
                    Ok(response)
                        if response.status().is_client_error()
                            && response.status().as_u16() != 429 =>
                    {
                        break;
                    }
                    _ if attempt < 2 => tokio::time::sleep(Duration::from_secs(1 << attempt)).await,
                    _ => eprintln!("OTLP trace export batch failed after bounded retries"),
                }
            }
        }
        if closed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn children_inherit_sampling_and_parent_ids_without_sensitive_fields() {
        use tracing_subscriber::prelude::*;
        let (tx, mut rx) = mpsc::channel(16);
        let subscriber = tracing_subscriber::registry().with(OtlpTraceLayer {
            tx: Some(tx),
            stdout_service: None,
            sample_every: 2,
            next: AtomicU64::new(0),
        });
        tracing::subscriber::with_default(subscriber, || {
            {
                let root = tracing::info_span!("request", token = "must-never-export");
                let _entered = root.enter();
                {
                    let _child = tracing::info_span!("database", query = "sensitive").entered();
                }
            }
            {
                let _unsampled = tracing::info_span!("second_request").entered();
            }
        });
        let child = rx.try_recv().unwrap();
        let root = rx.try_recv().unwrap();
        assert_eq!(child.name, "database");
        assert_eq!(root.name, "request");
        assert_eq!(child.trace_id, root.trace_id);
        assert_eq!(child.parent_span_id, root.span_id);
        assert!(root.parent_span_id.is_empty());
        assert!(child.attributes.is_empty());
        assert!(root.attributes.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn allowlist_exports_typed_metrics_and_host_status_only() {
        use tracing_subscriber::prelude::*;
        let (layer, mut rx) = OtlpTraceLayer::capture_for_test(1);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http.client.request", server.address = "api.example.com",
                http.response.status_code = tracing::field::Empty,
                db.response.rows = 3_u64, db.response.bytes = 42_u64,
                query = "private", token = "private", url = "https://example.com/?token=private");
            span.record("http.response.status_code", 200_u64);
        });
        let span = rx.try_recv().unwrap();
        assert_eq!(span.attributes.len(), 4);
        assert!(span.attributes.iter().all(|a| matches!(a.key.as_str(),
            "server.address" | "http.response.status_code" | "db.response.rows" | "db.response.bytes")));
        let (layer, mut rx) = OtlpTraceLayer::capture_for_test(1);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let _span = tracing::info_span!("http.client.request",
                server.address = "https://user:password@example.com/?secret=value",
                http.response.status_code = 999_u64, db.response.rows = u64::MAX);
        });
        assert!(rx.try_recv().unwrap().attributes.is_empty());
    }

    #[test]
    fn wire_batch_identifies_service_without_exporting_tracing_fields() {
        let decoded = ExportTraceServiceRequest::decode(
            batch(
                "nanosiem-api",
                vec![Span {
                    trace_id: vec![1; 16],
                    span_id: vec![2; 8],
                    name: "search".into(),
                    ..Default::default()
                }],
            )
            .as_slice(),
        )
        .unwrap();
        let resource = &decoded.resource_spans[0];
        assert_eq!(
            resource.resource.as_ref().unwrap().attributes[0].key,
            "service.name"
        );
        assert_eq!(resource.scope_spans[0].spans[0].trace_id.len(), 16);
        assert!(resource.scope_spans[0].spans[0].attributes.is_empty());
    }
}
