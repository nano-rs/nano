// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared tracing/telemetry initialization for all nano services
//!
//! Provides a single `init_tracing` function that both nanosiem-api and nanosiem-search
//! call at startup. Supports plaintext (default) and JSON log formats, and injects
//! deployment identity into every log line for centralized collection.
//!
//! When `SIEM_FORWARD_URL` is set, a background layer forwards log events as gzip'd
//! NDJSON to the org SIEM for operational monitoring. Zero overhead when not configured.

use std::io::Write as IoWrite;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Guard that keeps the root tracing span alive for the process lifetime.
/// Drop this to close the root span (typically held in main).
pub struct TracingGuard {
    _root_span_guard: tracing::span::EnteredSpan,
}

/// Initialize the tracing subscriber for a nano service.
///
/// - `service_name`: identifies the binary (e.g. "nanosiem-api", "nanosiem-search")
///
/// Environment variables:
/// - `RUST_LOG`: standard tracing filter (default: `info,sqlx::query=warn`)
/// - `LOG_FORMAT`: set to `json` for structured JSON output, anything else for plaintext
/// - `NANO_DEPLOYMENT_ID`: deployment identifier for centralized log collection
/// - `SIEM_FORWARD_URL`: HTTP endpoint to forward logs to (disabled if unset)
/// - `SIEM_FORWARD_TOKEN`: Bearer token for the forwarding endpoint
///
/// Returns a guard that must be held for the process lifetime to keep the root span active.
pub fn init_tracing(service_name: &str) -> TracingGuard {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,sqlx::query=warn".into());

    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();

    let forwarding_layer = SiemForwardingLayer::from_env(service_name);

    if log_format.eq_ignore_ascii_case("json") {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(true),
            )
            .with(forwarding_layer)
            .with(env_filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(forwarding_layer)
            .with(env_filter)
            .init();
    }

    let deployment_id = std::env::var("NANO_DEPLOYMENT_ID").unwrap_or_default();

    let version = env!("CARGO_PKG_VERSION");

    // Create a root span that all subsequent logs inherit
    let root_span = tracing::info_span!(
        "service",
        service.name = service_name,
        deployment_id = %deployment_id,
        version = version,
    );
    let guard = root_span.entered();

    TracingGuard {
        _root_span_guard: guard,
    }
}

// ---------------------------------------------------------------------------
// SIEM Forwarding Layer
// ---------------------------------------------------------------------------

/// A tracing layer that forwards log events to an org SIEM endpoint.
///
/// When `SIEM_FORWARD_URL` is not set, this is a true no-op — the `on_event`
/// implementation returns immediately with zero allocations.
///
/// When configured, events are serialized to JSON and sent through a bounded
/// mpsc channel to a background tokio task that batches, gzip-compresses, and
/// POSTs them as NDJSON.
struct SiemForwardingLayer {
    tx: Option<tokio::sync::mpsc::Sender<String>>,
    service_name: String,
    deployment_id: String,
}

impl SiemForwardingLayer {
    fn from_env(service_name: &str) -> Self {
        let url = std::env::var("SIEM_FORWARD_URL").unwrap_or_default();
        let token = std::env::var("SIEM_FORWARD_TOKEN").unwrap_or_default();
        let deployment_id = std::env::var("NANO_DEPLOYMENT_ID").unwrap_or_default();

        if url.is_empty() {
            return Self {
                tx: None,
                service_name: service_name.to_owned(),
                deployment_id,
            };
        }

        // Bounded channel — if the background flusher falls behind we drop events
        // rather than applying backpressure to the service.
        let (tx, rx) = tokio::sync::mpsc::channel::<String>(4096);

        tokio::spawn(siem_flush_task(rx, url, token));

        Self {
            tx: Some(tx),
            service_name: service_name.to_owned(),
            deployment_id,
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for SiemForwardingLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let tx = match &self.tx {
            Some(tx) => tx,
            None => return, // no-op
        };

        // Build a JSON object from the event fields + span context
        let mut fields = serde_json::Map::new();

        // Metadata
        let meta = event.metadata();
        fields.insert(
            "level".into(),
            serde_json::Value::String(meta.level().to_string()),
        );
        fields.insert(
            "target".into(),
            serde_json::Value::String(meta.target().to_string()),
        );
        fields.insert(
            "service.name".into(),
            serde_json::Value::String(self.service_name.clone()),
        );
        if !self.deployment_id.is_empty() {
            fields.insert(
                "deployment_id".into(),
                serde_json::Value::String(self.deployment_id.clone()),
            );
        }

        // Timestamp
        fields.insert(
            "timestamp".into(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );

        // Event fields (message, etc.)
        let mut visitor = JsonVisitor(&mut fields);
        event.record(&mut visitor);

        // Span fields — walk the scope and collect span fields
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                let exts = span.extensions();
                if let Some(storage) = exts.get::<SpanFieldStorage>() {
                    for (k, v) in &storage.0 {
                        fields.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
        }

        let json = serde_json::Value::Object(fields).to_string();

        // Fire-and-forget — try_send so we never block the service
        let _ = tx.try_send(json);
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if self.tx.is_none() {
            return;
        }
        let span = ctx.span(id).expect("span not found");
        let mut fields = serde_json::Map::new();
        let mut visitor = JsonVisitor(&mut fields);
        attrs.record(&mut visitor);
        let mut exts = span.extensions_mut();
        exts.insert(SpanFieldStorage(fields));
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if self.tx.is_none() {
            return;
        }
        let span = ctx.span(id).expect("span not found");
        let mut exts = span.extensions_mut();
        if let Some(storage) = exts.get_mut::<SpanFieldStorage>() {
            let mut visitor = JsonVisitor(&mut storage.0);
            values.record(&mut visitor);
        }
    }
}

/// Storage for span fields attached to span extensions.
struct SpanFieldStorage(serde_json::Map<String, serde_json::Value>);

/// Visitor that records tracing fields into a serde_json Map.
struct JsonVisitor<'a>(&'a mut serde_json::Map<String, serde_json::Value>);

impl<'a> tracing::field::Visit for JsonVisitor<'a> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::from(format!("{:?}", value)),
        );
    }
}

// ---------------------------------------------------------------------------
// Background flush task
// ---------------------------------------------------------------------------

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

async fn siem_flush_task(mut rx: tokio::sync::mpsc::Receiver<String>, url: String, token: String) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client for SIEM forwarding");

    let mut buffer: Vec<String> = Vec::with_capacity(BATCH_SIZE);
    let mut interval = tokio::time::interval(FLUSH_INTERVAL);
    // Don't let missed ticks pile up — just skip them
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Receive events from the channel
            msg = rx.recv() => {
                match msg {
                    Some(json) => {
                        buffer.push(json);
                        if buffer.len() >= BATCH_SIZE {
                            flush_batch(&client, &url, &token, &mut buffer).await;
                        }
                    }
                    None => {
                        // Channel closed (service shutting down) — flush remaining
                        if !buffer.is_empty() {
                            flush_batch(&client, &url, &token, &mut buffer).await;
                        }
                        return;
                    }
                }
            }
            // Periodic flush for low-volume periods
            _ = interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&client, &url, &token, &mut buffer).await;
                }
            }
        }
    }
}

async fn flush_batch(client: &reqwest::Client, url: &str, token: &str, buffer: &mut Vec<String>) {
    // Build NDJSON body
    let ndjson = buffer.join("\n");
    buffer.clear();

    // Gzip compress
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    if encoder.write_all(ndjson.as_bytes()).is_err() {
        return; // silently drop on compression failure
    }
    let compressed = match encoder.finish() {
        Ok(data) => data,
        Err(_) => return,
    };

    // POST to org SIEM — fire-and-forget, errors are silently ignored
    let mut req = client
        .post(url)
        .header("Content-Encoding", "gzip")
        .header("Content-Type", "application/x-ndjson")
        .header("X-Source-Type", "nano_operational")
        .body(compressed);

    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let _ = req.send().await;
}
