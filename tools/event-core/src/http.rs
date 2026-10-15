// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP send functions for the ingestion transports log-blaster supports.
//!
//! Three wire formats:
//!
//! - **Vector** (`Transport::Vector`) — Vector's `http` source: NDJSON body,
//!   `X-Source-Type` header per group, Bearer auth. Events are grouped by
//!   `source_type` because the header is per-request.
//! - **HEC** (`Transport::Hec`) — Splunk HEC `/services/collector/event`:
//!   line-delimited JSON envelopes with `sourcetype` in-band, Splunk auth
//!   (`Authorization: Splunk <token>`). No grouping — each envelope carries
//!   its own sourcetype, which the OOTB `hec_normalize` transform maps to
//!   `source_type`.
//! - **Tenzir** (`Transport::Tenzir`) — a Tenzir `accept_http` source: NDJSON
//!   body of the raw `Event` shape (`{message, timestamp, source_type}`).
//!   Source identity is in-band so there is no grouping, and the local-rig
//!   listener carries no auth. The receiving TQL pipeline parses the raw
//!   payloads to OCSF and writes directly into ClickHouse — see
//!   `tools/log-blaster/tenzir/` (NAN-1402).

use anyhow::Result;
use chrono::DateTime;
use reqwest::Client;
use serde::Serialize;
use tokio::time::Duration as TokioDuration;
use tracing::warn;

use crate::event::Event;

/// Compute the per-attempt retry backoff for HTTP/HEC send loops.
///
/// Exponential (`base × 2^(attempt-1)`) with both `attempt` and the
/// multiplier saturating so any caller passing a large `max_retries`
/// can't overflow into a multi-day sleep. NAN-953. Capped at ~128s
/// (2^8 × 500ms) — sufficient to ride out a transient outage without
/// pinning the runtime if a caller picks a pathological value.
fn retry_backoff(attempt: u32) -> TokioDuration {
    // `attempt` is the 1-indexed retry number (attempt=1 → first retry).
    // We clamp the exponent at 8 so 500ms × 2^8 = 128_000ms is the
    // absolute ceiling regardless of the caller's `max_retries`.
    let exp = (attempt.saturating_sub(1)).min(8);
    let millis = 500u64.saturating_mul(2u64.saturating_pow(exp));
    TokioDuration::from_millis(millis)
}

// ---------------------------------------------------------------------------
// NAN-2988: forwarder-style delivery (retry until accepted, honour Retry-After)
// ---------------------------------------------------------------------------

/// Largest Retry-After honoured; a longer hint is clamped so one bad header
/// cannot park a sender for hours.
pub const MAX_RETRY_AFTER: TokioDuration = TokioDuration::from_secs(120);
/// Ceiling of the exponential backoff used when no Retry-After was given.
pub const MAX_FORWARDER_BACKOFF: TokioDuration = TokioDuration::from_secs(30);
/// Floor between attempts, so `Retry-After: 0` cannot become a hot loop.
const MIN_RETRY_DELAY: TokioDuration = TokioDuration::from_millis(100);

/// How one refused or failed request is retried. A real forwarder (Splunk
/// UF, Cribl, Vector) keeps retrying a retryable failure until the receiver
/// accepts it; only a permanent refusal (a 4xx other than 408/429) is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt; `None` retries until accepted.
    pub max_retries: Option<u32>,
    /// Stop retrying once the next attempt would start later than this after
    /// the first one. `None` never gives up on a retryable failure.
    pub deadline: Option<TokioDuration>,
}

impl RetryPolicy {
    /// The historical bounded loop: `max_retries` retries, no deadline.
    pub fn bounded(max_retries: u32) -> Self {
        Self {
            max_retries: Some(max_retries),
            deadline: None,
        }
    }

    /// Retry every retryable failure until accepted, optionally bounded in time.
    pub fn until_accepted(deadline: Option<TokioDuration>) -> Self {
        Self {
            max_retries: None,
            deadline,
        }
    }
}

/// What delivering one request took.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReport {
    /// HTTP attempts, including the first.
    pub attempts: u32,
    /// Attempts the receiver shed with 429 or 503.
    pub shed: u32,
    /// Attempts answered with another retryable status (408, other 5xx).
    pub server_errors: u32,
    /// Attempts with no HTTP response (connect/TLS failure, timeout, reset).
    pub network_errors: u32,
}

impl DeliveryReport {
    /// True when the request needed at least one retry.
    pub fn retried(&self) -> bool {
        self.attempts > 1
    }
}

/// A request that was not accepted.
#[derive(Debug)]
pub struct DeliveryFailure {
    pub report: DeliveryReport,
    /// True for a refusal no retry can fix (4xx other than 408/429).
    pub permanent: bool,
    /// The last HTTP status, if the last attempt got one.
    pub status: Option<reqwest::StatusCode>,
    pub error: anyhow::Error,
}

impl DeliveryFailure {
    fn permanent(error: anyhow::Error) -> Self {
        Self {
            report: DeliveryReport::default(),
            permanent: true,
            status: None,
            error,
        }
    }
}

impl std::fmt::Display for DeliveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} after {} attempt(s)",
            self.error, self.report.attempts
        )
    }
}

impl std::error::Error for DeliveryFailure {}

/// 408, 429 and 5xx (except 501/505, which never change on retry) are
/// transient; every other 4xx is a permanent refusal of this exact request.
pub fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    match status.as_u16() {
        408 | 429 => true,
        501 | 505 => false,
        code => (500..600).contains(&code),
    }
}

/// `Retry-After` as delay-seconds (RFC 9110 §10.2.3), clamped to
/// [`MAX_RETRY_AFTER`]. An HTTP-date or a malformed value is ignored and the
/// caller falls back to its backoff.
pub fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<TokioDuration> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if value.is_empty() || value.len() > 9 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(TokioDuration::from_secs(value.parse::<u64>().ok()?).min(MAX_RETRY_AFTER))
}

/// Backoff between attempts when the receiver named no delay: 500 ms
/// doubling, capped at [`MAX_FORWARDER_BACKOFF`].
pub fn forwarder_backoff(retry: u32) -> TokioDuration {
    retry_backoff(retry).min(MAX_FORWARDER_BACKOFF)
}

/// Run `attempt` until the receiver accepts (2xx), the failure is permanent,
/// or `policy` gives up. Every attempt is reported to `observe` (its status,
/// or `None` for a network error) before it is classified. The caller builds
/// the identical request each time (same body, same idempotency key).
pub async fn deliver_with_policy<F, Fut>(
    policy: RetryPolicy,
    label: &str,
    mut attempt: F,
    observe: impl Fn(Option<reqwest::StatusCode>) + Send + Sync,
) -> std::result::Result<DeliveryReport, DeliveryFailure>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response>>,
{
    let started = tokio::time::Instant::now();
    let mut report = DeliveryReport::default();
    let mut hinted: Option<TokioDuration> = None;
    loop {
        if report.attempts > 0 {
            let delay = hinted
                .take()
                .unwrap_or_else(|| forwarder_backoff(report.attempts))
                .max(MIN_RETRY_DELAY);
            tokio::time::sleep(delay).await;
        }
        report.attempts += 1;
        let response = attempt().await;
        observe(response.as_ref().ok().map(|r| r.status()));
        let (status, error) = match response {
            Ok(response) if response.status().is_success() => return Ok(report),
            Ok(response) => {
                let status = response.status();
                hinted = retry_after(response.headers());
                let error = anyhow::Error::from(response.error_for_status().unwrap_err());
                if !is_retryable_status(status) {
                    return Err(DeliveryFailure {
                        report,
                        permanent: true,
                        status: Some(status),
                        error,
                    });
                }
                if status.as_u16() == 429 || status.as_u16() == 503 {
                    report.shed += 1;
                } else {
                    report.server_errors += 1;
                }
                (Some(status), error)
            }
            Err(error) => {
                report.network_errors += 1;
                (None, error)
            }
        };
        let exhausted = policy.max_retries.is_some_and(|max| report.attempts > max);
        let next = hinted
            .unwrap_or_else(|| forwarder_backoff(report.attempts))
            .max(MIN_RETRY_DELAY);
        let late = policy
            .deadline
            .is_some_and(|deadline| started.elapsed() + next > deadline);
        if exhausted || late {
            return Err(DeliveryFailure {
                report,
                permanent: false,
                status,
                error,
            });
        }
        tracing::debug!(
            "[{}] attempt {} failed ({}); retrying in {:?}",
            label,
            report.attempts,
            status.map_or_else(|| "network error".to_string(), |s| s.to_string()),
            next
        );
    }
}

/// Where to send events. Built once at startup; passed by reference through
/// the send call chain so the wire format never gets re-derived per call.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Vector HTTP source. `url` already includes any path suffix (e.g.
    /// `/ingest` for dev stacks); we POST directly to it.
    Vector {
        url: String,
        token: Option<String>,
        /// Optional stable-key namespace for hosted durable-ingest requests.
        /// Each logical HTTP request gets one UUID-suffixed key and retries
        /// reuse it. Customer-owned/open-core Vector endpoints leave this
        /// unset and preserve their existing wire contract.
        idempotency_key_prefix: Option<String>,
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
    /// Tenzir `accept_http` source. The body is NDJSON of the raw `Event`
    /// shape — `{message, timestamp, source_type}` — i.e. the pre-parse
    /// payloads, with feed identity in-band. The TQL side routes on
    /// `source_type`, parses `message`, and maps to OCSF (NAN-1402). The
    /// listener is a local validation rig, so there is no auth token.
    Tenzir { url: String },
    /// OTLP/HTTP JSON to Vector's `opentelemetry` receiver (NAN-1533). The
    /// realistic producer path: per-record OTLP/JSON is wrapped in the OTLP
    /// export envelope (`resourceSpans`/`resourceMetrics`/`resourceLogs`) and
    /// POSTed to `<base_url>/v1/{traces,metrics,logs}` with
    /// protobuf (`application/x-protobuf`). `base_url` is the receiver root (no
    /// `/v1/...` suffix — the signal-specific path is appended per send).
    /// Default `http://localhost:4318`. Open-core/local OTLP has no shared-token
    /// gate (auth terminates at the LB); managed deploys token-gate the receiver
    /// (FRO-518) and `abort` unauthenticated exports, so `token` carries the
    /// Bearer when one is configured (sent as `Authorization: Bearer <token>`).
    OtlpHttp {
        base_url: String,
        token: Option<String>,
    },
}

/// The three OTLP signal kinds log-blaster can emit. Selects the receiver path
/// (`/v1/<signal>`) and the export-envelope key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpSignal {
    Traces,
    Metrics,
    Logs,
}

impl OtlpSignal {
    /// OTLP/HTTP path suffix (appended to `OtlpHttp::base_url`).
    fn http_path(&self) -> &'static str {
        match self {
            OtlpSignal::Traces => "/v1/traces",
            OtlpSignal::Metrics => "/v1/metrics",
            OtlpSignal::Logs => "/v1/logs",
        }
    }
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
            Transport::Tenzir { url } => url,
            Transport::OtlpHttp { base_url, .. } => base_url,
        }
    }

    fn token(&self) -> Option<&str> {
        match self {
            Transport::Vector { token, .. } => token.as_deref(),
            Transport::Hec { token, .. } => token.as_deref(),
            Transport::Tenzir { .. } => None,
            Transport::OtlpHttp { token, .. } => token.as_deref(),
        }
    }

    fn fresh_vector_idempotency_key(&self) -> Option<String> {
        match self {
            Transport::Vector {
                idempotency_key_prefix: Some(prefix),
                ..
            } => Some(format!(
                "{}-{}",
                prefix,
                uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext))
            )),
            _ => None,
        }
    }

    /// Short human label for log lines.
    pub fn kind(&self) -> &'static str {
        match self {
            Transport::Vector { .. } => "vector",
            Transport::Hec { .. } => "hec",
            Transport::Tenzir { .. } => "tenzir",
            Transport::OtlpHttp { .. } => "otlp-http",
        }
    }
}

// ---------------------------------------------------------------------------
// OTLP transport (NAN-1533)
// ---------------------------------------------------------------------------
//
// OtlpHttp ships the per-record OTLP/JSON produced by `event_core::otlp` (one
// span / data point / log record per Value): N records are wrapped in the OTLP
// export envelope and POSTed to the receiver's /v1/<signal> endpoint.

/// Build the OTLP/HTTP export envelope for a batch of per-record JSON values.
/// Wraps records in the single-resource/single-scope envelope the OTLP spec
/// uses: `resourceSpans[].scopeSpans[].spans[]` (and the metrics/logs analogues).
/// One envelope per POST is valid OTLP — the receiver flattens it back out.
/// NAN-1575: reshape a FLAT log-blaster metric record into the standard OTLP
/// `Metric` the proto expects. Our generators emit flat points
/// (`{name, unit, type, timeUnixNano, asInt|asDouble | count/sum/bucketCounts/
/// explicitBounds, attributes}`) tailored to the direct-CH MV, but proto
/// `Metric` nests a single data oneof (`gauge`/`sum`/`histogram`) each with a
/// `dataPoints[]`. Without this, `from_value` yields a `Metric` with name/unit
/// but NO data points (the flat fields aren't proto Metric fields → dropped).
/// `resource` must already be stripped by the caller. Returns the input
/// unchanged for an unrecognized/absent `type` (fail-open).
fn flat_metric_to_otlp(rec: serde_json::Value) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let mut obj = match rec {
        Value::Object(o) => o,
        other => return other,
    };
    let kind = match obj.get("type").and_then(Value::as_str) {
        Some(k) => k.to_string(),
        None => return Value::Object(obj),
    };
    let name = obj.remove("name").unwrap_or(Value::Null);
    let unit = obj.remove("unit").unwrap_or(Value::Null);
    obj.remove("type");
    // `opentelemetry-proto` 0.27 `with-serde` decodes `HistogramDataPoint.bucketCounts`
    // (repeated u64) as JSON NUMBERS, but the generator emits the OTLP/JSON string
    // form. A string there fails the flattened decode and the whole metric is swept
    // to `data: None`. Coerce to numbers. (`count` is already a number; `asInt`/
    // `timeUnixNano` are strings which the proto's u64 deserializers accept.)
    if let Some(Value::Array(arr)) = obj.get_mut("bucketCounts") {
        for v in arr.iter_mut() {
            if let Some(n) = v.as_str().and_then(|s| s.parse::<u64>().ok()) {
                *v = Value::from(n);
            }
        }
    }
    // Whatever remains (timeUnixNano, asInt/asDouble or count/sum/bucketCounts/
    // explicitBounds, attributes) is the single data point.
    let datapoint = Value::Object(obj);
    let data = match kind.as_str() {
        "gauge" => json!({ "gauge": { "dataPoints": [datapoint] } }),
        // CUMULATIVE (2) monotonic counter.
        "sum" => json!({ "sum": {
            "dataPoints": [datapoint],
            "aggregationTemporality": 2,
            "isMonotonic": true,
        }}),
        "histogram" => json!({ "histogram": {
            "dataPoints": [datapoint],
            "aggregationTemporality": 2,
        }}),
        _ => return datapoint,
    };
    let mut out = Map::new();
    out.insert("name".to_string(), name);
    out.insert("unit".to_string(), unit);
    if let Value::Object(d) = data {
        out.extend(d);
    }
    Value::Object(out)
}

fn otlp_envelope(signal: OtlpSignal, records: &[serde_json::Value]) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let (resource_key, scope_key, records_key) = match signal {
        OtlpSignal::Traces => ("resourceSpans", "scopeSpans", "spans"),
        OtlpSignal::Metrics => ("resourceMetrics", "scopeMetrics", "metrics"),
        OtlpSignal::Logs => ("resourceLogs", "scopeLogs", "logRecords"),
    };
    // NAN-1575: in OTLP the `resource` lives at the `resourceX[]` level — the
    // span/metric/log-record proto messages have NO `resource` field. Our
    // generators embed `resource` (with `service.name`) ON each record, which
    // the direct-CH path reads from the `event` blob, but the proto/HTTP export
    // would silently drop it. Lift each record's `resource` up to its own
    // resourceX entry (one per record; receivers flatten) so the wire carries
    // service.name and Vector's `.resources` populates.
    let scope = json!({ "name": "log-blaster", "version": "1" });
    let entries: Vec<Value> = records
        .iter()
        .map(|rec| {
            let mut rec = rec.clone();
            let resource = rec
                .as_object_mut()
                .and_then(|o| o.remove("resource"))
                .unwrap_or_else(|| json!({}));
            // NAN-1575: flat metric points -> nested OTLP Metric (gauge/sum/
            // histogram + dataPoints) so the proto carries data, not just name.
            if signal == OtlpSignal::Metrics {
                rec = flat_metric_to_otlp(rec);
            }
            let mut scope_entry = Map::new();
            scope_entry.insert("scope".to_string(), scope.clone());
            scope_entry.insert(records_key.to_string(), json!([rec]));
            let mut entry = Map::new();
            entry.insert("resource".to_string(), resource);
            entry.insert(scope_key.to_string(), Value::Array(vec![Value::Object(scope_entry)]));
            Value::Object(entry)
        })
        .collect();
    let mut top = Map::new();
    top.insert(resource_key.to_string(), Value::Array(entries));
    Value::Object(top)
}

/// Ship a batch of per-record OTLP/JSON values for one signal over the
/// configured OTLP transport, with per-attempt retry. No-op on an empty batch.
pub async fn send_otlp_with_retry(
    client: &Client,
    transport: &Transport,
    signal: OtlpSignal,
    records: &[serde_json::Value],
    max_retries: u32,
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff = retry_backoff(attempt);
            warn!(
                "[{}] Retry {}/{} after {:?}",
                transport.kind(),
                attempt,
                max_retries,
                backoff
            );
            tokio::time::sleep(backoff).await;
        }
        let res = match transport {
            Transport::OtlpHttp { .. } => {
                send_otlp_http(client, transport, signal, records).await
            }
            other => {
                return Err(anyhow::anyhow!(
                    "send_otlp_with_retry called on non-OTLP transport: {}",
                    other.kind()
                ));
            }
        };
        match res {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap())
}

/// NAN-1575: assemble the OTLP metrics export request from individually-decoded
/// metrics. `serde_json` decodes the doubly-nested `#[serde(flatten)]` oneof
/// (`Metric.data` -> `NumberDataPoint.value`) for a metric at the TOP level, but
/// NOT when the metric is an array element inside the full envelope — the array
/// buffering defeats the inner flatten and `data` comes back `None`. So decode
/// each flat metric record standalone and build the ResourceMetrics tree from
/// proto structs. (Logs/traces only have a single flatten level, so they decode
/// fine straight from the envelope.)
fn build_metrics_request(
    records: &[serde_json::Value],
) -> Result<opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest> {
    use anyhow::Context;
    use opentelemetry_proto::tonic::{
        collector::metrics::v1::ExportMetricsServiceRequest,
        common::v1::InstrumentationScope,
        metrics::v1::{Metric, ResourceMetrics, ScopeMetrics},
        resource::v1::Resource,
    };

    let scope = InstrumentationScope {
        name: "log-blaster".to_string(),
        version: "1".to_string(),
        attributes: vec![],
        dropped_attributes_count: 0,
    };
    let mut resource_metrics = Vec::with_capacity(records.len());
    for rec in records {
        let mut rec = rec.clone();
        let resource_json = rec.as_object_mut().and_then(|o| o.remove("resource"));
        let metric_json = flat_metric_to_otlp(rec);
        // Top-level decode — the flatten oneofs resolve here.
        let metric: Metric = serde_json::from_str(&serde_json::to_string(&metric_json)?)
            .context("decode OTLP metric")?;
        let resource: Option<Resource> = match resource_json {
            Some(r) => Some(
                serde_json::from_str(&serde_json::to_string(&r)?).context("decode OTLP resource")?,
            ),
            None => None,
        };
        resource_metrics.push(ResourceMetrics {
            resource,
            scope_metrics: vec![ScopeMetrics {
                scope: Some(scope.clone()),
                metrics: vec![metric],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        });
    }
    Ok(ExportMetricsServiceRequest { resource_metrics })
}

/// OTLP/HTTP protobuf to Vector's `opentelemetry` receiver.
///
/// NAN-1575: Vector's `opentelemetry` source only accepts
/// `application/x-protobuf` — POSTing `application/json` is rejected with
/// `Rejection(InvalidHeader { name: "content-type" })` and the batch is
/// silently dropped. `with-serde` maps our OTLP/JSON envelope (camelCase fields,
/// hex trace/span ids, string-encoded u64 nanos) onto the proto export request;
/// prost encodes the wire bytes the receiver decodes.
async fn send_otlp_http(
    client: &Client,
    transport: &Transport,
    signal: OtlpSignal,
    records: &[serde_json::Value],
) -> Result<()> {
    use anyhow::Context;
    use opentelemetry_proto::tonic::collector::{
        logs::v1::ExportLogsServiceRequest, trace::v1::ExportTraceServiceRequest,
    };
    use prost::Message;

    let base = transport.url().trim_end_matches('/');
    let url = format!("{base}{}", signal.http_path());
    // Logs/traces: deserialize via the STRING/byte path (`from_slice`), NOT
    // `from_value` — serde_json's `from_value` mis-handles `#[serde(flatten)]`
    // oneofs (drops them to `None`). The streaming deserializer decodes the
    // single-flatten-level logs/traces correctly. Metrics have a doubly-nested
    // flatten that fails inside the envelope array, so they're assembled from
    // individually-decoded metrics in `build_metrics_request`.
    let body: Vec<u8> = match signal {
        OtlpSignal::Logs => {
            let json = serde_json::to_vec(&otlp_envelope(signal, records))
                .context("serialize OTLP logs envelope")?;
            serde_json::from_slice::<ExportLogsServiceRequest>(&json)
                .context("build OTLP logs export protobuf")?
                .encode_to_vec()
        }
        OtlpSignal::Traces => {
            let json = serde_json::to_vec(&otlp_envelope(signal, records))
                .context("serialize OTLP traces envelope")?;
            serde_json::from_slice::<ExportTraceServiceRequest>(&json)
                .context("build OTLP traces export protobuf")?
                .encode_to_vec()
        }
        OtlpSignal::Metrics => build_metrics_request(records)?.encode_to_vec(),
    };
    let mut req = client
        .post(url)
        .header("Content-Type", "application/x-protobuf")
        .body(body);
    // Managed deploys token-gate the OTLP receiver (FRO-518) and `abort`
    // unauthenticated exports — which a logs-style sink silently accepts (HTTP
    // 200) while dropping every record. Attach the Bearer when a token is
    // configured; open-core/local OTLP has no gate and ignores it.
    if let Some(tok) = transport.token() {
        req = req.bearer_auth(tok);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

/// Send a batch of pre-shaped JSON records as NDJSON under a fixed
/// `X-Source-Type` (e.g. `nano_enrich` for enrichment-lane records, NAN-1154).
/// Unlike `send_event`, the records aren't `Event`s — they're arbitrary
/// serializable payloads (e.g. identity seed records). Vector transport only.
pub async fn send_json_records<T: serde::Serialize>(
    client: &Client,
    transport: &Transport,
    source_type: &str,
    records: &[T],
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let body: String = records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let mut req = client
        .post(transport.url())
        .header("Content-Type", "application/x-ndjson")
        .header("X-Source-Type", source_type)
        .body(body);
    if let Some(key) = transport.fresh_vector_idempotency_key() {
        req = req.header("Idempotency-Key", key);
    }
    if let Some(t) = transport.token() {
        req = req.bearer_auth(t);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

/// Send a single event over the configured transport.
pub async fn send_event(client: &Client, transport: &Transport, event: &Event) -> Result<()> {
    match transport {
        Transport::Vector { .. } => send_event_vector(client, transport, event).await,
        Transport::Hec { .. } => send_event_hec(client, transport, event).await,
        Transport::Tenzir { .. } => send_tenzir_batch(client, transport, &[event]).await,
        // The OTLP transport carries OTLP/JSON records, not raw `Event`s — callers
        // use `send_otlp_with_retry`. Reaching here is a wiring bug.
        Transport::OtlpHttp { .. } => Err(anyhow::anyhow!(
            "send_event called on OTLP transport ({}); use send_otlp_with_retry",
            transport.kind()
        )),
    }
}

/// Send a batch with per-group retry. Vector groups by source_type; HEC and
/// Tenzir send a single line-delimited stream (source identity is in-band).
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
        Transport::Tenzir { .. } => {
            send_batch_tenzir_with_retry(client, transport, events, max_retries).await
        }
        Transport::OtlpHttp { .. } => Err(anyhow::anyhow!(
            "send_batch_with_retry called on OTLP transport ({}); use send_otlp_with_retry",
            transport.kind()
        )),
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
    if let Some(key) = transport.fresh_vector_idempotency_key() {
        req = req.header("Idempotency-Key", key);
    }
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
    idempotency_key: Option<&str>,
) -> Result<reqwest::Response> {
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

    if let Some(key) = idempotency_key {
        req = req.header("Idempotency-Key", key);
    }
    if let Some(t) = transport.token() {
        req = req.bearer_auth(t);
    }
    Ok(req.send().await?)
}

async fn send_ndjson_group_with_retry(
    client: &Client,
    transport: &Transport,
    source_type: &str,
    events: &[&Event],
    max_retries: u32,
) -> Result<()> {
    send_vector_group_observed(
        client,
        transport,
        source_type,
        events,
        RetryPolicy::bounded(max_retries),
        |_| {},
    )
    .await
    .map(|_| ())
    .map_err(|failure| failure.error)
}

/// Send one Vector source group, reporting every HTTP status (or network error).
/// Retries retain the same idempotency key. The observer runs before status validation.
pub async fn send_vector_group_observed(
    client: &Client,
    transport: &Transport,
    source_type: &str,
    events: &[&Event],
    policy: RetryPolicy,
    observe: impl Fn(Option<reqwest::StatusCode>) + Send + Sync,
) -> std::result::Result<DeliveryReport, DeliveryFailure> {
    if !matches!(transport, Transport::Vector { .. }) {
        return Err(DeliveryFailure::permanent(anyhow::anyhow!(
            "expected Vector transport"
        )));
    }
    // This is deliberately outside the retry loop: an ambiguous response
    // must retry the exact same durable request, never create a second one.
    let idempotency_key = transport.fresh_vector_idempotency_key();
    deliver_with_policy(
        policy,
        source_type,
        || {
            send_ndjson_group(
                client,
                transport,
                source_type,
                events,
                idempotency_key.as_deref(),
            )
        },
        observe,
    )
    .await
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

    // Vector's end-to-end acknowledgements wait for the durable sink. Waiting
    // for each source partition serially multiplies that latency by the number
    // of source types in a mixed batch and makes a 50 EPS generator behave like
    // a single-digit one. The groups are independent HTTP requests, so await
    // their durable acknowledgements together while keeping retry state scoped
    // to each source type.
    futures::future::try_join_all(grouped.iter().map(|(source_type, group)| {
        send_ndjson_group_with_retry(client, transport, source_type, group, max_retries)
    }))
    .await?;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    /// The raw log payload. We pass the message as a string — hec_normalize
    /// handles the `is_string(.event)` branch and lifts it into `.message`.
    event: &'a str,
}

impl<'a> HecEnvelope<'a> {
    fn from_event(event: &'a Event) -> Self {
        Self {
            time: event_epoch_seconds(event),
            sourcetype: &event.source_type,
            source: None,
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
        Transport::Tenzir { .. } => unreachable!("hec_channel called on Tenzir transport"),
        Transport::OtlpHttp { .. } => {
            unreachable!("hec_channel called on OTLP transport")
        }
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

/// Send a homogeneous HEC source batch with observable retries. Each batch gets
/// a UUID channel. An explicit prefix enables a stable idempotency key across retries.
/// Without a prefix, retries may duplicate events.
/// The raw message uses the same envelope as the legacy HEC sender.
pub async fn send_hec_group_observed(
    client: &Client,
    transport: &Transport,
    events: &[&Event],
    policy: RetryPolicy,
    idempotency_key_prefix: Option<&str>,
    observe: impl Fn(Option<reqwest::StatusCode>) + Send + Sync,
) -> std::result::Result<DeliveryReport, DeliveryFailure> {
    if !matches!(transport, Transport::Hec { .. }) {
        return Err(DeliveryFailure::permanent(anyhow::anyhow!(
            "expected HEC transport"
        )));
    }
    let channel = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string();
    let key = idempotency_key_prefix.map(|prefix| format!("{prefix}-{channel}"));
    let body = events
        .iter()
        .map(|event| {
            let mut envelope = HecEnvelope::from_event(event);
            envelope.source = Some(&event.source_type);
            serde_json::to_string(&envelope).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n");
    deliver_with_policy(
        policy,
        "hec",
        || {
            let mut req = client
                .post(transport.url())
                .header("Content-Type", "application/json")
                .header("X-Splunk-Request-Channel", &channel)
                .body(body.clone());
            if let Some(key) = &key {
                req = req.header("Idempotency-Key", key);
            }
            if let Some(token) = transport.token() {
                req = req.header("Authorization", format!("Splunk {token}"));
            }
            async move { Ok::<_, anyhow::Error>(req.send().await?) }
        },
        observe,
    )
    .await
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
            let backoff = retry_backoff(attempt);
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

// ---------------------------------------------------------------------------
// Tenzir transport (raw-Event NDJSON to an `accept_http` source, no auth)
// ---------------------------------------------------------------------------

/// Serialise events as NDJSON of the raw `Event` wire shape. Tenzir's
/// `read_ndjson` parses one envelope per line; the TQL router reads
/// `source_type` in-band, so unlike the Vector transport no per-source
/// grouping is needed.
fn tenzir_body(events: &[&Event]) -> String {
    events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn send_tenzir_batch(
    client: &Client,
    transport: &Transport,
    events: &[&Event],
) -> Result<()> {
    let body = tenzir_body(events);
    client
        .post(transport.url())
        .header("Content-Type", "application/x-ndjson")
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn send_batch_tenzir_with_retry(
    client: &Client,
    transport: &Transport,
    events: &[Event],
    max_retries: u32,
) -> Result<()> {
    let refs: Vec<&Event> = events.iter().collect();
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff = retry_backoff(attempt);
            warn!(
                "[tenzir] Retry {}/{} after {:?}",
                attempt, max_retries, backoff
            );
            tokio::time::sleep(backoff).await;
        }
        match send_tenzir_batch(client, transport, &refs).await {
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
            idempotency_key_prefix: None,
        };
        let h = Transport::Hec {
            url: "http://x:8088/services/collector/event".into(),
            token: None,
            channel: "00000000-0000-0000-0000-000000000000".into(),
        };
        let t = Transport::Tenzir {
            url: "http://x:9095".into(),
        };
        assert_eq!(v.kind(), "vector");
        assert_eq!(h.kind(), "hec");
        assert_eq!(t.kind(), "tenzir");
    }

    /// NAN-1402: the Tenzir body is NDJSON of the RAW Event shape — the TQL
    /// router reads `.message` (pre-parse payload), `.timestamp`, and
    /// `.source_type` in-band. No envelope rewrap, no JSON-array wrapping.
    #[test]
    fn tenzir_body_is_raw_event_ndjson() {
        let a = fake_event(
            "windows_sysmon",
            r#"{"event_id":1}"#,
            "2026-06-11T11:30:00Z",
        );
        let b = fake_event(
            "apache_access",
            r#"203.0.113.7 - - [11/Jun/2026:11:30:01 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.5.0""#,
            "2026-06-11T11:30:01Z",
        );
        let refs: Vec<&Event> = vec![&a, &b];
        let body = tenzir_body(&refs);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 lines, got: {body}");
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["source_type"], "windows_sysmon");
        assert_eq!(first["message"], r#"{"event_id":1}"#);
        assert_eq!(second["source_type"], "apache_access");
        assert!(
            second["message"].as_str().unwrap().contains("GET / HTTP/1.1"),
            "raw apache line must survive verbatim: {body}"
        );
        assert!(!body.starts_with('['), "body must not be wrapped in []: {body}");
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

    // ----------------------------------------------------------------------
    // NAN-953: retry_backoff must cap at ~128s so a caller passing a large
    // `max_retries` can't overflow into a multi-day sleep. The function is
    // pub(crate) so any future caller in this file inherits the cap.
    // ----------------------------------------------------------------------

    // NAN-2988: forwarder-style retry classification.
    #[test]
    fn retryable_statuses_are_408_429_and_transient_5xx() {
        use reqwest::StatusCode;
        for code in [408u16, 429, 500, 502, 503, 504, 507, 520] {
            assert!(
                is_retryable_status(StatusCode::from_u16(code).unwrap()),
                "{code}"
            );
        }
        for code in [400u16, 401, 403, 404, 405, 409, 413, 415, 501, 505] {
            assert!(
                !is_retryable_status(StatusCode::from_u16(code).unwrap()),
                "{code}"
            );
        }
    }

    #[test]
    fn retry_after_reads_delay_seconds_and_clamps() {
        use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            retry_after(&headers)
        };
        assert_eq!(retry_after(&HeaderMap::new()), None);
        assert_eq!(with("1"), Some(TokioDuration::from_secs(1)));
        assert_eq!(with(" 5 "), Some(TokioDuration::from_secs(5)));
        assert_eq!(with("0"), Some(TokioDuration::ZERO));
        assert_eq!(with("86400"), Some(MAX_RETRY_AFTER));
        assert_eq!(with("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(with("-1"), None);
        assert_eq!(with("1.5"), None);
    }

    #[test]
    fn forwarder_backoff_caps_at_30s() {
        assert_eq!(forwarder_backoff(1), TokioDuration::from_millis(500));
        assert_eq!(forwarder_backoff(4), TokioDuration::from_secs(4));
        assert_eq!(forwarder_backoff(20), MAX_FORWARDER_BACKOFF);
    }

    #[test]
    fn retry_backoff_first_attempt_is_500ms() {
        // attempt=1 → 500 × 2^0 = 500ms (unchanged from pre-NAN-953).
        assert_eq!(retry_backoff(1), TokioDuration::from_millis(500));
    }

    #[test]
    fn retry_backoff_second_attempt_is_1000ms() {
        // attempt=2 → 500 × 2^1 = 1000ms.
        assert_eq!(retry_backoff(2), TokioDuration::from_millis(1000));
    }

    #[test]
    fn retry_backoff_third_attempt_is_2000ms() {
        // attempt=3 → 500 × 2^2 = 2000ms (this is what current callers
        // see — they pass max_retries=3).
        assert_eq!(retry_backoff(3), TokioDuration::from_millis(2000));
    }

    #[test]
    fn retry_backoff_caps_at_128s_at_attempt_9() {
        // attempt=9 → exp clamped at 8 → 500 × 256 = 128_000ms.
        assert_eq!(retry_backoff(9), TokioDuration::from_millis(128_000));
    }

    #[test]
    fn retry_backoff_stays_capped_for_pathological_attempt() {
        // Pre-NAN-953 attempt=53 would have produced 2^52 × 500 ≈ 71 years
        // and attempt=64 would panic on `pow` overflow. Both must clamp.
        assert_eq!(retry_backoff(53), TokioDuration::from_millis(128_000));
        assert_eq!(retry_backoff(64), TokioDuration::from_millis(128_000));
        assert_eq!(retry_backoff(u32::MAX), TokioDuration::from_millis(128_000));
    }

    #[test]
    fn retry_backoff_handles_zero_attempt_gracefully() {
        // 0-attempt isn't expected (callers gate on `attempt > 0`) but
        // saturating_sub(1) yields 0, so 500 × 2^0 = 500ms — same as
        // attempt=1. No panic.
        assert_eq!(retry_backoff(0), TokioDuration::from_millis(500));
    }

    #[test]
    #[should_panic(expected = "hec_channel called on Vector transport")]
    fn hec_channel_panics_on_vector_transport() {
        let v = Transport::Vector {
            url: "http://x".into(),
            token: None,
            idempotency_key_prefix: None,
        };
        let _ = hec_channel(&v);
    }

    /// Realistic post-generator OTLP/JSON log record: hex trace/span ids,
    /// string-encoded `timeUnixNano`, an embedded per-record `resource` with
    /// `service.name` (the shape `gen_log` produces).
    fn sample_log_record() -> serde_json::Value {
        serde_json::json!({
            "timeUnixNano": "1700000000000000000",
            "observedTimeUnixNano": "1700000000000000000",
            "severityNumber": 9,
            "severityText": "INFO",
            "body": { "stringValue": "handled request (/api/x)" },
            "traceId": "5b8efff798038103d269b633813fc60c",
            "spanId": "eee19b7ec3c1b174",
            "attributes": [{ "key": "url.path", "value": { "stringValue": "/api/x" } }],
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": "frontend" } }
            ] }
        })
    }

    /// NAN-1575: the proto LogRecord has no `resource` field — resource lives at
    /// the resourceLogs[] level. `otlp_envelope` must lift the per-record
    /// `resource` up there (and strip it from the record) or service.name is
    /// dropped on the proto/HTTP export.
    #[test]
    fn otlp_envelope_lifts_resource_to_resource_level() {
        let env = otlp_envelope(OtlpSignal::Logs, &[sample_log_record()]);
        let rl = &env["resourceLogs"][0];
        assert_eq!(
            rl["resource"]["attributes"][0]["key"], "service.name",
            "resource must be lifted to the resourceLogs[] entry"
        );
        let lr = &rl["scopeLogs"][0]["logRecords"][0];
        assert!(
            lr.get("resource").is_none(),
            "the per-record `resource` must be stripped after lifting"
        );
        assert_eq!(lr["severityText"], "INFO");
    }

    /// NAN-1575: the load-bearing conversion — our OTLP/JSON envelope must
    /// deserialize into the proto export request via `with-serde` (honoring hex
    /// trace/span ids + string-encoded u64 nanos) and prost-encode to non-empty
    /// bytes. A regression here = `--otlp` silently drops every batch again.
    #[test]
    fn otlp_logs_envelope_round_trips_to_protobuf() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
        use prost::Message;

        let env = otlp_envelope(OtlpSignal::Logs, &[sample_log_record()]);
        let json = serde_json::to_vec(&env).unwrap();
        let req: ExportLogsServiceRequest =
            serde_json::from_slice(&json).expect("OTLP/JSON envelope must parse into the proto");
        let bytes = req.encode_to_vec();
        assert!(!bytes.is_empty(), "encoded protobuf must be non-empty");

        assert_eq!(req.resource_logs.len(), 1);
        let rl = &req.resource_logs[0];
        // service.name survived at the resource level.
        let res = rl.resource.as_ref().expect("resource present");
        assert!(res.attributes.iter().any(|kv| kv.key == "service.name"));
        let lr = &rl.scope_logs[0].log_records[0];
        assert_eq!(lr.severity_number, 9, "INFO severity number");
        assert_eq!(lr.severity_text, "INFO");
        // hex trace id decoded to the 16 raw bytes.
        assert_eq!(lr.trace_id.len(), 16, "hex traceId -> 16 bytes");
        assert_eq!(lr.span_id.len(), 8, "hex spanId -> 8 bytes");
    }

    /// NAN-1575: flat metric records must reshape into proto `Metric`s that
    /// actually carry data points (gauge/sum/histogram), not name-only shells.
    /// Guards the from_value path for the metrics signal (the bug codex caught).
    #[test]
    fn otlp_metrics_envelope_round_trips_with_datapoints() {
        use opentelemetry_proto::tonic::metrics::v1::metric::Data;
        use prost::Message;
        use serde_json::json;

        let gauge = json!({ "name": "inflight", "unit": "1", "type": "gauge",
            "timeUnixNano": "1", "asDouble": 3.0, "attributes": [],
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": "checkout" } }] } });
        let sum = json!({ "name": "requests", "unit": "1", "type": "sum",
            "timeUnixNano": "1", "asInt": "42", "attributes": [], "resource": { "attributes": [] } });
        let hist = json!({ "name": "latency", "unit": "ms", "type": "histogram",
            "timeUnixNano": "1", "count": 3, "sum": 12.0,
            "bucketCounts": ["1", "2"], "explicitBounds": [5.0],
            "attributes": [], "resource": { "attributes": [] } });

        let req = build_metrics_request(&[gauge, sum, hist]).expect("build metrics request");
        let metrics: Vec<_> = req
            .resource_metrics
            .iter()
            .flat_map(|rm| rm.scope_metrics.iter().flat_map(|sm| sm.metrics.iter()))
            .collect();
        assert_eq!(metrics.len(), 3, "one proto Metric per flat record");
        for m in &metrics {
            match m.data.as_ref().expect("metric carries a data oneof") {
                Data::Gauge(g) => assert_eq!(g.data_points.len(), 1, "gauge data point"),
                Data::Sum(s) => {
                    assert_eq!(s.data_points.len(), 1, "sum data point");
                    assert!(s.is_monotonic, "counter is monotonic");
                }
                Data::Histogram(h) => assert_eq!(h.data_points.len(), 1, "histogram data point"),
                other => panic!("unexpected metric data oneof: {other:?}"),
            }
        }
        assert!(!req.encode_to_vec().is_empty());
    }
}
