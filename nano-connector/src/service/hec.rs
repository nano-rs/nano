//! Splunk HEC emit to the tenant ingress with the feed's own credential.
//!
//! Wire contract (`HOSTED-INGRESS-CONTRACT.md`):
//! - `POST <ingress>/services/collector/event`, `Authorization: Splunk <feed
//!   token>`, a body of concatenated HEC envelopes `{"event": "<event JSON>",
//!   "sourcetype": ..., "source": ...}`, one per event. On hosted the
//!   credential binds the source slug; the envelope `sourcetype` is not used
//!   for routing there (dedicated / open core route on it).
//! - `event` is the vendor event as JSON TEXT, never a JSON object
//!   (NAN-3490). Vector's `splunk_hec` source spreads an object `event` over
//!   the log root and leaves `.message` unset, so `hec_normalize` hands the
//!   parser `message = ""`: every OCSF parser reads its record from
//!   `.message`, emits a Base Event with an empty `raw_data`, and the lake
//!   refuses every row (`raw_data_missing`). A string `event` becomes
//!   `.message` verbatim, the shape every parser is written for.
//! - A 2xx is the receipt: on hosted it means the batch is durable in the
//!   raw R2 handoff. [`HecSink::push`] returns `Ok` only after every batch of
//!   the page got one, and the engine checkpoints only after that.
//! - 429 / 5xx / 408 / connect errors: back off (honoring `Retry-After`) and
//!   retry the same bytes; when the retry budget is spent, fail without
//!   a receipt so the cursor does not move. Other 4xx fail at once.
//! - 401 / 403 (NAN-3660): the ingress no longer accepts the feed's
//!   credential (revoked, unknown, or not bound to the feed's source). The
//!   run fails with a [`CREDENTIAL_REVOKED`] / [`CREDENTIAL_REJECTED`]
//!   error, the runner backs off ([`CREDENTIAL_REFUSED_RETRY_SECS`]) and
//!   never re-enrolls on its own: only the explicit rotate operation issues
//!   a new credential, so a tenant's revoke is never silently undone.
//! - `Idempotency-Key` = a hash of the feed id and the batch bytes. A retry
//!   of a batch that was in fact accepted replays its first receipt instead
//!   of storing it twice. A re-run after a crash re-sends identical bytes
//!   only when the page is identical, so downstream still has to tolerate
//!   duplicates (at-least-once); the lake dedupes on the parser's
//!   `metadata.uid`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use super::feed::Secret;
use crate::engine::Sink;

const HEC_EVENT_PATH: &str = "/services/collector/event";

/// NAN-3660: error code of a run whose credential the ingress refused with
/// HTTP 401 (revoked or unknown token).
pub const CREDENTIAL_REVOKED: &str = "credential_revoked";
/// NAN-3660: error code of a run whose credential the ingress refused with
/// HTTP 403 (valid token, not authorized for the feed's source).
pub const CREDENTIAL_REJECTED: &str = "credential_rejected";
/// NAN-3660: how long a feed whose credential was refused waits before it
/// tries again (one batch). It does not hot-loop against the ingress; the
/// rotate operation makes it due at once.
pub const CREDENTIAL_REFUSED_RETRY_SECS: i64 = 3600;

/// NAN-3660: the operator-facing error for an ingress auth refusal, or
/// `None` for any other status. `class` is the ingress's
/// `x-nano-error-class` (never a credential).
pub fn credential_refusal(status: u16, class: &str) -> Option<String> {
    match status {
        401 => Some(format!(
            "{CREDENTIAL_REVOKED}: the ingest endpoint no longer accepts this feed's credential (HTTP 401, {class}); rotate the feed credential"
        )),
        403 => Some(format!(
            "{CREDENTIAL_REJECTED}: the feed's credential is not authorized for its source (HTTP 403, {class}); rotate the feed credential"
        )),
        _ => None,
    }
}

/// NAN-3660: the credential refusal inside a run error (the engine prefixes
/// sink errors), starting at its code.
pub fn credential_refusal_in(error: &str) -> Option<&str> {
    [CREDENTIAL_REVOKED, CREDENTIAL_REJECTED]
        .iter()
        .filter_map(|code| error.find(&format!("{code}: ")))
        .min()
        .map(|at| &error[at..])
}

#[derive(Debug, Clone)]
pub struct HecConfig {
    /// One POST at most this many bytes (the hosted request cap is 32 MiB).
    pub max_batch_bytes: usize,
    /// Local Vector HEC 200 only allocates an ackId; poll it before advancing a cursor.
    pub require_ack: bool,
    pub max_batch_events: usize,
    /// Attempts per batch, the first included.
    pub max_attempts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    /// Total time one batch may spend backing off.
    pub max_retry_total: Duration,
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    /// Allow `http://` ingress, and then only to a loopback / private
    /// address or an in-cluster name (dedicated / open-core Vector, tests).
    /// The runner refuses to set it on hosted-shared, so hosted ingress
    /// is always https.
    pub allow_http: bool,
    /// When set, the ingress host must be this host or end with this suffix
    /// (e.g. `.ingest.nano.rs`). Required on hosted-shared, so a feed row
    /// can never point the runner (and the feed credential) at an internal
    /// or foreign host.
    pub allowed_host_suffix: Option<String>,
}

impl Default for HecConfig {
    fn default() -> Self {
        Self {
            max_batch_bytes: 8 * 1024 * 1024,
            require_ack: false,
            max_batch_events: 5_000,
            max_attempts: 8,
            base_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            max_retry_total: Duration::from_secs(300),
            request_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            allow_http: false,
            allowed_host_suffix: None,
        }
    }
}

/// Per-run emit counters.
#[derive(Debug, Default)]
pub struct EmitStats {
    pub batches: AtomicU64,
    pub bytes: AtomicU64,
    pub events: AtomicU64,
    pub retries: AtomicU64,
    pub rejected_events: AtomicU64,
    pub last_receipt: Mutex<Option<String>>,
}

pub struct HecSink {
    client: reqwest::Client,
    endpoint: url::Url,
    token: Secret,
    feed_id: Uuid,
    source: String,
    cfg: HecConfig,
    pub stats: EmitStats,
}

#[derive(Debug, thiserror::Error)]
pub enum HecError {
    #[error("ingest URL is invalid: {0}")]
    Url(String),
    #[error("ingest client: {0}")]
    Client(String),
}

impl HecSink {
    /// `ingest_url` is the tenant ingress base (the HEC event path is
    /// appended) or the full event endpoint.
    pub fn new(ingest_url: &str, token: Secret, feed_id: Uuid, connector: &str, cfg: HecConfig) -> Result<Self, HecError> {
        let endpoint = hec_endpoint(ingest_url, cfg.allow_http)?;
        check_host(&endpoint, cfg.allowed_host_suffix.as_deref())?;
        let client = reqwest::Client::builder()
            .connect_timeout(cfg.connect_timeout)
            .timeout(cfg.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("nano-connector/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| HecError::Client(e.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            token,
            feed_id,
            source: format!("nano-connector:{connector}"),
            cfg,
            stats: EmitStats::default(),
        })
    }

    pub fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }

    /// Split a page into POST-sized batches of encoded envelopes.
    fn batches(&self, source_type: &str, events: &[Value]) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        let mut body = String::new();
        let mut n = 0usize;
        for e in events {
            let line = hec_envelope(e, source_type, &self.source).to_string();
            if n > 0 && (body.len() + 1 + line.len() > self.cfg.max_batch_bytes || n >= self.cfg.max_batch_events) {
                out.push((std::mem::take(&mut body), n));
                n = 0;
            }
            if n > 0 {
                body.push('\n');
            }
            body.push_str(&line);
            n += 1;
        }
        if n > 0 {
            out.push((body, n));
        }
        out
    }

    fn idempotency_key(&self, body: &str) -> String {
        let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        ctx.update(b"nano-connector-hec-v1\n");
        ctx.update(self.feed_id.as_bytes());
        ctx.update(b"\n");
        ctx.update(body.as_bytes());
        // 8..128 chars of [A-Za-z0-9._:~-] (the ingress contract).
        format!("nc1-{}", &hex::encode(ctx.finish().as_ref())[..60])
    }

    async fn wait_for_ack(&self, id: u64) -> Result<(), String> {
        let mut url = self.endpoint.clone();
        url.set_path("/services/collector/ack");
        let poll = async {
            loop {
                let response = self.client.post(url.clone())
                    .header("Authorization", format!("Splunk {}", self.token.expose()))
                    .header("X-Splunk-Request-Channel", self.feed_id.to_string())
                    .json(&json!({"acks": [id]})).send().await
                    .map_err(|_| "Vector HEC acknowledgement request failed")?;
                if !response.status().is_success() {
                    if let Some(refusal) = credential_refusal(response.status().as_u16(), "ack") {
                        return Err(refusal);
                    }
                    return Err("Vector HEC acknowledgement refused".to_string());
                }
                let body: Value = response.json().await.map_err(|_| "Invalid Vector HEC acknowledgement")?;
                if body.get("acks").and_then(|acks| acks.get(id.to_string())) == Some(&Value::Bool(true)) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
        tokio::time::timeout(self.cfg.max_retry_total, poll).await
            .map_err(|_| "Vector HEC acknowledgement timed out; checkpoint withheld".to_string())?
    }

    async fn post(&self, body: String, events: usize) -> Result<(), String> {
        let key = self.idempotency_key(&body);
        let started = std::time::Instant::now();
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let res = self
                .client
                .post(self.endpoint.clone())
                .header("Authorization", format!("Splunk {}", self.token.expose()))
                .header("Content-Type", "application/json")
                .header("Idempotency-Key", &key)
                .header("X-Splunk-Request-Channel", self.feed_id.to_string())
                .body(body.clone())
                .send()
                .await;
            let (retry_after, why) = match res {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let receipt = resp
                        .headers()
                        .get("x-nano-delivery-receipt")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .map(Duration::from_secs);
                    let class = resp.headers().get("x-nano-error-class").and_then(|v| v.to_str().ok()).map(str::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                        if let Some(code) = parsed.get("code").and_then(Value::as_i64) {
                            if code != 0 {
                                return Err(format!("ingest answered HTTP {status} with HEC code {code}"));
                            }
                        }
                        let rejected = parsed.get("rejected-event-count").and_then(Value::as_u64).unwrap_or(0);
                        if rejected > 0 {
                            tracing::warn!(feed_id = %self.feed_id, rejected, "ingress refused events individually (event_too_large)");
                        }
                        if self.cfg.require_ack {
                            let ack = parsed.get("ackId").and_then(Value::as_u64)
                                .ok_or("Vector HEC response has no ackId; checkpoint withheld")?;
                            self.wait_for_ack(ack).await?;
                        }
                        let receipt = receipt.or_else(|| parsed.get("ackId").map(|a| format!("ack:{a}")));
                        self.stats.batches.fetch_add(1, Ordering::SeqCst);
                        self.stats.bytes.fetch_add(body.len() as u64, Ordering::SeqCst);
                        self.stats.events.fetch_add(events as u64 - rejected.min(events as u64), Ordering::SeqCst);
                        self.stats.rejected_events.fetch_add(rejected, Ordering::SeqCst);
                        if let Some(r) = receipt {
                            *self.stats.last_receipt.lock().expect("receipt") = Some(r);
                        }
                        return Ok(());
                    }
                    let class = class.unwrap_or_else(|| "-".into());
                    if let Some(refusal) = credential_refusal(status, &class) {
                        return Err(refusal);
                    }
                    if !(status == 429 || status == 408 || status >= 500) {
                        // Error bodies come from fixed tables (never echo
                        // credentials), but keep only the class.
                        return Err(format!("ingest refused the batch: HTTP {status} ({class})"));
                    }
                    (retry_after, format!("HTTP {status} ({class})"))
                }
                Err(e) => (None, format!("transport: {}", without_url(&e))),
            };
            if attempt >= self.cfg.max_attempts {
                return Err(format!("ingest unavailable after {attempt} attempts; last: {why}"));
            }
            let exp = self.cfg.base_backoff.saturating_mul(1u32 << (attempt - 1).min(16)).min(self.cfg.max_backoff);
            let jitter = 0.8 + rand::random::<f64>() * 0.4;
            let wait = retry_after.unwrap_or(exp.mul_f64(jitter)).min(self.cfg.max_backoff);
            if started.elapsed() + wait > self.cfg.max_retry_total {
                return Err(format!("ingest retry budget ({:?}) spent after {attempt} attempts; last: {why}", self.cfg.max_retry_total));
            }
            self.stats.retries.fetch_add(1, Ordering::SeqCst);
            tracing::info!(feed_id = %self.feed_id, attempt, wait_ms = wait.as_millis() as u64, %why, "ingress back-pressure; retrying the same batch");
            tokio::time::sleep(wait).await;
        }
    }
}

#[async_trait::async_trait]
impl Sink for HecSink {
    async fn push(&self, source_type: &str, events: &[Value]) -> Result<(), String> {
        for (body, n) in self.batches(source_type, events) {
            self.post(body, n).await?;
        }
        Ok(())
    }
}

/// One HEC envelope: the event as JSON text in `event` (see the module docs).
pub fn hec_envelope(event: &Value, source_type: &str, source: &str) -> Value {
    json!({ "event": event.to_string(), "sourcetype": source_type, "source": source })
}

fn without_url(e: &reqwest::Error) -> String {
    // reqwest errors print the URL; ours carries no secret, but keep the
    // message short and stable.
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_request() {
        "request"
    } else {
        "other"
    };
    kind.to_string()
}

/// `http://` targets: loopback / RFC 1918 / ULA / link-local addresses,
/// `localhost`, single-label names and cluster DNS (`.svc`,
/// `.svc.cluster.local`, `.internal`). Public names must use https.
fn local_http_host(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost"
                || !d.contains('.')
                || d.ends_with(".svc")
                || d.ends_with(".svc.cluster.local")
                || d.ends_with(".internal")
        }
        None => false,
    }
}

/// Refuse an ingress host outside the configured suffix.
pub fn check_host(u: &url::Url, suffix: Option<&str>) -> Result<(), HecError> {
    let Some(suffix) = suffix.map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase()).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    if host == suffix || host.ends_with(&format!(".{suffix}")) {
        Ok(())
    } else {
        Err(HecError::Url(format!("ingress host `{host}` is outside `{suffix}`")))
    }
}

/// The HEC event endpoint for an ingress base URL.
pub fn hec_endpoint(ingest_url: &str, allow_http: bool) -> Result<url::Url, HecError> {
    let mut u = url::Url::parse(ingest_url).map_err(|e| HecError::Url(e.to_string()))?;
    match u.scheme() {
        "https" => {}
        "http" if allow_http => {
            if !local_http_host(&u) {
                return Err(HecError::Url(format!(
                    "http is only allowed to a loopback, private or in-cluster host, not `{}`",
                    u.host_str().unwrap_or_default()
                )));
            }
        }
        s => return Err(HecError::Url(format!("scheme `{s}` is not allowed"))),
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(HecError::Url("credentials in the URL are not allowed".into()));
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err(HecError::Url("query or fragment is not allowed".into()));
    }
    if u.path() != HEC_EVENT_PATH {
        if u.path() != "/" && !u.path().is_empty() {
            return Err(HecError::Url(format!("path must be empty or {HEC_EVENT_PATH}")));
        }
        u.set_path(HEC_EVENT_PATH);
    }
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_refusals_name_the_credential() {
        let revoked = credential_refusal(401, "-").unwrap();
        assert!(revoked.starts_with("credential_revoked: "), "{revoked}");
        assert!(revoked.ends_with("rotate the feed credential"));
        assert!(credential_refusal(403, "-").unwrap().starts_with("credential_rejected: "));
        for status in [400, 404, 413, 429, 500, 503] {
            assert_eq!(credential_refusal(status, "-"), None, "{status}");
        }
        let wrapped = format!("sink: {revoked}");
        assert_eq!(credential_refusal_in(&wrapped), Some(revoked.as_str()));
        assert_eq!(credential_refusal_in("sink: ingest refused the batch: HTTP 400 (-)"), None);
    }

    #[test]
    fn endpoint_rules() {
        assert_eq!(hec_endpoint("https://t.ingest.example", false).unwrap().as_str(), "https://t.ingest.example/services/collector/event");
        assert!(hec_endpoint("https://t.ingest.example/services/collector/event", false).is_ok());
        assert!(hec_endpoint("http://vector:8088", false).is_err());
        assert!(hec_endpoint("http://vector:8088", true).is_ok());
        assert!(hec_endpoint("http://127.0.0.1:8088", true).is_ok());
        assert!(hec_endpoint("http://10.2.3.4:8088", true).is_ok());
        assert!(hec_endpoint("http://vector.nano.svc.cluster.local:8088", true).is_ok());
        assert!(hec_endpoint("http://[::1]:8088", true).is_ok());
        // Public hosts never get http, even with allow_http.
        assert!(hec_endpoint("http://acme.ingest.nano.rs", true).is_err());
        assert!(hec_endpoint("http://93.184.215.14", true).is_err());
        assert!(hec_endpoint("https://u:p@t.example", false).is_err());
        assert!(hec_endpoint("https://t.example/other", false).is_err());
        assert!(hec_endpoint("https://t.example/?a=1", false).is_err());
        let u = hec_endpoint("https://acme.ingest.nano.rs", false).unwrap();
        assert!(check_host(&u, Some(".ingest.nano.rs")).is_ok());
        assert!(check_host(&u, None).is_ok());
        let evil = hec_endpoint("https://ingest.nano.rs.evil.example", false).unwrap();
        assert!(check_host(&evil, Some(".ingest.nano.rs")).is_err());
        let internal = hec_endpoint("https://10.0.0.5", false).unwrap();
        assert!(check_host(&internal, Some("ingest.nano.rs")).is_err());
    }

    #[test]
    fn batches_split_on_bytes_and_count_and_key_is_valid() {
        let cfg = HecConfig { max_batch_events: 3, max_batch_bytes: 10_000, ..Default::default() };
        let s = HecSink::new("https://t.example", Secret::new("tok"), Uuid::nil(), "okta", cfg).unwrap();
        let ev: Vec<Value> = (0..7).map(|i| json!({ "i": i })).collect();
        let b = s.batches("okta", &ev);
        assert_eq!(b.iter().map(|(_, n)| *n).collect::<Vec<_>>(), vec![3, 3, 1]);
        let first: Value = serde_json::from_str(b[0].0.lines().next().unwrap()).unwrap();
        // NAN-3490: the event travels as JSON text, so Vector's splunk_hec
        // source puts it in `.message` for the parser.
        let event = first["event"].as_str().expect("event is JSON text");
        assert_eq!(serde_json::from_str::<Value>(event).unwrap(), json!({ "i": 0 }));
        assert_eq!(first["sourcetype"], "okta");
        let k = s.idempotency_key(&b[0].0);
        assert!(k.len() >= 8 && k.len() <= 128);
        assert!(k.chars().all(|c| c.is_ascii_alphanumeric() || "._:~-".contains(c)));
        assert_eq!(k, s.idempotency_key(&b[0].0));
        assert_ne!(k, s.idempotency_key(&b[1].0));
    }
}
