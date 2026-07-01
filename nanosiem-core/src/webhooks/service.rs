// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook Service
//!
//! Handles webhook delivery for alert events.
//! Fire-and-forget via tokio::spawn — never blocks the detection pipeline.

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::inputlookup::{IpCidr, SsrfConfig, SsrfValidator};

use super::models::*;
use super::repository::WebhookRepository;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of matched events included in the webhook payload
const MAX_MATCHED_EVENTS: usize = 10;

/// HTTP request timeout for webhook delivery
const DELIVERY_TIMEOUT_SECS: u64 = 10;

/// Maximum concurrent webhook deliveries (actual in-flight HTTP requests).
const MAX_CONCURRENT_DELIVERIES: usize = 20;

/// Upper bound on total outstanding delivery tasks (in-flight + queued-for-a-
/// permit). Each alert/case fans out one spawned task per subscribed webhook;
/// without a cap an alert storm (or a slow/black-hole endpoint holding the 20
/// concurrency permits) would accumulate unbounded tasks + cloned payloads and
/// can OOM. Beyond this cap deliveries are shed with a warning rather than
/// queued forever — webhooks are best-effort notifications.
const MAX_INFLIGHT_DELIVERIES: usize = 512;

/// Total delivery attempts (1 initial + retries) before giving up. Retryable
/// failures are transport errors, HTTP 5xx, and 429.
const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// Base backoff between delivery attempts; doubles each retry (0.5s, 1s).
const RETRY_BASE_DELAY_MS: u64 = 500;

/// Parse the `NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST` value — a comma-separated list
/// of CIDRs / bare IPs (e.g. `10.0.0.0/8, 192.168.5.0/24, 10.1.2.3`). Invalid
/// entries are logged and skipped rather than failing the whole subsystem, so
/// one typo can't take webhooks down. Pure (no env read) for testability.
pub(crate) fn parse_egress_allowlist(raw: &str) -> Vec<IpCidr> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| match IpCidr::parse(entry) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("Ignoring invalid NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST entry '{entry}': {e}");
                None
            }
        })
        .collect()
}

/// Hard cap on how many bytes of a receiver's response we read before dropping
/// the rest. A malicious/compromised endpoint must not be able to exhaust
/// memory by returning a huge body (the delivery-log truncation happens only
/// *after* the buffer, so the read itself must be bounded). 8 KiB comfortably
/// covers the 1 KiB we persist.
const RESPONSE_READ_CAP: usize = 8 * 1024;

#[derive(Clone)]
pub struct WebhookService {
    repo: WebhookRepository,
    /// Gates actual in-flight HTTP requests.
    semaphore: Arc<Semaphore>,
    /// Bounds total outstanding delivery tasks (see `MAX_INFLIGHT_DELIVERIES`).
    /// A permit is taken before spawning; deliveries are shed when exhausted.
    inflight: Arc<Semaphore>,
}

impl WebhookService {
    pub fn new(repo: WebhookRepository) -> Self {
        // NOTE: the HTTP client is built per-delivery, not stored, because the
        // SSRF guard pins the connection to the target's validated IP(s) via
        // `resolve_to_addrs` (see `ssrf_checked_client`) — a shared client can't
        // be pinned to a per-URL address set. Redirects are disabled on every
        // client so there is no second, unvalidated hop.
        Self {
            repo,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_DELIVERIES)),
        }
    }

    /// The SSRF validator used for BOTH the create-time URL check and the
    /// delivery-time re-resolve/pin. Single source of truth so the two can never
    /// diverge (a URL that passes at config time must be evaluated by identical
    /// rules at fire time). Delegates to the shared DNS-aware `SsrfValidator`
    /// (NAN-1369): loopback / private / CGNAT / link-local / cloud-metadata /
    /// scheme are all blocked. `allow_http` is on (webhook receivers are often
    /// plain-http); the instance's own hostname is blocked to keep the
    /// alert → webhook → alert self-reference loop guard.
    fn validator() -> SsrfValidator {
        let mut blocked_domains = vec!["localhost".to_string()];
        if let Ok(self_hostname) = std::env::var("NANOSIEM_HOSTNAME") {
            if !self_hostname.is_empty() {
                blocked_domains.push(self_hostname);
            }
        }

        // Internal-target egress controls (secure default: all private blocked).
        // Two knobs, most-scoped first:
        //   NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST — CIDRs/IPs that a webhook MAY
        //     reach even though they're private (e.g. "10.0.0.0/8,192.168.5.7").
        //     Preferred: it scopes egress to exactly the intended receivers
        //     (NAN-1633).
        //   NANOSIEM_WEBHOOK_ALLOW_PRIVATE=1 — legacy blanket opt-in that allows
        //     ALL private/loopback ranges. Kept for back-compat; the allowlist
        //     is the narrower, recommended replacement.
        // Either way, cloud-metadata, loopback, link-local, and the
        // `localhost` + self-hostname loop guard stay blocked (the allowlist
        // only rescues RFC1918 / CGNAT / IPv6-ULA; SsrfConfig upholds the rest).
        let allow_private = std::env::var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);
        let allowed_cidrs = std::env::var("NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST")
            .ok()
            .map(|raw| parse_egress_allowlist(&raw))
            .unwrap_or_default();

        SsrfValidator::new(SsrfConfig {
            allow_http: true,
            blocked_domains,
            allow_private_networks: allow_private,
            allowed_cidrs,
            ..Default::default()
        })
    }

    /// Validate that a webhook URL is safe to call (not targeting internal
    /// services). Rejects private IPs, loopback, link-local (cloud metadata),
    /// cloud-metadata hostnames, self-referencing URLs, and non-HTTP schemes.
    /// Performs DNS resolution to catch rebinding at config time. This is the
    /// fast create/update UX check; `ssrf_checked_client` re-validates and pins
    /// again at delivery so a rebind after config-time can't get through.
    pub async fn validate_url(url: &str) -> Result<(), String> {
        Self::validator()
            .validate_with_dns(url)
            .await
            .map(|_| ())
            .map_err(|e| format!("Webhook URL rejected: {}", e))
    }

    /// Build a reqwest client whose connection is pinned to the validated,
    /// resolved IP(s) of `url` — the delivery-time SSRF guard (NAN-1546).
    ///
    /// Mirrors the synthetic runner: `validate_and_resolve` rejects bad schemes
    /// and blocked IP literals, then resolves the host and re-validates every
    /// resolved IP, returning the addrs to pin. We pin reqwest to exactly those
    /// via `resolve_to_addrs` so DNS can't be rebound to an internal IP between
    /// config-time validation and connect. Redirects are disabled so there is no
    /// second, unvalidated hop. Returns the rejection reason on block (recorded
    /// as the delivery failure).
    async fn ssrf_checked_client(url: &str) -> Result<reqwest::Client, String> {
        let (parsed, addrs) = Self::validator()
            .validate_and_resolve(url)
            .await
            .map_err(|e| format!("blocked by SSRF guard: {e}"))?;

        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(DELIVERY_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none());

        // IP-literal hosts return an empty Vec (reqwest dials the already-
        // validated literal). DNS-name hosts: pin reqwest to the pre-validated
        // addrs so DNS can't be rebound after validation.
        if !addrs.is_empty() {
            let host = parsed
                .host_str()
                .ok_or_else(|| "URL missing host".to_string())?;
            builder = builder.resolve_to_addrs(host, &addrs);
        }

        builder
            .build()
            .map_err(|e| format!("HTTP client build failed: {e}"))
    }

    /// Read at most `RESPONSE_READ_CAP` bytes of a receiver's response, then
    /// drop the rest. Bounds memory against a hostile endpoint returning a huge
    /// body — `reqwest::Response::text()`/`bytes()` would buffer it all first.
    async fn read_body_capped(mut response: reqwest::Response) -> String {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            if buf.len() >= RESPONSE_READ_CAP {
                break;
            }
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = RESPONSE_READ_CAP - buf.len();
                    let take = remaining.min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                    if take < chunk.len() {
                        break; // hit the cap mid-chunk; discard the remainder
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Build a deep link back to a resource in the nano UI, or `None` when
    /// `NANOSIEM_HOSTNAME` is unset (same source the OIDC issuer uses). `path`
    /// is the SPA route without a leading slash, e.g. `alerts/alert_…`.
    fn ui_link(path: &str) -> Option<String> {
        std::env::var("NANOSIEM_HOSTNAME").ok().and_then(|h| {
            if h.is_empty() {
                None
            } else {
                Some(format!("https://{h}/{path}"))
            }
        })
    }

    /// Fire webhook notifications for a newly created alert of any `kind`
    /// (`detection` | `metric_monitor` | `slo` | `synthetic`).
    ///
    /// Loads enabled webhooks, filters by (a) subscription category — SIEM vs
    /// observability, derived from `kind` — and (b) severity, then spawns async
    /// delivery tasks. Never blocks the caller. `rule_id` is `None` for
    /// observability alerts (which have a monitor/check as `source_id`, not a
    /// rule); `rule_name` carries the human name of the producer either way.
    #[allow(clippy::too_many_arguments)]
    pub async fn fire_alert(
        &self,
        alert_id: Uuid,
        kind: &str,
        rule_id: Option<Uuid>,
        rule_name: &str,
        severity: &str,
        entity: Option<String>,
        matched_events: &serde_json::Value,
        created_at: chrono::DateTime<Utc>,
    ) {
        let webhooks = match self.repo.list_enabled().await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to load webhooks: {}", e);
                return;
            }
        };

        if webhooks.is_empty() {
            return;
        }

        // Which subscription checkbox gates this alert (siem_alert | obs_alert).
        let category = alert_kind_to_event_type(kind);

        // Build the payload once for all webhooks
        let events_array = match matched_events.as_array() {
            Some(arr) => arr.iter().take(MAX_MATCHED_EVENTS).cloned().collect(),
            None => vec![],
        };
        let matched_event_count = matched_events.as_array().map_or(0, |a| a.len()) as i64;

        let payload = WebhookPayload {
            event_type: "alert.created".to_string(),
            kind: Some(kind.to_string()),
            alert_id: Some(alert_id),
            rule_id,
            rule_name: Some(rule_name.to_string()),
            severity: Some(severity.to_string()),
            entity,
            link_url: Self::ui_link(&format!(
                "alerts/{}",
                crate::typeid::encode(crate::typeid::alert::PREFIX, &alert_id)
            )),
            matched_event_count: Some(matched_event_count),
            matched_events: Some(events_array),
            created_at,
        };

        let severity_lower = severity.to_lowercase();

        for webhook in webhooks {
            // Subscription filter: skip webhooks not subscribed to this stream.
            if !webhook.subscribes_to(category) {
                debug!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    category = category,
                    "Skipping webhook: not subscribed to event stream"
                );
                continue;
            }

            // Check severity filter
            if let Some(ref filter) = webhook.severity_filter {
                if !filter.is_empty() {
                    let matches = filter.iter().any(|s| s.to_lowercase() == severity_lower);
                    if !matches {
                        debug!(
                            webhook_id = %webhook.id,
                            webhook_name = %webhook.name,
                            severity = %severity,
                            "Skipping webhook: severity not in filter"
                        );
                        continue;
                    }
                }
            }

            // Bound total outstanding tasks: take an in-flight slot before
            // spawning, shed (don't queue) when saturated so a storm / slow
            // endpoint can't OOM us.
            let inflight_permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        "Webhook delivery shed: in-flight cap reached (alert storm or slow endpoint)"
                    );
                    continue;
                }
            };

            let svc = self.clone();
            let payload = payload.clone();
            let alert_id_copy = alert_id;

            // Fire-and-forget with concurrency limit
            tokio::spawn(async move {
                let _inflight = inflight_permit; // held for the task's lifetime
                let _permit = svc.semaphore.acquire().await;
                svc.deliver(&webhook, &payload, Some(alert_id_copy), "alert.created")
                    .await;
            });
        }
    }

    /// Fire webhook notifications for a case lifecycle event (created / status
    /// changed). Gated by the `case` subscription category. Called from the
    /// enterprise case service (cases are enterprise-only); no-op for any
    /// webhook that hasn't opted into the `case` stream.
    ///
    /// `event_type` is the fine-grained event name (`case.created` /
    /// `case.status_changed`); `case_id` is the raw UUID (encoded to a `case_…`
    /// typeid for the link-back). `title` / `status` / `assignee` populate the
    /// payload for the consumer.
    #[allow(clippy::too_many_arguments)]
    pub async fn fire_case_event(
        &self,
        case_id: Uuid,
        event_type: &str,
        title: &str,
        status: &str,
        assignee: Option<String>,
        created_at: chrono::DateTime<Utc>,
    ) {
        let webhooks = match self.repo.list_enabled().await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to load webhooks: {}", e);
                return;
            }
        };
        if webhooks.is_empty() {
            return;
        }

        // Reuse WebhookPayload: case events carry title in `rule_name`, status in
        // `severity`, assignee in `entity` — the generic string slots — plus the
        // case typeid link. `kind = "case"` disambiguates for the consumer.
        let payload = WebhookPayload {
            event_type: event_type.to_string(),
            kind: Some("case".to_string()),
            alert_id: None,
            rule_id: None,
            rule_name: Some(title.to_string()),
            severity: Some(status.to_string()),
            entity: assignee,
            link_url: Self::ui_link(&format!(
                "cases/{}",
                crate::typeid::encode(crate::typeid::case::PREFIX, &case_id)
            )),
            matched_event_count: None,
            matched_events: None,
            created_at,
        };

        for webhook in webhooks {
            if !webhook.subscribes_to(EVENT_TYPE_CASE) {
                continue;
            }
            let inflight_permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        "Webhook case delivery shed: in-flight cap reached"
                    );
                    continue;
                }
            };
            let svc = self.clone();
            let payload = payload.clone();
            let event_type = event_type.to_string();
            tokio::spawn(async move {
                let _inflight = inflight_permit;
                let _permit = svc.semaphore.acquire().await;
                svc.deliver(&webhook, &payload, None, &event_type).await;
            });
        }
    }

    /// Build a request with custom headers and HMAC signature. The `client` is
    /// the per-delivery SSRF-pinned client (see `ssrf_checked_client`).
    ///
    /// **Fails closed on a crypto error.** If a webhook has configured custom
    /// headers or an HMAC secret that cannot be decrypted (e.g. the encryption
    /// key was rotated), this returns `Err` and the caller must NOT send — a
    /// silent downgrade to an unsigned request, or one missing its configured
    /// auth headers, would be a security regression the receiver can't detect.
    fn build_request(
        &self,
        client: &reqwest::Client,
        webhook: &super::models::Webhook,
        payload_bytes: &[u8],
    ) -> Result<reqwest::RequestBuilder, String> {
        let mut request = client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "NanoSIEM-Webhook/1.0");

        // Add custom headers. reqwest's typed `HeaderName`/`HeaderValue` reject
        // CRLF / control chars, so a header key/value can't be used to inject a
        // second header or smuggle a request; an invalid pair surfaces as a
        // build error at send. A decrypt failure fails closed (below).
        if let Some(ref encrypted) = webhook.headers_encrypted {
            if !encrypted.is_empty() {
                let headers = self
                    .repo
                    .decrypt_json::<HashMap<String, String>>(encrypted)
                    .map_err(|e| {
                        format!("configured custom headers could not be decrypted: {e}")
                    })?;
                for (key, value) in &headers {
                    request = request.header(key, value);
                }
            }
        }

        // Add HMAC signature. If a secret is configured it MUST sign; a decrypt
        // failure fails closed rather than delivering unsigned.
        if let Some(ref encrypted_secret) = webhook.secret_encrypted {
            if !encrypted_secret.is_empty() {
                let secret = self
                    .repo
                    .decrypt_string(encrypted_secret)
                    .map_err(|e| format!("configured HMAC secret could not be decrypted: {e}"))?;
                // Sign `<unix_ts>.<body>` (Stripe-style) and send the timestamp
                // in `X-NanoSIEM-Timestamp` so a receiver can reject stale
                // replays within a freshness window — HMAC-over-body alone is
                // replayable forever. A fresh timestamp per attempt is fine
                // (each retry is an independently-fresh request).
                let timestamp = Utc::now().timestamp();
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .map_err(|e| format!("HMAC init failed: {e}"))?;
                mac.update(timestamp.to_string().as_bytes());
                mac.update(b".");
                mac.update(payload_bytes);
                let signature = hex::encode(mac.finalize().into_bytes());
                request = request
                    .header("X-NanoSIEM-Timestamp", timestamp.to_string())
                    .header("X-NanoSIEM-Signature", format!("sha256={}", signature));
            }
        }

        Ok(request)
    }

    /// Deliver a webhook payload with delivery-time SSRF pinning and bounded
    /// retries, then log a single delivery-log row for the final outcome.
    ///
    /// Retry policy: up to `MAX_DELIVERY_ATTEMPTS` attempts, exponential backoff
    /// (`RETRY_BASE_DELAY_MS` doubling each retry). Transport errors, HTTP 5xx,
    /// and 429 are retried; 2xx succeeds; other 4xx are terminal (a bad request
    /// won't fix itself). Each attempt is traced; only the final result is
    /// persisted to the delivery log (one row per logical delivery). Runs inside
    /// the fire-and-forget spawn, so the backoff sleeps never block the caller.
    async fn deliver(
        &self,
        webhook: &super::models::Webhook,
        payload: &WebhookPayload,
        alert_id: Option<Uuid>,
        event_type: &str,
    ) {
        let start = Instant::now();

        let payload_bytes = match serde_json::to_vec(payload) {
            Ok(b) => b,
            Err(e) => {
                error!(webhook_id = %webhook.id, "Failed to serialize webhook payload: {}", e);
                return;
            }
        };

        // Delivery-time SSRF guard: re-resolve + pin to validated IP(s). A
        // blocked target is recorded as a failed delivery and never sent — this
        // closes the DNS-rebind window between config-time validation and fire.
        let client = match Self::ssrf_checked_client(&webhook.url).await {
            Ok(c) => c,
            Err(reason) => {
                warn!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    reason = %reason,
                    "Webhook delivery blocked by SSRF guard"
                );
                let duration_ms = start.elapsed().as_millis() as i32;
                self.record(webhook, alert_id, event_type, None, None, false, Some(&reason), duration_ms)
                    .await;
                return;
            }
        };

        for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            // Fail closed on a crypto error (deterministic — don't burn retries).
            let request = match self.build_request(&client, webhook, &payload_bytes) {
                Ok(r) => r,
                Err(reason) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        reason = %reason,
                        "Webhook not sent (fail-closed): request could not be built with configured auth"
                    );
                    let duration_ms = start.elapsed().as_millis() as i32;
                    self.record(webhook, alert_id, event_type, None, None, false, Some(&reason), duration_ms)
                        .await;
                    return;
                }
            };
            match request.body(payload_bytes.clone()).send().await {
                Ok(response) => {
                    let status = response.status().as_u16() as i32;
                    let success = response.status().is_success();
                    let retryable = response.status().is_server_error() || status == 429;
                    let body = Self::read_body_capped(response).await;

                    if success {
                        info!(
                            webhook_id = %webhook.id,
                            webhook_name = %webhook.name,
                            status_code = status,
                            attempt,
                            "Webhook delivered successfully"
                        );
                        let duration_ms = start.elapsed().as_millis() as i32;
                        self.record(webhook, alert_id, event_type, Some(status), Some(&body), true, None, duration_ms)
                            .await;
                        return;
                    }

                    if retryable && attempt < MAX_DELIVERY_ATTEMPTS {
                        let delay = RETRY_BASE_DELAY_MS << (attempt - 1);
                        warn!(
                            webhook_id = %webhook.id,
                            status_code = status,
                            attempt,
                            next_delay_ms = delay,
                            "Webhook returned retryable status; retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        continue;
                    }

                    // Terminal 4xx, or a retryable status on the final attempt.
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        status_code = status,
                        attempt,
                        "Webhook delivery failed (non-success status)"
                    );
                    let duration_ms = start.elapsed().as_millis() as i32;
                    let err = format!("HTTP {status} after {attempt} attempt(s)");
                    self.record(webhook, alert_id, event_type, Some(status), Some(&body), false, Some(&err), duration_ms)
                        .await;
                    return;
                }
                Err(e) => {
                    let error_msg = e.to_string();

                    if attempt < MAX_DELIVERY_ATTEMPTS {
                        let delay = RETRY_BASE_DELAY_MS << (attempt - 1);
                        warn!(
                            webhook_id = %webhook.id,
                            error = %error_msg,
                            attempt,
                            next_delay_ms = delay,
                            "Webhook transport error; retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        continue;
                    }

                    error!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        error = %error_msg,
                        attempt,
                        "Webhook delivery failed (transport error, retries exhausted)"
                    );
                    let duration_ms = start.elapsed().as_millis() as i32;
                    let err = format!("{error_msg} after {attempt} attempt(s)");
                    self.record(webhook, alert_id, event_type, None, None, false, Some(&err), duration_ms)
                        .await;
                    return;
                }
            }
        }
    }

    /// Persist a single delivery-log row, logging (but not propagating) a
    /// logging failure. Centralizes the `log_delivery` error handling shared by
    /// `deliver` and `send_test`.
    #[allow(clippy::too_many_arguments)]
    async fn record(
        &self,
        webhook: &super::models::Webhook,
        alert_id: Option<Uuid>,
        event_type: &str,
        status_code: Option<i32>,
        response_body: Option<&str>,
        success: bool,
        error_message: Option<&str>,
        duration_ms: i32,
    ) {
        if let Err(e) = self
            .repo
            .log_delivery(
                webhook.id,
                alert_id,
                event_type,
                status_code,
                response_body,
                success,
                error_message,
                Some(duration_ms),
            )
            .await
        {
            error!(webhook_id = %webhook.id, "Failed to log webhook delivery: {}", e);
        }
    }

    /// Send a synchronous test delivery to a webhook endpoint.
    pub async fn send_test(&self, webhook_id: Uuid) -> Result<WebhookTestResult, String> {
        let webhook = self
            .repo
            .get(webhook_id)
            .await
            .map_err(|e| format!("Webhook not found: {}", e))?;

        let payload = WebhookPayload {
            event_type: "webhook.test".to_string(),
            kind: None,
            alert_id: None,
            rule_id: None,
            rule_name: Some("Test Webhook Delivery".to_string()),
            severity: Some("informational".to_string()),
            entity: None,
            link_url: None,
            matched_event_count: Some(0),
            matched_events: Some(vec![]),
            created_at: Utc::now(),
        };

        let start = Instant::now();

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| format!("Serialization error: {}", e))?;

        // Test delivery is a single, synchronous attempt (immediate UX feedback,
        // no retries), but still SSRF-pinned like real delivery.
        let client = match Self::ssrf_checked_client(&webhook.url).await {
            Ok(c) => c,
            Err(reason) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&reason),
                        Some(duration_ms as i32),
                    )
                    .await;
                return Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms,
                });
            }
        };

        let request = match self.build_request(&client, &webhook, &payload_bytes) {
            Ok(r) => r,
            Err(reason) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&reason),
                        Some(duration_ms as i32),
                    )
                    .await;
                return Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms,
                });
            }
        };
        let result = request.body(payload_bytes).send().await;
        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let status = response.status().as_u16();
                let success = response.status().is_success();
                let body = Self::read_body_capped(response).await;

                // Log test delivery
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        Some(status as i32),
                        Some(&body),
                        success,
                        if success {
                            None
                        } else {
                            Some("Non-success status code")
                        },
                        Some(duration_ms as i32),
                    )
                    .await;

                Ok(WebhookTestResult {
                    success,
                    status_code: Some(status),
                    error: if success {
                        None
                    } else {
                        Some(format!("HTTP {}", status))
                    },
                    duration_ms,
                })
            }
            Err(e) => {
                let error_msg = e.to_string();

                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&error_msg),
                        Some(duration_ms as i32),
                    )
                    .await;

                Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(error_msg),
                    duration_ms,
                })
            }
        }
    }

    /// Get the repository (for use by API handlers)
    pub fn repo(&self) -> &WebhookRepository {
        &self.repo
    }
}

