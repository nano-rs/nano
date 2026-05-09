// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook Service
//!
//! Handles webhook delivery for alert events.
//! Fire-and-forget via tokio::spawn — never blocks the detection pipeline.

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use url::Url;
use uuid::Uuid;

use super::models::*;
use super::repository::WebhookRepository;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of matched events included in the webhook payload
const MAX_MATCHED_EVENTS: usize = 10;

/// HTTP request timeout for webhook delivery
const DELIVERY_TIMEOUT_SECS: u64 = 10;

/// Maximum concurrent webhook deliveries
const MAX_CONCURRENT_DELIVERIES: usize = 20;

#[derive(Clone)]
pub struct WebhookService {
    repo: WebhookRepository,
    client: reqwest::Client,
    semaphore: Arc<Semaphore>,
}

impl WebhookService {
    pub fn new(repo: WebhookRepository) -> Self {
        // SECURITY: Disable automatic redirect following to prevent SSRF bypass.
        // An attacker could create a webhook pointing to a public URL that 302-redirects
        // to an internal service (e.g., http://127.0.0.1:8123). validate_url() only checks
        // the initial URL, so the redirect would bypass SSRF protections.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(DELIVERY_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        Self {
            repo,
            client,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
        }
    }

    /// Validate that a webhook URL is safe to call (not targeting internal services).
    ///
    /// Rejects private IPs, loopback, link-local (cloud metadata), cloud metadata hostnames,
    /// self-referencing URLs, and non-HTTP schemes. Performs DNS resolution to prevent
    /// DNS rebinding attacks.
    pub async fn validate_url(url: &str) -> Result<(), String> {
        let parsed = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "URL scheme '{}' is not allowed; use http or https",
                    scheme
                ))
            }
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| "URL must have a host".to_string())?;

        // Check for localhost variants
        if host == "localhost" || host == "ip6-localhost" {
            return Err("Webhook URLs must not target localhost".to_string());
        }

        // Block known cloud metadata hostnames (DNS rebinding protection)
        const METADATA_HOSTS: &[&str] = &[
            "metadata.google.internal",
            "metadata.goog",
            "169.254.169.254.nip.io",
            "instance-data",
            "kubernetes.default.svc",
        ];
        let host_lower = host.to_lowercase();
        if METADATA_HOSTS
            .iter()
            .any(|&h| host_lower == h || host_lower.ends_with(&format!(".{}", h)))
        {
            return Err("Webhook URLs must not target cloud metadata endpoints".to_string());
        }

        // Block self-referencing URLs (prevent alert → webhook → alert loops)
        if let Ok(self_hostname) = std::env::var("NANOSIEM_HOSTNAME") {
            if host.eq_ignore_ascii_case(&self_hostname) {
                return Err("Webhook URLs must not target the NanoSIEM instance itself".to_string());
            }
        }

        // Parse IP addresses and check for private/reserved ranges
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_or_reserved(ip) {
                return Err(format!(
                    "Webhook URLs must not target private or reserved IP addresses ({})",
                    ip
                ));
            }
            return Ok(());
        }

        // Check for bracket-wrapped IPv6
        let trimmed = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            if is_private_or_reserved(ip) {
                return Err(format!(
                    "Webhook URLs must not target private or reserved IP addresses ({})",
                    ip
                ));
            }
            return Ok(());
        }

        // DNS resolution check — resolve hostname and validate all resolved IPs
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addr = format!("{}:{}", host, port);
        let addrs: Vec<_> = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("DNS resolution returned no addresses for {}", host));
        }
        for sock_addr in &addrs {
            if is_private_or_reserved(sock_addr.ip()) {
                return Err(format!(
                    "Webhook URL resolves to private/reserved IP: {}",
                    sock_addr.ip()
                ));
            }
        }

        Ok(())
    }

    /// Fire webhook notifications for a newly created alert.
    ///
    /// Loads all enabled webhooks, filters by severity, and spawns async
    /// delivery tasks. Never blocks the caller.
    pub async fn fire_alert_created(
        &self,
        alert_id: Uuid,
        rule_id: Uuid,
        rule_name: &str,
        severity: &str,
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

        // Build the payload once for all webhooks
        let events_array = match matched_events.as_array() {
            Some(arr) => arr.iter().take(MAX_MATCHED_EVENTS).cloned().collect(),
            None => vec![],
        };
        let matched_event_count = matched_events.as_array().map_or(0, |a| a.len()) as i64;

        let payload = WebhookPayload {
            event_type: "alert.created".to_string(),
            alert_id: Some(alert_id),
            rule_id: Some(rule_id),
            rule_name: Some(rule_name.to_string()),
            severity: Some(severity.to_string()),
            matched_event_count: Some(matched_event_count),
            matched_events: Some(events_array),
            created_at,
        };

        let severity_lower = severity.to_lowercase();

        for webhook in webhooks {
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

            let svc = self.clone();
            let payload = payload.clone();
            let alert_id_copy = alert_id;

            // Fire-and-forget with concurrency limit
            tokio::spawn(async move {
                let _permit = svc.semaphore.acquire().await;
                svc.deliver(&webhook, &payload, Some(alert_id_copy), "alert.created")
                    .await;
            });
        }
    }

    /// Build a request with custom headers and HMAC signature.
    fn build_request(
        &self,
        webhook: &super::models::Webhook,
        payload_bytes: &[u8],
    ) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "NanoSIEM-Webhook/1.0");

        // Add custom headers
        if let Some(ref encrypted) = webhook.headers_encrypted {
            if !encrypted.is_empty() {
                match self.repo.decrypt_json::<HashMap<String, String>>(encrypted) {
                    Ok(headers) => {
                        for (key, value) in &headers {
                            request = request.header(key, value);
                        }
                    }
                    Err(e) => {
                        warn!(webhook_id = %webhook.id, "Failed to decrypt webhook headers: {}", e);
                    }
                }
            }
        }

        // Add HMAC signature
        if let Some(ref encrypted_secret) = webhook.secret_encrypted {
            if !encrypted_secret.is_empty() {
                match self.repo.decrypt_string(encrypted_secret) {
                    Ok(secret) => {
                        if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                            mac.update(payload_bytes);
                            let signature = hex::encode(mac.finalize().into_bytes());
                            request = request
                                .header("X-NanoSIEM-Signature", format!("sha256={}", signature));
                        }
                    }
                    Err(e) => {
                        warn!(webhook_id = %webhook.id, "Failed to decrypt webhook secret: {}", e);
                    }
                }
            }
        }

        request
    }

    /// Deliver a webhook payload and log the result.
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

        let request = self.build_request(webhook, &payload_bytes);
        let result = request.body(payload_bytes).send().await;
        let duration_ms = start.elapsed().as_millis() as i32;

        match result {
            Ok(response) => {
                let status = response.status().as_u16() as i32;
                let success = response.status().is_success();
                let body = response.text().await.unwrap_or_default();

                if success {
                    info!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        status_code = status,
                        duration_ms = duration_ms,
                        "Webhook delivered successfully"
                    );
                } else {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        status_code = status,
                        duration_ms = duration_ms,
                        "Webhook delivery returned non-success status"
                    );
                }

                if let Err(e) = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        alert_id,
                        event_type,
                        Some(status),
                        Some(&body),
                        success,
                        None,
                        Some(duration_ms),
                    )
                    .await
                {
                    error!(webhook_id = %webhook.id, "Failed to log webhook delivery: {}", e);
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                error!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    error = %error_msg,
                    duration_ms = duration_ms,
                    "Webhook delivery failed"
                );

                if let Err(log_err) = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        alert_id,
                        event_type,
                        None,
                        None,
                        false,
                        Some(&error_msg),
                        Some(duration_ms),
                    )
                    .await
                {
                    error!(webhook_id = %webhook.id, "Failed to log webhook delivery error: {}", log_err);
                }
            }
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
            alert_id: None,
            rule_id: None,
            rule_name: Some("Test Webhook Delivery".to_string()),
            severity: Some("informational".to_string()),
            matched_event_count: Some(0),
            matched_events: Some(vec![]),
            created_at: Utc::now(),
        };

        let start = Instant::now();

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| format!("Serialization error: {}", e))?;

        let request = self.build_request(&webhook, &payload_bytes);
        let result = request.body(payload_bytes).send().await;
        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let status = response.status().as_u16();
                let success = response.status().is_success();
                let body = response.text().await.unwrap_or_default();

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

/// Check if an IP address is private, loopback, link-local, or otherwise reserved.
fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()              // 127.0.0.0/8
            || v4.is_private()            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()         // 169.254.0.0/16 (cloud metadata)
            || v4.is_broadcast()          // 255.255.255.255
            || v4.is_unspecified()        // 0.0.0.0
            || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()              // ::1
            || v6.is_unspecified()        // ::
            // H1: Check link-local (fe80::/10)
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // H1: Check unique local (fc00::/7)
            || (v6.segments()[0] & 0xfe00) == 0xfc00
            // H1: Check IPv6-mapped IPv4 (::ffff:x.x.x.x) — validate inner IPv4
            || v6.to_ipv4_mapped().map_or(false, |v4| {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
            })
        }
    }
}
