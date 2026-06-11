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

use crate::inputlookup::{SsrfConfig, SsrfValidator};

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
        // Delegates to the shared DNS-aware SsrfValidator (NAN-1369) so webhook
        // delivery uses exactly the same SSRF rules — loopback / private /
        // CGNAT / link-local / cloud-metadata / scheme — as every other
        // outbound path. Webhooks may target plain-http receivers, so allow_http
        // is on. The instance's own hostname is added as a blocked domain to
        // keep the self-referencing (alert → webhook → alert loop) guard.
        // The delivery client separately disables redirect-following (see new()).
        let mut blocked_domains = vec!["localhost".to_string()];
        if let Ok(self_hostname) = std::env::var("NANOSIEM_HOSTNAME") {
            if !self_hostname.is_empty() {
                blocked_domains.push(self_hostname);
            }
        }

        let validator = SsrfValidator::new(SsrfConfig {
            allow_http: true,
            blocked_domains,
            ..Default::default()
        });

        validator
            .validate_with_dns(url)
            .await
            .map(|_| ())
            .map_err(|e| format!("Webhook URL rejected: {}", e))
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

