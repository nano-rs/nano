// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process-isolated environment proxy / redirect regression. Local fixtures only; no database.
use nanosiem_core::{crypto::EncryptionService, webhooks::{Webhook, WebhookPayload, WebhookService}};
use nanosiem_core::webhooks::service::attempt_webhook_delivery;
use nanosiem_core::webhooks::repository::encrypt_envelope_string;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path}};

#[tokio::test]
async fn webhook_dials_receiver_directly_and_never_follows_redirects() {
    let receiver = MockServer::start().await;
    let proxy = MockServer::start().await;
    let redirect_target = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)).mount(&proxy).await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)).mount(&redirect_target).await;
    Mock::given(path("/hook")).respond_with(ResponseTemplate::new(200)).mount(&receiver).await;
    Mock::given(path("/redirect")).respond_with(ResponseTemplate::new(302)
        .insert_header("Location", format!("{}/internal", redirect_target.uri()))).mount(&receiver).await;
    // This binary has one test: opt-in permits our loopback fixture, never a live destination.
    std::env::set_var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE", "1");
    for name in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(name, proxy.uri());
    }
    for name in ["NO_PROXY", "no_proxy"] { std::env::set_var(name, ""); }
    let encryption = EncryptionService::new(&[7; 32]);
    let now = chrono::Utc::now();
    let mut webhook = Webhook {
        id: uuid::Uuid::new_v4(), name: "local transport fixture".into(), url: format!("{}/hook", receiver.uri()),
        url_encrypted: None, url_host: None, headers_encrypted: None,
        secret_encrypted: Some(encrypt_envelope_string(&encryption, "local-fixture-signing-key").unwrap()),
        severity_filter: None, event_types: vec!["siem_alert".into()], channel_type: "generic".into(),
        channel_config: serde_json::json!({}), rule_filter: None, health_category_filter: None,
        health_resource_filter: None, enabled: true, created_at: now, updated_at: now,
    };
    let payload: WebhookPayload = serde_json::from_value(serde_json::json!({
        "event_type": "alert.created", "alert_id": null, "rule_id": null,
        "created_at": now, "idempotency_key": "local-fixture-delivery",
    })).unwrap();
    assert!(attempt_webhook_delivery(&encryption, &webhook, &payload).await.success);
    let received = receiver.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "the validated receiver must receive the POST");
    assert_eq!(received[0].headers["x-nanosiem-idempotency-key"], "local-fixture-delivery");
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&received[0].body).unwrap()["event_type"], "alert.created");
    let timestamp = received[0].headers["x-nanosiem-timestamp"].to_str().unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"local-fixture-signing-key").unwrap();
    mac.update(timestamp.as_bytes()); mac.update(b"."); mac.update(&received[0].body);
    assert_eq!(received[0].headers["x-nanosiem-signature"], format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
    webhook.url = format!("{}/redirect", receiver.uri());
    let outcome = attempt_webhook_delivery(&encryption, &webhook, &payload).await;
    assert_eq!(outcome.status_code, Some(302));
    assert!(!outcome.success && !outcome.retryable);
    assert!(redirect_target.received_requests().await.unwrap().is_empty());
    assert!(proxy.received_requests().await.unwrap().is_empty(), "system proxies must not bypass DNS pinning");

    std::env::remove_var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE");
    std::env::remove_var("NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST");
    for url in ["https://10.0.0.1/hook", "https://172.16.0.1/hook", "https://192.168.0.1/hook",
        "https://169.254.169.254/", "https://[fe80::1]/", "https://[fc00::1]/",
        "https://api.tenant.svc.cluster.local./", "https://metadata.google.internal./"] {
        assert!(WebhookService::validate_url(url).await.is_err(), "private/cluster target must be refused");
    }
}
