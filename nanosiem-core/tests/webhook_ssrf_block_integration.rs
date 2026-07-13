// SPDX-License-Identifier: AGPL-3.0-or-later

//! Negative SSRF test for webhook delivery (NAN-1546): with the internal-target
//! opt-in OFF (the default), a webhook pointed at a loopback receiver must be
//! BLOCKED at delivery time and never actually POST. Lives in its own test
//! binary so it never shares the `NANOSIEM_WEBHOOK_ALLOW_PRIVATE` process env
//! with the happy-path suite.
//!
//!   NANOSIEM_ALLOW_DEFAULT_KEYS=true \
//!   cargo test -p nanosiem-core --test webhook_ssrf_block_integration \
//!     -- --ignored --test-threads=1

mod common;

use common::migrated_pool;
use nanosiem_core::webhooks::{CreateWebhookRequest, WebhookRepository, WebhookService};
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn loopback_target_blocked_without_opt_in() {
    // Explicitly ensure the opt-in is OFF.
    std::env::remove_var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE");
    std::env::set_var(
        "NANOSIEM_ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef",
    );

    let pool = migrated_pool().await;
    sqlx::query("DELETE FROM webhook_delivery_log").execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM webhooks").execute(&pool).await.unwrap();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let repo = WebhookRepository::new(pool.clone());
    let webhook = repo
        .create(&CreateWebhookRequest {
            name: "internal".to_string(),
            url: format!("{}/hook", server.uri()), // 127.0.0.1:PORT — loopback
            headers: None,
            secret: None,
            severity_filter: None,
            event_types: Some(vec!["siem_alert".to_string()]),
            channel_type: None,
            channel_config: None,
            rule_filter: None,
            enabled: Some(true),
        })
        .await
        .unwrap();

    let svc = WebhookService::new(repo);

    // The synchronous test path surfaces the SSRF rejection directly.
    let result = svc.send_test(webhook.id).await.unwrap();
    assert!(!result.success, "delivery to loopback must fail");
    let err = result.error.unwrap_or_default();
    assert!(
        err.to_lowercase().contains("ssrf"),
        "failure attributed to SSRF guard, got: {err}"
    );

    // The receiver must have seen NOTHING — it was never dialed.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "blocked target must never be POSTed to"
    );

    // And the block is recorded as a failed delivery for the audit trail.
    let logs = svc.repo().list_deliveries(webhook.id, 10).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert!(!logs[0].success);
}
