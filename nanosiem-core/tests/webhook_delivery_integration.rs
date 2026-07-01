// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end webhook delivery validation (NAN-1546).
//!
//! Fires the real `WebhookService` against a live local receiver (wiremock) and
//! a migrated Postgres, proving the things that had never been validated:
//! payload shape + completeness, HMAC signature correctness, event-type
//! scoping (SIEM vs observability), and retry-on-5xx.
//!
//! Loopback receivers are blocked by the delivery SSRF guard by default, so
//! these run with `NANOSIEM_WEBHOOK_ALLOW_PRIVATE=1` (the documented internal-
//! target opt-in). Because `fire_alert` fans out to ALL enabled webhooks, the
//! suite MUST run single-threaded and each test starts from a clean table:
//!
//!   NANOSIEM_ALLOW_DEFAULT_KEYS=true \
//!   cargo test -p nanosiem-core --test webhook_delivery_integration \
//!     -- --ignored --test-threads=1

mod common;

use common::migrated_pool;
use hmac::{Hmac, KeyInit, Mac};
use nanosiem_core::webhooks::{CreateWebhookRequest, WebhookRepository, WebhookService};
use sha2::Sha256;
use sqlx::PgPool;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type HmacSha256 = Hmac<Sha256>;

/// Test-fixed 32-byte encryption key + internal-target opt-in. Set before any
/// `WebhookRepository::new` (which reads the key via `EncryptionService::from_env`).
fn set_env() {
    std::env::set_var(
        "NANOSIEM_ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef",
    );
    std::env::set_var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE", "1");
}

async fn clean(pool: &PgPool) {
    sqlx::query("DELETE FROM webhook_delivery_log")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM webhooks")
        .execute(pool)
        .await
        .unwrap();
}

fn create_req(name: &str, url: String, event_types: Vec<&str>, secret: Option<&str>) -> CreateWebhookRequest {
    CreateWebhookRequest {
        name: name.to_string(),
        url,
        headers: None,
        secret: secret.map(str::to_string),
        severity_filter: None,
        event_types: Some(event_types.into_iter().map(str::to_string).collect()),
        enabled: Some(true),
    }
}

/// Poll the mock's received-request count until it reaches `want` or `timeout`.
/// Returns the final count (may be < want on timeout).
async fn wait_for(server: &MockServer, want: usize, timeout: Duration) -> usize {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let n = server
            .received_requests()
            .await
            .map(|r| r.len())
            .unwrap_or(0);
        if n >= want || std::time::Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "requires Postgres (docker compose up -d postgres); run with --test-threads=1"]
async fn detection_alert_delivers_complete_payload_with_valid_hmac() {
    set_env();
    std::env::set_var("NANOSIEM_HOSTNAME", "nano.test");
    let pool = migrated_pool().await;
    clean(&pool).await;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let repo = WebhookRepository::new(pool.clone());
    let secret = "s3cr3t-signing-key";
    let webhook = repo
        .create(&create_req(
            "siem-hook",
            format!("{}/hook", server.uri()),
            vec!["siem_alert"],
            Some(secret),
        ))
        .await
        .unwrap();

    let svc = WebhookService::new(repo);
    let alert_id = uuid::Uuid::now_v7();
    let rule_id = uuid::Uuid::now_v7();
    let matched = serde_json::json!([{ "src_ip": "10.0.0.5", "user": "alice" }]);
    svc.fire_alert(
        alert_id,
        "detection",
        Some(rule_id),
        "Impossible travel",
        "high",
        Some("10.0.0.5".to_string()),
        &matched,
        chrono::Utc::now(),
    )
    .await;

    assert_eq!(wait_for(&server, 1, Duration::from_secs(5)).await, 1, "one delivery");

    let reqs = server.received_requests().await.unwrap();
    let req = &reqs[0];
    let body = req.body.clone();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Payload shape + completeness
    assert_eq!(v["event_type"], "alert.created");
    assert_eq!(v["kind"], "detection");
    assert_eq!(v["severity"], "high");
    assert_eq!(v["rule_name"], "Impossible travel");
    assert_eq!(v["entity"], "10.0.0.5");
    assert_eq!(v["link_url"], format!("https://nano.test/alerts/{}",
        nanosiem_core::typeid::encode(nanosiem_core::typeid::alert::PREFIX, &alert_id)));
    assert!(v["alert_id"].as_str().unwrap().starts_with("alert_"));
    assert!(v["rule_id"].as_str().unwrap().starts_with("rule_"));

    // HMAC signature correctness — recompute over `<timestamp>.<body>`.
    let ts = req
        .headers
        .get("X-NanoSIEM-Timestamp")
        .expect("timestamp header present")
        .to_str()
        .unwrap();
    let sig = req
        .headers
        .get("X-NanoSIEM-Signature")
        .expect("signature header present")
        .to_str()
        .unwrap();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(ts.as_bytes());
    mac.update(b".");
    mac.update(&body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(sig, expected, "HMAC signature matches timestamp.body");

    // Delivery log records success.
    let logs = svc.repo().list_deliveries(webhook.id, 10).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].success);
    assert_eq!(logs[0].status_code, Some(200));

    std::env::remove_var("NANOSIEM_HOSTNAME");
}

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn event_type_scoping_isolates_siem_and_observability() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    // One receiver, two paths so we can tell the streams apart.
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/siem"))
        .respond_with(ResponseTemplate::new(200)).mount(&server).await;
    Mock::given(method("POST")).and(path("/obs"))
        .respond_with(ResponseTemplate::new(200)).mount(&server).await;

    let repo = WebhookRepository::new(pool.clone());
    repo.create(&create_req("siem-only", format!("{}/siem", server.uri()), vec!["siem_alert"], None)).await.unwrap();
    repo.create(&create_req("obs-only", format!("{}/obs", server.uri()), vec!["obs_alert"], None)).await.unwrap();

    let svc = WebhookService::new(repo);
    let matched = serde_json::json!([{ "check": "api-health" }]);

    // A detection alert must reach ONLY the siem-only webhook.
    svc.fire_alert(uuid::Uuid::now_v7(), "detection", Some(uuid::Uuid::now_v7()),
        "rule", "medium", None, &matched, chrono::Utc::now()).await;
    // A synthetic (observability) alert must reach ONLY the obs-only webhook.
    svc.fire_alert(uuid::Uuid::now_v7(), "synthetic", None,
        "api-health", "high", Some("https://api".to_string()), &matched, chrono::Utc::now()).await;

    // Both deliveries land (2 total); give the fan-out time to settle.
    assert_eq!(wait_for(&server, 2, Duration::from_secs(5)).await, 2);
    tokio::time::sleep(Duration::from_millis(300)).await; // catch any erroneous extra

    let reqs = server.received_requests().await.unwrap();
    let siem_hits = reqs.iter().filter(|r| r.url.path() == "/siem").count();
    let obs_hits = reqs.iter().filter(|r| r.url.path() == "/obs").count();
    assert_eq!(siem_hits, 1, "detection -> siem only");
    assert_eq!(obs_hits, 1, "synthetic -> obs only");

    // And the payloads carry the right kind.
    let siem_body: serde_json::Value = serde_json::from_slice(
        &reqs.iter().find(|r| r.url.path() == "/siem").unwrap().body).unwrap();
    let obs_body: serde_json::Value = serde_json::from_slice(
        &reqs.iter().find(|r| r.url.path() == "/obs").unwrap().body).unwrap();
    assert_eq!(siem_body["kind"], "detection");
    assert_eq!(obs_body["kind"], "synthetic");
}

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn delivery_retries_on_5xx_then_gives_up() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    // Persistent 500 → the service should attempt exactly MAX_DELIVERY_ATTEMPTS.
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path("/hook"))
        .respond_with(ResponseTemplate::new(500)).mount(&server).await;

    let repo = WebhookRepository::new(pool.clone());
    let webhook = repo.create(&create_req(
        "flaky", format!("{}/hook", server.uri()), vec!["siem_alert"], None)).await.unwrap();

    let svc = WebhookService::new(repo);
    svc.fire_alert(uuid::Uuid::now_v7(), "detection", Some(uuid::Uuid::now_v7()),
        "rule", "low", None, &serde_json::json!([{}]), chrono::Utc::now()).await;

    // 3 attempts with 0.5s + 1s backoff ≈ 1.5s; allow generous headroom.
    let n = wait_for(&server, 3, Duration::from_secs(8)).await;
    assert_eq!(n, 3, "exactly MAX_DELIVERY_ATTEMPTS attempts on persistent 5xx");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.received_requests().await.unwrap().len(), 3, "no 4th attempt");

    // One delivery-log row for the logical delivery, marked failed.
    let logs = svc.repo().list_deliveries(webhook.id, 10).await.unwrap();
    assert_eq!(logs.len(), 1, "single log row per logical delivery");
    assert!(!logs[0].success);
    assert_eq!(logs[0].status_code, Some(500));
}
