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
use nanosiem_core::webhooks::{
    CreateWebhookRequest, UpdateWebhookRequest, WebhookDeliveryLog, WebhookRepository,
    WebhookResponse, WebhookService,
};
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
    // NAN-2207: egress redaction is now decided by this registry for every
    // origin including `audit`, so a row leaking between tests would silently
    // flip the expected payload shape.
    sqlx::query("DELETE FROM restricted_source_types")
        .execute(pool)
        .await
        .unwrap();
    // NAN-2210: `resolve_base_url` prefers `system_settings.notification_base_url`
    // OVER the `NANOSIEM_HOSTNAME` the deep-link test sets, so a database with a
    // base URL configured silently wins and the asserted link is whatever that
    // row says. The test passed only against a database that happened to have
    // none — true of a fresh CI Postgres, false of any developer box that has
    // run the dev stack, where this fails with
    //   left: "http://localhost:5173/alerts/…"  right: "https://nano.test/alerts/…"
    //
    // Clearing it here makes the env var actually decide, which is what the test
    // always meant. Scoped to the settings row's own column, so unrelated
    // settings survive.
    sqlx::query("UPDATE system_settings SET notification_base_url = NULL WHERE id = 'default'")
        .execute(pool)
        .await
        .unwrap();
}

/// Register a `source_type` as restricted — the admin action that makes egress
/// redaction apply to it (NAN-2207).
async fn restrict(pool: &PgPool, source_type: &str) {
    sqlx::query("INSERT INTO restricted_source_types (source_type) VALUES ($1)")
        .bind(source_type)
        .execute(pool)
        .await
        .unwrap();
}

/// Fire one detection alert at a single receiver and return the delivered body.
async fn fire_and_capture(
    pool: &PgPool,
    matched: serde_json::Value,
) -> serde_json::Value {
    fire_and_capture_kind(pool, "detection", "siem_alert", matched).await
}

/// Fire one alert of any `kind` at a single receiver and return the delivered
/// body. `stream` is the subscription category the receiver signs up for —
/// detection/risk_notable land on `siem_alert`, observability kinds on
/// `obs_alert` (NAN-2227 needs both).
async fn fire_and_capture_kind(
    pool: &PgPool,
    kind: &str,
    stream: &str,
    matched: serde_json::Value,
) -> serde_json::Value {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let repo = WebhookRepository::new(pool.clone());
    repo.create(&create_req(
        "soar",
        format!("{}/hook", server.uri()),
        vec![stream],
        None,
    ))
    .await
    .unwrap();

    // `new` self-builds the scope resolver from the repo pool, so redaction is
    // live here exactly as it is in production (see `WebhookService::new`).
    let svc = WebhookService::new(repo);
    svc.fire_alert(
        uuid::Uuid::now_v7(),
        kind,
        // Observability alerts have no rule (the FK is nullable).
        (kind == "detection").then(uuid::Uuid::now_v7),
        "malicious login from bad ip",
        "medium",
        Some("10.0.0.5".to_string()),
        &matched,
        chrono::Utc::now(),
    )
    .await;

    assert_eq!(
        wait_for(&server, 1, Duration::from_secs(5)).await,
        1,
        "the alert must be delivered — redaction strips evidence, it never drops the notification"
    );
    let reqs = server.received_requests().await.unwrap();
    serde_json::from_slice(&reqs[0].body).unwrap()
}

fn create_req(name: &str, url: String, event_types: Vec<&str>, secret: Option<&str>) -> CreateWebhookRequest {
    CreateWebhookRequest {
        name: name.to_string(),
        url,
        headers: None,
        secret: secret.map(str::to_string),
        severity_filter: None,
        event_types: Some(event_types.into_iter().map(str::to_string).collect()),
        channel_type: None,
        channel_config: None,
        rule_filter: None,
        health_category_filter: None,
        health_resource_filter: None,
        enabled: Some(true),
    }
}

/// Count requests on `server` whose payload carries `alert_id` (NAN-2210).
///
/// `received_requests()` counts every packet that reached the socket, which is
/// not the same as "attempts at the delivery this test fired". Deliveries are
/// detached (`tokio::spawn`) and retry with 0.5s + 1s backoff, so a previous
/// test's delivery can still be retrying after that test returns and its
/// `MockServer` is dropped — and the OS is free to hand the freed ephemeral port
/// to the next test's server. The stale retry then lands here and is counted as
/// ours.
///
/// That is how `delivery_retries_on_5xx_then_gives_up` saw a 4th attempt against
/// a service that hard-caps at `MAX_DELIVERY_ATTEMPTS = 3` — reproducible at
/// roughly 2-in-10 under CPU saturation, invisible on an idle machine.
///
/// Filtering by the alert id makes the count mean what the assertion says it
/// means, regardless of what else reaches the socket.
async fn requests_for_alert(server: &MockServer, alert_id: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| {
            serde_json::from_slice::<serde_json::Value>(&r.body)
                .ok()
                .and_then(|v| v["alert_id"].as_str().map(|s| s == alert_id))
                .unwrap_or(false)
        })
        .count()
}

/// Poll until `alert_id` has been attempted `want` times, or `timeout`.
/// Returns the final count (may be < want on timeout).
async fn wait_for_alert(
    server: &MockServer,
    alert_id: &str,
    want: usize,
    timeout: Duration,
) -> usize {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let n = requests_for_alert(server, alert_id).await;
        if n >= want || std::time::Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
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

/// Poll the delivery log until it holds `want` rows or `timeout` elapses,
/// returning whatever is there at the end (NAN-2210).
///
/// Observing the request at the mock server does NOT mean the delivery has been
/// logged. `webhooks::service` is fire-and-forget by design —
///
///   > Fire-and-forget via `tokio::spawn` — never blocks the detection pipeline.
///
/// — and `log_delivery` runs inside that detached task, *after* the HTTP request
/// the mock observes. So a test that reads the log the moment the request lands
/// is racing a write it never ordered against: it passes when the write wins and
/// fails when a loaded runner delays it. That is how
/// `detection_alert_delivers_complete_payload_with_valid_hmac` failed the merge
/// gate on an unrelated PR while the change that last touched it was green.
///
/// This returns rather than asserts so the caller still owns the assertion and a
/// genuine "never logged" failure reports as the count mismatch it always did —
/// the fix must not degrade into asserting nothing.
///
/// The production design is deliberate and stays as it is; the test is what
/// needed to learn to wait.
async fn wait_for_deliveries(
    repo: &WebhookRepository,
    webhook_id: uuid::Uuid,
    want: usize,
    timeout: Duration,
) -> Vec<WebhookDeliveryLog> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let logs = repo
            .list_deliveries(webhook_id, 10)
            .await
            .unwrap_or_default();
        if logs.len() >= want || std::time::Instant::now() >= deadline {
            return logs;
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

    // Delivery log records success. Waited for, not assumed — the log write
    // happens on the detached delivery task, after the request above landed.
    let logs = wait_for_deliveries(svc.repo(), webhook.id, 1, Duration::from_secs(5)).await;
    assert_eq!(logs.len(), 1);
    assert!(logs[0].success);
    assert_eq!(logs[0].status_code, Some(200));

    std::env::remove_var("NANOSIEM_HOSTNAME");
}

// ---------------------------------------------------------------------------
// Origin redaction at egress (NAN-1800 / NAN-2155 / NAN-2207)
//
// The regression these lock down: an audit-sourced detection rule is the normal
// way to alert on logins to nano itself, and NAN-2155 silently reduced those
// payloads to a stub — `matched_event_count` retained, `matched_events` and
// `entity` gone — on deployments that had configured no source scoping at all.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn audit_origin_delivers_full_evidence_when_nothing_is_restricted() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    let body = fire_and_capture(
        &pool,
        serde_json::json!([{
            "source_type": "audit",
            "user": "admin@example.test",
            "src_ip": "10.0.0.5",
            "message": "[auth] login_success on user 'admin@example.test' by admin@example.test"
        }]),
    )
    .await;

    assert_eq!(body["matched_event_count"], 1);
    let events = body["matched_events"]
        .as_array()
        .expect("audit evidence must reach the receiver when nothing is restricted");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["user"], "admin@example.test");
    assert_eq!(
        body["entity"], "10.0.0.5",
        "entity is stripped by the same branch, so it proves the branch did not fire"
    );
}

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn audit_origin_is_redacted_once_an_admin_registers_audit() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;
    // The deployment's own statement that audit is sensitive — the escape hatch
    // that replaces NAN-2155's unconditional hard-wire.
    restrict(&pool, "audit").await;

    let body = fire_and_capture(
        &pool,
        serde_json::json!([{
            "source_type": "audit",
            "user": "admin@example.test",
            "message": "[auth] login_success on user 'admin@example.test' by admin@example.test"
        }]),
    )
    .await;

    assert_eq!(
        body["matched_event_count"], 1,
        "the count survives redaction — that asymmetry is the signature of the stub"
    );
    assert!(
        body.get("matched_events").is_none(),
        "registered audit must not egress evidence, got {body}"
    );
    assert!(body.get("entity").is_none(), "entity is stripped too");
}

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn unresolved_provenance_is_redacted_with_an_empty_registry() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    // The engine stamps this when it cannot attribute an aggregate window.
    // Unlike `audit`, it must redact with NO registry entry at all: "we could
    // not tell where this came from" is not a policy an admin opts into.
    let body = fire_and_capture(
        &pool,
        serde_json::json!([{
            "count": 7,
            "_nano_source_types": [nanosiem_core::auth::UNRESOLVED_SOURCE_SENTINEL]
        }]),
    )
    .await;

    assert_eq!(body["matched_event_count"], 1);
    assert!(
        body.get("matched_events").is_none(),
        "unresolved provenance must stay fail-closed, got {body}"
    );
}

// ---------------------------------------------------------------------------
// Not-source-derived alerts (NAN-2227)
//
// "This alert has no source dimension" and "we could not determine this alert's
// source" are different facts. NAN-2155 collapsed them, so two whole classes of
// alert silently lost their evidence at egress.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn spans_metrics_shaped_alert_delivers_evidence_even_when_scoping_is_configured() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;
    // A scoped deployment: something IS restricted, just not this alert's origin.
    // This is the case the empty-registry test cannot catch — pre-NAN-2227 the
    // unattributed fallback redacted here purely because the registry was
    // non-empty.
    restrict(&pool, "insider_threat").await;

    // The stamp the engine writes for a spans/metrics rule: resolved, and
    // nothing about it is source-derived.
    let body = fire_and_capture(
        &pool,
        serde_json::json!([{
            "count": 4,
            "service_name": "checkout-api",
            "_nano_source_types": []
        }]),
    )
    .await;

    assert_eq!(body["matched_event_count"], 1);
    let events = body["matched_events"]
        .as_array()
        .expect("a not-source-derived alert must egress its evidence");
    assert_eq!(events[0]["service_name"], "checkout-api");
    assert_eq!(body["entity"], "10.0.0.5");
}

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn observability_alerts_deliver_their_payload_on_a_scoped_deployment() {
    set_env();
    let pool = migrated_pool().await;

    // The real metric-monitor payload shape (state/schedulers.rs): a descriptor
    // of the monitor and the breach, containing no ingested event at all.
    for kind in ["metric_monitor", "slo", "synthetic"] {
        // Reset per iteration: `fire_and_capture_kind` registers a receiver, and
        // `fire_alert` fans out to EVERY enabled webhook — a leftover from the
        // previous iteration would double-deliver.
        clean(&pool).await;
        restrict(&pool, "insider_threat").await;

        let body = fire_and_capture_kind(
            &pool,
            kind,
            "obs_alert",
            serde_json::json!([{
                "monitor_name": "checkout latency",
                "comparator": "gt",
                "threshold": 500.0,
                "value": 912.0
            }]),
        )
        .await;

        let events = body["matched_events"]
            .as_array()
            .unwrap_or_else(|| panic!("{kind} payload must not be redacted, got {body}"));
        assert_eq!(events[0]["monitor_name"], "checkout latency");
    }
}

#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn risk_notable_is_not_exempted_from_origin_checks() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    // risk_notable rides the SIEM stream and is derived from the findings
    // stream, so it CAN carry restricted-origin entity data — it must keep going
    // through the checks rather than ride the observability exemption.
    let body = fire_and_capture_kind(
        &pool,
        "risk_notable",
        "siem_alert",
        serde_json::json!([{
            "count": 3,
            "_nano_source_types": [nanosiem_core::auth::UNRESOLVED_SOURCE_SENTINEL]
        }]),
    )
    .await;

    assert!(
        body.get("matched_events").is_none(),
        "risk_notable must still fail closed on unresolved provenance, got {body}"
    );
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
    // Held so attempts can be attributed to THIS delivery — a stale retry from an
    // earlier test can reach this socket via a reused ephemeral port (NAN-2210).
    let alert_uuid = uuid::Uuid::now_v7();
    let alert_id = nanosiem_core::typeid::encode(nanosiem_core::typeid::alert::PREFIX, &alert_uuid);
    svc.fire_alert(alert_uuid, "detection", Some(uuid::Uuid::now_v7()),
        "rule", "low", None, &serde_json::json!([{}]), chrono::Utc::now()).await;

    // 3 attempts with 0.5s + 1s backoff ≈ 1.5s; allow generous headroom.
    let n = wait_for_alert(&server, &alert_id, 3, Duration::from_secs(8)).await;
    assert_eq!(n, 3, "exactly MAX_DELIVERY_ATTEMPTS attempts on persistent 5xx");
    // Proving a NEGATIVE, so this stays a fixed wait — there is no state to poll
    // toward. Counted per-alert so an unrelated delivery cannot fail it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        requests_for_alert(&server, &alert_id).await,
        3,
        "no 4th attempt"
    );

    // One delivery-log row for the logical delivery, marked failed. Same race as
    // the success path: the row is written after the final attempt returns.
    let logs = wait_for_deliveries(svc.repo(), webhook.id, 1, Duration::from_secs(5)).await;
    assert_eq!(logs.len(), 1, "single log row per logical delivery");
    assert!(!logs[0].success);
    assert_eq!(logs[0].status_code, Some(500));
}

/// F-39 regression: the FE no longer round-trips the (write-only) URL, so a
/// PUT that omits `url` must LEAVE the stored destination unchanged — and the
/// delivery read path must still decrypt it back to the original value.
#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn update_without_url_preserves_stored_url() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    let repo = WebhookRepository::new(pool.clone());
    let original_url = "https://hooks.slack.com/services/T/B/XXXSECRET?tenant=1";
    let created = repo
        .create(&CreateWebhookRequest {
            name: "slack".into(),
            url: original_url.into(),
            headers: None,
            secret: None,
            severity_filter: None,
            event_types: Some(vec!["siem_alert".into()]),
            channel_type: Some("slack".into()),
            channel_config: None,
            rule_filter: None,
            health_category_filter: None,
            health_resource_filter: None,
            enabled: Some(true),
        })
        .await
        .unwrap();

    // The response DTO exposes only the non-secret host, never the raw URL.
    let resp = WebhookResponse::from(&created);
    assert_eq!(resp.url_host.as_deref(), Some("hooks.slack.com"));
    let resp_json = serde_json::to_string(&resp).unwrap();
    assert!(!resp_json.contains("XXXSECRET"), "response must not leak the URL secret");

    // Update WITHOUT touching the URL (url: None = "keep").
    let update = UpdateWebhookRequest {
        name: Some("slack-renamed".into()),
        url: None,
        headers: None,
        secret: None,
        severity_filter: None,
        event_types: None,
        channel_type: None,
        channel_config: None,
        rule_filter: None,
        health_category_filter: None,
        health_resource_filter: None,
        enabled: None,
    };
    repo.update(created.id, &update).await.unwrap();

    // The delivery read path decrypts url_encrypted back to the original URL.
    let reloaded = repo.get(created.id).await.unwrap();
    assert_eq!(reloaded.name, "slack-renamed", "name updated");
    assert_eq!(
        reloaded.url, original_url,
        "url unchanged across a url:None update (catches the FE round-trip regression)"
    );
}

/// F-39: an existing plaintext-only row (created before migration 254) is
/// lazy-encrypted on its next delivery read, and the encrypted value decrypts
/// back to the original URL.
#[tokio::test]
#[ignore = "requires Postgres; run with --test-threads=1"]
async fn legacy_plaintext_url_is_lazy_encrypted_on_read() {
    set_env();
    let pool = migrated_pool().await;
    clean(&pool).await;

    // Simulate a pre-254 row: plaintext url, NULL url_encrypted / url_host.
    let id = uuid::Uuid::now_v7();
    let legacy_url = "https://hooks.slack.com/services/L/E/GACYSECRET";
    sqlx::query(
        "INSERT INTO webhooks (id, name, url, channel_type, enabled) \
         VALUES ($1, $2, $3, 'slack', true)",
    )
    .bind(id)
    .bind("legacy")
    .bind(legacy_url)
    .execute(&pool)
    .await
    .unwrap();

    let repo = WebhookRepository::new(pool.clone());
    // get() is a delivery read path → hydrate + lazy-migrate.
    let loaded = repo.get(id).await.unwrap();
    assert_eq!(loaded.url, legacy_url, "delivery url available from plaintext");

    // The row now has an encrypted column persisted.
    let enc: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT url_encrypted FROM webhooks WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let enc = enc.expect("url_encrypted persisted by lazy migration");
    assert_eq!(
        repo.decrypt_string(&enc).unwrap(),
        legacy_url,
        "lazy-encrypted value decrypts to the original url"
    );
    let host: Option<String> = sqlx::query_scalar("SELECT url_host FROM webhooks WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(host.as_deref(), Some("hooks.slack.com"), "display host persisted");
}
