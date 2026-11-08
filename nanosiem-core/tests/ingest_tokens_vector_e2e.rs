// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4907 end-to-end: `IngestTokenService` writes the hashed tokens file, the
//! real nano-rs/vector fork (shipped 00-base.toml + 02-hec-source.toml) reads
//! it, and every event lands in its token's source. Driven by
//! `scripts/tests/ingest-tokens-vector-e2e.sh`, which starts a throwaway
//! PostgreSQL and Vector and sets the `NAN4907_E2E_*` variables; skipped (and
//! `#[ignore]`d) otherwise.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nanosiem_core::ingest_tokens::{IngestTokenService, IngestTokenRepository, INSTALL_CREDENTIAL_ID};
use nanosiem_core::ingestion::VectorIngestClient;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const MIGRATION: &str = include_str!("../../migrations/postgres/290_ingest_tokens.sql");
const APACHE: Uuid = Uuid::from_u128(0xa1);
const FIREWALL: Uuid = Uuid::from_u128(0xf1);
/// Vector re-reads the file every 2 s; allow a margin for the request path.
const RELOAD_WINDOW: Duration = Duration::from_secs(6);

struct Env {
    tokens_file: PathBuf,
    events: PathBuf,
    http: String,
    hec: String,
    metrics: String,
    install: String,
    database_url: String,
}

fn env() -> Option<Env> {
    let get = |k: &str| std::env::var(k).ok();
    Some(Env {
        tokens_file: get("NAN4907_E2E_TOKENS_FILE")?.into(),
        events: get("NAN4907_E2E_EVENTS")?.into(),
        http: get("NAN4907_E2E_HTTP")?,
        hec: get("NAN4907_E2E_HEC")?,
        metrics: get("NAN4907_E2E_METRICS")?,
        install: get("NAN4907_E2E_INSTALL_TOKEN")?,
        database_url: get("NANOSIEM_TEST_DATABASE_URL")?,
    })
}

async fn pool(url: &str) -> PgPool {
    let schema = format!("nan4907_e2e_{}", Uuid::new_v4().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect({
            let schema = schema.clone();
            move |conn, _| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str())
                        .await
                        .map(|_| ())
                })
            }
        })
        .connect(url)
        .await
        .expect("connect");
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema};
         CREATE TABLE {schema}.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), status TEXT);
         CREATE TABLE {schema}.log_sources (
             id UUID PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
             match_values TEXT[], enabled BOOLEAN NOT NULL DEFAULT TRUE,
             deployed BOOLEAN NOT NULL DEFAULT FALSE,
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
         INSERT INTO {schema}.log_sources (id, name, source_type, match_values) VALUES
             ('{APACHE}', 'Apache', 'routed', ARRAY['apache_access']),
             ('{FIREWALL}', 'Palo Alto', 'splunk_hec', ARRAY['pan_traffic']);"
    ))
    .execute(&pool)
    .await
    .expect("setup");
    // A fresh install: strict mode, install token unbound.
    sqlx::raw_sql(&MIGRATION.replace("SET LOCAL lock_timeout = '5s';", ""))
        .execute(&pool)
        .await
        .expect("migration 290");
    pool
}

async fn send_http(env: &Env, token: &str, claimed: &str, message: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/", env.http))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .header("X-Source-Type", claimed)
        .body(json!({ "message": message }).to_string())
        .send()
        .await
        .expect("http send")
        .status()
        .as_u16()
}

async fn send_hec(env: &Env, token: &str, sourcetype: &str, event: Value) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/services/collector/event", env.hec))
        .header("Authorization", format!("Splunk {token}"))
        .header("X-Splunk-Request-Channel", Uuid::new_v4().to_string())
        .body(json!({ "event": event, "sourcetype": sourcetype }).to_string())
        .send()
        .await
        .expect("hec send")
        .status()
        .as_u16()
}

/// Polls `send` until it returns `want` or the reload window passes.
async fn eventually<F, Fut>(want: u16, mut send: F) -> (u16, Duration)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = u16>,
{
    let start = Instant::now();
    loop {
        let got = send().await;
        if got == want || start.elapsed() > RELOAD_WINDOW {
            return (got, start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The captured event whose message contains `marker`.
async fn captured(env: &Env, marker: &str) -> Value {
    let start = Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(&env.events) {
            if let Some(line) = text.lines().find(|l| l.contains(marker)) {
                return serde_json::from_str(line).expect("event json");
            }
        }
        assert!(start.elapsed() < Duration::from_secs(20), "no event for {marker}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
#[ignore = "run by scripts/tests/ingest-tokens-vector-e2e.sh"]
async fn per_source_tokens_against_a_live_vector() {
    let Some(env) = env() else {
        eprintln!("NAN4907_E2E_* not set; run scripts/tests/ingest-tokens-vector-e2e.sh");
        return;
    };
    let pool = pool(&env.database_url).await;
    const PLATFORM: &str = "e2e-platform-secret-not-the-install-token";
    let svc = IngestTokenService::with_paths(
        pool.clone(),
        env.tokens_file.clone(),
        env.metrics.clone(),
        Some(env.install.clone()),
    )
    .with_platform_token(Some(PLATFORM.into()));
    let repo = IngestTokenRepository::new(pool.clone());

    // 0. No tokens file yet: fails closed (no explicit static fallback). The
    //    install token gets 401 on HTTP; a HEC event is dropped, never stored.
    assert!(!env.tokens_file.exists());
    assert_eq!(send_http(&env, &env.install, "legacy_fw", "m-nofile-http").await, 401);
    send_hec(&env, &env.install, "legacy_hec", json!("m-nofile-hec")).await;
    println!("ok: missing tokens file fails closed (HTTP install token -> 401)");

    // Two sources, two tokens.
    let (apache, apache_value) = svc.create("edge-apache", APACHE, None).await.unwrap();
    let (fw, fw_value) = svc.create("edge-fw", FIREWALL, None).await.unwrap();
    tokio::time::sleep(RELOAD_WINDOW).await;

    // 1. Both ingest; the token decides the source, a claim is kept raw.
    assert_eq!(send_http(&env, &apache_value, "windows_sysmon", "m-apache-http").await, 200);
    assert_eq!(send_hec(&env, &fw_value, "spoofed_type", json!("m-fw-hec-string")).await, 200);
    assert_eq!(
        send_hec(&env, &fw_value, "pan_traffic", json!({"user": "alice", "tag": "m-fw-hec-object"})).await,
        200
    );
    let e = captured(&env, "m-apache-http").await;
    assert_eq!(e["source_type"], "apache_access", "{e}");
    assert_eq!(e["claimed_source_type"], "windows_sysmon", "{e}");
    assert_eq!(e["credential_id"], apache.credential_id.to_string());
    let e = captured(&env, "m-fw-hec-string").await;
    assert_eq!(e["source_type"], "pan_traffic", "{e}");
    assert_eq!(e["claimed_source_type"], "spoofed_type", "{e}");
    assert_eq!(e["credential_id"], fw.credential_id.to_string());
    let e = captured(&env, "m-fw-hec-object").await;
    assert_eq!(e["source_type"], "pan_traffic", "{e}");
    assert!(e["message"].as_str().unwrap().contains("alice"), "object event keeps a message: {e}");
    println!("ok: two sources ingest; events carry their token's source and credential id");

    // 2. Refused credentials: the literal placeholder, an unknown token, and
    //    the install token while strict and unbound.
    for token in ["${VECTOR_AUTH_TOKEN}", "nit_notatokenatallnotatokenatallnotatoken", env.install.as_str()] {
        assert_eq!(send_http(&env, token, "x", "m-refused").await, 401, "http {token:.8}");
        assert_eq!(send_hec(&env, token, "x", json!("m-refused")).await, 401, "hec {token:.8}");
    }
    println!("ok: literal ${{VECTOR_AUTH_TOKEN}}, unknown and unbound install token -> 401");

    // 3. Revoke one: 401 within the reload window; the other is unaffected.
    svc.revoke(apache.credential_id, None).await.unwrap();
    let (status, took) = eventually(401, || send_http(&env, &apache_value, "x", "m-after-revoke")).await;
    assert_eq!(status, 401, "revoked token still accepted after {took:?}");
    assert_eq!(send_hec(&env, &fw_value, "x", json!("m-fw-after-revoke")).await, 200);
    println!("ok: revoked token -> 401 after {took:?}; the other source still 200");

    // 4. Rotate: the old value is refused, the new one lands in the same source.
    let (_, rotated, rotated_value) = svc.rotate(fw.credential_id, None).await.unwrap();
    let (status, took) = eventually(401, || send_hec(&env, &fw_value, "x", json!("m-old-fw"))).await;
    assert_eq!(status, 401, "rotated-away token still accepted after {took:?}");
    let (status, _) = eventually(200, || send_hec(&env, &rotated_value, "x", json!("m-rotated-fw"))).await;
    assert_eq!(status, 200);
    let e = captured(&env, "m-rotated-fw").await;
    assert_eq!(e["source_type"], "pan_traffic");
    assert_eq!(e["credential_id"], rotated.credential_id.to_string());
    println!("ok: rotated token -> old 401 after {took:?}, new value routes to the same source");

    // 5. Legacy multiplex (an upgraded install): the install token routes on
    //    the declared type again.
    sqlx::query("UPDATE ingest_token_settings SET install_token_mode = 'legacy_multiplex'")
        .execute(&pool)
        .await
        .unwrap();
    svc.publish().await.unwrap();
    let (status, _) = eventually(200, || send_http(&env, &env.install, "legacy_fw", "m-legacy-http")).await;
    assert_eq!(status, 200);
    // Each source re-reads the file on its own clock (at most every 2 s).
    let (status, _) = eventually(200, || send_hec(&env, &env.install, "legacy_hec", json!("m-legacy-hec"))).await;
    assert_eq!(status, 200);
    let e = captured(&env, "m-legacy-http").await;
    assert_eq!(e["source_type"], "legacy_fw", "{e}");
    assert!(e["claimed_source_type"].is_null());
    assert_eq!(e["credential_id"], INSTALL_CREDENTIAL_ID.to_string());
    assert_eq!(captured(&env, "m-legacy-hec").await["source_type"], "legacy_hec");
    println!("ok: legacy multiplex install token routes by X-Source-Type / sourcetype");

    // 6. nano-api's own senders: the platform pull credential keeps its type.
    let client = VectorIngestClient::new(format!("{}/", env.http), None)
        .with_platform_token(Some(PLATFORM.into()), Some(env.install.clone()));
    client
        .push("okta", &[json!({"message": "m-platform-pull"})])
        .await
        .expect("platform pull push");
    let e = captured(&env, "m-platform-pull").await;
    assert_eq!(e["source_type"], "okta", "{e}");
    println!("ok: platform credential keeps its declared type");

    // 6b. The install token never doubles as the platform credential: back in
    //     strict mode it is refused, while the platform secret still works.
    svc.set_install_token_strict(None).await.unwrap();
    let (status, _) = eventually(401, || send_http(&env, &env.install, "okta", "m-strict-again")).await;
    assert_eq!(status, 401);
    let (status, _) = eventually(200, || send_http(&env, PLATFORM, "okta", "m-platform-again")).await;
    assert_eq!(status, 200);
    println!("ok: strict install token -> 401 while the platform credential still routes");

    // The HEC event sent while the file was missing never reached a sink.
    let text = std::fs::read_to_string(&env.events).unwrap_or_default();
    assert!(!text.contains("m-nofile-hec"), "fail-closed HEC event was stored");
    assert!(!text.contains("m-nofile-http"));

    // 7. Per-token request counts from Vector's counter.
    let start = Instant::now();
    loop {
        svc.sample_usage().await.expect("metrics");
        let token = repo.get(rotated.credential_id).await.unwrap().unwrap();
        if token.request_count >= 1 && token.last_used_at.is_some() {
            println!("ok: per-token usage sampled (requests={})", token.request_count);
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "usage never sampled");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
