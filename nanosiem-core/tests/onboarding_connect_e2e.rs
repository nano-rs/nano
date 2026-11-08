// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4912 phase 2 end-to-end: connect-first onboarding on the ClickHouse
//! product, against a live nano-rs/vector 0.61 fork running the shipped base
//! configs plus the router / pipeline that `VectorConfigManager` renders, a
//! throwaway ClickHouse (`logs` + the per-source rollup) and a throwaway,
//! fully-migrated PostgreSQL. Driven by `scripts/tests/onboarding-connect-e2e.sh`,
//! which sets the `NAN4912_E2E_*` variables; skipped (and `#[ignore]`d)
//! otherwise.
//!
//! Proves the plan's acceptance path:
//! 1. create a draft source -> issue a token (value returned once);
//! 2. HEC string + object events and an HTTP event with a spoofed
//!    X-Source-Type land in `logs` as `source_type=<route key>` BEFORE any
//!    parser is published (the router's `generic` catch-all keeps
//!    `source_type`), the spoofed claim survives as `ext.claimed_source_type`,
//!    and the source reads "receiving, not parsed";
//! 3. publishing the parser through the real deploy path parses new events;
//! 4. an unassigned key (legacy multiplex install token) converts into a
//!    source with the tokens file byte-for-byte unchanged, and the sender keeps
//!    working;
//! 5. an unbound token converts: bound to the new source with the SAME value,
//!    which Vector accepts again.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nanosiem_core::db::{DualPool, DualPoolConfig};
use nanosiem_core::ingest_tokens::IngestTokenService;
use nanosiem_core::log_sources::connect::{
    claimed_route_keys, connect_statuses, convert_unassigned, unassigned_sources, ConvertError,
    ConnectState, ConvertUnassignedRequest, SourceActivityReader,
};
use nanosiem_core::log_sources::{LogSourceService, NewLogSource, UpdateLogSource};
use nanosiem_core::parsers::VectorConfigManager;
use nanosiem_core::auth::ScopeSet;
use serde_json::{json, Value};
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(45);
/// Vector re-reads the tokens file every 2 s; allow a margin.
const RELOAD_WINDOW: Duration = Duration::from_secs(8);

struct Env {
    tokens_file: PathBuf,
    vector_dir: PathBuf,
    http: String,
    hec: String,
    metrics: String,
    install: String,
    ch_url: String,
    database_url: String,
}

fn env() -> Option<Env> {
    let get = |k: &str| std::env::var(k).ok();
    Some(Env {
        tokens_file: get("NAN4912_E2E_TOKENS_FILE")?.into(),
        vector_dir: get("NAN4912_E2E_VECTOR_DIR")?.into(),
        http: get("NAN4912_E2E_HTTP")?,
        hec: get("NAN4912_E2E_HEC")?,
        metrics: get("NAN4912_E2E_METRICS")?,
        install: get("NAN4912_E2E_INSTALL_TOKEN")?,
        ch_url: get("NAN4912_E2E_CH_URL")?,
        database_url: get("NANOSIEM_TEST_DATABASE_URL")?,
    })
}

fn draft(name: &str, key: &str) -> NewLogSource {
    NewLogSource {
        name: name.into(),
        description: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        source_type: "routed".into(),
        parser_vrl: String::new(),
        output_fields: None,
        dispatch_source_config_id: None,
        category: None,
        vendor: None,
        product: None,
        icon: None,
        color: None,
        match_field: None,
        match_pattern: None,
        match_values: Some(vec![key.into()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        lifecycle_status: Some("draft".into()),
    }
}

async fn send_http(env: &Env, token: &str, claimed: Option<&str>, message: &str) -> u16 {
    let mut req = reqwest::Client::new()
        .post(format!("{}/", env.http))
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .body(json!({ "message": message }).to_string());
    if let Some(claimed) = claimed {
        req = req.header("X-Source-Type", claimed);
    }
    req.send().await.expect("http send").status().as_u16()
}

async fn send_hec(env: &Env, token: &str, event: Value) -> u16 {
    reqwest::Client::new()
        .post(format!("{}/services/collector/event", env.hec))
        .header("Authorization", format!("Splunk {token}"))
        .header("X-Splunk-Request-Channel", Uuid::new_v4().to_string())
        .body(json!({ "event": event }).to_string())
        .send()
        .await
        .expect("hec send")
        .status()
        .as_u16()
}

async fn eventually_status<F, Fut>(want: u16, mut send: F) -> u16
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = u16>,
{
    let start = Instant::now();
    loop {
        let got = send().await;
        if got == want || start.elapsed() > RELOAD_WINDOW {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The stored row whose message contains `marker` (polls until it lands).
async fn stored(ch: &clickhouse::Client, marker: &str) -> Value {
    let sql = format!(
        "SELECT source_type, message, toJSONString(ext) AS ext FROM nanosiem.logs \
         WHERE timestamp >= now() - INTERVAL 1 HOUR AND position(message, '{}') > 0 \
         FORMAT JSONEachRow",
        marker.replace('\'', "")
    );
    let start = Instant::now();
    loop {
        let mut cursor = ch.query(&sql).fetch_bytes("JSONEachRow").expect("query");
        let mut body = Vec::new();
        while let Some(chunk) = cursor.next().await.expect("read") {
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).unwrap();
        if let Some(line) = body.lines().find(|l| !l.trim().is_empty()) {
            let mut row: Value = serde_json::from_str(line).expect("row json");
            let ext = row["ext"].as_str().unwrap_or("{}").to_string();
            row["ext"] = serde_json::from_str(&ext).unwrap_or(Value::Null);
            return row;
        }
        assert!(start.elapsed() < WAIT, "no stored row for {marker}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore = "run by scripts/tests/onboarding-connect-e2e.sh"]
async fn connect_first_onboarding_against_live_vector_and_clickhouse() {
    let Some(env) = env() else {
        eprintln!("NAN4912_E2E_* not set; run scripts/tests/onboarding-connect-e2e.sh");
        return;
    };
    let mut config = DualPoolConfig::with_auth(
        env.database_url.clone(),
        env.ch_url.clone(),
        "nanosiem",
        "nanosiem",
        "nanosiem",
    );
    config.clickhouse_rawsql_password = Some("rawsql".into());
    config.clickhouse_rawsql_noaudit_password = Some("rawsql".into());
    let dual = DualPool::new(&config).await.expect("dual pool");
    let pg = dual.postgres().clone();
    nanosiem_core::db::run_postgres_migrations(&pg).await.expect("migrations");

    let vector = Arc::new(VectorConfigManager::new(&env.vector_dir));
    let sources = LogSourceService::with_dual_pool_and_vector_config(&dual, Arc::clone(&vector));
    let tokens = IngestTokenService::with_paths(
        pg.clone(),
        env.tokens_file.clone(),
        env.metrics.clone(),
        Some(env.install.clone()),
    );
    let activity = SourceActivityReader::new(dual.clickhouse().clone(), dual.table_names());
    let ch = dual.clickhouse().clone();

    // The router / pipeline with no parser published, exactly as the product
    // renders them; Vector reloads on the HUP.
    vector.deploy_parsers(&[]).await.expect("render router + pipeline");
    vector.reload_vector().await.expect("reload Vector");
    tokens.publish().await.expect("publish tokens file");

    // ---- 1. Create a source; its token is shown once. -----------------------
    let vpn = sources.create(draft("Acme VPN", "acme_vpn")).await.expect("draft source");
    assert_eq!(vpn.lifecycle_status, "draft");
    assert!(!vpn.deployed);
    let (credential, value) = tokens.create("acme-vpn-edge", vpn.id, None).await.expect("issue token");
    assert!(value.starts_with("nit_"));
    let listed = tokens.get(credential.credential_id).await.unwrap().unwrap();
    assert_eq!(listed.token_prefix, credential.token_prefix);
    let file = std::fs::read_to_string(&env.tokens_file).unwrap();
    assert!(file.contains(&nanosiem_core::ingest_tokens::sha256_hex(&value)));
    assert!(!file.contains(&value), "the tokens file never holds a value");
    println!("ok: draft source + token issued (value once, hash in tokens.json)");

    // ---- 2. Data visible before the parser is published. --------------------
    assert_eq!(eventually_status(200, || send_hec(&env, &value, json!("m-vpn-hec-string"))).await, 200);
    assert_eq!(send_hec(&env, &value, json!({"user": "alice", "tag": "m-vpn-hec-object"})).await, 200);
    assert_eq!(send_http(&env, &value, Some("something_else"), "m-vpn-http-spoof").await, 200);

    let row = stored(&ch, "m-vpn-hec-string").await;
    assert_eq!(row["source_type"], "acme_vpn", "{row}");
    assert_eq!(row["ext"]["nano_credential_id"], credential.credential_id.to_string(), "{row}");
    let row = stored(&ch, "m-vpn-hec-object").await;
    assert_eq!(row["source_type"], "acme_vpn", "{row}");
    assert!(row["message"].as_str().unwrap().contains("alice"), "object event keeps a message: {row}");
    let row = stored(&ch, "m-vpn-http-spoof").await;
    assert_eq!(row["source_type"], "acme_vpn", "the token decides the source: {row}");
    assert_eq!(row["ext"]["claimed_source_type"], "something_else", "{row}");
    println!("ok: 3 events in logs as source_type=acme_vpn before publish; claim kept in ext");

    let scope = ScopeSet::unrestricted();
    let start = Instant::now();
    let status = loop {
        let rows = activity.activity(24, &scope).await.expect("activity");
        let listed = tokens.list().await.unwrap();
        let status = connect_statuses(std::slice::from_ref(&sources.get(vpn.id).await.unwrap()), &rows, &listed)
            .pop()
            .unwrap();
        if status.events_24h >= 3 || start.elapsed() > WAIT {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(status.state, ConnectState::ReceivingUnparsed, "{status:?}");
    assert_eq!(status.events_24h, 3);
    assert_eq!(status.active_tokens, 1);
    assert!(status.last_seen.is_some());
    println!("ok: connect status = receiving_unparsed (3 events, 1 token)");

    // ---- 3. Publish the parser through the real deploy path. ----------------
    sources
        .update(
            vpn.id,
            UpdateLogSource {
                // Root-replacing parser (codex P2-3): the claim must survive `. = {..}`.
                parser_vrl: Some(". = { \"message\": .message, \"ext\": { \"nan4912_parsed\": \"yes\" } }".into()),
                ..Default::default()
            },
        )
        .await
        .expect("set parser");
    let deployed = sources.deploy(vpn.id).await.expect("deploy");
    assert!(deployed.success, "deploy failed: {}", deployed.message);
    let start = Instant::now();
    let row = loop {
        let marker = format!("m-vpn-after-publish-{}", start.elapsed().as_millis());
        assert_eq!(send_http(&env, &value, Some("spoofed_after"), &marker).await, 200);
        let row = stored(&ch, &marker).await;
        if row["ext"]["nan4912_parsed"] == "yes" || start.elapsed() > WAIT {
            break row;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    assert_eq!(row["source_type"], "acme_vpn", "{row}");
    assert_eq!(row["ext"]["nan4912_parsed"], "yes", "published parser never ran: {row}");
    assert_eq!(row["ext"]["claimed_source_type"], "spoofed_after", "claim lost on the parsed lane: {row}");
    println!("ok: after publish new events are parsed by the source's parser");

    // ---- 4. Unassigned key -> source, no token change. ----------------------
    sqlx::query("UPDATE ingest_token_settings SET install_token_mode = 'legacy_multiplex'")
        .execute(&pg)
        .await
        .unwrap();
    tokens.publish().await.unwrap();
    assert_eq!(
        eventually_status(200, || send_http(&env, &env.install, Some("legacy_fw"), "m-legacy-1")).await,
        200
    );
    assert_eq!(stored(&ch, "m-legacy-1").await["source_type"], "legacy_fw");
    let start = Instant::now();
    loop {
        let rows = activity.activity(24, &scope).await.unwrap();
        let un = unassigned_sources(&sources.list(None).await.unwrap(), &rows);
        if let Some(u) = un.iter().find(|u| u.route_key == "legacy_fw") {
            assert!(u.convertible);
            assert!(!un.iter().any(|u| u.route_key == "acme_vpn"), "a claimed key is never unassigned");
            break;
        }
        assert!(start.elapsed() < WAIT, "legacy_fw never listed as unassigned");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let file_before = std::fs::read(&env.tokens_file).unwrap();
    let tokens_before = tokens.list().await.unwrap();
    let converted = convert_unassigned(
        &pg,
        &sources,
        &tokens,
        ConvertUnassignedRequest {
            route_key: "legacy_fw".into(),
            name: Some("Legacy firewall".into()),
            credential_id: None,
            category: None,
            vendor: None,
            product: None,
        },
        None,
    )
    .await
    .expect("convert");
    assert_eq!(converted.log_source.lifecycle_status, "draft");
    assert_eq!(converted.log_source.match_values.as_deref(), Some(&["legacy_fw".to_string()][..]));
    assert_eq!(std::fs::read(&env.tokens_file).unwrap(), file_before, "tokens file changed");
    assert_eq!(tokens.list().await.unwrap(), tokens_before, "a token changed");
    assert_eq!(send_http(&env, &env.install, Some("legacy_fw"), "m-legacy-2").await, 200);
    assert_eq!(stored(&ch, "m-legacy-2").await["source_type"], "legacy_fw");
    let rows = activity.activity(24, &scope).await.unwrap();
    assert!(!unassigned_sources(&sources.list(None).await.unwrap(), &rows)
        .iter()
        .any(|u| u.route_key == "legacy_fw"));
    let status = connect_statuses(std::slice::from_ref(&converted.log_source), &rows, &[]).pop().unwrap();
    assert_eq!(status.state, ConnectState::ReceivingUnparsed);
    // A second conversion of the same key is refused.
    let again = convert_unassigned(
        &pg,
        &sources,
        &tokens,
        ConvertUnassignedRequest {
            route_key: "legacy_fw".into(),
            name: Some("dup".into()),
            credential_id: None,
            category: None,
            vendor: None,
            product: None,
        },
        None,
    )
    .await;
    assert!(again.is_err());
    println!("ok: unassigned legacy_fw converted; tokens file + tokens unchanged; sender still 200");

    // ---- 5. Unbound token -> converted source, same value. ------------------
    let temp = sources.create(draft("Temp app", "temp_app")).await.unwrap();
    let (orphan, orphan_value) = tokens.create("orphan-sender", temp.id, None).await.unwrap();
    sources.delete(temp.id).await.expect("delete source");
    tokens.publish().await.unwrap();
    assert_eq!(tokens.get(orphan.credential_id).await.unwrap().unwrap().state, "unbound");
    assert_eq!(eventually_status(401, || send_hec(&env, &orphan_value, json!("m-orphan-refused"))).await, 401);
    let converted = convert_unassigned(
        &pg,
        &sources,
        &tokens,
        ConvertUnassignedRequest {
            route_key: "orphan_app".into(),
            name: None,
            credential_id: Some(orphan.credential_id),
            category: None,
            vendor: None,
            product: None,
        },
        None,
    )
    .await
    .expect("convert with token");
    let bound = converted.bound_token.expect("bound token");
    assert_eq!(bound.credential_id, orphan.credential_id);
    assert_eq!(bound.token_prefix, orphan.token_prefix, "no rotation");
    assert_eq!(bound.state, "active");
    assert_eq!(eventually_status(200, || send_hec(&env, &orphan_value, json!("m-orphan-back"))).await, 200);
    assert_eq!(stored(&ch, "m-orphan-back").await["source_type"], "orphan_app");
    println!("ok: unbound token converted; same value accepted again, lands as orphan_app");

    // An active token cannot be re-assigned by a conversion.
    let refused = convert_unassigned(
        &pg,
        &sources,
        &tokens,
        ConvertUnassignedRequest {
            route_key: "steal_attempt".into(),
            name: None,
            credential_id: Some(credential.credential_id),
            category: None,
            vendor: None,
            product: None,
        },
        None,
    )
    .await;
    assert!(refused.is_err());
    assert!(sources.list(None).await.unwrap().iter().all(|s| s.name != "steal_attempt"), "refusal left a draft behind");
    println!("ok: an active token is never re-bound; nothing left behind");
}

fn convert_req(key: &str, name: &str, credential: Option<Uuid>) -> ConvertUnassignedRequest {
    ConvertUnassignedRequest {
        route_key: key.into(),
        name: Some(name.into()),
        credential_id: credential,
        category: None,
        vendor: None,
        product: None,
    }
}

/// Codex P1-2 + P2-4, against the same throwaway PG / ClickHouse (no Vector):
/// two "replicas" (separate pools and services) converting one key at once
/// produce exactly one source and bind only the winner's token; and a quiet
/// known source among 1,000 noisy unassigned keys still reads as receiving.
#[tokio::test]
#[ignore = "run by scripts/tests/onboarding-connect-e2e.sh"]
async fn conversions_serialise_across_replicas_and_quiet_sources_stay_visible() {
    let Some(env) = env() else {
        eprintln!("NAN4912_E2E_* not set; run scripts/tests/onboarding-connect-e2e.sh");
        return;
    };
    let replica = |dir: &str| {
        let mut config = DualPoolConfig::with_auth(
            env.database_url.clone(),
            env.ch_url.clone(),
            "nanosiem",
            "nanosiem",
            "nanosiem",
        );
        config.clickhouse_rawsql_password = Some("rawsql".into());
        config.clickhouse_rawsql_noaudit_password = Some("rawsql".into());
        let dir = env.vector_dir.join(dir);
        let tokens_file = env.tokens_file.clone();
        let metrics = env.metrics.clone();
        let install = env.install.clone();
        async move {
            let dual = DualPool::new(&config).await.expect("dual pool");
            let pg = dual.postgres().clone();
            let sources = LogSourceService::with_dual_pool_and_vector_config(
                &dual,
                Arc::new(VectorConfigManager::new(&dir)),
            );
            let tokens = IngestTokenService::with_paths(pg.clone(), tokens_file, metrics, Some(install));
            (dual, pg, sources, tokens)
        }
    };
    let (dual, pg_a, sources_a, tokens_a) = replica("replica-a").await;
    nanosiem_core::db::run_postgres_migrations(&pg_a).await.expect("migrations");
    let (_dual_b, pg_b, sources_b, tokens_b) = replica("replica-b").await;

    // Two unbound tokens (their source was deleted).
    let temp = sources_a.create(draft("Race temp", "race_temp")).await.unwrap();
    let (tok_a, _) = tokens_a.create("race-a", temp.id, None).await.unwrap();
    let (tok_b, _) = tokens_a.create("race-b", temp.id, None).await.unwrap();
    sources_a.delete(temp.id).await.unwrap();

    for round in 0..5 {
        let key = format!("race_fw_{round}");
        let (a, b) = tokio::join!(
            convert_unassigned(&pg_a, &sources_a, &tokens_a, convert_req(&key, &format!("Race A {round}"), (round == 0).then_some(tok_a.credential_id)), None),
            convert_unassigned(&pg_b, &sources_b, &tokens_b, convert_req(&key, &format!("Race B {round}"), (round == 0).then_some(tok_b.credential_id)), None),
        );
        let wins = [a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count();
        assert_eq!(wins, 1, "round {round}: exactly one conversion wins (a={a:?} b={b:?})");
        let loser = if a.is_ok() { b } else { a };
        assert!(matches!(loser, Err(ConvertError::AlreadyClaimed(_, _))), "round {round}: {loser:?}");
        let claimed = sources_a
            .list(None)
            .await
            .unwrap()
            .into_iter()
            .filter(|s| claimed_route_keys(std::slice::from_ref(s)).contains(&key))
            .count();
        assert_eq!(claimed, 1, "round {round}: one source claims {key}");
        if round == 0 {
            let a_state = tokens_a.get(tok_a.credential_id).await.unwrap().unwrap().state;
            let b_state = tokens_a.get(tok_b.credential_id).await.unwrap().unwrap().state;
            let mut states = vec![a_state, b_state];
            states.sort();
            assert_eq!(states, vec!["active".to_string(), "unbound".to_string()], "only the winner's token is bound");
        }
    }
    println!("ok: concurrent conversions on two replicas -> one source, loser AlreadyClaimed, loser token unbound (5 rounds)");

    // A quiet known source among 1,000 noisier unassigned keys.
    let quiet = sources_a.create(draft("Quiet app", "quiet_app")).await.unwrap();
    let ch = dual.clickhouse().clone();
    ch.query(
        "INSERT INTO nanosiem.logs (id, timestamp, source_type, message) \
         SELECT generateUUIDv4(), now64(6), concat('noisy_', toString(number % 1000)), 'n' \
         FROM numbers(2000)",
    )
    .execute()
    .await
    .expect("noise");
    ch.query("INSERT INTO nanosiem.logs (id, timestamp, source_type, message) VALUES (generateUUIDv4(), now64(6), 'quiet_app', 'q')")
        .execute()
        .await
        .expect("quiet event");
    let reader = SourceActivityReader::new(ch, dual.table_names());
    let scope = ScopeSet::unrestricted();
    let inventory = reader.activity(24, &scope).await.unwrap();
    assert_eq!(inventory.len(), 1000, "the inventory stays capped");
    assert!(!inventory.iter().any(|a| a.route_key == "quiet_app"), "quiet key is beyond the busiest 1,000");
    let all = sources_a.list(None).await.unwrap();
    let keys: Vec<String> = claimed_route_keys(&all).into_iter().collect();
    let known = reader.activity_for(&keys, 24, &scope).await.unwrap();
    let status = connect_statuses(std::slice::from_ref(&quiet), &known, &[]).pop().unwrap();
    assert_eq!(status.state, ConnectState::ReceivingUnparsed, "{status:?}");
    assert_eq!(status.events_24h, 1);
    println!("ok: quiet known source among 1,000 noisy keys reads receiving_unparsed");
}
