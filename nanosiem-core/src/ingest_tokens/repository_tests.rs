// SPDX-License-Identifier: AGPL-3.0-or-later

//! DB-backed tests for the ingest token repository, service and migration 290.
//! They need a disposable PostgreSQL at `NANOSIEM_TEST_DATABASE_URL`; each test
//! creates a throwaway schema with a minimal `users` and `log_sources` and
//! applies migration 290 to it.

use std::path::PathBuf;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::{
    sha256_hex, TokenDelivery, IngestTokenRepository, IngestTokenRepositoryError, IngestTokenService,
    IngestTokenServiceError, InstallTokenMode, INSTALL_CREDENTIAL_ID, MULTIPLEX_ROUTE,
    PLATFORM_PULL_CREDENTIAL_ID,
};

const MIGRATION: &str = include_str!("../../../migrations/postgres/290_ingest_tokens.sql");
const APACHE: Uuid = Uuid::from_u128(0xa1);
const FIREWALL: Uuid = Uuid::from_u128(0xf1);
const OTLP: Uuid = Uuid::from_u128(0x07);
const KAFKA: Uuid = Uuid::from_u128(0x0c);

/// A schema with `users`, `log_sources` and `before` applied, then migration
/// 290. `None` when no test database is configured.
async fn pool_with(before: &str) -> Option<(PgPool, String)> {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
    let schema = format!("nan4907_{}", Uuid::new_v4().simple());
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
        .connect(&url)
        .await
        .expect("connect");
    let setup = format!(
        "CREATE SCHEMA {schema};
         CREATE TABLE {schema}.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), status TEXT);
         INSERT INTO {schema}.users (status) VALUES ('system');
         CREATE TABLE {schema}.log_sources (
             id UUID PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
             match_values TEXT[], enabled BOOLEAN NOT NULL DEFAULT TRUE,
             deployed BOOLEAN NOT NULL DEFAULT FALSE,
             created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());"
    );
    sqlx::raw_sql(&setup).execute(&pool).await.expect("setup");
    if !before.is_empty() {
        sqlx::raw_sql(before).execute(&pool).await.expect("pre-290 state");
    }
    sqlx::raw_sql(&MIGRATION.replace("SET LOCAL lock_timeout = '5s';", ""))
        .execute(&pool)
        .await
        .expect("migration 290");
    Some((pool, schema))
}

async fn drop_schema(pool: &PgPool, schema: &str) {
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(pool)
        .await
        .unwrap();
}

async fn add_source(pool: &PgPool, id: Uuid, name: &str, transport: &str, values: &[&str]) {
    sqlx::query("INSERT INTO log_sources (id, name, source_type, match_values) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(name)
        .bind(transport)
        .bind(values.iter().map(|v| v.to_string()).collect::<Vec<_>>())
        .execute(pool)
        .await
        .unwrap();
}

const PLATFORM: &str = "platform-secret-not-the-install-token";

fn service(pool: &PgPool, file: PathBuf, install: Option<&str>) -> IngestTokenService {
    IngestTokenService::with_paths(pool.clone(), file, String::new(), install.map(Into::into))
        .with_platform_token(Some(PLATFORM.into()))
}

fn read_file(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A fresh install (only the system user) starts strict; an upgrade (a real
/// user exists) starts in legacy multiplex mode. Re-running never changes it.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn migration_picks_the_install_token_mode() {
    let Some((fresh, fresh_schema)) = pool_with("").await else {
        return;
    };
    let repo = IngestTokenRepository::new(fresh.clone());
    assert_eq!(repo.settings().await.unwrap().install_token_mode, InstallTokenMode::Strict);
    drop_schema(&fresh, &fresh_schema).await;

    let (upgraded, schema) = pool_with("INSERT INTO users (status) VALUES ('active');")
        .await
        .unwrap();
    let repo = IngestTokenRepository::new(upgraded.clone());
    let settings = repo.settings().await.unwrap();
    assert_eq!(settings.install_token_mode, InstallTokenMode::LegacyMultiplex);
    assert!(settings.install_token_enabled);
    sqlx::raw_sql(&MIGRATION.replace("SET LOCAL lock_timeout = '5s';", ""))
        .execute(&upgraded)
        .await
        .expect("idempotent");
    assert_eq!(
        repo.settings().await.unwrap().install_token_mode,
        InstallTokenMode::LegacyMultiplex
    );
    drop_schema(&upgraded, &schema).await;
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn lifecycle_binds_rotates_and_revokes() {
    let Some((pool, schema)) = pool_with("").await else {
        return;
    };
    add_source(&pool, APACHE, "Apache", "routed", &["apache_access", "apache"]).await;
    add_source(&pool, FIREWALL, "Palo Alto", "splunk_hec", &[]).await;
    add_source(&pool, KAFKA, "Kafka feed", "kafka", &["kafka_feed"]).await;
    add_source(&pool, Uuid::from_u128(0xe1), "Enrich", "routed", &["nano_enrich"]).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ingest-tokens/tokens.json");
    let svc = service(&pool, file.clone(), Some("install-secret"));
    let repo = IngestTokenRepository::new(pool.clone());

    // Pulled sources and the internal enrichment lane are never bindable.
    let sources = svc.bindable_sources().await.unwrap();
    assert_eq!(sources.len(), 2);
    assert!(matches!(
        svc.create("kafka", KAFKA, None).await,
        Err(IngestTokenServiceError::InvalidSource(_))
    ));

    // Two sources, two tokens, both in the file with their route keys.
    let (apache, apache_value) = svc.create("edge-01", APACHE, None).await.unwrap();
    let (fw, _fw_value) = svc.create("fw-01", FIREWALL, None).await.unwrap();
    assert_eq!(apache.state, "active");
    assert_eq!(apache.route_key.as_deref(), Some("apache_access"));
    assert_eq!(fw.route_key.as_deref(), Some("palo_alto"));
    let doc = read_file(&file);
    assert_eq!(doc["fallback_enabled"], false, "install token configured: no static fallback");
    let routes: Vec<(String, String)> = doc["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["id"].as_str().unwrap().to_string(), t["name"].as_str().unwrap().to_string()))
        .collect();
    assert!(routes.contains(&(apache.credential_id.to_string(), "apache_access".into())));
    assert!(routes.contains(&(fw.credential_id.to_string(), "palo_alto".into())));
    assert!(routes.contains(&(PLATFORM_PULL_CREDENTIAL_ID.to_string(), MULTIPLEX_ROUTE.into())));
    // Fresh install: strict and unbound, so the install token is not listed.
    assert!(!routes.iter().any(|(id, _)| *id == INSTALL_CREDENTIAL_ID.to_string()));
    // Hashes only, never the value.
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains(&sha256_hex(&apache_value)));
    assert!(!text.contains(&apache_value));

    // Names are unique among active tokens, case-insensitively.
    assert!(matches!(
        svc.create("EDGE-01", FIREWALL, None).await,
        Err(IngestTokenServiceError::Repository(IngestTokenRepositoryError::DuplicateName(_)))
    ));

    // Rotation: same name and source, new value; the old one is revoked and
    // leaves the file.
    let (old, new, new_value) = svc.rotate(apache.credential_id, None).await.unwrap();
    assert_eq!(old.state, "revoked");
    assert_eq!(new.state, "active");
    assert_eq!(new.name, "edge-01");
    assert_eq!(new.source_id, Some(APACHE));
    assert_eq!(new.rotated_from, Some(apache.credential_id));
    assert_ne!(new_value, apache_value);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains(&sha256_hex(&apache_value)));
    assert!(text.contains(&sha256_hex(&new_value)));
    assert!(matches!(
        svc.rotate(apache.credential_id, None).await,
        Err(IngestTokenServiceError::AlreadyRevoked)
    ));

    // Revoke one: the other stays listed.
    svc.revoke(new.credential_id, None).await.unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains(&new.credential_id.to_string()));
    assert!(text.contains(&fw.credential_id.to_string()));
    assert!(matches!(
        svc.revoke(new.credential_id, None).await,
        Err(IngestTokenServiceError::AlreadyRevoked)
    ));

    // Deleting a source unbinds its token (out of the file, bindable again);
    // a bound token is never rebound.
    assert!(matches!(
        svc.bind(fw.credential_id, APACHE, None).await,
        Err(IngestTokenServiceError::AlreadyBound)
    ));
    sqlx::query("DELETE FROM log_sources WHERE id = $1")
        .bind(FIREWALL)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(repo.get(fw.credential_id).await.unwrap().unwrap().state, "unbound");
    svc.publish().await.unwrap();
    assert!(!std::fs::read_to_string(&file).unwrap().contains(&fw.credential_id.to_string()));
    assert!(matches!(
        svc.rotate(fw.credential_id, None).await,
        Err(IngestTokenServiceError::NotRotatable)
    ));
    let rebound = svc.bind(fw.credential_id, APACHE, None).await.unwrap();
    assert_eq!(rebound.route_key.as_deref(), Some("apache_access"));

    // Request counts accumulate from Vector's counter; resets and repeated
    // samples never double count; last_used never moves back.
    let id = rebound.credential_id;
    let now = Utc::now();
    assert_eq!(repo.record_usage(&[(id, 5.0)], now).await.unwrap(), 1);
    assert_eq!(repo.record_usage(&[(id, 5.0)], now).await.unwrap(), 0);
    assert_eq!(repo.record_usage(&[(id, 8.0)], now).await.unwrap(), 1);
    assert_eq!(repo.record_usage(&[(id, 2.0)], now).await.unwrap(), 1);
    repo.record_usage(&[(id, 3.0)], now - chrono::Duration::minutes(5))
        .await
        .unwrap();
    let token = repo.get(id).await.unwrap().unwrap();
    assert_eq!(token.request_count, 5 + 3 + 2 + 1);
    assert_eq!(
        token.last_used_at.map(|t| t.timestamp_micros()),
        Some(now.timestamp_micros())
    );

    // The token hash is never in a listed row.
    let listed = serde_json::to_string(&svc.list().await.unwrap()).unwrap();
    assert!(!listed.contains(&sha256_hex(&new_value)));
    drop_schema(&pool, &schema).await;
}

/// Legacy multiplex -> bound -> disabled, as rendered into the file.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn install_token_modes_render_into_the_file() {
    let Some((pool, schema)) = pool_with("INSERT INTO users (status) VALUES ('active');").await
    else {
        return;
    };
    add_source(&pool, APACHE, "Apache", "routed", &["apache_access"]).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tokens.json");
    let svc = service(&pool, file.clone(), Some("install-secret"));
    let install_entry = |doc: &serde_json::Value| -> Option<String> {
        doc["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == INSTALL_CREDENTIAL_ID.to_string())
            .map(|t| {
                assert_eq!(t["sha256"], sha256_hex("install-secret"));
                t["name"].as_str().unwrap().to_string()
            })
    };

    svc.publish().await.unwrap();
    assert_eq!(install_entry(&read_file(&file)).as_deref(), Some(MULTIPLEX_ROUTE));

    let settings = svc.bind_install_token(APACHE, None).await.unwrap();
    assert_eq!(settings.install_token_mode, InstallTokenMode::Strict);
    assert_eq!(install_entry(&read_file(&file)).as_deref(), Some("apache_access"));
    assert!(matches!(
        svc.bind_install_token(APACHE, None).await,
        Err(IngestTokenServiceError::AlreadyBound)
    ));

    svc.set_install_token_enabled(false, None).await.unwrap();
    assert_eq!(install_entry(&read_file(&file)), None);
    svc.set_install_token_enabled(true, None).await.unwrap();
    assert_eq!(install_entry(&read_file(&file)).as_deref(), Some("apache_access"));

    // No install token: the static fallback is the only gate (opt-in).
    let bare = service(&pool, dir.path().join("bare.json"), None);
    bare.publish().await.unwrap();
    let doc = read_file(&dir.path().join("bare.json"));
    assert_eq!(doc["fallback_enabled"], true);
    assert!(install_entry(&doc).is_none());
    drop_schema(&pool, &schema).await;
}

/// Leaving legacy multiplex mode without binding refuses the install token.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn leaving_legacy_mode_unbound_refuses_the_install_token() {
    let Some((pool, schema)) = pool_with("INSERT INTO users (status) VALUES ('active');").await
    else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tokens.json");
    let svc = service(&pool, file.clone(), Some("install-secret"));
    svc.set_install_token_strict(None).await.unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains(&INSTALL_CREDENTIAL_ID.to_string()));
    assert!(text.contains(&PLATFORM_PULL_CREDENTIAL_ID.to_string()));
    drop_schema(&pool, &schema).await;
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn otlp_authentication_lifecycle() {
    let Some((pool, schema)) = pool_with("").await else {
        return;
    };
    add_source(&pool, OTLP, "OTLP logs", "otlp", &["otlp_log"]).await;
    let dir = tempfile::tempdir().unwrap();
    let svc = service(&pool, dir.path().join("t.json"), Some("synthetic-install"));
    let (token, value) = svc.create("otlp sender", OTLP, None).await.unwrap();
    assert!(svc.authenticate_otlp("wrong").await.unwrap().is_none());
    let authenticated = svc.authenticate_otlp(&value).await.unwrap().unwrap();
    assert_eq!(authenticated.id, token.credential_id);
    assert_eq!(authenticated.route, "otlp_log");
    // The unbound install token is refused; once bound, accepted.
    assert!(svc.authenticate_otlp("synthetic-install").await.unwrap().is_none());
    svc.bind_install_token(OTLP, None).await.unwrap();
    assert_eq!(
        svc.authenticate_otlp("synthetic-install").await.unwrap().unwrap().id,
        INSTALL_CREDENTIAL_ID
    );
    svc.set_install_token_enabled(false, None).await.unwrap();
    assert!(svc.authenticate_otlp("synthetic-install").await.unwrap().is_none());
    // NAN-4922: an undeployed (draft) source receives before its parser
    // exists, so its tokens authenticate even while `enabled` is false.
    sqlx::query("UPDATE log_sources SET enabled = false, deployed = false WHERE id = $1")
        .bind(OTLP)
        .execute(&pool)
        .await
        .unwrap();
    assert!(svc.authenticate_otlp(&value).await.unwrap().is_some());
    // A disabled deployed source refuses its tokens; re-enabled, accepts again.
    sqlx::query("UPDATE log_sources SET enabled = false, deployed = true WHERE id = $1")
        .bind(OTLP)
        .execute(&pool)
        .await
        .unwrap();
    assert!(svc.authenticate_otlp(&value).await.unwrap().is_none());
    sqlx::query("UPDATE log_sources SET enabled = true WHERE id = $1")
        .bind(OTLP)
        .execute(&pool)
        .await
        .unwrap();
    assert!(svc.authenticate_otlp(&value).await.unwrap().is_some());
    svc.revoke(token.credential_id, None).await.unwrap();
    assert!(svc.authenticate_otlp(&value).await.unwrap().is_none());
    drop_schema(&pool, &schema).await;
}

/// P2-7: any sign of a pre-existing deployment selects legacy multiplex, even
/// with no human user left.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn migration_detects_pre_existing_deployments_without_users() {
    for (signal, before) in [
        ("old migration", "CREATE TABLE _sqlx_migrations (version BIGINT, installed_on TIMESTAMPTZ);
          INSERT INTO _sqlx_migrations VALUES (1, NOW() - interval '3 days');"),
        ("old log source", "INSERT INTO log_sources (id, name, source_type, created_at)
          VALUES (gen_random_uuid(), 'old', 'routed', NOW() - interval '2 hours');"),
        ("deployment record", "CREATE TABLE log_source_deployments (id INT); INSERT INTO log_source_deployments VALUES (1);"),
        ("old source config", "CREATE TABLE source_configurations (created_at TIMESTAMPTZ);
          INSERT INTO source_configurations VALUES (NOW() - interval '1 day');"),
    ] {
        let Some((pool, schema)) = pool_with(before).await else {
            return;
        };
        let mode = IngestTokenRepository::new(pool.clone()).settings().await.unwrap().install_token_mode;
        assert_eq!(mode, InstallTokenMode::LegacyMultiplex, "{signal}");
        drop_schema(&pool, &schema).await;
    }
    // Freshly seeded rows (a fresh install) stay strict.
    let (pool, schema) = pool_with(
        "CREATE TABLE _sqlx_migrations (version BIGINT, installed_on TIMESTAMPTZ);
         INSERT INTO _sqlx_migrations VALUES (1, NOW() - interval '2 minutes');
         INSERT INTO log_sources (id, name, source_type) VALUES (gen_random_uuid(), 'seed', 'routed');",
    )
    .await
    .unwrap();
    let mode = IngestTokenRepository::new(pool.clone()).settings().await.unwrap().install_token_mode;
    assert_eq!(mode, InstallTokenMode::Strict);
    drop_schema(&pool, &schema).await;
}

/// P1-5: a rotation whose replacement cannot be published changes nothing:
/// the old token stays active and listed in Vector's file, no replacement
/// survives, and a later rotation works.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn rotation_with_a_failing_publisher_keeps_the_old_token() {
    let Some((pool, schema)) = pool_with("").await else {
        return;
    };
    add_source(&pool, APACHE, "Apache", "routed", &["apache_access"]).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tokens.json");
    let good = service(&pool, file.clone(), Some("install-secret"));
    let (token, value) = good.create("edge", APACHE, None).await.unwrap();
    // A publisher that cannot write: its directory is a regular file.
    std::fs::write(dir.path().join("blocked"), b"x").unwrap();
    let failing = service(&pool, dir.path().join("blocked/tokens.json"), Some("install-secret"));
    assert!(matches!(
        failing.rotate(token.credential_id, None).await,
        Err(IngestTokenServiceError::Publish { .. })
    ));
    let repo = IngestTokenRepository::new(pool.clone());
    assert_eq!(repo.get(token.credential_id).await.unwrap().unwrap().state, "active");
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM ingest_tokens WHERE rotation_pending")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 0, "the replacement was rolled back");
    assert_eq!(good.list().await.unwrap().len(), 1);
    good.publish().await.unwrap();
    assert!(std::fs::read_to_string(&file).unwrap().contains(&sha256_hex(&value)));

    // The healthy publisher rotates; a crash-left pending row is purged.
    let (_, new, new_value) = good.rotate(token.credential_id, None).await.unwrap();
    assert_eq!(new.state, "active");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains(&sha256_hex(&new_value)) && !text.contains(&sha256_hex(&value)));
    let stray = super::generate_token();
    repo.rotate_begin(new.credential_id, &stray.prefix, &stray.sha256_hex, None)
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE ingest_tokens SET created_at = NOW() - interval '1 hour' WHERE rotation_pending")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(repo.purge_stale_pending(super::ROTATION_PENDING_TTL).await.unwrap(), 1);
    drop_schema(&pool, &schema).await;
}

/// P1-3: without a configured delivery path, nothing is issued (no false
/// success) and no file is written; revoking still works.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn no_delivery_refuses_to_issue_tokens() {
    let Some((pool, schema)) = pool_with("").await else {
        return;
    };
    add_source(&pool, APACHE, "Apache", "routed", &["apache_access"]).await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tokens.json");
    let good = service(&pool, file.clone(), Some("install-secret"));
    let (token, _) = good.create("edge", APACHE, None).await.unwrap();
    std::fs::remove_file(&file).unwrap();
    let undelivered = service(&pool, file.clone(), Some("install-secret")).with_delivery(TokenDelivery::None);
    assert!(matches!(
        undelivered.create("other", APACHE, None).await,
        Err(IngestTokenServiceError::DeliveryNotConfigured)
    ));
    assert!(matches!(
        undelivered.rotate(token.credential_id, None).await,
        Err(IngestTokenServiceError::DeliveryNotConfigured)
    ));
    assert!(matches!(
        undelivered.bind_install_token(APACHE, None).await,
        Err(IngestTokenServiceError::DeliveryNotConfigured)
    ));
    assert!(!undelivered.publish().await.unwrap());
    assert!(!file.exists(), "no file without a delivery path");
    undelivered.revoke(token.credential_id, None).await.unwrap();
    assert_eq!(undelivered.list().await.unwrap().len(), 1);
    drop_schema(&pool, &schema).await;
}

/// P1-2: the platform credential is its own secret, listed by its hash; the
/// install token's hash never gets the multiplex route in strict mode.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn platform_credential_is_independent_of_the_install_token() {
    let Some((pool, schema)) = pool_with("").await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tokens.json");
    service(&pool, file.clone(), Some("install-secret")).publish().await.unwrap();
    let doc = read_file(&file);
    let tokens = doc["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["id"], PLATFORM_PULL_CREDENTIAL_ID.to_string());
    assert_eq!(tokens[0]["sha256"], sha256_hex(PLATFORM));
    assert!(!std::fs::read_to_string(&file).unwrap().contains(&sha256_hex("install-secret")));
    drop_schema(&pool, &schema).await;
}


/// NAN-4973: the `http` delivery (Helm chart) issues tokens without writing a
/// file, and `render_current` returns exactly what `shared_volume` would have
/// written for the same state. Any other delivery refuses to render.
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn http_delivery_renders_what_the_file_would_hold() {
    let Some((pool, schema)) = pool_with("").await else {
        return;
    };
    add_source(&pool, APACHE, "Apache", "routed", &["apache_access"]).await;
    let dir = tempfile::tempdir().unwrap();
    let http_file = dir.path().join("never-written.json");
    let http = service(&pool, http_file.clone(), Some("install-secret")).with_delivery(TokenDelivery::Http);
    let (token, _) = http.create("edge", APACHE, None).await.unwrap();
    assert!(!http_file.exists(), "http delivery writes no file");
    assert!(!http.publish().await.unwrap());

    let rendered = http.render_current().await.unwrap();
    let shared_file = dir.path().join("tokens.json");
    let shared = service(&pool, shared_file.clone(), Some("install-secret"));
    shared.publish().await.unwrap();
    assert_eq!(rendered, std::fs::read_to_string(&shared_file).unwrap());
    let doc: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert!(
        doc["tokens"].as_array().unwrap().iter().any(|t| t["id"] == token.credential_id.to_string()),
        "the issued token is listed: {doc}"
    );

    assert!(matches!(
        shared.render_current().await,
        Err(IngestTokenServiceError::DeliveryNotConfigured)
    ));
    drop_schema(&pool, &schema).await;
}
