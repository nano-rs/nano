// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live-Postgres regression for NAN-5147: moving a source config that uses a
//! stored credential to a different broker/endpoint needs `credentials:edit`,
//! not just `credentials:use`.
//!
//! Run with:
//! `NANOSIEM_ALLOW_DEFAULT_KEYS=true cargo test -p nanosiem-core \
//!   --test source_config_credential_retarget_integration -- --ignored`

mod common;

use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::source_configs::{
    NewSourceConfiguration, SourceConfigService, SourceConfigServiceError,
    UpdateSourceConfiguration,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const BROKERS: &str = "kafka-1.corp.example:9093,kafka-2.corp.example:9093";

/// Editor-like: credentials:use without credentials:edit.
fn editor() -> CredentialUseGrant {
    CredentialUseGrant::granted().with_credential_edit(false)
}

/// Admin-like / credential owner: credentials:use and credentials:edit.
fn admin() -> CredentialUseGrant {
    CredentialUseGrant::granted().with_credential_edit(true)
}

async fn seed(pool: &PgPool) -> (Uuid, Uuid) {
    let suffix = Uuid::now_v7().simple().to_string();
    let credential_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cloud_credentials (id, name, provider, credentials_encrypted, nonce)
         VALUES ($1, $2, 'kafka', $3, 'intentionally-invalid')",
    )
    .bind(credential_id)
    .bind(format!("nan5147-credential-{suffix}"))
    .bind(vec![0_u8])
    .execute(pool)
    .await
    .expect("insert credential fixture");

    let config_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO source_configurations
            (id, name, description, config_type, connection_config,
             credential_id, enabled, deployed)
         VALUES ($1, $2, 'original', 'kafka', $3, $4, TRUE, FALSE)",
    )
    .bind(config_id)
    .bind(format!("nan5147-source-{suffix}"))
    .bind(json!({"bootstrap_servers": BROKERS, "group_id": "nano", "topics": ["events"]}))
    .bind(credential_id)
    .execute(pool)
    .await
    .expect("insert credential-bound kafka config");
    (config_id, credential_id)
}

async fn stored_conn(pool: &PgPool, id: Uuid) -> Value {
    sqlx::query_scalar("SELECT connection_config FROM source_configurations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read connection_config")
}

async fn cleanup(pool: &PgPool, config_id: Uuid, credential_id: Uuid) {
    sqlx::query("DELETE FROM source_configurations WHERE id = $1")
        .bind(config_id)
        .execute(pool)
        .await
        .expect("clean source fixture");
    sqlx::query("DELETE FROM cloud_credentials WHERE id = $1")
        .bind(credential_id)
        .execute(pool)
        .await
        .expect("clean credential fixture");
}

fn retarget(brokers: &str) -> UpdateSourceConfiguration {
    UpdateSourceConfiguration {
        connection_config: Some(json!({
            "bootstrap_servers": brokers,
            "group_id": "nano",
            "topics": ["events"],
        })),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn editor_cannot_move_bound_credential_to_another_broker() {
    let pool = common::migrated_pool().await;
    let (config_id, credential_id) = seed(&pool).await;
    let service = SourceConfigService::new(pool.clone());

    let err = service
        .update(config_id, retarget("broker.elsewhere.example:9093"), editor())
        .await
        .expect_err("an Editor must not repoint a bound credential");
    assert!(
        matches!(err, SourceConfigServiceError::CredentialRetargetRequired),
        "got {err:?}"
    );
    assert_eq!(stored_conn(&pool, config_id).await["bootstrap_servers"], BROKERS);

    // Re-sending the same credential id is not a way around the check.
    let mut rebind = retarget("broker.elsewhere.example:9093");
    rebind.credential_id = Some(credential_id);
    let err = service
        .update(config_id, rebind, editor())
        .await
        .expect_err("echoing the bound credential id does not authorize a move");
    assert!(matches!(err, SourceConfigServiceError::CredentialRetargetRequired));
    assert_eq!(stored_conn(&pool, config_id).await["bootstrap_servers"], BROKERS);

    cleanup(&pool, config_id, credential_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn credential_editor_can_move_bound_credential() {
    let pool = common::migrated_pool().await;
    let (config_id, credential_id) = seed(&pool).await;
    let service = SourceConfigService::new(pool.clone());

    let updated = service
        .update(config_id, retarget("kafka-new.corp.example:9093"), admin())
        .await
        .expect("credentials:edit holder may move the source");
    assert_eq!(
        updated.connection_config["bootstrap_servers"],
        "kafka-new.corp.example:9093"
    );

    cleanup(&pool, config_id, credential_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn editor_non_host_edits_still_work() {
    let pool = common::migrated_pool().await;
    let (config_id, credential_id) = seed(&pool).await;
    let service = SourceConfigService::new(pool.clone());

    // Description-only edit, echoing the bound credential id back the way the
    // UI's read-modify-write does.
    service
        .update(
            config_id,
            UpdateSourceConfiguration {
                description: Some("edited by editor".to_string()),
                credential_id: Some(credential_id),
                ..Default::default()
            },
            editor(),
        )
        .await
        .expect("non-connection edit by an Editor");

    // Connection edit that keeps the same brokers (reordered) but changes topics.
    let updated = service
        .update(
            config_id,
            UpdateSourceConfiguration {
                connection_config: Some(json!({
                    "bootstrap_servers": "kafka-2.corp.example:9093, kafka-1.corp.example:9093",
                    "group_id": "nano-2",
                    "topics": ["events", "audit"],
                })),
                ..Default::default()
            },
            editor(),
        )
        .await
        .expect("same-host connection edit by an Editor");
    assert_eq!(updated.description.as_deref(), Some("edited by editor"));
    assert_eq!(updated.connection_config["group_id"], "nano-2");

    cleanup(&pool, config_id, credential_id).await;
}

async fn seed_credentialless(pool: &PgPool, brokers: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO source_configurations
            (id, name, description, config_type, connection_config, enabled, deployed)
         VALUES ($1, $2, 'no credential', 'kafka', $3, TRUE, FALSE)",
    )
    .bind(id)
    .bind(format!("nan5147-plain-{}", Uuid::now_v7().simple()))
    .bind(json!({"bootstrap_servers": brokers, "group_id": "nano", "topics": ["events"]}))
    .execute(pool)
    .await
    .expect("insert credential-less kafka config");
    id
}

fn new_kafka_with_credential(credential_id: Uuid, brokers: &str) -> NewSourceConfiguration {
    NewSourceConfiguration {
        name: format!("nan5147-new-{}", Uuid::now_v7().simple()),
        description: None,
        config_type: "kafka".to_string(),
        connection_config: json!({"bootstrap_servers": brokers, "group_id": "nano", "topics": ["events"]}),
        credential_id: Some(credential_id),
        default_source_type: None,
        routing_rules: None,
    }
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn editor_cannot_create_a_config_bound_to_a_stored_credential() {
    let pool = common::migrated_pool().await;
    let (seed_config, credential_id) = seed(&pool).await;
    let service = SourceConfigService::new(pool.clone());

    let request = new_kafka_with_credential(credential_id, "broker.elsewhere.example:9093");
    let name = request.name.clone();
    let err = service
        .create(request, editor())
        .await
        .expect_err("an Editor must not bind a stored credential on create");
    assert!(matches!(err, SourceConfigServiceError::CredentialRetargetRequired), "got {err:?}");
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM source_configurations WHERE name = $1")
            .bind(&name)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(persisted, 0);

    let created = service
        .create(new_kafka_with_credential(credential_id, BROKERS), admin())
        .await
        .expect("credentials:edit holder may create a bound config");
    assert_eq!(created.credential_id, Some(credential_id));

    sqlx::query("DELETE FROM source_configurations WHERE id = $1")
        .bind(created.id)
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, seed_config, credential_id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn editor_cannot_bind_a_credential_to_an_existing_config() {
    let pool = common::migrated_pool().await;
    let (seed_config, credential_id) = seed(&pool).await;
    let service = SourceConfigService::new(pool.clone());

    // Host first (no credential, so no gate), then bind only the credential.
    let plain = seed_credentialless(&pool, "broker.elsewhere.example:9093").await;
    let err = service
        .update(
            plain,
            UpdateSourceConfiguration {
                credential_id: Some(credential_id),
                ..Default::default()
            },
            editor(),
        )
        .await
        .expect_err("binding a credential needs credentials:edit");
    assert!(matches!(err, SourceConfigServiceError::CredentialRetargetRequired), "got {err:?}");
    let bound: Option<Uuid> =
        sqlx::query_scalar("SELECT credential_id FROM source_configurations WHERE id = $1")
            .bind(plain)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bound, None, "credential not bound");

    let updated = service
        .update(
            plain,
            UpdateSourceConfiguration {
                credential_id: Some(credential_id),
                ..Default::default()
            },
            admin(),
        )
        .await
        .expect("credentials:edit holder may bind");
    assert_eq!(updated.credential_id, Some(credential_id));

    sqlx::query("DELETE FROM source_configurations WHERE id = $1")
        .bind(plain)
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, seed_config, credential_id).await;
}
