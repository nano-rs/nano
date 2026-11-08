// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933 (codex review P1s): the durable credential write fence.
//!
//! Proves on a live Postgres that retirement does not depend on membership
//! heartbeats: a writer still holding a retired key (a process paused past the
//! membership TTL, then resumed) is refused in its own transaction; a write in
//! flight when retirement starts makes retirement wait and then refuse; an
//! unregistered key cannot store secrets; a process whose ACTIVE key is
//! retired cannot register (boot is fatal), while a retired decrypt-only key
//! only warns; and every present secret column carries the fence trigger.
//! `#[ignore]`d: pg-integration lane only.
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use nanosiem_core::crypto::rotation::{self, CredentialKeyRepository, RotationError};
use nanosiem_core::crypto::EncryptionService;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

fn ring(active: &str, keys: &[(&str, u8)]) -> EncryptionService {
    let keys: Vec<_> = keys.iter().map(|(id, b)| json!({"id": id, "key": STANDARD.encode([*b; 32])})).collect();
    EncryptionService::from_config(&json!({"version": 1, "active": active, "keys": keys}).to_string()).unwrap()
}

/// A pool that declares `key` as its write key, like every api/jobs pool.
async fn writer_pool(key: &str) -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap();
    rotation::declare_write_key(PgPoolOptions::new().max_connections(3), key.to_owned())
        .connect(&url)
        .await
        .unwrap()
}

async fn insert_credential(pool: &PgPool, cipher: &EncryptionService, name: &str) -> Result<Uuid, sqlx::Error> {
    let sealed = cipher.encrypt_json(&json!({"secret_access_key": name})).unwrap();
    let (bytes, nonce) = sealed.to_bytea().unwrap();
    sqlx::query_scalar(
        "INSERT INTO cloud_credentials (name, provider, credentials_encrypted, nonce) VALUES ($1, 'aws_s3', $2, $3) RETURNING id",
    )
    .bind(name)
    .bind(bytes)
    .bind(nonce)
    .fetch_one(pool)
    .await
}

async fn cleanup(pool: &PgPool, prefix: &str, keys: &[&str], nodes: &[&str]) {
    sqlx::query("DELETE FROM cloud_credentials WHERE name LIKE $1").bind(format!("{prefix}%")).execute(pool).await.ok();
    for k in keys {
        sqlx::query("DELETE FROM credential_keys WHERE key_id = $1").bind(k).execute(pool).await.ok();
    }
    for n in nodes {
        sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(n).execute(pool).await.ok();
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn a_paused_writer_holding_a_retired_key_is_refused() {
    let pool = common::migrated_pool().await;
    let s = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_new) = (format!("wold-{s}"), format!("wnew-{s}"));
    let (node_old, node_new) = (format!("paused-{s}"), format!("current-{s}"));
    let repo = CredentialKeyRepository::new(pool.clone());
    let on_old = ring(&k_old, &[(&k_old, 1)]);
    let current = ring(&k_new, &[(&k_new, 2), (&k_old, 1)]);

    // The paused process registered with the old key, then stopped reporting.
    repo.register(&on_old, &node_old, "api").await.unwrap();
    let paused_writer = writer_pool(&k_old).await;
    repo.register(&current, &node_new, "jobs").await.unwrap();
    // Its membership aged out (simulated): heartbeats are not the authority.
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(&node_old).execute(&pool).await.unwrap();

    repo.retire(&current, &k_old, None).await.expect("nothing references the old key yet");

    // The process resumes and tries to store a secret under the retired key.
    let refused = insert_credential(&paused_writer, &on_old, &format!("wf-{s}-late")).await;
    let message = refused.expect_err("a write under a retired key must be refused").to_string();
    assert!(message.contains("retired"), "{message}");
    // Updates are fenced too, not only inserts.
    let new_writer = writer_pool(&k_new).await;
    let id = insert_credential(&new_writer, &current, &format!("wf-{s}-ok")).await.expect("current key writes");
    let stale = on_old.encrypt(b"late").unwrap().to_bytea().unwrap();
    let update = sqlx::query("UPDATE cloud_credentials SET credentials_encrypted = $2, nonce = $3 WHERE id = $1")
        .bind(id).bind(stale.0).bind(stale.1).execute(&paused_writer).await;
    assert!(update.is_err(), "an update under a retired key must be refused");
    // An unrelated column update on the same row is not a secret write.
    sqlx::query("UPDATE cloud_credentials SET description = 'touched' WHERE id = $1")
        .bind(id).execute(&paused_writer).await.expect("non-secret columns are not fenced");

    paused_writer.close().await;
    new_writer.close().await;
    cleanup(&pool, &format!("wf-{s}"), &[&k_old, &k_new], &[&node_old, &node_new]).await;
    common::reset_write_fence(&pool).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn retirement_waits_for_an_in_flight_writer_then_refuses() {
    let pool = common::migrated_pool().await;
    let s = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_new) = (format!("iold-{s}"), format!("inew-{s}"));
    let node = format!("inode-{s}");
    let repo = CredentialKeyRepository::new(pool.clone());
    let on_old = ring(&k_old, &[(&k_old, 3)]);
    let current = ring(&k_new, &[(&k_new, 4), (&k_old, 3)]);
    repo.register(&on_old, &format!("{node}-old"), "api").await.unwrap();
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(format!("{node}-old")).execute(&pool).await.unwrap();
    repo.register(&current, &node, "jobs").await.unwrap();

    // A writer on the old key is mid-transaction (its trigger holds FOR SHARE).
    let writer = writer_pool(&k_old).await;
    let mut tx = writer.begin().await.unwrap();
    let sealed = on_old.encrypt_json(&json!({"secret_access_key": "in-flight"})).unwrap().to_bytea().unwrap();
    sqlx::query("INSERT INTO cloud_credentials (name, provider, credentials_encrypted, nonce) VALUES ($1, 'aws_s3', $2, $3)")
        .bind(format!("if-{s}")).bind(sealed.0).bind(sealed.1).execute(&mut *tx).await.unwrap();

    let retire = {
        let repo = repo.clone();
        let current = current.clone();
        let k_old = k_old.clone();
        tokio::spawn(async move { repo.retire(&current, &k_old, None).await })
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!retire.is_finished(), "retirement must wait for the in-flight writer");
    tx.commit().await.unwrap();
    match retire.await.unwrap() {
        Err(RotationError::StillReferenced { count, .. }) => assert!(count >= 1),
        other => panic!("the committed write must block retirement, got {other:?}"),
    }

    writer.close().await;
    cleanup(&pool, &format!("if-{s}"), &[&k_old, &k_new], &[&node]).await;
    common::reset_write_fence(&pool).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn boot_refuses_a_retired_active_key_and_unregistered_keys_cannot_write() {
    let pool = common::migrated_pool().await;
    let s = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_new) = (format!("bold-{s}"), format!("bnew-{s}"));
    let node = format!("bnode-{s}");
    let repo = CredentialKeyRepository::new(pool.clone());
    let current = ring(&k_new, &[(&k_new, 6), (&k_old, 5)]);
    repo.register(&ring(&k_old, &[(&k_old, 5)]), &format!("{node}-old"), "api").await.unwrap();
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(format!("{node}-old")).execute(&pool).await.unwrap();
    repo.register(&current, &node, "jobs").await.unwrap();
    repo.retire(&current, &k_old, None).await.unwrap();

    // A rollback / stale secret selecting the retired key as active: fatal.
    let rolled_back = ring(&k_old, &[(&k_old, 5), (&k_new, 6)]);
    assert!(matches!(
        repo.register(&rolled_back, &format!("{node}-rollback"), "api").await,
        Err(RotationError::ActiveKeyRetired(id)) if id == k_old
    ));
    // Keeping the retired key only as decrypt-only is allowed (warning).
    repo.register(&current, &node, "jobs").await.expect("retired decrypt-only key is a warning");

    // A key that was never registered cannot store secrets.
    let unknown = format!("ghost-{s}");
    let ghost = writer_pool(&unknown).await;
    let err = insert_credential(&ghost, &ring(&unknown, &[(&unknown, 7)]), &format!("bf-{s}-ghost")).await.unwrap_err();
    assert!(err.to_string().contains("not registered"), "{err}");
    ghost.close().await;

    cleanup(&pool, &format!("bf-{s}"), &[&k_old, &k_new], &[&node]).await;
    common::reset_write_fence(&pool).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn every_present_secret_column_carries_the_write_fence() {
    let pool = common::migrated_pool().await;
    for target in rotation::TARGETS {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)",
        )
        .bind(target.table)
        .bind(target.column)
        .fetch_one(&pool)
        .await
        .unwrap();
        if !present {
            continue;
        }
        let fenced: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
              WHERE c.relname = $1 AND t.tgname = $2 AND NOT t.tgisinternal)",
        )
        .bind(target.table)
        .bind(format!("credential_write_fence_{}", target.column))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(fenced, "{} has no credential write fence trigger", target.name);
    }
}

/// Codex fence review P2: retirement's confirming scan runs on its own
/// transaction's connection, so a single-connection pool still retires.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn retirement_works_on_a_single_connection_pool() {
    let pool = common::migrated_pool().await;
    let s = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_new) = (format!("sold-{s}"), format!("snew-{s}"));
    let node = format!("snode-{s}");
    let current = ring(&k_new, &[(&k_new, 12), (&k_old, 11)]);
    CredentialKeyRepository::new(pool.clone()).register(&current, &node, "jobs").await.unwrap();
    let url = std::env::var("DATABASE_URL").unwrap();
    let one = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .unwrap();
    let repo = CredentialKeyRepository::new(one.clone());
    let report = tokio::time::timeout(Duration::from_secs(30), repo.retire(&current, &k_old, None))
        .await
        .expect("retirement must not starve waiting for a second connection")
        .expect("unreferenced key retires");
    assert_eq!(report.by_key.get(&k_old).copied().unwrap_or(0), 0);
    one.close().await;
    cleanup(&pool, &format!("sp-{s}"), &[&k_old, &k_new], &[&node]).await;
    common::reset_write_fence(&pool).await;
}
