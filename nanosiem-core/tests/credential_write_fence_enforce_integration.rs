// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933 (codex fence review P1): the credential write fence fails closed
//! for sessions that declare no key, once enforced (migration 306).
//!
//! Its own test binary with ONE test: it owns the global enforcement flag.
//! Proves rollout mode (undeclared writes still allowed, so old pods keep
//! working during a rolling deploy), that enforcing waits for an in-flight
//! undeclared write, that afterwards an undeclared secret write is refused
//! while declared writers keep working, and that the first retirement
//! enforces automatically. Restores rollout mode for later suites.
//! `#[ignore]`d: pg-integration lane only.
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use nanosiem_core::crypto::rotation::CredentialKeyRepository;
use nanosiem_core::crypto::EncryptionService;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

fn ring(active: &str, keys: &[(&str, u8)]) -> EncryptionService {
    let keys: Vec<_> = keys.iter().map(|(id, b)| json!({"id": id, "key": STANDARD.encode([*b; 32])})).collect();
    EncryptionService::from_config(&json!({"version": 1, "active": active, "keys": keys}).to_string()).unwrap()
}

fn sealed(cipher: &EncryptionService, value: &str) -> (Vec<u8>, String) {
    cipher.encrypt_json(&json!({"secret_access_key": value})).unwrap().to_bytea().unwrap()
}

async fn insert(pool: &PgPool, cipher: &EncryptionService, name: &str) -> Result<(), sqlx::Error> {
    let (bytes, nonce) = sealed(cipher, name);
    sqlx::query("INSERT INTO cloud_credentials (name, provider, credentials_encrypted, nonce) VALUES ($1, 'aws_s3', $2, $3)")
        .bind(name)
        .bind(bytes)
        .bind(nonce)
        .execute(pool)
        .await
        .map(|_| ())
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn undeclared_writers_are_refused_once_enforced() {
    let pool = common::migrated_pool().await;
    common::reset_write_fence(&pool).await;
    let s = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_new) = (format!("eold-{s}"), format!("enew-{s}"));
    let node = format!("enode-{s}");
    let repo = CredentialKeyRepository::new(pool.clone());
    let current = ring(&k_new, &[(&k_new, 2), (&k_old, 1)]);
    repo.register(&current, &node, "jobs").await.unwrap();
    let declared = common::declared_pool(&k_new).await;
    assert!(!repo.fence_enforced().await.unwrap(), "installed in rollout mode");

    // Rollout mode: a pre-upgrade pod (undeclared session) can still write.
    insert(&pool, &current, &format!("ef-{s}-rollout")).await.expect("undeclared write allowed before enforcement");

    // An undeclared write in flight blocks enforcement until it commits.
    let mut tx = pool.begin().await.unwrap();
    let (bytes, nonce) = sealed(&current, "in-flight");
    sqlx::query("INSERT INTO cloud_credentials (name, provider, credentials_encrypted, nonce) VALUES ($1, 'aws_s3', $2, $3)")
        .bind(format!("ef-{s}-inflight")).bind(bytes).bind(nonce).execute(&mut *tx).await.unwrap();
    let enforce = {
        let repo = repo.clone();
        tokio::spawn(async move { repo.enforce_fence("test").await })
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!enforce.is_finished(), "enforcement must wait for the in-flight undeclared write");
    tx.commit().await.unwrap();
    assert!(enforce.await.unwrap().unwrap(), "this call flipped the fence");
    assert!(repo.fence_enforced().await.unwrap());

    // Enforced: undeclared secret writes are refused (insert and update)...
    let err = insert(&pool, &current, &format!("ef-{s}-late")).await.unwrap_err().to_string();
    assert!(err.contains("declares no credential key"), "{err}");
    let (bytes, nonce) = sealed(&current, "late-update");
    let update = sqlx::query("UPDATE cloud_credentials SET credentials_encrypted = $2, nonce = $3 WHERE name = $1")
        .bind(format!("ef-{s}-rollout")).bind(bytes).bind(nonce).execute(&pool).await;
    assert!(update.is_err(), "undeclared secret update refused");
    // ...non-secret columns are not, and declared writers still write.
    sqlx::query("UPDATE cloud_credentials SET description = 'touched' WHERE name = $1")
        .bind(format!("ef-{s}-rollout")).execute(&pool).await.expect("non-secret update allowed");
    insert(&declared, &current, &format!("ef-{s}-declared")).await.expect("declared writer still writes");
    assert!(!repo.enforce_fence("again").await.unwrap(), "one-way: already enforced");

    // A retirement REFUSED by its prechecks (a live process still writes
    // with the key) enforces nothing.
    common::reset_write_fence(&pool).await;
    let lagging = format!("{node}-lagging");
    repo.register(&ring(&k_old, &[(&k_old, 1)]), &lagging, "api").await.unwrap();
    assert!(repo.retire(&current, &k_old, None).await.is_err());
    assert!(!repo.fence_enforced().await.unwrap(), "a refused retirement must not enforce");
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(&lagging).execute(&pool).await.unwrap();

    // The first successful retirement enforces by itself.
    repo.retire(&current, &k_old, None).await.expect("unreferenced old key retires");
    assert!(repo.fence_enforced().await.unwrap(), "retirement enforces the fence");

    sqlx::query("DELETE FROM cloud_credentials WHERE name LIKE $1").bind(format!("ef-{s}%")).execute(&pool).await.ok();
    for k in [&k_old, &k_new] {
        sqlx::query("DELETE FROM credential_keys WHERE key_id = $1").bind(k).execute(&pool).await.ok();
    }
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(&node).execute(&pool).await.ok();
    common::reset_write_fence(&pool).await;
}
