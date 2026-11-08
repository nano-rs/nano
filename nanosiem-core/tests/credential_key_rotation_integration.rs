// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933: online credential key rotation against a live Postgres.
//!
//! Seeds secrets in two storage shapes (BYTEA + nonce column, JSON-in-BYTEA)
//! under an old key, rotates the ring, and proves: mixed-key rows all open,
//! the re-wrap moves every row to the active key (and is idempotent), an old
//! key that is still referenced or still active somewhere cannot be retired,
//! a re-used key id with different material is refused, and once nothing
//! references the old key it retires and the rows open without it.
//!
//! `#[ignore]`d: runs in the pg-integration lane (`-- --ignored`) with
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1` against a throwaway database.
mod common;

use base64::{engine::general_purpose::STANDARD, Engine};
use nanosiem_core::crypto::rotation::{self, CredentialKeyRepository, RotationError};
use nanosiem_core::crypto::{EncryptedData, EncryptionService};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn root(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

/// A ring with the given active id over the given (id, root byte) keys.
fn ring(active: &str, keys: &[(&str, u8)]) -> EncryptionService {
    let keys: Vec<_> = keys
        .iter()
        .map(|(id, byte)| json!({"id": id, "key": root(*byte)}))
        .collect();
    EncryptionService::from_config(&json!({"version": 1, "active": active, "keys": keys}).to_string())
        .unwrap()
}

struct Seeded {
    credential_id: Uuid,
    webhook_id: Uuid,
}

async fn seed(pool: &PgPool, cipher: &EncryptionService, tag: &str) -> Seeded {
    let credential = cipher
        .encrypt_json(&json!({"access_key_id": "AKIA", "secret_access_key": format!("s-{tag}")}))
        .unwrap();
    let (bytes, nonce) = credential.to_bytea().unwrap();
    let credential_id: Uuid = sqlx::query_scalar(
        "INSERT INTO cloud_credentials (name, provider, credentials_encrypted, nonce) \
         VALUES ($1, 'aws_s3', $2, $3) RETURNING id",
    )
    .bind(format!("nan4933-{tag}"))
    .bind(bytes)
    .bind(nonce)
    .fetch_one(pool)
    .await
    .expect("seed cloud credential");
    let secret = cipher.encrypt(format!("hook-{tag}").as_bytes()).unwrap();
    let webhook_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhooks (id, name, url, channel_type, enabled, secret_encrypted) \
         VALUES ($1, $2, 'https://example.invalid/hook', 'slack', false, $3)",
    )
    .bind(webhook_id)
    .bind(format!("nan4933-{tag}"))
    .bind(secret.to_json_bytes().unwrap())
    .execute(pool)
    .await
    .expect("seed webhook");
    Seeded {
        credential_id,
        webhook_id,
    }
}

async fn stored(pool: &PgPool, seeded: &Seeded) -> (EncryptedData, EncryptedData) {
    let (bytes, nonce): (Vec<u8>, String) = sqlx::query_as(
        "SELECT credentials_encrypted, nonce FROM cloud_credentials WHERE id = $1",
    )
    .bind(seeded.credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let hook: Vec<u8> = sqlx::query_scalar("SELECT secret_encrypted FROM webhooks WHERE id = $1")
        .bind(seeded.webhook_id)
        .fetch_one(pool)
        .await
        .unwrap();
    (
        EncryptedData::from_bytea(&bytes, &nonce),
        EncryptedData::from_json_bytes(&hook).unwrap(),
    )
}

async fn cleanup(pool: &PgPool, seeded: &[&Seeded], key_ids: &[&str]) {
    for s in seeded {
        sqlx::query("DELETE FROM cloud_credentials WHERE id = $1")
            .bind(s.credential_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM webhooks WHERE id = $1")
            .bind(s.webhook_id)
            .execute(pool)
            .await
            .ok();
    }
    for id in key_ids {
        sqlx::query("DELETE FROM credential_keys WHERE key_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn rotation_rewraps_mixed_rows_and_retires_only_unreferenced_keys() {
    let pool = common::migrated_pool().await;
    let suffix = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_mid, k_new) = (
        format!("old-{suffix}"),
        format!("mid-{suffix}"),
        format!("new-{suffix}"),
    );
    let node = format!("test-node-{suffix}");
    // Every secret writer declares its key (write fence); this process's
    // active key is k_new, registered before anything is written.
    let writer = common::declared_pool(&k_new).await;
    let repo = CredentialKeyRepository::new(writer.clone());
    let current = ring(&k_new, &[(&k_new, 3), (&k_mid, 2), (&k_old, 1)]);
    repo.register(&current, &node, "jobs").await.unwrap();

    // Rows written by an install on k_old, then more after a first rotation to k_mid.
    let on_old = ring(&k_old, &[(&k_old, 1)]);
    let on_mid = ring(&k_mid, &[(&k_mid, 2), (&k_old, 1)]);
    let a = seed(&writer, &on_old, &format!("{suffix}-a")).await;
    let b = seed(&writer, &on_mid, &format!("{suffix}-b")).await;

    // Rotate to k_new keeping both old keys decrypt-only (registered above).

    // Mixed-key rows all open, each reporting its key.
    let (cred_a, hook_a) = stored(&pool, &a).await;
    let (cred_b, hook_b) = stored(&pool, &b).await;
    assert_eq!(current.decrypt_with_key_id(&cred_a).unwrap().1, k_old);
    assert_eq!(current.decrypt_with_key_id(&hook_a).unwrap().1, k_old);
    assert_eq!(current.decrypt_with_key_id(&cred_b).unwrap().1, k_mid);
    assert_eq!(current.decrypt_with_key_id(&hook_b).unwrap().1, k_mid);
    let before = rotation::scan(&pool, &current).await.unwrap();
    assert!(before.by_key.get(&k_old).copied().unwrap_or(0) >= 2);
    assert!(before.by_key.get(&k_mid).copied().unwrap_or(0) >= 2);
    assert!(before.pending_rewrap >= 4);

    // Still referenced: refused, with the count.
    match repo.retire(&current, &k_old, None).await {
        Err(RotationError::StillReferenced { count, .. }) => assert!(count >= 2),
        other => panic!("retire of a referenced key must be refused, got {other:?}"),
    }
    // The active key is never retirable.
    assert!(matches!(
        repo.retire(&current, &k_new, None).await,
        Err(RotationError::KeyActive { .. })
    ));

    // A ring with the right ids but the wrong bytes cannot act (codex fence
    // review P1): re-wrap and retire both verify fingerprints first. Without
    // that, retiring k_old with wrong bytes would see its rows as merely
    // "undecryptable" and, k_old being in the ring, retire a referenced key.
    let wrong_active = ring(&k_new, &[(&k_new, 9), (&k_mid, 2), (&k_old, 1)]);
    assert!(matches!(
        rotation::run_pass(&repo, &wrong_active, "manual", &node).await,
        Err(RotationError::FingerprintMismatch(id)) if id == k_new
    ));
    let wrong_old = ring(&k_new, &[(&k_new, 3), (&k_mid, 2), (&k_old, 8)]);
    assert!(matches!(
        repo.retire(&wrong_old, &k_old, None).await,
        Err(RotationError::FingerprintMismatch(id)) if id == k_old
    ));

    // Re-wrap moves every row onto k_new; a second pass has nothing to do.
    let (outcome, after) = rotation::run_pass(&repo, &current, "manual", &node).await.unwrap();
    assert!(outcome.rewrapped >= 4, "{outcome:?}");
    assert_eq!(after.by_key.get(&k_old).copied().unwrap_or(0), 0);
    assert_eq!(after.by_key.get(&k_mid).copied().unwrap_or(0), 0);
    let (second, _) = rotation::run_pass(&repo, &current, "manual", &node).await.unwrap();
    assert_eq!(second.rewrapped, 0);
    let recorded: Option<i64> =
        sqlx::query_scalar("SELECT referenced_rows FROM credential_keys WHERE key_id = $1")
            .bind(&k_old)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(recorded, Some(0), "the visible count reaches zero");

    // Plaintext preserved, now on k_new only.
    let only_new = ring(&k_new, &[(&k_new, 3)]);
    let (cred_a, hook_a) = stored(&pool, &a).await;
    let (cred_b, hook_b) = stored(&pool, &b).await;
    let creds: serde_json::Value = only_new.decrypt_json(&cred_a).unwrap();
    assert_eq!(creds["secret_access_key"], format!("s-{suffix}-a"));
    assert_eq!(only_new.decrypt(&hook_a).unwrap(), format!("hook-{suffix}-a").as_bytes());
    assert!(only_new.decrypt(&cred_b).is_ok() && only_new.decrypt(&hook_b).is_ok());

    // A live process still WRITING with k_mid blocks its retirement.
    let lagging = ring(&k_mid, &[(&k_mid, 2), (&k_old, 1)]);
    repo.register(&lagging, &format!("{node}-lagging"), "api").await.unwrap();
    assert!(matches!(
        repo.retire(&current, &k_mid, None).await,
        Err(RotationError::KeyActive { .. })
    ));
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1")
        .bind(format!("{node}-lagging"))
        .execute(&pool)
        .await
        .unwrap();

    // Nothing references k_old / k_mid any more: both retire.
    repo.retire(&current, &k_old, None).await.unwrap();
    repo.retire(&current, &k_mid, None).await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM credential_keys WHERE key_id = $1")
        .bind(&k_old)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "retired");

    // Key ids are immutable: k_old with different material is refused.
    let reused = ring(&k_new, &[(&k_new, 3), (&k_old, 9)]);
    assert!(matches!(
        repo.register(&reused, &node, "jobs").await,
        Err(RotationError::FingerprintMismatch(_))
    ));

    // Wrong key fails closed: a ring without k_new opens none of the rows.
    let wrong = ring(&k_old, &[(&k_old, 1), (&k_mid, 2)]);
    assert!(wrong.decrypt(&cred_a).is_err());
    let wrong_scan = rotation::scan(&pool, &wrong).await.unwrap();
    assert!(wrong_scan.undecryptable >= 4);
    // ...and it cannot "prove" a key it does not hold is unreferenced.
    let outsider = ring(&k_old, &[(&k_old, 1)]);
    assert!(matches!(
        repo.retire(&outsider, &k_new, None).await,
        Err(RotationError::KeyActive { .. }) | Err(RotationError::Unprovable { .. })
    ));

    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1")
        .bind(&node)
        .execute(&pool)
        .await
        .ok();
    cleanup(&pool, &[&a, &b], &[&k_old, &k_mid, &k_new]).await;
    common::reset_write_fence(&pool).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn concurrent_writer_wins_over_rewrap() {
    let pool = common::migrated_pool().await;
    let suffix = &Uuid::new_v4().simple().to_string()[..10];
    let (k_old, k_new) = (format!("cold-{suffix}"), format!("cnew-{suffix}"));
    let on_old = ring(&k_old, &[(&k_old, 4)]);
    let current = ring(&k_new, &[(&k_new, 5), (&k_old, 4)]);
    let node = format!("cw-node-{suffix}");
    CredentialKeyRepository::new(pool.clone()).register(&current, &node, "jobs").await.unwrap();
    let pool = common::declared_pool(&k_new).await;
    let seeded = seed(&pool, &on_old, &format!("{suffix}-c")).await;

    // A writer replaces the secret (under the active key) after the re-wrap
    // read it: the optimistic guard leaves the writer's value in place.
    let (old_cred, _) = stored(&pool, &seeded).await;
    let (fresh, _) = current.rewrap(&old_cred).unwrap().unwrap();
    let written = current
        .encrypt_json(&json!({"access_key_id": "AKIA", "secret_access_key": "rotated-by-user"}))
        .unwrap();
    let (bytes, nonce) = written.to_bytea().unwrap();
    sqlx::query("UPDATE cloud_credentials SET credentials_encrypted = $2, nonce = $3 WHERE id = $1")
        .bind(seeded.credential_id)
        .bind(bytes)
        .bind(nonce)
        .execute(&pool)
        .await
        .unwrap();
    let (stale_bytes, stale_nonce) = old_cred.to_bytea().unwrap();
    let (fresh_bytes, fresh_nonce) = fresh.to_bytea().unwrap();
    let affected = sqlx::query(
        "UPDATE cloud_credentials SET credentials_encrypted = $1, nonce = $2 \
          WHERE id::text = $3 AND credentials_encrypted = $4 AND nonce::text IS NOT DISTINCT FROM $5",
    )
    .bind(fresh_bytes)
    .bind(fresh_nonce)
    .bind(seeded.credential_id.to_string())
    .bind(stale_bytes)
    .bind(Some(stale_nonce))
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(affected, 0, "the re-wrap's guard must not clobber a newer write");
    let (now, _) = stored(&pool, &seeded).await;
    let value: serde_json::Value = current.decrypt_json(&now).unwrap();
    assert_eq!(value["secret_access_key"], "rotated-by-user");

    cleanup(&pool, &[&seeded], &[&k_old, &k_new]).await;
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(&node).execute(&pool).await.ok();
}

/// The live schema agrees with the migration scan
/// (`credential_rotation_inventory.rs`): every `*_encrypted` / ciphertext
/// column that actually exists is a re-wrap target or a reasoned exception.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn every_live_secret_column_is_a_rewrap_target() {
    let pool = common::migrated_pool().await;
    let live: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns \
          WHERE table_schema = 'public' \
            AND (column_name LIKE '%\\_encrypted' OR column_name LIKE '%ciphertext%' OR column_name LIKE '%sealed%') \
          ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(live.iter().any(|(t, _)| t == "cloud_credentials"), "query matched nothing: {live:?}");
    let exceptions = [("melod_settings", "credentials_encrypted")];
    let missing: Vec<_> = live
        .iter()
        .filter(|(t, c)| {
            !rotation::TARGETS.iter().any(|x| x.table == t && x.column == c)
                && !exceptions.iter().any(|(et, ec)| et == t && ec == c)
        })
        .collect();
    assert!(missing.is_empty(), "live secret columns with no re-wrap target: {missing:?}");
}
