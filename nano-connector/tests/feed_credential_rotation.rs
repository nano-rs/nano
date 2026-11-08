// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4933: a connector pull feed's vendor secret survives credential key
//! rotation. The secret lives in the credentials store (`cloud_credentials`,
//! bound by `connector_feeds.credential_id`); the re-wrap moves it to the new
//! key and the runner's claim path (`PgFeedStore::claim_due`) still opens it
//! with a ring that no longer holds the old key.
//!
//! `#[ignore]`d: needs a disposable migrated Postgres at DATABASE_URL and
//! NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 (it claims every due feed).

use base64::{engine::general_purpose::STANDARD, Engine};
use nano_connector::first_party;
use nano_connector::service::admin::NewFeed;
use nano_connector::service::pg::PgFeedStore;
use nano_connector::service::FeedStore;
use nanosiem_core::crypto::rotation::{self, CredentialKeyRepository};
use nanosiem_core::crypto::EncryptionService;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn ring(active: &str, keys: &[(&str, u8)]) -> EncryptionService {
    let keys: Vec<_> = keys.iter().map(|(id, b)| json!({"id": id, "key": STANDARD.encode([*b; 32])})).collect();
    EncryptionService::from_config(&json!({"version": 1, "active": active, "keys": keys}).to_string()).unwrap()
}

async fn declared(key: &str) -> PgPool {
    rotation::declare_write_key(sqlx::postgres::PgPoolOptions::new().max_connections(3), key.to_owned())
        .connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .unwrap()
}

async fn pool() -> PgPool {
    assert!(
        std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").is_ok_and(|v| v == "1" || v == "true"),
        "set NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 against a disposable database"
    );
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL")).await.unwrap();
    nanosiem_core::db::run_postgres_migrations(&pool).await.unwrap();
    pool
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL); run with --ignored"]
async fn feed_secret_rewraps_and_still_opens_at_claim() {
    let pool = pool().await;
    let s = &Uuid::new_v4().simple().to_string()[..10];
    let (old_id, new_id) = (format!("fold-{s}"), format!("fnew-{s}"));
    let old = ring(&old_id, &[(&old_id, 7)]);
    let current = ring(&new_id, &[(&new_id, 8), (&old_id, 7)]);
    // Every secret writer declares its registered key (NAN-4933 write fence).
    let repo_plain = CredentialKeyRepository::new(pool.clone());
    repo_plain.register(&old, &format!("feed-old-{s}"), "api").await.unwrap();
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(format!("feed-old-{s}")).execute(&pool).await.unwrap();
    repo_plain.register(&current, &format!("feed-new-{s}"), "jobs").await.unwrap();
    let old_writer = declared(&old_id).await;
    let new_writer = declared(&new_id).await;

    // The credential the feed binds, written under the old key.
    let sealed = old.encrypt_json(&json!({"API_TOKEN": format!("okta-token-{s}")})).unwrap();
    let (bytes, nonce) = sealed.to_bytea().unwrap();
    let credential_id: Uuid = sqlx::query_scalar(
        "INSERT INTO cloud_credentials (name, provider, credentials_encrypted, nonce) VALUES ($1, 'okta', $2, $3) RETURNING id",
    )
    .bind(format!("feed-{s}"))
    .bind(bytes)
    .bind(nonce)
    .fetch_one(&old_writer)
    .await
    .expect("seed okta credential");
    let plan = first_party::plan("okta_system_log").unwrap();
    let feed = NewFeed {
        name: format!("okta-{s}"),
        config: json!({"OKTA_DOMAIN": "acme.okta.com"}).as_object().cloned().unwrap(),
        credential_id: Some(credential_id),
        enabled: true,
        ..Default::default()
    };
    let feed_id = PgFeedStore::new(pool.clone(), old.clone()).create_feed(&plan, &feed, None).await.unwrap();

    // Rotate: new active key, old key decrypt-only; the re-wrap moves the row.
    let repo = CredentialKeyRepository::new(new_writer.clone());
    let (outcome, usage) = rotation::run_pass(&repo, &current, "manual", &format!("feed-test-{s}")).await.unwrap();
    assert!(outcome.from_key.get(&old_id).copied().unwrap_or(0) >= 1, "{outcome:?}");
    assert_eq!(usage.by_key.get(&old_id).copied().unwrap_or(0), 0);

    // The runner, holding only the new key, claims the feed with its secret.
    let runner = PgFeedStore::new(pool.clone(), ring(&new_id, &[(&new_id, 8)]));
    let claims = runner.claim_due("rotation-test", 100, &|_| 60).await.unwrap();
    let claim = claims.iter().find(|c| c.feed.feed_id == feed_id).expect("feed claimed with an opened credential");
    assert_eq!(claim.feed.vendor_credentials["API_TOKEN"].expose(), format!("okta-token-{s}"));

    // The old key alone can no longer open it (fail closed: the claim is
    // recorded as a failed run, never handed to the runner empty).
    sqlx::query("UPDATE connector_feeds SET lease_owner = NULL, lease_expires_at = NULL, next_run_at = now() WHERE id = $1")
        .bind(feed_id)
        .execute(&pool)
        .await
        .unwrap();
    let stale = PgFeedStore::new(pool.clone(), old).claim_due("rotation-test-old", 100, &|_| 60).await.unwrap();
    assert!(stale.iter().all(|c| c.feed.feed_id != feed_id));

    sqlx::query("DELETE FROM connector_feeds WHERE id = $1").bind(feed_id).execute(&pool).await.ok();
    sqlx::query("DELETE FROM cloud_credentials WHERE id = $1").bind(credential_id).execute(&pool).await.ok();
    sqlx::query("DELETE FROM credential_key_ring_members WHERE node_id = $1").bind(format!("feed-new-{s}")).execute(&pool).await.ok();
    for id in [&old_id, &new_id] {
        sqlx::query("DELETE FROM credential_keys WHERE key_id = $1").bind(id).execute(&pool).await.ok();
    }
}
