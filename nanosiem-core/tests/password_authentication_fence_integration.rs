// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression coverage for the enterprise-shared password/reset MVCC race.
//!
//! A login may finish bcrypt against the old row version while a reset has an
//! uncommitted replacement hash. Post-bcrypt authentication must wait for that
//! writer and reject the stale hash instead of minting a continuation whose
//! timestamp happens to follow the reset watermark.

mod common;

use std::time::Duration;

use nanosiem_core::auth::repository::UserRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool, password_hash: &str) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users (id, email, name, password_hash, status)
        VALUES ($1, $2, 'Password fence test', $3, 'active')
        "#,
    )
    .bind(user_id)
    .bind(format!("password-fence-{user_id}@example.test"))
    .bind(password_hash)
    .execute(pool)
    .await
    .expect("create password-fence user");
    user_id
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn uncommitted_reset_wins_before_post_bcrypt_hash_lock() {
    let pool = common::migrated_pool().await;
    let user_id = create_user(&pool, "verified-old-hash").await;

    let mut reset = pool.begin().await.expect("begin reset transaction");
    sqlx::query(
        r#"
        UPDATE users
        SET password_hash = 'replacement-hash',
            tokens_valid_from = clock_timestamp(),
            updated_at = clock_timestamp()
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(&mut *reset)
    .await
    .expect("stage uncommitted reset");

    let repository = UserRepository::new(pool.clone());
    let mut authentication = tokio::spawn(async move {
        repository
            .lock_current_password_authentication(user_id, "verified-old-hash")
            .await
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut authentication)
            .await
            .is_err(),
        "post-bcrypt authentication must wait behind the password writer",
    );

    reset.commit().await.expect("commit password reset");
    let fence = authentication
        .await
        .expect("join password authentication")
        .expect("revalidate password authentication");
    assert!(
        fence.is_none(),
        "the hash verified before the reset must not mint a continuation",
    );
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn exact_current_hash_returns_a_database_authentication_fence() {
    let pool = common::migrated_pool().await;
    let user_id = create_user(&pool, "current-hash").await;
    let repository = UserRepository::new(pool);

    assert!(repository
        .lock_current_password_authentication(user_id, "stale-hash")
        .await
        .expect("reject stale hash")
        .is_none());
    assert!(repository
        .lock_current_password_authentication(user_id, "current-hash")
        .await
        .expect("accept exact current hash")
        .is_some());
}
