// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-1391: refresh-token rotation must be single-use.
//!
//! `SessionRepository::rotate_refresh_token` used to update `WHERE id = $1`
//! only, so concurrent `POST /api/auth/refresh` requests bearing the same
//! token all read the session, all minted a token pair, and all wrote — every
//! one succeeded, minting multiple valid pairs from a single-use token. The
//! rotation is now a compare-and-swap on the current hash: exactly one of N
//! concurrent rotations wins, the rest get `NotFoundByToken` (-> 401), and a
//! replay of an already-rotated token also fails.
//!
//! Gated like the other DB suites: compiles with every `cargo test` but is
//! `#[ignore]`d — run via the `pg-integration-tests` CI job, or locally with
//! `docker compose up -d postgres` and `cargo test -- --ignored`.

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::auth::repository::sessions::{SessionRepository, SessionRepositoryError};
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Rotation Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("rotate-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn concurrent_rotation_mints_exactly_one_winner() {
    let pool = common::migrated_pool().await;
    let repo = SessionRepository::new(pool.clone());
    let user_id = create_user(&pool).await;

    let old_hash = format!("old-{}", Uuid::now_v7());
    let expires = Utc::now() + Duration::hours(1);
    let session = repo
        .create_session(user_id, &old_hash, None, None, expires)
        .await
        .expect("create session");

    // Fire many rotations of the same session against the same old hash
    // concurrently — only one compare-and-swap may win.
    let new_expires = Utc::now() + Duration::hours(2);
    let mut handles = Vec::new();
    for i in 0..16 {
        let repo = repo.clone();
        let old_hash = old_hash.clone();
        let new_hash = format!("new-{i}-{}", Uuid::now_v7());
        handles.push(tokio::spawn(async move {
            repo.rotate_refresh_token(session.id, &old_hash, &new_hash, new_expires)
                .await
        }));
    }

    let mut winners = 0;
    let mut losers = 0;
    for h in handles {
        match h.await.expect("task join") {
            Ok(_) => winners += 1,
            Err(SessionRepositoryError::NotFoundByToken) => losers += 1,
            Err(e) => panic!("unexpected rotation error: {e}"),
        }
    }

    assert_eq!(winners, 1, "exactly one concurrent rotation must win");
    assert_eq!(losers, 15, "all other rotations must fail as NotFoundByToken");

    // Cleanup
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn replay_of_rotated_token_is_rejected() {
    let pool = common::migrated_pool().await;
    let repo = SessionRepository::new(pool.clone());
    let user_id = create_user(&pool).await;

    let old_hash = format!("old-{}", Uuid::now_v7());
    let expires = Utc::now() + Duration::hours(1);
    let session = repo
        .create_session(user_id, &old_hash, None, None, expires)
        .await
        .expect("create session");

    let new_hash = format!("new-{}", Uuid::now_v7());
    let new_expires = Utc::now() + Duration::hours(2);

    // First rotation succeeds.
    repo.rotate_refresh_token(session.id, &old_hash, &new_hash, new_expires)
        .await
        .expect("first rotation wins");

    // Replaying the original (now-rotated) hash must fail — the session no
    // longer holds it.
    let replay_hash = format!("replay-{}", Uuid::now_v7());
    let err = repo
        .rotate_refresh_token(session.id, &old_hash, &replay_hash, new_expires)
        .await
        .expect_err("replay of rotated token must fail");
    assert!(matches!(err, SessionRepositoryError::NotFoundByToken));

    // Cleanup
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("cleanup user");
}
