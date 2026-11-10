// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5237: the first-admin claim behind `POST /api/setup/initialize` is
//! atomic. Concurrent callers produce exactly one Admin; an initialized system
//! refuses; a failed claim leaves nothing behind.
//!
//! Each test runs in its OWN freshly created and migrated database on the
//! `DATABASE_URL` server (dropped afterwards), because the claim depends on
//! "no human users exist yet", which a shared test database never satisfies.
//!
//! `#[ignore]`d like the other DB suites: run against a DISPOSABLE Postgres
//! with `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=... cargo test -p
//! nanosiem-core --test first_admin_claim_integration -- --ignored`.

mod common;

use std::sync::Arc;

use nanosiem_core::auth::first_admin::{claim_first_admin, is_system_initialized, FirstAdminError};
use nanosiem_core::auth::{builtin_roles, CreateUserRequest};
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

const PASSWORD: &str = "Setup-Claim-5237-pass!";

/// A brand-new migrated database; returns (admin pool, scratch pool, name).
async fn scratch_db() -> (PgPool, PgPool, String) {
    let admin = common::migrated_pool().await;
    let name = format!("nan5237_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .expect("create scratch database");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let (head, query) = match base.split_once('?') {
        Some((h, q)) => (h.to_string(), format!("?{q}")),
        None => (base.clone(), String::new()),
    };
    let server = head.rsplit_once('/').map(|(s, _)| s).expect("database URL has a path");
    let url = format!("{server}/{name}{query}");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("connect scratch database");
    nanosiem_core::db::run_postgres_migrations(&pool)
        .await
        .expect("migrate scratch database");
    (admin, pool, name)
}

async fn drop_db(admin: PgPool, pool: PgPool, name: String) {
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .ok();
}

fn request(email: &str, password: &str) -> CreateUserRequest {
    CreateUserRequest {
        email: email.to_string(),
        name: "First Admin".to_string(),
        password: password.to_string(),
        group_ids: vec![],
    }
}

async fn human_users(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status != 'system'")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn admin_role_holders(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT ug.user_id) FROM user_groups ug \
         JOIN group_roles gr ON gr.group_id = ug.group_id \
         JOIN users u ON u.id = ug.user_id \
         WHERE gr.role_id = $1 AND u.status != 'system'",
    )
    .bind(builtin_roles::ADMIN_ID)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "needs a disposable Postgres (DATABASE_URL + NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1)"]
async fn concurrent_initialize_creates_exactly_one_admin() {
    let (admin, pool, name) = scratch_db().await;

    const RACERS: usize = 4;
    let barrier = Arc::new(Barrier::new(RACERS));
    let mut handles = Vec::new();
    for i in 0..RACERS {
        let pool = pool.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            claim_first_admin(&pool, &request(&format!("racer-{i}@example.invalid"), PASSWORD)).await
        }));
    }
    let mut won = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => won += 1,
            Err(FirstAdminError::AlreadyInitialized) | Err(FirstAdminError::UsersExist) => {}
            Err(other) => panic!("unexpected claim error: {other}"),
        }
    }

    let users = human_users(&pool).await;
    let admins = admin_role_holders(&pool).await;
    let initialized = is_system_initialized(&pool).await.unwrap();
    drop_db(admin, pool, name).await;

    assert_eq!(won, 1, "exactly one concurrent claim may succeed");
    assert_eq!(users, 1, "exactly one human user");
    assert_eq!(admins, 1, "exactly one Admin");
    assert!(initialized);
}

#[tokio::test]
#[ignore = "needs a disposable Postgres (DATABASE_URL + NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1)"]
async fn already_initialized_is_refused() {
    let (admin, pool, name) = scratch_db().await;

    let first = claim_first_admin(&pool, &request("first@example.invalid", PASSWORD)).await;
    let second = claim_first_admin(&pool, &request("second@example.invalid", PASSWORD)).await;
    let users = human_users(&pool).await;
    drop_db(admin, pool, name).await;

    assert!(first.is_ok(), "first claim: {:?}", first.err());
    assert!(matches!(second, Err(FirstAdminError::AlreadyInitialized)), "second claim: {second:?}");
    assert_eq!(users, 1);
}

#[tokio::test]
#[ignore = "needs a disposable Postgres (DATABASE_URL + NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1)"]
async fn existing_users_are_refused() {
    let (admin, pool, name) = scratch_db().await;
    sqlx::query(
        "INSERT INTO users (email, name, password_hash, status) VALUES ('pre@example.invalid', 'Pre', 'x', 'active')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let claim = claim_first_admin(&pool, &request("late@example.invalid", PASSWORD)).await;
    let users = human_users(&pool).await;
    let initialized = is_system_initialized(&pool).await.unwrap();
    drop_db(admin, pool, name).await;

    assert!(matches!(claim, Err(FirstAdminError::UsersExist)), "claim: {claim:?}");
    assert_eq!(users, 1);
    assert!(!initialized);
}

#[tokio::test]
#[ignore = "needs a disposable Postgres (DATABASE_URL + NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1)"]
async fn failed_claim_leaves_nothing_behind() {
    let (admin, pool, name) = scratch_db().await;

    let weak = claim_first_admin(&pool, &request("weak@example.invalid", "short")).await;
    let users = human_users(&pool).await;
    let initialized = is_system_initialized(&pool).await.unwrap();
    let retry = claim_first_admin(&pool, &request("weak@example.invalid", PASSWORD)).await;
    drop_db(admin, pool, name).await;

    assert!(matches!(weak, Err(FirstAdminError::User(_))), "weak claim: {weak:?}");
    assert_eq!(users, 0);
    assert!(!initialized);
    assert!(retry.is_ok(), "a corrected retry succeeds: {:?}", retry.err());
}
