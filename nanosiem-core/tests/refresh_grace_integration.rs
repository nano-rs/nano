// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-2453: refresh rotation tolerates two tabs presenting the same cookie.
//!
//! The refresh token stays single-use, but the immediately previous token is
//! honoured for REFRESH_GRACE_SECS after a rotation: it yields an access token
//! for the same session WITHOUT rotating (no new refresh token, so the client
//! keeps the winner's cookie) and never forks the chain. Older tokens are
//! refused as before. `#[ignore]`d DB suite (throwaway Postgres).

mod common;

use nanosiem_core::auth::repository::{GroupRepository, SessionRepository, UserRepository};
use nanosiem_core::auth::{AuthConfig, AuthError, AuthService, TokenConfig, TokenService, User};
use nanosiem_core::settings::local_auth::LocalAuthSettings;
use sqlx::PgPool;
use uuid::Uuid;

fn service(pool: &PgPool) -> AuthService {
    AuthService::new(
        UserRepository::new(pool.clone()),
        SessionRepository::new(pool.clone()),
        GroupRepository::new(pool.clone()),
        TokenService::new(TokenConfig::new("test-jwt-secret-not-for-production-32+chars".to_string())),
        AuthConfig::default(),
        LocalAuthSettings::new(pool.clone()),
    )
}

async fn user(pool: &PgPool) -> User {
    let id = Uuid::now_v7();
    sqlx::query_as::<_, User>(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'Grace', 'x', 'active') RETURNING *",
    )
    .bind(id)
    .bind(format!("grace-{id}@example.com"))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn previous_token_within_grace_gets_access_without_rotation() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;

    // Tab A rotates t0 -> t1.
    let a = auth.refresh_token(&t0, None, None).await.unwrap();
    assert!(a.rotated);
    let t1 = a.tokens.refresh_token.clone();
    assert!(!t1.is_empty() && t1 != t0);

    // Tab B presents t0 a moment later: access token, no rotation, no new
    // refresh token — the session still holds t1.
    let b = auth.refresh_token(&t0, None, None).await.unwrap();
    assert!(!b.rotated);
    assert!(b.tokens.refresh_token.is_empty());
    assert!(!b.tokens.access_token.is_empty());

    // The chain is not forked: t1 still rotates, and then t0 is two
    // rotations old and refused.
    let c = auth.refresh_token(&t1, None, None).await.unwrap();
    assert!(c.rotated);
    assert!(matches!(auth.refresh_token(&t0, None, None).await, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn concurrent_refreshes_of_one_cookie_all_succeed_with_one_rotation() {
    let pool = common::migrated_pool().await;
    let auth = std::sync::Arc::new(service(&pool));
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let auth = auth.clone();
            let t0 = t0.clone();
            tokio::spawn(async move { auth.refresh_token(&t0, None, None).await })
        })
        .collect();
    let mut rotated = 0;
    for h in handles {
        let outcome = h.await.unwrap().expect("no tab is refused");
        rotated += usize::from(outcome.rotated);
    }
    assert_eq!(rotated, 1, "exactly one rotation");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn previous_token_after_the_grace_window_is_refused() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    auth.refresh_token(&t0, None, None).await.unwrap();
    // Age the rotation past the window.
    sqlx::query("UPDATE sessions SET rotated_at = clock_timestamp() - interval '1 minute' WHERE user_id = $1")
        .bind(u.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(auth.refresh_token(&t0, None, None).await, Err(AuthError::SessionNotFound)));
}
