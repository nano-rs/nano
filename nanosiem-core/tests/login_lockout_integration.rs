// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-1622: the failed-login throttle must signal a *fresh*
//! lockout (`AuthError::AccountLocked`) exactly once — on the attempt whose
//! increment first crosses `lockout_threshold` — not on every subsequent
//! attempt against an already-throttled account.
//!
//! The login handler audits `user_locked` whenever `login()` returns
//! `AccountLocked`; before the fix the service returned it on every attempt
//! `>= threshold`, inflating the audit log with one `user_locked` per bad
//! password. This pins the once-per-lock-episode invariant.
//!
//! Gated like the other DB suites: compiles with every `cargo test` but is
//! `#[ignore]`d — run via the `pg-integration-tests` CI job, or locally with
//! `docker compose up -d postgres` and `cargo test -- --ignored`.

mod common;

use nanosiem_core::auth::repository::{GroupRepository, SessionRepository, UserRepository};
use nanosiem_core::auth::{
    hash_password, AuthConfig, AuthError, AuthService, TokenConfig, TokenService,
};
use nanosiem_core::settings::local_auth::LocalAuthSettings;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_active_user(pool: &PgPool, password: &str) -> String {
    let id = Uuid::now_v7();
    let email = format!("lockout-{id}@example.com");
    let hash = hash_password(password).expect("hash password");
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Lockout Test', $3, 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("create user");
    email
}

fn auth_service(pool: PgPool) -> AuthService {
    let token_service = TokenService::new(TokenConfig::new(
        "test-jwt-secret-not-for-production-32+chars".to_string(),
    ));
    AuthService::new(
        UserRepository::new(pool.clone()),
        SessionRepository::new(pool.clone()),
        GroupRepository::new(pool.clone()),
        token_service,
        AuthConfig::default(),
        // NAN-2181 added this parameter; these tests exercise the password
        // path, which the default (local sign-in enabled) leaves reachable.
        LocalAuthSettings::new(pool.clone()),
    )
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn account_locked_signaled_once_on_threshold_crossing() {
    let pool = common::migrated_pool().await;
    let email = create_active_user(&pool, "correct-horse-battery-staple").await;
    let svc = auth_service(pool);
    let threshold = AuthConfig::default().lockout_threshold; // 5

    // Attempts below the threshold return the generic credential error and do
    // NOT signal a lock.
    for attempt in 1..threshold {
        let err = svc
            .login(&email, "wrong-password", None, None)
            .await
            .expect_err("wrong password must fail");
        assert!(
            matches!(err, AuthError::InvalidCredentials),
            "attempt {attempt} (< threshold) must be generic InvalidCredentials, got {err:?}"
        );
    }

    // The attempt whose increment first reaches the threshold is the single
    // fresh-lock signal the handler audits as `user_locked`.
    let crossing = svc
        .login(&email, "wrong-password", None, None)
        .await
        .expect_err("crossing attempt must fail");
    assert!(
        matches!(crossing, AuthError::AccountLocked),
        "the threshold-crossing attempt must signal AccountLocked, got {crossing:?}"
    );

    // A further bad attempt against the already-throttled account must NOT
    // re-signal a fresh lock (audit-inflation guard) — it falls back to the
    // generic error while still being throttled.
    let after = svc
        .login(&email, "wrong-password", None, None)
        .await
        .expect_err("post-lock attempt must fail");
    assert!(
        matches!(after, AuthError::InvalidCredentials),
        "attempts against an already-locked account must not re-signal AccountLocked, got {after:?}"
    );
}
