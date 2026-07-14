// SPDX-License-Identifier: AGPL-3.0-or-later

//! F-32(a): disabling a user must immediately revoke their session/identity.
//!
//! Before the fix, `disable_user` only flipped `status='disabled'`; the auth
//! middleware never re-read the `users` row (trusting the JWT until natural
//! expiry) and API-key validation never consulted the owner's status, so a
//! disabled user's access token AND API key kept working. These `#[ignore]`d
//! DB-backed tests (pg-integration CI: `cargo test -- --ignored`) exercise the
//! new controls against a real migrated Postgres — they are also the only
//! guard against schema drift for the `users.tokens_valid_from` column
//! (migration 253) and the runtime `sqlx` in `UserStatusResolver` /
//! `ApiKeyService::validate_key`.

mod common;

use nanosiem_core::auth::repository::ApiKeyRepository;
use nanosiem_core::auth::{
    ApiKeyService, ApiKeyServiceError, CreateApiKeyRequest, UserRepository, UserStatusResolver,
};
use nanosiem_core::db::repository::RateLimitRepository;
use sqlx::PgPool;
use uuid::Uuid;

fn suffix() -> String {
    Uuid::now_v7().simple().to_string()[..16].to_string()
}

/// Mint a `users` row with the given status. Returns its id.
async fn create_user(pool: &PgPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Revocation Test', 'x', $3, NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("revoke-{id}@example.com"))
    .bind(status)
    .execute(pool)
    .await
    .expect("create user");
    id
}

/// The status gate: disabling a user flips `status` AND stamps
/// `tokens_valid_from`, so the resolver the middleware consults reports the
/// account as no longer active and any pre-disable token as revoked.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn disable_user_makes_status_gate_reject() {
    let pool = common::migrated_pool().await;
    let user_repo = UserRepository::new(pool.clone());
    let resolver = UserStatusResolver::new(pool.clone());

    let user = create_user(&pool, "active").await;

    // Active: the gate passes and no token is revoked.
    let snap = resolver.resolve(user).await.expect("resolve active");
    assert!(snap.is_active(), "freshly-created user must be active");
    assert!(
        !snap.token_predates_revocation(chrono::Utc::now().timestamp()),
        "no watermark yet — nothing revoked"
    );

    // Disable → status flips AND tokens_valid_from is stamped (same UPDATE).
    user_repo.disable_user(user).await.expect("disable");
    resolver.invalidate_user(user); // bypass the short TTL for a deterministic read

    let snap = resolver.resolve(user).await.expect("resolve disabled");
    assert!(
        !snap.is_active(),
        "disabled account must fail the status gate; status = {:?}",
        snap.status
    );
    // A token minted before the disable (an hour ago) is now revoked.
    let hour_ago = chrono::Utc::now().timestamp() - 3600;
    assert!(
        snap.token_predates_revocation(hour_ago),
        "a pre-disable token must be rejected by the revocation watermark"
    );
}

/// The password-change hole: `tokens_valid_from` is stamped without changing
/// status, so a still-`active` user's previously-issued access tokens are
/// rejected by the watermark while new ones pass.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn password_change_watermark_revokes_old_tokens_only() {
    let pool = common::migrated_pool().await;
    let user_repo = UserRepository::new(pool.clone());
    let resolver = UserStatusResolver::new(pool.clone());

    let user = create_user(&pool, "active").await;

    // Simulate the change_password stamp (auth::service calls this).
    user_repo
        .stamp_tokens_valid_from(user)
        .await
        .expect("stamp watermark");
    resolver.invalidate_user(user);

    let snap = resolver.resolve(user).await.expect("resolve");
    assert!(snap.is_active(), "password change keeps the account active");
    assert!(
        snap.token_predates_revocation(chrono::Utc::now().timestamp() - 3600),
        "a token issued before the password change must be revoked"
    );
    assert!(
        !snap.token_predates_revocation(chrono::Utc::now().timestamp() + 3600),
        "a token issued after the password change must remain valid"
    );
}

/// API keys: `validate_key` must reject a key whose OWNER is disabled, keep
/// serving an active owner's key, and (carve-out) keep serving a `system`
/// service-account owner's key.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn api_key_rejected_when_owner_disabled() {
    let pool = common::migrated_pool().await;
    let user_repo = UserRepository::new(pool.clone());
    let api_key_service = ApiKeyService::new(
        ApiKeyRepository::new(pool.clone()),
        RateLimitRepository::new(pool.clone()),
    );

    let sfx = suffix();
    let owner = create_user(&pool, "active").await;
    let created = api_key_service
        .create_key(
            CreateApiKeyRequest {
                name: format!("k-{sfx}"),
                description: None,
                permissions: vec!["search:view".to_string()],
                expires_at: None,
                rate_limit: None,
            },
            Some(owner),
            None,
            None,
        )
        .await
        .expect("create key");

    // Active owner → key validates.
    api_key_service
        .validate_key(&created.key, None)
        .await
        .expect("active owner key must validate");

    // Disable the owner → the same key is now rejected.
    user_repo.disable_user(owner).await.expect("disable owner");
    let err = api_key_service
        .validate_key(&created.key, None)
        .await
        .expect_err("disabled owner's key must be rejected");
    assert!(
        matches!(err, ApiKeyServiceError::Disabled),
        "disabled owner must surface as Disabled, got {err:?}"
    );
}

/// A `system` service-account owner is exempt from the active-status check — its
/// non-interactive keys must keep working.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn api_key_allowed_for_system_owner() {
    let pool = common::migrated_pool().await;
    let api_key_service = ApiKeyService::new(
        ApiKeyRepository::new(pool.clone()),
        RateLimitRepository::new(pool.clone()),
    );

    let sfx = suffix();
    let owner = create_user(&pool, "system").await;
    let created = api_key_service
        .create_key(
            CreateApiKeyRequest {
                name: format!("svc-{sfx}"),
                description: None,
                permissions: vec!["search:view".to_string()],
                expires_at: None,
                rate_limit: None,
            },
            Some(owner),
            None,
            None,
        )
        .await
        .expect("create key");

    api_key_service
        .validate_key(&created.key, None)
        .await
        .expect("system service-account key must keep validating");
}
