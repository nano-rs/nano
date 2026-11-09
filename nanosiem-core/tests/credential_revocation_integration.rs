// SPDX-License-Identifier: AGPL-3.0-or-later

//! Security review (2026-11-08), group D — DB-backed regression coverage.
//!
//! - NAN-5014: every credential change revokes everything already issued to
//!   the target (watermark + sessions + reset token), atomically.
//! - NAN-5048: password-reset tokens are stored as digests; a stored value can
//!   never be redeemed.
//! - NAN-5044: an API key runs with stored ∩ owner's CURRENT permissions.
//!
//! `#[ignore]`d like the other DB suites: run against a DISPOSABLE migrated
//! Postgres with `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=... cargo
//! test -p nanosiem-core --test credential_revocation_integration -- --ignored`.

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::auth::repository::{ApiKeyRepository, SessionRepository};
use nanosiem_core::auth::{
    ApiKeyService, CreateApiKeyRequest, GrantAuthorityStamp, OwnerClampMode, PermissionResolver,
    PrincipalAction, UpdateUserRequest, UserRepository, UserRepositoryError, UserStatusResolver,
};
use nanosiem_core::db::repository::RateLimitRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Group D Test', 'x', $3, NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("groupd-{id}@example.invalid"))
    .bind(status)
    .execute(pool)
    .await
    .expect("create user");
    id
}

/// A custom role + group carrying `perms`, joined by `user`. Returns the group.
async fn grant(pool: &PgPool, user: Uuid, perms: &[&str]) -> Uuid {
    let role = Uuid::now_v7();
    let group = Uuid::now_v7();
    sqlx::query("INSERT INTO roles (id, name, description, is_system) VALUES ($1, $2, 't', FALSE)")
        .bind(role)
        .bind(format!("groupd-role-{role}"))
        .execute(pool)
        .await
        .unwrap();
    for p in perms {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(role)
            .bind(p)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO groups (id, name, description, is_system) VALUES ($1, $2, 't', FALSE)")
        .bind(group)
        .bind(format!("groupd-group-{group}"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)")
        .bind(group)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(user)
        .bind(group)
        .execute(pool)
        .await
        .unwrap();
    group
}

async fn open_session(pool: &PgPool, user: Uuid) {
    SessionRepository::new(pool.clone())
        .create_session(
            user,
            &format!("hash-{}", Uuid::now_v7()),
            None,
            None,
            Utc::now() + Duration::days(7),
        )
        .await
        .expect("create session");
}

async fn session_count(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn current_stamp(pool: &PgPool) -> GrantAuthorityStamp {
    let v: i64 =
        sqlx::query_scalar("SELECT version FROM grant_authority_version WHERE singleton = TRUE")
            .fetch_one(pool)
            .await
            .unwrap();
    GrantAuthorityStamp::new(v)
}

/// Parallel tests in this binary bump the global grant-authority version (every
/// user/group insert does), so a fresh stamp can go stale before the write. The
/// production behaviour under test is "a stale stamp is refused"; here we only
/// need a CURRENT one, so retry on `GrantAuthorityChanged`.
async fn update_authorized(pool: &PgPool, id: Uuid, req: &UpdateUserRequest) {
    let repo = UserRepository::new(pool.clone());
    for _ in 0..20 {
        match repo
            .update_user_with_groups_authorized(id, req, None, current_stamp(pool).await)
            .await
        {
            Ok(_) => return,
            Err(UserRepositoryError::GrantAuthorityChanged) => continue,
            Err(e) => panic!("update failed: {e:?}"),
        }
    }
    panic!("could not obtain a current grant-authority stamp");
}

async fn action_authorized(pool: &PgPool, id: Uuid, action: PrincipalAction) {
    let repo = UserRepository::new(pool.clone());
    for _ in 0..20 {
        match repo
            .apply_principal_action_authorized(id, action, current_stamp(pool).await)
            .await
        {
            Ok(()) => return,
            Err(UserRepositoryError::GrantAuthorityChanged) => continue,
            Err(e) => panic!("action failed: {e:?}"),
        }
    }
    panic!("could not obtain a current grant-authority stamp");
}

fn update(password: Option<&str>, email: Option<String>, name: Option<&str>) -> UpdateUserRequest {
    UpdateUserRequest {
        email,
        name: name.map(str::to_string),
        password: password.map(str::to_string),
        status: None,
        group_ids: None,
        revoke_api_keys: None,
        local_login_break_glass: None,
    }
}

/// Asserts a token minted an hour ago is revoked and the sessions are gone.
async fn assert_revoked(pool: &PgPool, user: Uuid, what: &str) {
    let snap = UserStatusResolver::new(pool.clone()).resolve(user).await.unwrap();
    assert!(
        snap.token_predates_revocation(Utc::now().timestamp() - 3600),
        "{what}: an access token issued before the change must be rejected"
    );
    assert_eq!(session_count(pool, user).await, 0, "{what}: refresh sessions must be gone");
}

// ---------------------------------------------------------------------------
// NAN-5014
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn admin_password_reset_revokes_the_targets_tokens_and_sessions() {
    let pool = common::migrated_pool().await;
    let target = create_user(&pool, "active").await;
    open_session(&pool, target).await;
    open_session(&pool, target).await;

    update_authorized(&pool, target, &update(Some("N3w-Passw0rd!-reset"), None, None)).await;

    assert_revoked(&pool, target, "admin password reset").await;
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn admin_email_change_revokes_but_a_rename_does_not() {
    let pool = common::migrated_pool().await;

    let renamed = create_user(&pool, "active").await;
    open_session(&pool, renamed).await;
    update_authorized(&pool, renamed, &update(None, None, Some("New Name"))).await;
    assert_eq!(session_count(&pool, renamed).await, 1, "a rename must not sign the user out");

    let target = create_user(&pool, "active").await;
    open_session(&pool, target).await;
    update_authorized(&pool, target, &update(None, Some(format!("moved-{target}@example.invalid")), None)).await;
    assert_revoked(&pool, target, "admin email change").await;
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn opt_in_key_revocation_deletes_the_targets_keys_only_when_asked() {
    let pool = common::migrated_pool().await;
    let keys = ApiKeyService::new(
        ApiKeyRepository::new(pool.clone()),
        RateLimitRepository::new(pool.clone()),
    );
    let target = create_user(&pool, "active").await;
    for _ in 0..2 {
        keys.create_key(
            CreateApiKeyRequest {
                name: format!("k-{}", Uuid::now_v7()),
                description: None,
                permissions: vec!["search:view".into()],
                expires_at: None,
                rate_limit: None,
            },
            Some(target),
            None,
            None,
        )
        .await
        .unwrap();
    }
    let count = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_keys WHERE created_by = $1")
            .bind(target)
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    update_authorized(&pool, target, &update(Some("N3w-Passw0rd!-one"), None, None)).await;
    assert_eq!(count(pool.clone()).await, 2, "keys survive a reset by default");

    let mut req = update(Some("N3w-Passw0rd!-two"), None, None);
    req.revoke_api_keys = Some(true);
    update_authorized(&pool, target, &req).await;
    assert_eq!(count(pool).await, 0, "opt-in revocation deletes the target's keys");
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn token_reset_and_self_change_revoke_access_tokens_too() {
    let pool = common::migrated_pool().await;
    let repo = UserRepository::new(pool.clone());
    let user = create_user(&pool, "active").await;
    open_session(&pool, user).await;

    // Both the public token reset and the self-service change go through
    // `update_password`; it previously left access tokens valid.
    repo.update_password(user, "N3w-Passw0rd!-tok").await.unwrap();
    assert_revoked(&pool, user, "update_password").await;
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn admin_mfa_reset_and_disable_revoke_and_honour_the_stamp() {
    let pool = common::migrated_pool().await;
    let repo = UserRepository::new(pool.clone());

    let target = create_user(&pool, "active").await;
    open_session(&pool, target).await;
    action_authorized(&pool, target, PrincipalAction::ResetMfa).await;
    assert_revoked(&pool, target, "admin MFA reset").await;

    let target = create_user(&pool, "active").await;
    open_session(&pool, target).await;
    action_authorized(&pool, target, PrincipalAction::Disable).await;
    assert_revoked(&pool, target, "disable").await;

    // A stamp taken before an authority change is refused and writes nothing.
    let other = create_user(&pool, "active").await;
    let stale = current_stamp(&pool).await;
    grant(&pool, other, &["search:view"]).await; // bumps grant_authority_version
    let err = repo
        .apply_principal_action_authorized(other, PrincipalAction::Disable, stale)
        .await
        .unwrap_err();
    assert!(matches!(err, UserRepositoryError::GrantAuthorityChanged));
    let status: String = sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(other)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "active", "a stale-stamp action must not mutate the target");
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn signing_another_user_out_revokes_access_tokens() {
    let pool = common::migrated_pool().await;
    let sessions = SessionRepository::new(pool.clone());
    let target = create_user(&pool, "active").await;
    open_session(&pool, target).await;
    let n = sessions.revoke_user_credentials(target).await.unwrap();
    assert_eq!(n, 1);
    assert_revoked(&pool, target, "admin sign-out").await;
}

// ---------------------------------------------------------------------------
// NAN-5048
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn reset_token_read_from_the_database_cannot_be_redeemed() {
    let pool = common::migrated_pool().await;
    let repo = UserRepository::new(pool.clone());
    let user = create_user(&pool, "active").await;
    let plaintext = format!("{:064x}", Uuid::now_v7().as_u128());
    repo.set_password_reset_token(user, &plaintext, Utc::now() + Duration::hours(1))
        .await
        .unwrap();

    let stored: String = sqlx::query_scalar("SELECT password_reset_token FROM users WHERE id = $1")
        .bind(user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(stored, plaintext, "the plaintext reset token must not be at rest");

    // Exploit: a DB reader presents what it read.
    let err = repo.get_user_by_reset_token(&stored).await.unwrap_err();
    assert!(matches!(err, UserRepositoryError::InvalidResetToken), "got {err:?}");

    // Legit: the holder of the plaintext redeems it.
    let found = repo.get_user_by_reset_token(&plaintext).await.unwrap();
    assert_eq!(found.id, user);

    // ...once: the password change clears it.
    repo.update_password(user, "N3w-Passw0rd!-rst").await.unwrap();
    assert!(repo.get_user_by_reset_token(&plaintext).await.is_err());
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn credential_change_clears_a_pending_reset_token() {
    let pool = common::migrated_pool().await;
    let repo = UserRepository::new(pool.clone());
    let user = create_user(&pool, "active").await;
    let plaintext = "f".repeat(64);
    repo.set_password_reset_token(user, &plaintext, Utc::now() + Duration::hours(1))
        .await
        .unwrap();
    update_authorized(&pool, user, &update(None, Some(format!("moved2-{user}@example.invalid")), None)).await;
    assert!(repo.get_user_by_reset_token(&plaintext).await.is_err());
}

// ---------------------------------------------------------------------------
// NAN-5044
// ---------------------------------------------------------------------------

async fn key_service(pool: &PgPool) -> ApiKeyService {
    ApiKeyService::new(
        ApiKeyRepository::new(pool.clone()),
        RateLimitRepository::new(pool.clone()),
    )
    .with_permission_resolver(PermissionResolver::new(pool.clone()))
}

async fn mint(svc: &ApiKeyService, owner: Option<Uuid>, perms: &[&str]) -> String {
    svc.create_key(
        CreateApiKeyRequest {
            name: format!("clamp-{}", Uuid::now_v7()),
            description: None,
            permissions: perms.iter().map(|p| p.to_string()).collect(),
            expires_at: None,
            rate_limit: None,
        },
        owner,
        None,
        None,
    )
    .await
    .unwrap()
    .key
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn demoting_the_owner_demotes_the_key_on_the_next_request() {
    let pool = common::migrated_pool().await;
    let svc = key_service(&pool).await;
    // Ensure enforce (the default) regardless of what a previous run left.
    svc.set_owner_clamp_mode(OwnerClampMode::Enforce).await.unwrap();

    let owner = create_user(&pool, "active").await;
    let admin_group = grant(&pool, owner, &["users:edit", "groups:edit", "search:view"]).await;
    let key = mint(&svc, Some(owner), &["users:edit", "groups:edit", "search:view"]).await;

    let info = svc.validate_key(&key, None).await.unwrap();
    assert_eq!(sorted(info.permissions), vec!["groups:edit", "search:view", "users:edit"]);

    // Demote: drop the privileged group, keep a read-only one.
    grant(&pool, owner, &["search:view"]).await;
    sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2")
        .bind(owner)
        .bind(admin_group)
        .execute(&pool)
        .await
        .unwrap();

    // Same service instance (warm cache) AND a second replica both see it.
    let info = svc.validate_key(&key, None).await.unwrap();
    assert_eq!(info.permissions, vec!["search:view"], "warm cache must honour the demotion");
    let replica = key_service(&pool).await;
    let info = replica.validate_key(&key, None).await.unwrap();
    assert_eq!(info.permissions, vec!["search:view"], "second replica must honour the demotion");
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn audit_mode_keeps_the_stored_set_and_system_and_ownerless_keys_are_not_clamped() {
    let pool = common::migrated_pool().await;
    let svc = key_service(&pool).await;

    let owner = create_user(&pool, "active").await;
    grant(&pool, owner, &["search:view"]).await;
    let key = mint(&svc, Some(owner), &["search:view", "users:edit"]).await;

    svc.set_owner_clamp_mode(OwnerClampMode::Audit).await.unwrap();
    let info = svc.validate_key(&key, None).await.unwrap();
    assert_eq!(sorted(info.permissions), vec!["search:view", "users:edit"]);

    svc.set_owner_clamp_mode(OwnerClampMode::Enforce).await.unwrap();
    let info = svc.validate_key(&key, None).await.unwrap();
    assert_eq!(info.permissions, vec!["search:view"]);

    // `system` service account (no groups): stored set stands.
    let system = create_user(&pool, "system").await;
    let skey = mint(&svc, Some(system), &["search:view", "alerts:view"]).await;
    let info = svc.validate_key(&skey, None).await.unwrap();
    assert_eq!(sorted(info.permissions), vec!["alerts:view", "search:view"]);

    // Ownerless legacy key: audit-only in v2.0.1.
    let okey = mint(&svc, None, &["search:view"]).await;
    let info = svc.validate_key(&okey, None).await.unwrap();
    assert_eq!(info.permissions, vec!["search:view"]);
}
