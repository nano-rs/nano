// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL integration coverage for NAN-2134.
//!
//! Run against a disposable, fully migrated database:
//! `TEST_DATABASE_URL=... cargo test -p nanosiem-api-lib --test grant_authority_integration -- --ignored`

use nanosiem_api_lib::{grant_authz, AuthContext};
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::repository::{GroupRepository, GroupRepositoryError};
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::{ScopeSet, TokenClaims};
use nanosiem_core::db::repository::{SourceScopeError, SourceScopeRepository};
use sqlx::PgPool;
use uuid::Uuid;

fn stale_auth(user_id: Uuid) -> AuthContext {
    let claims = TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: user_id,
        roles: vec![],
        // Deliberately broader than the database state. The production
        // validator must ignore these stale grant/source capabilities.
        permissions: vec![
            permissions::GROUPS_EDIT.to_string(),
            permissions::SOURCE_SCOPES_MANAGE.to_string(),
            permissions::SOURCE_SCOPES_VIEW_ALL.to_string(),
            permissions::SEARCH_VIEW.to_string(),
        ],
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    };
    let mut auth = AuthContext::from_jwt(claims);
    auth.denied_sources = ScopeSet::unrestricted();
    auth
}

async fn insert_role(pool: &PgPool, id: Uuid, name: &str, permissions: &[&str]) {
    sqlx::query(
        "INSERT INTO roles (id, name, description, is_system) VALUES ($1, $2, 'test', FALSE)",
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await
    .unwrap();
    for permission in permissions {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(id)
            .bind(permission)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn insert_group(pool: &PgPool, id: Uuid, name: &str, role_id: Option<Uuid>) {
    sqlx::query(
        "INSERT INTO groups (id, name, description, is_system) VALUES ($1, $2, 'test', FALSE)",
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await
    .unwrap();
    if let Some(role_id) = role_id {
        sqlx::query("INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)")
            .bind(id)
            .bind(role_id)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn changed_role_entitlements_abort_the_real_assignment_write() {
    let pool = PgPool::connect(
        &std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required"),
    )
    .await
    .unwrap();
    let suffix = Uuid::now_v7();
    let caller = Uuid::now_v7();
    let caller_role = Uuid::now_v7();
    let caller_group = Uuid::now_v7();
    let target_role = Uuid::now_v7();
    let target_group = Uuid::now_v7();

    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'caller', 'x', 'active')",
    )
    .bind(caller)
    .bind(format!("nan2134-{suffix}@example.invalid"))
    .execute(&pool)
    .await
    .unwrap();
    insert_role(
        &pool,
        caller_role,
        &format!("nan2134-caller-{suffix}"),
        &[
            permissions::GROUPS_EDIT,
            permissions::SOURCE_SCOPES_MANAGE,
            permissions::SEARCH_VIEW,
        ],
    )
    .await;
    insert_group(
        &pool,
        caller_group,
        &format!("nan2134-caller-{suffix}"),
        Some(caller_role),
    )
    .await;
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(caller)
        .bind(caller_group)
        .execute(&pool)
        .await
        .unwrap();
    insert_role(
        &pool,
        target_role,
        &format!("nan2134-target-{suffix}"),
        &[permissions::SEARCH_VIEW],
    )
    .await;
    insert_group(
        &pool,
        target_group,
        &format!("nan2134-target-{suffix}"),
        None,
    )
    .await;

    // An API key's stale in-memory permission list is not grant authority.
    let api_key_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO api_keys
            (id, name, key_hash, key_prefix, permissions, enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, TRUE, $6)
        "#,
    )
    .bind(api_key_id)
    .bind(format!("nan2134-key-{suffix}"))
    .bind(format!("hash-{suffix}"))
    .bind(&suffix.simple().to_string()[..10])
    .bind(vec![permissions::GROUPS_EDIT.to_string()])
    .bind(caller)
    .execute(&pool)
    .await
    .unwrap();
    let mut stale_key_auth = stale_auth(caller);
    stale_key_auth.is_api_key = true;
    stale_key_auth.api_key_id = Some(api_key_id);
    assert!(
        grant_authz::ensure_can_grant_roles(
            &stale_key_auth,
            &pool,
            permissions::GROUPS_EDIT,
            &[target_role],
        )
        .await
        .is_err(),
        "current API-key permissions must override its stale in-memory search:view claim"
    );

    let auth = stale_auth(caller);
    let stamp =
        grant_authz::ensure_can_grant_roles(&auth, &pool, permissions::GROUPS_EDIT, &[target_role])
            .await
            .expect("initial current entitlement is grantable");

    // Change the real target entitlement after validation. Calling the
    // production repository assignment with the stale stamp must abort before
    // it inserts any group_roles row.
    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(target_role)
        .bind(permissions::SETTINGS_SYSTEM)
        .execute(&pool)
        .await
        .unwrap();
    let repo = GroupRepository::new(pool.clone());
    let err = repo
        .set_group_roles_authorized(target_group, &[target_role], stamp)
        .await
        .unwrap_err();
    assert!(matches!(err, GroupRepositoryError::GrantAuthorityChanged));
    let assigned: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_roles WHERE group_id = $1 AND role_id = $2)",
    )
    .bind(target_group)
    .bind(target_role)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !assigned,
        "the stale-authority write must not partially land"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn committed_scope_revocation_denies_stale_context_and_stale_stamp() {
    let pool = PgPool::connect(
        &std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required"),
    )
    .await
    .unwrap();
    let suffix = Uuid::now_v7();
    let caller = Uuid::now_v7();
    let caller_role = Uuid::now_v7();
    let caller_group = Uuid::now_v7();
    let target_group = Uuid::now_v7();
    let source = format!("nan2134_secret_{suffix}");

    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'caller', 'x', 'active')",
    )
    .bind(caller)
    .bind(format!("nan2134-source-{suffix}@example.invalid"))
    .execute(&pool)
    .await
    .unwrap();
    insert_role(
        &pool,
        caller_role,
        &format!("nan2134-source-role-{suffix}"),
        &[permissions::SOURCE_SCOPES_MANAGE],
    )
    .await;
    insert_group(
        &pool,
        caller_group,
        &format!("nan2134-source-caller-{suffix}"),
        Some(caller_role),
    )
    .await;
    insert_group(
        &pool,
        target_group,
        &format!("nan2134-source-target-{suffix}"),
        None,
    )
    .await;
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(caller)
        .bind(caller_group)
        .execute(&pool)
        .await
        .unwrap();

    let repo = SourceScopeRepository::new(pool.clone());
    repo.add_restricted(&source, None, Some(caller))
        .await
        .unwrap();
    repo.add_grant(&source, caller_group, Some(caller))
        .await
        .unwrap();
    let auth = stale_auth(caller);
    let stamp = grant_authz::ensure_can_mutate_source(&auth, &pool, &source)
        .await
        .expect("caller currently holds the source grant");

    // Simulate revocation committed on another API replica.
    repo.remove_grant(&source, caller_group).await.unwrap();

    let stale_write = repo
        .add_grant_authorized(&source, target_group, Some(caller), stamp)
        .await
        .unwrap_err();
    assert!(matches!(
        stale_write,
        SourceScopeError::GrantAuthorityChanged
    ));
    assert!(
        grant_authz::ensure_can_mutate_source(&auth, &pool, &source)
            .await
            .is_err(),
        "fresh PostgreSQL authority must override stale token/cache view_all state"
    );
}
