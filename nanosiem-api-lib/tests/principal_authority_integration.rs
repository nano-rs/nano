// SPDX-License-Identifier: AGPL-3.0-or-later

//! Security review (2026-11-08), group D — authority over ANOTHER principal
//! (NAN-5027) and the API-key grant clamp (NAN-5044), exercised as a
//! LOW-PRIVILEGE delegated caller against a real migrated PostgreSQL.
//!
//! `TEST_DATABASE_URL=... cargo test -p nanosiem-api-lib --test principal_authority_integration -- --ignored`

use nanosiem_api_lib::{grant_authz, AuthContext};
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::types::builtin_roles;
use nanosiem_core::auth::{ApiKeyInfo, ScopeSet, TokenClaims};
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    PgPool::connect(&std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required"))
        .await
        .unwrap()
}

async fn user(pool: &PgPool, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'p', 'x', $3)",
    )
    .bind(id)
    .bind(format!("nan5027-{id}@example.invalid"))
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Put `user` in a fresh custom group whose single role carries `perms`.
async fn grant(pool: &PgPool, user: Uuid, perms: &[&str]) -> Uuid {
    let role = Uuid::now_v7();
    let group = Uuid::now_v7();
    sqlx::query("INSERT INTO roles (id, name, description, is_system) VALUES ($1, $2, 't', FALSE)")
        .bind(role)
        .bind(format!("nan5027-role-{role}"))
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
        .bind(format!("nan5027-group-{group}"))
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

/// Join `user` to a fresh group bound to the built-in Admin role.
async fn make_admin(pool: &PgPool, user: Uuid) {
    let group = Uuid::now_v7();
    sqlx::query("INSERT INTO groups (id, name, description, is_system) VALUES ($1, $2, 't', FALSE)")
        .bind(group)
        .bind(format!("nan5027-admins-{group}"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)")
        .bind(group)
        .bind(builtin_roles::ADMIN_ID)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(user)
        .bind(group)
        .execute(pool)
        .await
        .unwrap();
}

fn session(user: Uuid) -> AuthContext {
    let mut auth = AuthContext::from_jwt(TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: user,
        roles: vec![],
        permissions: vec![],
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    });
    auth.denied_sources = ScopeSet::unrestricted();
    auth
}

async fn key(pool: &PgPool, owner: Uuid, perms: &[&str]) -> AuthContext {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO api_keys (id, name, key_hash, key_prefix, permissions, enabled, created_by) \
         VALUES ($1, $2, $3, $4, $5, TRUE, $6)",
    )
    .bind(id)
    .bind(format!("nan5044-{id}"))
    .bind(format!("hash-{id}"))
    .bind(&id.simple().to_string()[..10])
    .bind(perms.iter().map(|p| p.to_string()).collect::<Vec<_>>())
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
    let mut auth = AuthContext::from_api_key(&ApiKeyInfo {
        id,
        name: "k".into(),
        permissions: perms.iter().map(|p| p.to_string()).collect(),
        user_id: Some(owner),
    });
    auth.denied_sources = ScopeSet::unrestricted();
    auth
}

const HELPDESK: &[&str] = &["users:view", "users:edit", "search:view", "alerts:view"];

async fn manage(auth: &AuthContext, pool: &PgPool, target: Uuid) -> Result<(), String> {
    grant_authz::ensure_can_manage_principal(auth, pool, permissions::USERS_EDIT, target, None)
        .await
        .map(|_| ())
        .map_err(|e| e.code.to_string())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn delegated_users_edit_cannot_take_over_a_more_privileged_account() {
    let pool = pool().await;
    let helpdesk = user(&pool, "active").await;
    grant(&pool, helpdesk, HELPDESK).await;

    // Target: an Admin (the built-in Admins group carries every permission).
    let admin = user(&pool, "active").await;
    make_admin(&pool, admin).await;

    // Exploit (NAN-5027): users:edit alone used to rewrite this Admin's
    // password / email / MFA. Now refused, via a session AND via a key.
    assert_eq!(
        manage(&session(helpdesk), &pool, admin).await.unwrap_err(),
        "target_privilege_exceeds_caller"
    );
    let helpdesk_key = key(&pool, helpdesk, HELPDESK).await;
    assert_eq!(
        manage(&helpdesk_key, &pool, admin).await.unwrap_err(),
        "target_privilege_exceeds_caller"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn delegated_users_edit_still_manages_principals_it_covers() {
    let pool = pool().await;
    let helpdesk = user(&pool, "active").await;
    grant(&pool, helpdesk, HELPDESK).await;

    let analyst = user(&pool, "active").await;
    grant(&pool, analyst, &["search:view", "alerts:view"]).await;
    manage(&session(helpdesk), &pool, analyst)
        .await
        .expect("a helpdesk role covering the analyst manages them");

    // A session acting on itself is always allowed.
    manage(&session(helpdesk), &pool, helpdesk).await.expect("self");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn system_accounts_and_missing_targets_are_refused() {
    let pool = pool().await;
    let caller = user(&pool, "active").await;
    make_admin(&pool, caller).await;
    let system = user(&pool, "system").await;
    assert_eq!(manage(&session(caller), &pool, system).await.unwrap_err(), "system_account");
    assert_eq!(
        manage(&session(caller), &pool, Uuid::now_v7()).await.unwrap_err(),
        "not_found"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn a_key_minted_before_demotion_cannot_re_promote_its_owner() {
    let pool = pool().await;
    let owner = user(&pool, "active").await;
    let privileged = grant(
        &pool,
        owner,
        &["users:view", "users:edit", "groups:view", "groups:edit", "search:view"],
    )
    .await;
    let target_group = Uuid::now_v7();
    // A group conferring users:edit + groups:edit (what the key wants to re-grant).
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO roles (id, name, description, is_system) VALUES ($1, $2, 't', FALSE)")
        .bind(role)
        .bind(format!("nan5044-repromote-{role}"))
        .execute(&pool)
        .await
        .unwrap();
    for p in ["users:edit", "groups:edit"] {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(role)
            .bind(p)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO groups (id, name, description, is_system) VALUES ($1, $2, 't', FALSE)")
        .bind(target_group)
        .bind(format!("nan5044-repromote-{target_group}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)")
        .bind(target_group)
        .bind(role)
        .execute(&pool)
        .await
        .unwrap();

    let k = key(
        &pool,
        owner,
        &["users:view", "users:edit", "groups:view", "groups:edit", "search:view"],
    )
    .await;
    // Before demotion the key may grant the group (owner holds everything).
    grant_authz::ensure_can_grant_groups(&k, &pool, permissions::USERS_EDIT, &[target_group])
        .await
        .expect("pre-demotion grant is within the owner's authority");

    // Demote the owner to read-only. The key's stored array is unchanged.
    grant(&pool, owner, &["search:view", "users:view"]).await;
    sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2")
        .bind(owner)
        .bind(privileged)
        .execute(&pool)
        .await
        .unwrap();

    // Exploit (NAN-5044): the frozen key re-adds its owner to the privileged
    // group. Now its grant authority is clamped to the owner → refused.
    let err = grant_authz::ensure_can_grant_groups(&k, &pool, permissions::USERS_EDIT, &[target_group])
        .await
        .unwrap_err();
    assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn narrow_group_and_role_editors_cannot_strip_authority_they_lack() {
    let pool = pool().await;
    let editor = user(&pool, "active").await;
    grant(&pool, editor, &["groups:edit", "groups:delete", "roles:edit", "roles:delete", "search:view"]).await;

    // A privileged group/role the editor does not cover.
    let holder = user(&pool, "active").await;
    let privileged_group = grant(&pool, holder, &["users:edit", "settings:system"]).await;
    let privileged_role: Uuid = sqlx::query_scalar("SELECT role_id FROM group_roles WHERE group_id = $1")
        .bind(privileged_group)
        .fetch_one(&pool)
        .await
        .unwrap();

    let e = session(editor);
    for (what, res) in [
        ("group roles", grant_authz::ensure_can_revoke_group(&e, &pool, permissions::GROUPS_EDIT, privileged_group).await),
        ("group delete", grant_authz::ensure_can_revoke_group(&e, &pool, permissions::GROUPS_DELETE, privileged_group).await),
        ("role edit", grant_authz::ensure_can_revoke_role(&e, &pool, permissions::ROLES_EDIT, privileged_role).await),
        ("role delete", grant_authz::ensure_can_revoke_role(&e, &pool, permissions::ROLES_DELETE, privileged_role).await),
    ] {
        assert_eq!(res.unwrap_err().status, axum::http::StatusCode::FORBIDDEN, "{what}");
    }

    // A group/role the editor covers can still be changed.
    let peer = user(&pool, "active").await;
    let peer_group = grant(&pool, peer, &["search:view"]).await;
    grant_authz::ensure_can_revoke_group(&e, &pool, permissions::GROUPS_EDIT, peer_group)
        .await
        .expect("covered group");
}
