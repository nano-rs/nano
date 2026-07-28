// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL integration coverage for NAN-2134 and NAN-2223.
//!
//! Run against a disposable, fully migrated database:
//! `TEST_DATABASE_URL=... cargo test -p nanosiem-api-lib --test grant_authority_integration -- --ignored`

use nanosiem_api_lib::{grant_authz, AuthContext};
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::repository::{GroupRepository, GroupRepositoryError};
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::types::builtin_groups;
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

// ---------------------------------------------------------------------------
// NAN-2223: the built-in Everyone baseline is an implicit floor, not a grant.
// ---------------------------------------------------------------------------

async fn test_pool() -> PgPool {
    PgPool::connect(&std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required"))
        .await
        .unwrap()
}

async fn insert_user(pool: &PgPool, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'caller', 'x', 'active')",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .unwrap();
}

/// An API key whose grant authority is EXACTLY `perms` — the frozen
/// `api_keys.permissions` array is the only thing the validator reads for a key
/// principal, never its owner's roles.
async fn insert_api_key(pool: &PgPool, id: Uuid, owner: Uuid, suffix: Uuid, perms: &[&str]) {
    sqlx::query(
        r#"
        INSERT INTO api_keys (id, name, key_hash, key_prefix, permissions, enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, TRUE, $6)
        "#,
    )
    .bind(id)
    .bind(format!("nan2223-key-{suffix}"))
    .bind(format!("hash-{suffix}"))
    .bind(&suffix.simple().to_string()[..10])
    .bind(perms.iter().map(|p| p.to_string()).collect::<Vec<_>>())
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
}

/// The context the auth middleware builds for an API-key request: `claims.sub` is
/// the key OWNER (for FK/audit attribution) and `api_key_id` is the key itself.
fn api_key_auth(owner: Uuid, api_key_id: Uuid, perms: &[&str]) -> AuthContext {
    let claims = TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: owner,
        roles: vec![],
        permissions: perms.iter().map(|p| p.to_string()).collect(),
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    };
    let mut auth = AuthContext::from_jwt(claims);
    auth.is_api_key = true;
    auth.api_key_id = Some(api_key_id);
    auth
}

/// (a) A least-privilege provisioning key can create users and rotate OIDC
/// client secrets again.
///
/// Before NAN-2223 both paths unioned the built-in Everyone group into the
/// validated set, so the caller had to hold every one of the seeded ReadOnly
/// role's 21 permissions. A key scoped to `["users:create","users:view"]` — or to
/// `["settings:system"]` for the OIDC admin surface, whose update path demands
/// grant authority unless the request explicitly disables the provider — could
/// never satisfy that, and failed 403 permanently.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn least_privilege_api_key_can_provision_users_and_rotate_oidc_secrets() {
    let pool = test_pool().await;
    let suffix = Uuid::now_v7();
    let owner = Uuid::now_v7();
    insert_user(&pool, owner, &format!("nan2223-a-{suffix}@example.invalid")).await;

    // POST /api/users with no groups requested.
    let provisioning_key = Uuid::now_v7();
    insert_api_key(
        &pool,
        provisioning_key,
        owner,
        Uuid::now_v7(),
        &[permissions::USERS_CREATE, permissions::USERS_VIEW],
    )
    .await;
    let auth = api_key_auth(
        owner,
        provisioning_key,
        &[permissions::USERS_CREATE, permissions::USERS_VIEW],
    );
    grant_authz::ensure_can_grant_groups(&auth, &pool, permissions::USERS_CREATE, &[])
        .await
        .expect("a users:create key must be able to create a user in the Everyone baseline");

    // PUT /api/users/{id}/groups clearing a user back to the baseline.
    let editor_key = Uuid::now_v7();
    insert_api_key(
        &pool,
        editor_key,
        owner,
        Uuid::now_v7(),
        &[permissions::USERS_EDIT],
    )
    .await;
    let editor_auth = api_key_auth(owner, editor_key, &[permissions::USERS_EDIT]);
    grant_authz::ensure_can_grant_groups(&editor_auth, &pool, permissions::USERS_EDIT, &[])
        .await
        .expect("a users:edit key must be able to set a user's groups back to the baseline");

    // OIDC provider create/update/enable — `ensure_oidc_jit_grant_authority`
    // validates exactly this call, and `update_requires_grant_authority` makes a
    // secret rotation (`enabled: None`) take the same path.
    let sso_key = Uuid::now_v7();
    insert_api_key(
        &pool,
        sso_key,
        owner,
        Uuid::now_v7(),
        &[permissions::SETTINGS_SYSTEM],
    )
    .await;
    let sso_auth = api_key_auth(owner, sso_key, &[permissions::SETTINGS_SYSTEM]);
    grant_authz::ensure_can_grant_groups(&sso_auth, &pool, permissions::SETTINGS_SYSTEM, &[])
        .await
        .expect("a settings:system key must be able to rotate an OIDC client secret");

    // The required permission itself is still enforced against CURRENT database
    // state: the same key cannot borrow an authority its array does not carry.
    let err = grant_authz::ensure_can_grant_groups(&auth, &pool, permissions::SETTINGS_SYSTEM, &[])
        .await
        .unwrap_err();
    assert_eq!(err.status.as_u16(), 403);
    assert!(err.message.contains(permissions::SETTINGS_SYSTEM));
}

/// (b) The NAN-2121 hold-to-grant guard is untouched for every group the caller
/// EXPLICITLY names — including when Everyone is named alongside it, which must
/// not launder the privileged group past the check.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn explicit_group_grants_are_still_denied_when_the_caller_lacks_their_privileges() {
    let pool = test_pool().await;
    let suffix = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let privileged_role = Uuid::now_v7();
    let privileged_group = Uuid::now_v7();
    insert_user(&pool, owner, &format!("nan2223-b-{suffix}@example.invalid")).await;
    insert_role(
        &pool,
        privileged_role,
        &format!("nan2223-privileged-{suffix}"),
        &[permissions::SETTINGS_SYSTEM],
    )
    .await;
    insert_group(
        &pool,
        privileged_group,
        &format!("nan2223-privileged-{suffix}"),
        Some(privileged_role),
    )
    .await;

    let key = Uuid::now_v7();
    insert_api_key(
        &pool,
        key,
        owner,
        Uuid::now_v7(),
        &[permissions::USERS_CREATE, permissions::USERS_VIEW],
    )
    .await;
    let auth = api_key_auth(
        owner,
        key,
        &[permissions::USERS_CREATE, permissions::USERS_VIEW],
    );

    let err = grant_authz::ensure_can_grant_groups(
        &auth,
        &pool,
        permissions::USERS_CREATE,
        &[privileged_group],
    )
    .await
    .unwrap_err();
    assert_eq!(err.status.as_u16(), 403);
    assert!(
        err.message.contains(permissions::SETTINGS_SYSTEM),
        "the escalation the caller attempted must still be named: {}",
        err.message
    );

    // Naming Everyone next to it must not dilute the check — the exemption is
    // keyed on one hard-coded id, not on "the request mentions Everyone".
    let err = grant_authz::ensure_can_grant_groups(
        &auth,
        &pool,
        permissions::USERS_CREATE,
        &[builtin_groups::EVERYONE_ID, privileged_group],
    )
    .await
    .unwrap_err();
    assert_eq!(err.status.as_u16(), 403);
    assert!(err.message.contains(permissions::SETTINGS_SYSTEM));

    // A nonexistent explicit group is still a 400, not a silently-empty grant.
    let err = grant_authz::ensure_can_grant_groups(
        &auth,
        &pool,
        permissions::USERS_CREATE,
        &[Uuid::now_v7()],
    )
    .await
    .unwrap_err();
    assert_eq!(err.status.as_u16(), 400);
}

/// (c) Naming Everyone explicitly is indistinguishable from omitting it, because
/// the resulting membership is identical either way — while
/// `ensure_can_grant_groups_exact`, which callers use where the grant does NOT
/// confer Everyone membership, keeps validating whatever it is handed.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn naming_everyone_explicitly_matches_omitting_it() {
    let pool = test_pool().await;
    let suffix = Uuid::now_v7();
    let owner = Uuid::now_v7();
    insert_user(&pool, owner, &format!("nan2223-c-{suffix}@example.invalid")).await;
    let key = Uuid::now_v7();
    insert_api_key(
        &pool,
        key,
        owner,
        Uuid::now_v7(),
        &[permissions::USERS_EDIT],
    )
    .await;
    let auth = api_key_auth(owner, key, &[permissions::USERS_EDIT]);

    grant_authz::ensure_can_grant_groups(&auth, &pool, permissions::USERS_EDIT, &[])
        .await
        .expect("omitting Everyone is allowed");
    grant_authz::ensure_can_grant_groups(
        &auth,
        &pool,
        permissions::USERS_EDIT,
        &[builtin_groups::EVERYONE_ID],
    )
    .await
    .expect("naming Everyone must behave identically — membership is unconditional either way");
    // Duplicates collapse the same way.
    grant_authz::ensure_can_grant_groups(
        &auth,
        &pool,
        permissions::USERS_EDIT,
        &[builtin_groups::EVERYONE_ID, builtin_groups::EVERYONE_ID],
    )
    .await
    .expect("a repeated Everyone is still just the baseline");

    // The `_exact` entry point is deliberately NOT exempted: it exists for grants
    // that do not confer Everyone membership (OIDC claim→group mappings), where
    // naming Everyone IS a discretionary choice.
    assert!(
        grant_authz::ensure_can_grant_groups_exact(
            &auth,
            &pool,
            permissions::USERS_EDIT,
            &[builtin_groups::EVERYONE_ID],
        )
        .await
        .is_err(),
        "the exemption must stay confined to the membership entry point"
    );
}

/// The floor covers the whole Everyone baseline, not just its role permissions.
///
/// An API key resolves SOURCE scope against the KEY id, which has no group
/// memberships, so it is denied every restricted source unless it holds
/// `source_scopes:view_all`. Unioning Everyone therefore also failed the
/// source-scope half of the check the moment a tenant granted any restricted
/// source to Everyone — locking out user provisioning entirely on exactly the
/// grant that makes the source visible to every account anyway.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable fully migrated PostgreSQL database"]
async fn everyone_source_baseline_does_not_block_provisioning() {
    let pool = test_pool().await;
    let suffix = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let source = format!("nan2223_baseline_{suffix}");
    insert_user(&pool, owner, &format!("nan2223-d-{suffix}@example.invalid")).await;
    let key = Uuid::now_v7();
    insert_api_key(
        &pool,
        key,
        owner,
        Uuid::now_v7(),
        &[permissions::USERS_CREATE],
    )
    .await;
    let auth = api_key_auth(owner, key, &[permissions::USERS_CREATE]);

    let repo = SourceScopeRepository::new(pool.clone());
    repo.add_restricted(&source, None, Some(owner))
        .await
        .unwrap();
    repo.add_grant(&source, builtin_groups::EVERYONE_ID, Some(owner))
        .await
        .unwrap();

    let result =
        grant_authz::ensure_can_grant_groups(&auth, &pool, permissions::USERS_CREATE, &[]).await;

    // Clean up before asserting so a failure cannot leave the tenant-wide grant
    // behind for the rest of the suite.
    repo.remove_grant(&source, builtin_groups::EVERYONE_ID)
        .await
        .unwrap();
    repo.remove_restricted(&source).await.unwrap();

    result.expect("a tenant-wide baseline source grant must not block user provisioning");
}
