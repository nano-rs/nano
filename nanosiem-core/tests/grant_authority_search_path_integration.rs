// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3917: the grant-authority trigger chain resolves names through a pinned
//! search_path (migration 289), not the caller's.
//!
//! Ported for clickhouse/dev. Main's version also covers OIDC group admission
//! (its migration 368), which this branch does not carry.
mod common;

use nanosiem_core::auth::{CreateUserRequest, GroupRepository, UserRepository};
use sqlx::PgPool;
use uuid::Uuid;

const PINNED: &str = "search_path=pg_catalog, public, pg_temp";

/// Every function migration 289 pins (and overlay 9000071 re-pins).
const PINNED_FUNCTIONS: &[&str] = &[
    "bump_grant_authority_version",
    "normalize_reserved_role_name",
    "guard_reserved_role_name_write",
    "sync_playbook_acl_role_label",
    "normalize_playbook_permission_role_key",
    "lock_playbook_acl_compatibility_write",
    "assert_playbook_acl_compatibility_write",
    "lock_playbook_acl_role_permission_write",
    "assert_playbook_acl_role_permission_write",
];

async fn version(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT version FROM public.grant_authority_version WHERE singleton")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn grant_authority_trigger_functions_pin_search_path() {
    let pool = common::migrated_pool().await;
    for name in PINNED_FUNCTIONS {
        let config: Option<Vec<String>> = sqlx::query_scalar(
            "SELECT p.proconfig FROM pg_proc p
               JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = $1",
        )
        .bind(name)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{name} must exist: {e}"));
        assert!(
            config.unwrap_or_default().iter().any(|c| c == PINNED),
            "{name} must pin `{PINNED}`"
        );
    }
}

/// A caller whose search_path puts a shadow `grant_authority_version` first
/// must not redirect the bump: the real generation advances and the shadow
/// stays untouched. Without the pin the trigger updated the shadow table.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn a_shadowing_caller_search_path_cannot_redirect_the_grant_bump() {
    let pool = common::migrated_pool().await;
    let before = version(&pool).await;

    let mut tx = pool.begin().await.unwrap();
    let schema = format!("nan3917_shadow_{}", Uuid::new_v4().simple());
    for sql in [
        format!("CREATE SCHEMA {schema}"),
        format!(
            "CREATE TABLE {schema}.grant_authority_version
                 (singleton BOOLEAN PRIMARY KEY, version BIGINT NOT NULL)"
        ),
        format!("INSERT INTO {schema}.grant_authority_version VALUES (TRUE, 0)"),
        format!("SET LOCAL search_path = {schema}, public"),
    ] {
        sqlx::query(&sql).execute(&mut *tx).await.unwrap();
    }

    // Any grant-table write fires the statement trigger.
    let group = Uuid::new_v4();
    sqlx::query("INSERT INTO public.groups (id, name) VALUES ($1, $2)")
        .bind(group)
        .bind(format!("NAN-3917 {group}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO public.group_roles (group_id, role_id) VALUES ($1, $2)")
        .bind(group)
        .bind(Uuid::from_u128(1))
        .execute(&mut *tx)
        .await
        .unwrap();

    let real: i64 = sqlx::query_scalar(
        "SELECT version FROM public.grant_authority_version WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let shadow: i64 = sqlx::query_scalar(&format!(
        "SELECT version FROM {schema}.grant_authority_version WHERE singleton"
    ))
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();

    assert!(real > before, "the real generation must advance");
    assert_eq!(shadow, 0, "the caller's shadow table must not be touched");
}

/// The setup path (`/api/setup/initialize`): create_user fires the Everyone
/// group trigger, whose nested user_groups insert fires the grant bump.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn setup_admin_membership_still_advances_grant_authority() {
    std::env::set_var(
        "NANOSIEM_ENCRYPTION_KEY",
        "nan3917-disposable-test-key-32bytes",
    );
    let pool = common::migrated_pool().await;
    let users = UserRepository::new(pool.clone());
    let groups = GroupRepository::new(pool.clone());

    let before = version(&pool).await;
    let admin = users
        .create_user(&CreateUserRequest {
            email: format!("setup-{}@example.test", Uuid::new_v4()),
            name: "Setup admin".into(),
            password: "Disposable-3917-Password!".into(),
            group_ids: vec![],
        })
        .await
        .unwrap();
    assert!(version(&pool).await > before);
    assert!(groups
        .is_user_in_group(admin.id, Uuid::from_u128(1))
        .await
        .unwrap());

    let group = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(group)
        .bind(format!("Admission {group}"))
        .execute(&pool)
        .await
        .unwrap();
    let before = version(&pool).await;
    groups.add_user_to_group(admin.id, group).await.unwrap();
    assert!(version(&pool).await > before);
    assert!(groups.is_user_in_group(admin.id, group).await.unwrap());

    let before = version(&pool).await;
    users
        .set_user_groups(admin.id, &[group, Uuid::from_u128(1)])
        .await
        .unwrap();
    assert!(version(&pool).await > before);
}
