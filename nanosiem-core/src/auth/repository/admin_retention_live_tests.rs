// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5707 live PostgreSQL tests: an administrator cannot remove their own
//! Admin access (group replacement through `set_user_groups_authorized` /
//! `update_user_with_groups_authorized`), and no write may leave the tenant
//! without an active administrator.
//!
//! Against a disposable, fully migrated database only:
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:test@127.0.0.1:38433/nanosiem \
//!   cargo test -p nanosiem-core --lib -- admin_retention_live_tests --ignored --test-threads=1
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::users::{PrincipalAction, UserRepository, UserRepositoryError};
use crate::auth::types::{builtin_roles, UpdateUserRequest};
use crate::auth::GrantAuthorityStamp;

async fn pool() -> Option<PgPool> {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.expect("connect");
    crate::db::run_postgres_migrations(&pool).await.expect("migrations");
    Some(pool)
}

async fn stamp(pool: &PgPool) -> GrantAuthorityStamp {
    let v: i64 = sqlx::query_scalar("SELECT version FROM grant_authority_version WHERE singleton = TRUE")
        .fetch_one(pool)
        .await
        .expect("authority version");
    GrantAuthorityStamp::new(v)
}

async fn user_in(conn: &mut PgConnection, tag: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO users (email, name) VALUES ($1, $1) RETURNING id")
        .bind(format!("{tag}-{}@nan5707.test", Uuid::new_v4().simple()))
        .fetch_one(conn)
        .await
        .expect("user")
}

/// A fresh group bound to the built-in Admin role.
async fn admin_group_in(conn: &mut PgConnection) -> Uuid {
    let group: Uuid = sqlx::query_scalar("INSERT INTO groups (name) VALUES ($1) RETURNING id")
        .bind(format!("nan5707_admins_{}", Uuid::new_v4().simple()))
        .fetch_one(&mut *conn)
        .await
        .expect("group");
    sqlx::query("INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)")
        .bind(group)
        .bind(builtin_roles::ADMIN_ID)
        .execute(&mut *conn)
        .await
        .expect("bind admin role");
    group
}

async fn join_in(conn: &mut PgConnection, user: Uuid, group: Uuid) {
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(user)
        .bind(group)
        .execute(conn)
        .await
        .expect("membership");
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn an_admin_cannot_remove_their_own_admin_groups() {
    let Some(pool) = pool().await else { return };
    let repo = UserRepository::new(pool.clone());
    let mut conn = pool.acquire().await.unwrap();
    let group = admin_group_in(&mut conn).await;
    let me = user_in(&mut conn, "self").await;
    let other = user_in(&mut conn, "other").await;
    join_in(&mut conn, me, group).await;
    join_in(&mut conn, other, group).await;
    drop(conn);

    // PUT /api/users/{self}/groups {"group_ids": []}, even with another admin.
    let err = repo.set_user_groups_authorized(me, &[], stamp(&pool).await, me).await.unwrap_err();
    assert!(matches!(err, UserRepositoryError::CannotRemoveOwnAdmin), "{err:?}");

    // PUT /api/users/{self} {"group_ids": []}: same refusal, nothing written.
    let req = UpdateUserRequest {
        email: None,
        name: Some("renamed".into()),
        password: None,
        status: None,
        group_ids: Some(vec![]),
        revoke_api_keys: None,
        local_login_break_glass: None,
    };
    let err = repo
        .update_user_with_groups_authorized(me, &req, Some(&[]), stamp(&pool).await, me)
        .await
        .unwrap_err();
    assert!(matches!(err, UserRepositoryError::CannotRemoveOwnAdmin), "{err:?}");
    let name: String = sqlx::query_scalar("SELECT name FROM users WHERE id = $1")
        .bind(me)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(name, "renamed", "the refused update rolled back");

    // Another admin may demote me while an admin remains (them).
    repo.set_user_groups_authorized(me, &[], stamp(&pool).await, other).await.expect("demote by other");
    // ...and keeping Admin while editing my own other fields is fine.
    repo.set_user_groups_authorized(other, &[group], stamp(&pool).await, other).await.expect("no-op keep");
}

/// The last-admin rule, checked in a transaction where every other active
/// user is disabled first (rolled back at the end, so the shared database is
/// untouched).
#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn no_write_may_leave_zero_active_admins() {
    let Some(pool) = pool().await else { return };
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET status = 'disabled' WHERE status = 'active'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let group = admin_group_in(&mut tx).await;
    let last = user_in(&mut tx, "last").await;
    let actor = user_in(&mut tx, "actor").await; // a non-Admin-role superuser
    join_in(&mut tx, last, group).await;

    assert!(UserRepository::is_active_admin_in(&mut tx, last).await.unwrap());
    sqlx::query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2")
        .bind(last)
        .bind(group)
        .execute(&mut *tx)
        .await
        .unwrap();
    let err = UserRepository::ensure_admin_retained_in(&mut tx, last, actor, true).await.unwrap_err();
    assert!(matches!(err, UserRepositoryError::LastAdminRequired), "{err:?}");
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn disabling_or_deleting_the_last_admin_is_refused() {
    let Some(pool) = pool().await else { return };
    let repo = UserRepository::new(pool.clone());
    let mut conn = pool.acquire().await.unwrap();
    let group = admin_group_in(&mut conn).await;
    let a = user_in(&mut conn, "a").await;
    let b = user_in(&mut conn, "b").await;
    join_in(&mut conn, a, group).await;
    join_in(&mut conn, b, group).await;
    drop(conn);

    // With another admin present, disabling one admin is allowed.
    repo.apply_principal_action_authorized(a, PrincipalAction::Disable, stamp(&pool).await)
        .await
        .expect("another admin remains");

    // Park every other active admin so `b` is the last one, then try.
    let parked: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE users SET status = 'disabled' WHERE status = 'active' AND id <> $1 RETURNING id",
    )
    .bind(b)
    .fetch_all(&pool)
    .await
    .unwrap();
    let disable = repo.apply_principal_action_authorized(b, PrincipalAction::Disable, stamp(&pool).await).await;
    let delete = repo.apply_principal_action_authorized(b, PrincipalAction::Delete, stamp(&pool).await).await;
    sqlx::query("UPDATE users SET status = 'active' WHERE id = ANY($1)")
        .bind(&parked)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(disable, Err(UserRepositoryError::LastAdminRequired)), "{disable:?}");
    assert!(matches!(delete, Err(UserRepositoryError::LastAdminRequired)), "{delete:?}");
    let status: String = sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(b)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "active", "refused writes roll back");
}
