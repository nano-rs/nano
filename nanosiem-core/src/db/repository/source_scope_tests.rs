// SPDX-License-Identifier: AGPL-3.0-or-later

//! DB-backed tests for [`SourceScopeRepository`] (NAN-1797).
//!
//! `#[ignore]`d: they need a live, migrated Postgres. Run with
//! `cargo test -p nanosiem-core -- --ignored source_scope` after
//! `docker compose up -d postgres` (or in the `pg-integration-tests` CI lane).
//!
//! Each test connects to `DATABASE_URL` (default: the compose `postgres`
//! service), applies the canonical migrations once, and uses randomised
//! `source_type`/email values plus explicit cleanup so parallel runs and
//! re-runs don't collide. Everything created (group, users, registry rows) is
//! torn down at the end; `restricted_source_types` deletes cascade to grants.

use super::*;

const DEFAULT_URL: &str = "postgres://nanosiem:nanosiem@localhost:5432/nanosiem";

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    let pool = PgPool::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("connect to test Postgres at {url}: {e}"));
    crate::db::run_postgres_migrations(&pool)
        .await
        .expect("apply Postgres migrations to the test database");
    pool
}

/// Insert a throwaway group, returning its id.
async fn make_group(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO groups (name, description) VALUES ($1, 'scope test') RETURNING id"#,
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("insert test group")
}

/// Insert a throwaway user, returning its id.
async fn make_user(pool: &PgPool) -> Uuid {
    let email = format!("scope-test-{}@example.test", Uuid::new_v4());
    sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO users (email, name) VALUES ($1, 'scope test') RETURNING id"#,
    )
    .bind(&email)
    .fetch_one(pool)
    .await
    .expect("insert test user")
}

#[tokio::test]
#[ignore = "requires a live migrated Postgres"]
async fn registry_crud_and_notfound() {
    let pool = pool().await;
    let repo = SourceScopeRepository::new(pool.clone());
    let src = format!("insider_threat_test_{}", Uuid::new_v4().simple());

    // add is idempotent + refreshes description.
    let row = repo
        .add_restricted(&src, Some("first"), None)
        .await
        .expect("add");
    assert_eq!(row.source_type, src);
    assert_eq!(row.description.as_deref(), Some("first"));
    let row2 = repo
        .add_restricted(&src, Some("second"), None)
        .await
        .expect("re-add");
    assert_eq!(row2.description.as_deref(), Some("second"));

    // list contains it.
    let listed = repo.list_restricted().await.expect("list");
    assert!(listed.iter().any(|r| r.source_type == src));

    // remove, then a second remove is NotFound.
    repo.remove_restricted(&src).await.expect("remove");
    let err = repo.remove_restricted(&src).await.unwrap_err();
    assert!(matches!(err, SourceScopeError::NotFound(s) if s == src));
}

#[tokio::test]
#[ignore = "requires a live migrated Postgres"]
async fn grants_and_denied_difference() {
    let pool = pool().await;
    let repo = SourceScopeRepository::new(pool.clone());
    let src = format!("insider_threat_test_{}", Uuid::new_v4().simple());

    let group_id = make_group(&pool, "scope-test-group").await;
    let granted_user = make_user(&pool).await; // member of the granted group
    let ungranted_user = make_user(&pool).await; // member of no group
    sqlx::query(r#"INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)"#)
        .bind(granted_user)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("join group");

    repo.add_restricted(&src, None, None).await.expect("add");

    // Before any grant: both users are denied.
    assert!(repo
        .denied_for_user(granted_user)
        .await
        .expect("denied")
        .contains(&src));
    assert!(repo
        .denied_for_user(ungranted_user)
        .await
        .expect("denied")
        .contains(&src));

    // Grant to the group (idempotent, joins the group name).
    let grant = repo.add_grant(&src, group_id, None).await.expect("grant");
    assert_eq!(grant.group_id, group_id);
    assert_eq!(grant.group_name.as_deref(), Some("scope-test-group"));
    let _again = repo.add_grant(&src, group_id, None).await.expect("re-grant");

    assert_eq!(repo.list_grants(&src).await.expect("list").len(), 1);
    assert!(repo
        .list_grants_for_group(group_id)
        .await
        .expect("by group")
        .iter()
        .any(|g| g.source_type == src));

    // After grant: granted user no longer denied; ungranted still denied.
    assert!(!repo
        .denied_for_user(granted_user)
        .await
        .expect("denied")
        .contains(&src));
    assert!(repo
        .denied_for_user(ungranted_user)
        .await
        .expect("denied")
        .contains(&src));

    // Revoke; second revoke is NotFound.
    repo.remove_grant(&src, group_id).await.expect("revoke");
    let err = repo.remove_grant(&src, group_id).await.unwrap_err();
    assert!(matches!(err, SourceScopeError::NotFound(_)));

    // Cleanup (registry delete cascades any remaining grants).
    repo.remove_restricted(&src).await.expect("cleanup src");
    sqlx::query(r#"DELETE FROM user_groups WHERE group_id = $1"#)
        .bind(group_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query(r#"DELETE FROM groups WHERE id = $1"#)
        .bind(group_id)
        .execute(&pool)
        .await
        .ok();
    for u in [granted_user, ungranted_user] {
        sqlx::query(r#"DELETE FROM users WHERE id = $1"#)
            .bind(u)
            .execute(&pool)
            .await
            .ok();
    }
}
