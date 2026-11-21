// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5711: an owner-scoped dashboard delete that removes nothing says why
//! without disclosing a dashboard the caller cannot see.
//!
//! - missing (e.g. a retried delete) → `NotFound` (404), as an admin and `GET` get;
//! - private dashboard owned by someone else → `NotFound` (existence not leaked);
//! - public dashboard owned by someone else → `AccessDenied` (403).
//!
//! Needs a disposable Postgres: `DATABASE_URL=... NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1
//! cargo test -p nanosiem-core --test dashboard_delete_status_integration -- --ignored`

mod common;

use nanosiem_core::db::repository::{DashboardRepository, DashboardRepositoryError};
use nanosiem_core::models::NewDashboard;
use sqlx::PgPool;
use uuid::Uuid;

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Dashboard Delete Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("dd-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn dashboard(repo: &DashboardRepository, owner: Uuid, visibility: &str) -> Uuid {
    repo.create(&NewDashboard {
        name: format!("nan5711-{}", Uuid::now_v7()),
        description: None,
        layout: serde_json::json!([]),
        panels: serde_json::json!([]),
        refresh_interval: None,
        owner_id: Some(owner),
        visibility: visibility.to_string(),
    })
    .await
    .expect("create dashboard")
    .id
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL)"]
async fn deleting_a_missing_dashboard_is_not_found_for_a_non_admin() {
    let pool = common::migrated_pool().await;
    let repo = DashboardRepository::new(pool.clone());
    let owner = user(&pool).await;
    let id = dashboard(&repo, owner, "private").await;

    repo.delete_owned(id, owner).await.expect("owner deletes");
    // The retried delete: already gone.
    assert!(matches!(
        repo.delete_owned(id, owner).await,
        Err(DashboardRepositoryError::NotFound(got)) if got == id
    ));
    // Same answer the admin path gives.
    assert!(matches!(repo.delete_as_admin(id).await, Err(DashboardRepositoryError::NotFound(_))));
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL)"]
async fn deleting_someone_elses_private_dashboard_does_not_reveal_it() {
    let pool = common::migrated_pool().await;
    let repo = DashboardRepository::new(pool.clone());
    let owner = user(&pool).await;
    let other = user(&pool).await;
    let id = dashboard(&repo, owner, "private").await;

    assert!(matches!(
        repo.delete_owned(id, other).await,
        Err(DashboardRepositoryError::NotFound(got)) if got == id
    ));
    assert!(repo.find_by_id(id).await.is_ok(), "the dashboard must survive");
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL)"]
async fn deleting_someone_elses_visible_dashboard_is_forbidden() {
    let pool = common::migrated_pool().await;
    let repo = DashboardRepository::new(pool.clone());
    let owner = user(&pool).await;
    let other = user(&pool).await;
    let id = dashboard(&repo, owner, "public").await;

    assert!(matches!(
        repo.delete_owned(id, other).await,
        Err(DashboardRepositoryError::AccessDenied(got)) if got == id
    ));
    assert!(repo.find_by_id(id).await.is_ok(), "the dashboard must survive");
}
