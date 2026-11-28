// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5637: the server is the source of truth for who may change a dashboard.
//! `PUT /api/dashboards/:id` from a non-admin goes through `update_owned`
//! (admins, `settings:system`, through `update_as_admin`), and the handler maps
//! `AccessDenied` to 403. pivt's add/edit-panel actions and the page's Edit
//! button both save through that route, so:
//!
//! - a `dashboards:edit` user who does not own a dashboard shared with them
//!   (public) is refused and nothing changes, panels or name;
//! - the owner's save goes through;
//! - an admin may edit a dashboard they don't own.
//!
//! Needs a disposable Postgres: `DATABASE_URL=... NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1
//! cargo test -p nanosiem-core --test dashboard_update_owner_integration -- --ignored`

mod common;

use nanosiem_core::db::repository::{DashboardRepository, DashboardRepositoryError};
use nanosiem_core::models::{NewDashboard, UpdateDashboard};
use sqlx::PgPool;
use uuid::Uuid;

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Dashboard Update Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("du-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn dashboard(repo: &DashboardRepository, owner: Uuid, visibility: &str) -> Uuid {
    repo.create(&NewDashboard {
        name: format!("nan5637-{}", Uuid::now_v7()),
        description: None,
        layout: serde_json::json!({"columns": 12, "rowHeight": 80, "items": []}),
        panels: serde_json::json!([]),
        refresh_interval: None,
        owner_id: Some(owner),
        visibility: visibility.to_string(),
    })
    .await
    .expect("create dashboard")
    .id
}

/// What pivt's `dashboards.add_panel` sends: the panel list with one more panel.
fn add_panel() -> UpdateDashboard {
    UpdateDashboard {
        name: None,
        description: None,
        layout: None,
        panels: Some(serde_json::json!([{
            "id": "panel-nope",
            "title": "Nope",
            "query": "class_name=\"Authentication\" | stats count",
            "queryMode": "piped",
            "visualizationType": "table",
            "visualizationConfig": {},
        }])),
        refresh_interval: None,
    }
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn a_non_owner_cannot_add_a_panel_to_a_shared_dashboard() {
    let pool = common::migrated_pool().await;
    let repo = DashboardRepository::new(pool.clone());
    let owner = user(&pool).await;
    let other = user(&pool).await;
    let id = dashboard(&repo, owner, "public").await;
    let before = repo.find_by_id(id).await.expect("exists");

    assert!(matches!(
        repo.update_owned(id, other, &add_panel(), Some(before.updated_at)).await,
        Err(DashboardRepositoryError::AccessDenied(got)) if got == id
    ));
    let rename = UpdateDashboard { name: Some("taken over".into()), ..add_panel() };
    assert!(matches!(
        repo.update_owned(id, other, &rename, None).await,
        Err(DashboardRepositoryError::AccessDenied(_))
    ));

    let after = repo.find_by_id(id).await.expect("still exists");
    assert_eq!(after.panels, serde_json::json!([]), "no panel was added");
    assert_eq!(after.name, before.name, "not renamed");
    assert_eq!(after.updated_at, before.updated_at, "nothing was written");
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn the_owner_and_an_admin_can_add_a_panel() {
    let pool = common::migrated_pool().await;
    let repo = DashboardRepository::new(pool.clone());
    let owner = user(&pool).await;
    let id = dashboard(&repo, owner, "public").await;
    let before = repo.find_by_id(id).await.expect("exists");

    let saved = repo
        .update_owned(id, owner, &add_panel(), Some(before.updated_at))
        .await
        .expect("the owner saves");
    assert_eq!(saved.panels.as_array().map(Vec::len), Some(1));

    // The admin path (settings:system at the handler) is not owner-scoped.
    let cleared = UpdateDashboard { panels: Some(serde_json::json!([])), ..add_panel() };
    let saved = repo.update_as_admin(id, &cleared, Some(saved.updated_at)).await.expect("an admin saves");
    assert_eq!(saved.panels, serde_json::json!([]));
}
