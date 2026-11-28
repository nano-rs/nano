// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5696 / NAN-5695: a saved search keeps its description through create,
//! list and get; an edit can change or clear it; an edit that omits it leaves
//! it alone; and the owner can delete the search.
//!
//! Needs a disposable Postgres: `DATABASE_URL=... NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1
//! cargo test -p nanosiem-core --test saved_search_description_integration -- --ignored`

mod common;

use nanosiem_core::db::repository::{SavedSearchRepository, SavedSearchRepositoryError};
use nanosiem_core::models::{NewSavedSearch, UpdateSavedSearch};
use sqlx::PgPool;
use uuid::Uuid;

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Saved Search Description Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("ssd-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

fn update(name: Option<&str>, query: Option<&str>, description: Option<&str>) -> UpdateSavedSearch {
    UpdateSavedSearch {
        name: name.map(str::to_string),
        query: query.map(str::to_string),
        description: description.map(str::to_string),
        time_range: None,
    }
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn description_survives_create_edit_and_clear_and_the_owner_can_delete() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;

    let created = repo
        .create(
            &NewSavedSearch {
                name: format!("ssd-{}", Uuid::now_v7()),
                query: "src_ip=10.0.0.1 | stats count by user".to_string(),
                description: Some("  failed console logins  ".to_string()),
                time_range: None,
                visibility: None,
                group_ids: None,
            },
            owner,
        )
        .await
        .expect("create");
    assert_eq!(created.description.as_deref(), Some("failed console logins"));

    let mine = repo.list_owned_by_user(owner).await.unwrap();
    let listed = mine.iter().find(|s| s.id == created.id).expect("listed");
    assert_eq!(listed.description.as_deref(), Some("failed console logins"));

    // An edit of name + query that omits the description keeps it.
    let edited = repo
        .update(created.id, &update(Some("renamed"), Some("user=root"), None), owner)
        .await
        .expect("edit");
    assert_eq!(edited.name, "renamed");
    assert_eq!(edited.query, "user=root");
    assert_eq!(edited.description.as_deref(), Some("failed console logins"));

    let changed = repo
        .update(created.id, &update(None, None, Some("root logins")), owner)
        .await
        .unwrap();
    assert_eq!(changed.description.as_deref(), Some("root logins"));

    let cleared = repo.update(created.id, &update(None, None, Some("")), owner).await.unwrap();
    assert_eq!(cleared.description, None);
    let got = repo.find_by_id_for_user(created.id, owner).await.unwrap();
    assert_eq!(got.description, None);

    // Someone else cannot edit or delete it; it is private, so to them it
    // does not exist (see saved_search_owner_mutation_status_integration).
    let stranger = user(&pool).await;
    assert!(matches!(
        repo.update(created.id, &update(Some("hijack"), None, None), stranger).await,
        Err(SavedSearchRepositoryError::NotFound(_))
    ));
    assert!(matches!(
        repo.delete(created.id, stranger).await,
        Err(SavedSearchRepositoryError::NotFound(_))
    ));

    repo.delete(created.id, owner).await.expect("owner deletes");
    assert!(matches!(
        repo.find_by_id(created.id).await,
        Err(SavedSearchRepositoryError::NotFound(_))
    ));
}
