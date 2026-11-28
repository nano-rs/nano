// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5695 (NAN-5711 semantics): an owner-only saved-search mutation
//! (update, delete, share) by someone else says why it was refused without
//! disclosing a search the caller cannot see.
//!
//! - missing → `NotFound` (404);
//! - private, or shared with a group the caller is not in → `NotFound`;
//! - public, or shared with the caller's group → `AccessDenied` (403).
//!
//! In every refused case the search is left unchanged.
//!
//! Needs a disposable Postgres: `DATABASE_URL=... NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1
//! cargo test -p nanosiem-core --test saved_search_owner_mutation_status_integration -- --ignored`

mod common;

use nanosiem_core::db::repository::{SavedSearchRepository, SavedSearchRepositoryError};
use nanosiem_core::models::{NewSavedSearch, ShareSavedSearchRequest, UpdateSavedSearch};
use sqlx::PgPool;
use uuid::Uuid;

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Saved Search Owner Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("sso-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn group_with(pool: &PgPool, members: &[Uuid]) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("sso-group-{id}"))
        .execute(pool)
        .await
        .expect("create group");
    for member in members {
        sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
            .bind(member)
            .bind(id)
            .execute(pool)
            .await
            .expect("add member");
    }
    id
}

async fn search(repo: &SavedSearchRepository, owner: Uuid, visibility: &str, groups: Option<Vec<Uuid>>) -> Uuid {
    repo.create(
        &NewSavedSearch {
            name: format!("sso-{visibility}-{}", Uuid::now_v7()),
            query: "src_ip=10.0.0.1".to_string(),
            description: None,
            time_range: None,
            visibility: Some(visibility.to_string()),
            group_ids: groups,
        },
        owner,
    )
    .await
    .expect("create saved search")
    .id
}

fn rename() -> UpdateSavedSearch {
    UpdateSavedSearch { name: Some("hijacked".to_string()), query: None, description: None, time_range: None }
}

fn make_public() -> ShareSavedSearchRequest {
    ShareSavedSearchRequest { visibility: "public".to_string(), group_ids: None }
}

/// Update, delete and share by `caller` are all refused with the same kind,
/// and the search survives untouched.
async fn assert_all_refused(
    repo: &SavedSearchRepository,
    id: Uuid,
    caller: Uuid,
    want_not_found: bool,
) {
    let check = |label: &str, err: SavedSearchRepositoryError| match (&err, want_not_found) {
        (SavedSearchRepositoryError::NotFound(got), true) => assert_eq!(*got, id, "{label}"),
        (SavedSearchRepositoryError::AccessDenied, false) => {}
        _ => panic!("{label}: expected {}, got {err:?}", if want_not_found { "NotFound" } else { "AccessDenied" }),
    };
    check("update", repo.update(id, &rename(), caller).await.expect_err("update refused"));
    check("delete", repo.delete(id, caller).await.expect_err("delete refused"));
    check("share", repo.share(id, &make_public(), caller).await.err().expect("share refused"));

    let still = repo.find_by_id(id).await.expect("the search must survive");
    assert_ne!(still.name, "hijacked");
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn missing_saved_search_is_not_found() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let caller = user(&pool).await;
    let owner = user(&pool).await;
    let id = search(&repo, owner, "private", None).await;
    repo.delete(id, owner).await.expect("owner deletes");

    for err in [
        repo.update(id, &rename(), caller).await.expect_err("update"),
        repo.delete(id, caller).await.expect_err("delete"),
        repo.delete(id, owner).await.expect_err("owner's retried delete"),
    ] {
        assert!(matches!(err, SavedSearchRepositoryError::NotFound(got) if got == id), "{err:?}");
    }
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn someone_elses_private_search_is_not_found() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let stranger = user(&pool).await;
    let id = search(&repo, owner, "private", None).await;
    assert_all_refused(&repo, id, stranger, true).await;
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn search_shared_with_a_group_the_caller_is_not_in_is_not_found() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let outsider = user(&pool).await;
    let group = group_with(&pool, &[owner]).await;
    let id = search(&repo, owner, "group", Some(vec![group])).await;
    assert_all_refused(&repo, id, outsider, true).await;
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn someone_elses_public_search_is_forbidden() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let other = user(&pool).await;
    let id = search(&repo, owner, "public", None).await;
    assert_all_refused(&repo, id, other, false).await;
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn search_shared_with_the_callers_group_is_forbidden() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let member = user(&pool).await;
    let group = group_with(&pool, &[owner, member]).await;
    let id = search(&repo, owner, "group", Some(vec![group])).await;
    assert_all_refused(&repo, id, member, false).await;
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn the_owner_can_still_update_share_and_delete() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let id = search(&repo, owner, "private", None).await;
    assert_eq!(repo.update(id, &rename(), owner).await.unwrap().name, "hijacked");
    assert_eq!(repo.share(id, &make_public(), owner).await.unwrap().search.visibility, "public");
    repo.delete(id, owner).await.expect("owner deletes");
}

/// Review finding on #10108: `update` checked ownership, then wrote with
/// `WHERE id = $1` and `fetch_one`. A delete committing between the two made
/// the write match nothing → `RowNotFound` → HTTP 500. The ownership check is
/// now part of the write, and a miss is reported as `NotFound`.
///
/// Reproduced deterministically: an open transaction deletes the row (holding
/// its lock), the owner's update starts and blocks on that lock, then the
/// delete commits.
#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn an_update_racing_a_delete_is_not_found_not_a_database_error() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let id = search(&repo, owner, "private", None).await;

    let mut deleting = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM saved_searches WHERE id = $1")
        .bind(id)
        .execute(&mut *deleting)
        .await
        .unwrap();

    let racing = {
        let repo = repo.clone();
        tokio::spawn(async move { repo.update(id, &rename(), owner).await })
    };
    // Let the update reach the row lock held by the open delete.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!racing.is_finished(), "the update should be waiting on the row lock");
    deleting.commit().await.unwrap();

    let err = racing.await.unwrap().expect_err("the row is gone");
    assert!(matches!(err, SavedSearchRepositoryError::NotFound(got) if got == id), "{err:?}");
}

/// The same race for delete: two owners' deletes (a double click) — the
/// second reports `NotFound`.
#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn a_delete_racing_a_delete_is_not_found() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let id = search(&repo, owner, "private", None).await;

    let mut deleting = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM saved_searches WHERE id = $1")
        .bind(id)
        .execute(&mut *deleting)
        .await
        .unwrap();
    let racing = {
        let repo = repo.clone();
        tokio::spawn(async move { repo.delete(id, owner).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    deleting.commit().await.unwrap();

    let err = racing.await.unwrap().expect_err("already deleted");
    assert!(matches!(err, SavedSearchRepositoryError::NotFound(got) if got == id), "{err:?}");
}

/// Bad input is a 400 before any ownership lookup, so it discloses nothing
/// about a search the caller cannot see.
#[tokio::test]
#[ignore = "requires a disposable Postgres (NANOSIEM_TEST_DATABASE_URL)"]
async fn an_over_long_description_is_invalid_input_for_anyone() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let stranger = user(&pool).await;
    let id = search(&repo, owner, "private", None).await;
    let too_long = UpdateSavedSearch { description: Some("x".repeat(2001)), ..rename() };
    for caller in [owner, stranger] {
        let err = repo.update(id, &too_long, caller).await.expect_err("too long");
        assert!(matches!(err, SavedSearchRepositoryError::InvalidInput(_)), "{err:?}");
    }
}
