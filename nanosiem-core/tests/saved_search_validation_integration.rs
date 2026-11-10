// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5162: saved-search create/share validate `visibility` and `group_ids`
//! before writing, so a bad request is a typed `InvalidInput` (HTTP 400) with
//! no PostgreSQL text, and nothing is half-written. Also covers the normal
//! save → share → list path.
//!
//! Needs a disposable Postgres: `DATABASE_URL=... NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1
//! cargo test -p nanosiem-core --test saved_search_validation_integration -- --ignored`

mod common;

use nanosiem_core::db::repository::{SavedSearchRepository, SavedSearchRepositoryError};
use nanosiem_core::models::{NewSavedSearch, ShareSavedSearchRequest};
use sqlx::PgPool;
use uuid::Uuid;

async fn user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Saved Search Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("ss-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn group_with_member(pool: &PgPool, member: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("ss-group-{id}"))
        .execute(pool)
        .await
        .expect("create group");
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(member)
        .bind(id)
        .execute(pool)
        .await
        .expect("add member");
    id
}

fn new_search(name: &str, visibility: Option<&str>, group_ids: Option<Vec<Uuid>>) -> NewSavedSearch {
    NewSavedSearch {
        name: name.to_string(),
        query: "src_ip=10.0.0.1 | stats count by user".to_string(),
        time_range: None,
        visibility: visibility.map(str::to_string),
        group_ids,
    }
}

async fn count_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM saved_searches WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn assert_invalid_input_without_sql(err: SavedSearchRepositoryError) {
    match err {
        SavedSearchRepositoryError::InvalidInput(msg) => {
            for leak in ["saved_search", "constraint", "violates", "relation", "fkey"] {
                assert!(!msg.contains(leak), "database text leaked into: {msg}");
            }
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL)"]
async fn invalid_visibility_is_rejected_before_any_write() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let name = format!("bad-vis-{}", Uuid::now_v7());

    let err = repo
        .create(&new_search(&name, Some("everyone"), None), owner)
        .await
        .expect_err("invalid visibility must be rejected");
    assert_invalid_input_without_sql(err);
    assert_eq!(count_named(&pool, &name).await, 0, "nothing may be written");

    // Share with an invalid visibility leaves the existing search untouched.
    let ok = repo.create(&new_search(&name, None, None), owner).await.unwrap();
    let err = repo
        .share(
            ok.id,
            &ShareSavedSearchRequest { visibility: "everyone".to_string(), group_ids: None },
            owner,
        )
        .await
        .expect_err("invalid visibility must be rejected");
    assert_invalid_input_without_sql(err);
    let still = repo.find_by_id(ok.id).await.unwrap();
    assert_eq!(still.visibility.as_deref(), Some("private"));
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL)"]
async fn unknown_group_ids_are_rejected_before_any_write() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let real = group_with_member(&pool, owner).await;
    let name = format!("bad-group-{}", Uuid::now_v7());

    let err = repo
        .create(&new_search(&name, Some("group"), Some(vec![real, Uuid::now_v7()])), owner)
        .await
        .expect_err("unknown group id must be rejected");
    assert_invalid_input_without_sql(err);
    assert_eq!(count_named(&pool, &name).await, 0, "no half-created search");

    let ok = repo.create(&new_search(&name, None, None), owner).await.unwrap();
    let err = repo
        .share(
            ok.id,
            &ShareSavedSearchRequest {
                visibility: "group".to_string(),
                group_ids: Some(vec![Uuid::now_v7()]),
            },
            owner,
        )
        .await
        .expect_err("unknown group id must be rejected");
    assert_invalid_input_without_sql(err);
    assert_eq!(
        repo.find_by_id(ok.id).await.unwrap().visibility.as_deref(),
        Some("private")
    );
}

#[tokio::test]
#[ignore = "requires a disposable Postgres (DATABASE_URL)"]
async fn normal_save_share_and_list_still_work() {
    let pool = common::migrated_pool().await;
    let repo = SavedSearchRepository::new(pool.clone());
    let owner = user(&pool).await;
    let peer = user(&pool).await;
    let group = group_with_member(&pool, owner).await;
    sqlx::query("INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)")
        .bind(peer)
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();

    let name = format!("ok-{}", Uuid::now_v7());
    let created = repo
        .create(&new_search(&name, Some("group"), Some(vec![group])), owner)
        .await
        .expect("valid group save");
    assert_eq!(created.visibility.as_deref(), Some("group"));

    let shared = repo.list_shared_with_user(peer).await.unwrap();
    assert!(shared.iter().any(|s| s.id == created.id), "peer sees the group share");

    let result = repo
        .share(
            created.id,
            &ShareSavedSearchRequest { visibility: "public".to_string(), group_ids: None },
            owner,
        )
        .await
        .expect("valid share");
    assert_eq!(result.search.visibility, "public");
    assert!(result.users_who_lost_access.iter().any(|u| u.user_id == peer));

    let mine = repo.list_owned_by_user(owner).await.unwrap();
    assert!(mine.iter().any(|s| s.id == created.id));
    let visible = repo.list_for_user(peer).await.unwrap();
    assert!(visible.iter().any(|s| s.id == created.id), "public is visible");
}
