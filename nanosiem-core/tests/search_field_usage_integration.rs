// SPDX-License-Identifier: AGPL-3.0-or-later
//! Search-autocomplete field usage reads `search_history` (NAN-3812).
//!
//! `field_usage_rows(Some(user))` must return only that user's piped queries
//! (the "Recent" group); `field_usage_rows(None)` returns every user's piped
//! queries in the deployment (the "Popular" group). Simple-mode queries and
//! rows outside the window never count. Gated like the other DB suites.

mod common;

use chrono::Utc;
use nanosiem_core::db::repository::SearchHistoryRepository;
use nanosiem_core::search::field_usage::rank_field_usage;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Field Usage Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("field-usage-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn history(pool: &PgPool, user: Uuid, query: &str, mode: &str, days_ago: i32) {
    sqlx::query(
        r#"INSERT INTO search_history (id, user_id, query, query_mode, time_range_type, created_at)
           VALUES ($1, $2, $3, $4, 'relative', NOW() - make_interval(days => $5))"#,
    )
    .bind(Uuid::now_v7())
    .bind(user)
    .bind(query)
    .bind(mode)
    .bind(days_ago)
    .execute(pool)
    .await
    .expect("insert history");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn recent_is_per_user_and_popular_is_workspace_wide() {
    let pool = common::migrated_pool().await;
    let repo = SearchHistoryRepository::new(pool.clone());
    let (me, peer) = (create_user(&pool).await, create_user(&pool).await);
    let (peer2, peer3) = (create_user(&pool).await, create_user(&pool).await);

    history(&pool, me, "src_ip=10.0.0.1 | stats count by dest_ip", "piped", 0).await;
    history(&pool, me, "hostname=web01", "simple", 0).await;
    history(&pool, me, "file_hash=abc", "piped", 200).await;
    history(&pool, peer, "process_name=cmd.exe", "piped", 1).await;
    // Popular needs three distinct users; a custom field never crosses users.
    history(&pool, peer2, "process_name=cmd.exe | stats count by ext.codename", "piped", 1).await;
    history(&pool, peer3, "process_name=powershell.exe ext.codename=x", "piped", 1).await;

    let mine = repo.field_usage_rows(Some(me), 200, 90).await.expect("user rows");
    assert_eq!(mine.len(), 1, "only my piped rows inside the window: {mine:?}");
    assert!(mine.iter().all(|r| r.user_id == me));

    let workspace = repo.field_usage_rows(None, 2_000, 90).await.expect("workspace rows");
    assert!(workspace.iter().any(|r| r.user_id == peer));
    assert!(workspace.iter().all(|r| r.query != "hostname=web01" && r.query != "file_hash=abc"));

    let usage = rank_field_usage(me, &mine, &workspace, Utc::now());
    // Same query, same weight: ties break by name.
    assert_eq!(usage.recent, vec!["dest_ip".to_string(), "src_ip".to_string()]);
    assert!(usage.popular.contains(&"process_name".to_string()), "{:?}", usage.popular);
    assert!(!usage.recent.contains(&"process_name".to_string()), "peer field leaked into my Recent");
    assert!(!usage.popular.iter().any(|f| f.starts_with("ext.")), "custom field crossed users: {:?}", usage.popular);
}
