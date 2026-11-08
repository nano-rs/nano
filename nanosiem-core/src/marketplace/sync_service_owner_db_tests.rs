// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4946 (codex P1/P2): a repository sync never takes over a slug another
//! repository owns, and two syncs of one repository exclude each other across
//! service instances (the advisory lock, not process memory).
//!
//! Needs a disposable, fully migrated nano PostgreSQL at
//! `NANOSIEM_TEST_DATABASE_URL` (skips otherwise).

use sqlx::PgPool;
use uuid::Uuid;

use super::db_tests::local_repo;
use super::{MarketplaceSyncService, RepoSyncLock};
use crate::marketplace::MarketplaceError;

async fn insert_repo(pool: &PgPool, slug: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO enrichment_marketplace_repos (name, slug, url, branch, enrichments_path, auto_sync_enabled, sync_interval_hours, enabled)
         VALUES ($1, $1, 'https://github.com/nano-rs/nano-integrations', 'main', 'enrichments/', false, 24, true) RETURNING id",
    )
    .bind(slug)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_sync_skips_slugs_owned_elsewhere_and_syncs_are_mutually_exclusive() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else {
        eprintln!("skipped: NANOSIEM_TEST_DATABASE_URL not set");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
    let owner_slug = format!("nan4946-owner-{tag}");
    let other_slug = format!("nan4946-other-{tag}");
    let shared = format!("nan4946-shared-{tag}");
    let own = format!("nan4946-own-{tag}");
    let Some(data_dir) = local_repo(&other_slug, &[&shared, &own]) else {
        eprintln!("skipped: git not available");
        return;
    };
    if super::validate_repo_url("https://github.com/nano-rs/nano-integrations").await.is_err() {
        eprintln!("skipped: DNS unavailable");
        return;
    }
    let owner = insert_repo(&pool, &owner_slug).await;
    let other = insert_repo(&pool, &other_slug).await;
    sqlx::query(
        "INSERT INTO marketplace_catalog (slug, name, category, source_type, repository_id, manifest_version, execution_backend, code)
         VALUES ($1, 'owned', 'identity', 'repository', $2, 1, 'identity', 'owner-code')",
    )
    .bind(&shared)
    .bind(owner)
    .execute(&pool)
    .await
    .unwrap();

    // A lock held elsewhere (another replica) refuses the sync.
    let held = RepoSyncLock::try_acquire(&pool, other).await.unwrap().expect("first lock");
    let service = MarketplaceSyncService::with_data_dir(pool.clone(), data_dir.path().to_path_buf());
    let blocked = service.sync_repository(other).await;
    held.release().await;
    let synced = service.sync_repository(other).await;

    let shared_row: (Option<Uuid>, Option<String>, String) =
        sqlx::query_as("SELECT repository_id, code, name FROM marketplace_catalog WHERE slug = $1")
            .bind(&shared)
            .fetch_one(&pool)
            .await
            .unwrap();
    let own_owner: Option<Uuid> = sqlx::query_scalar("SELECT repository_id FROM marketplace_catalog WHERE slug = $1")
        .bind(&own)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .flatten();

    sqlx::query("DELETE FROM marketplace_catalog WHERE repository_id = ANY($1)").bind(vec![owner, other]).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM enrichment_marketplace_repos WHERE id = ANY($1)").bind(vec![owner, other]).execute(&pool).await.unwrap();

    assert!(matches!(blocked, Err(MarketplaceError::SyncInProgress(_))), "a held lock must refuse the sync: {blocked:?}");
    synced.expect("the sync runs once the lock is free");
    assert_eq!(shared_row, (Some(owner), Some("owner-code".to_string()), "owned".to_string()), "the owner's row is untouched");
    assert_eq!(own_owner, Some(other), "the repository's own slug syncs");
}
