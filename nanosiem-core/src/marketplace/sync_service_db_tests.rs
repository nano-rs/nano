// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4930: a catalog failure mid re-parse fails the whole sync, leaves the
//! catalog untouched (one transaction) and leaves `last_sync_schema_version`
//! unstamped, so the next sync at the same commit retries.
//!
//! Needs a disposable, fully migrated nano PostgreSQL at
//! `NANOSIEM_TEST_DATABASE_URL` (skips otherwise). The test adds its own repo
//! row, a uniquely named failure trigger, and removes both.

use std::path::Path;
use std::process::Command;

use sqlx::PgPool;
use uuid::Uuid;

use super::{MarketplaceSyncService, SYNC_SCHEMA_VERSION};

/// `<data_dir>/enrichment_repos/<slug>` cloned from a local origin holding
/// one manifest per slug, so `git_pull` works offline.
pub(super) fn local_repo(slug: &str, manifests: &[&str]) -> Option<tempfile::TempDir> {
    let data_dir = tempfile::tempdir().ok()?;
    let origin = data_dir.path().join("origin");
    for manifest in manifests {
        let dir = origin.join("enrichments/identity").join(manifest);
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::write(
            dir.join("manifest.yaml"),
            format!("name: {manifest}\nslug: {manifest}\ncategory: identity\ndescription: d\n"),
        )
        .ok()?;
    }
    let git = |dir: &Path, args: &[&str]| {
        Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    git(&origin, &["init", "-q", "-b", "main"])?;
    git(&origin, &["add", "."])?;
    git(&origin, &["commit", "-q", "-m", "init"])?;
    let clone = data_dir.path().join("enrichment_repos").join(slug);
    std::fs::create_dir_all(clone.parent()?).ok()?;
    git(data_dir.path(), &["clone", "-q", "-b", "main", origin.to_str()?, clone.to_str()?])?;
    Some(data_dir)
}

async fn repo_state(pool: &PgPool, id: Uuid) -> (Option<String>, i32) {
    sqlx::query_as("SELECT last_sync_status, last_sync_schema_version FROM enrichment_marketplace_repos WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn catalog_slugs(pool: &PgPool, repo_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT slug FROM marketplace_catalog WHERE repository_id = $1 ORDER BY slug")
        .bind(repo_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_failed_reparse_is_not_stamped_and_the_next_sync_retries() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else {
        eprintln!("skipped: NANOSIEM_TEST_DATABASE_URL not set");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
    let slug = format!("nan4930-{tag}");
    let ok_slug = format!("nan4930-ok-{tag}");
    let fail_slug = format!("nan4930-zfail-{tag}");
    let Some(data_dir) = local_repo(&slug, &[&ok_slug, &fail_slug]) else {
        eprintln!("skipped: git not available");
        return;
    };
    // validate_repo_url resolves the host (SSRF check); skip when offline.
    let url_ok = super::validate_repo_url("https://github.com/nano-rs/nano-integrations").await;
    if url_ok.is_err() {
        eprintln!("skipped: DNS unavailable");
        return;
    }

    let repo_id: Uuid = sqlx::query_scalar(
        "INSERT INTO enrichment_marketplace_repos (name, slug, url, branch, enrichments_path, auto_sync_enabled, sync_interval_hours, enabled)
         VALUES ($1, $1, 'https://github.com/nano-rs/nano-integrations', 'main', 'enrichments/', false, 24, true) RETURNING id",
    )
    .bind(&slug)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Force a catalog failure on one of the two manifests. Without the
    // transaction the other one would already be written (or kept) when the
    // sync fails.
    let func = format!("nan4930_fail_{tag}");
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.slug = '{fail_slug}' THEN RAISE EXCEPTION 'nan4930 forced catalog failure'; END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER {func} BEFORE INSERT OR UPDATE ON marketplace_catalog
           FOR EACH ROW EXECUTE FUNCTION {func}();"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let service = MarketplaceSyncService::with_data_dir(pool.clone(), data_dir.path().to_path_buf());
    let first = service.sync_repository(repo_id).await;
    let after_failure = (repo_state(&pool, repo_id).await, catalog_slugs(&pool, repo_id).await);

    sqlx::raw_sql(&format!("DROP TRIGGER {func} ON marketplace_catalog; DROP FUNCTION {func}();"))
        .execute(&pool)
        .await
        .unwrap();

    let second = service.sync_repository(repo_id).await;
    let after_retry = (repo_state(&pool, repo_id).await, catalog_slugs(&pool, repo_id).await);
    let third = service.sync_repository(repo_id).await;

    // Clean up before asserting so a failure leaves nothing behind.
    sqlx::query("DELETE FROM marketplace_catalog WHERE repository_id = $1").bind(repo_id).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM enrichment_marketplace_repos WHERE id = $1").bind(repo_id).execute(&pool).await.unwrap();

    assert!(first.is_err(), "the forced catalog failure must fail the sync: {first:?}");
    assert_eq!(after_failure.0, (Some("failed".to_string()), 0), "a failed sync must not stamp the version");
    assert!(after_failure.1.is_empty(), "the catalog apply is all-or-nothing: {:?}", after_failure.1);

    let second = second.expect("the retry at the unchanged commit re-parses");
    assert_eq!(second.enrichments_added, 2);
    assert_eq!(after_retry.0, (Some("success".to_string()), SYNC_SCHEMA_VERSION));
    assert_eq!(after_retry.1, vec![ok_slug, fail_slug]);

    let third = third.expect("third sync");
    assert_eq!(third.enrichments_added + third.enrichments_updated, 0, "now up to date: skipped");
}
