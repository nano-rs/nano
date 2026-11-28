// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4930: a catalog failure mid re-parse fails the whole sync, leaves the
//! catalog untouched (one transaction) and leaves `last_sync_schema_version`
//! unstamped, so the next sync at the same commit retries.
//!
//! Needs a disposable nano PostgreSQL at `NANOSIEM_TEST_DATABASE_URL` (skips
//! locally when unset, fails in CI), git and DNS (a failure of either always
//! fails); `#[ignore]`d, run by pg-integration. The test applies the open
//! migrations itself (NAN-5988: it must not depend on another suite having
//! migrated the database first), adds its own repo row and a uniquely named
//! failure trigger, and removes both.

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

/// The test Postgres URL, or `None` to skip. NAN-5988: in CI (`CI=true`,
/// which GitHub Actions sets) a missing URL FAILS the test, so a CI job that
/// lost its database can never pass it with no assertions. Locally an unset
/// URL skips.
pub(super) fn pg_url_or_skip() -> Option<String> {
    let ci = std::env::var("CI").is_ok_and(|v| v.trim().eq_ignore_ascii_case("true"));
    pg_url_or_skip_with(ci, nanosiem_test_db::pg_url().map_err(|unset| unset.to_string()))
}

/// [`pg_url_or_skip`] with the CI flag and the resolved URL passed in
/// (testable without the process environment).
fn pg_url_or_skip_with(ci: bool, url: Result<String, String>) -> Option<String> {
    match url {
        Ok(url) => Some(url),
        Err(unset) if ci => panic!("CI=true but the test Postgres is not configured: {unset}"),
        Err(unset) => {
            eprintln!("skipped: {unset}");
            None
        }
    }
}

#[test]
#[should_panic(expected = "CI=true but the test Postgres is not configured")]
fn in_ci_a_missing_database_url_fails_instead_of_skipping() {
    pg_url_or_skip_with(true, Err("the test Postgres URL is not set".into()));
}

#[test]
fn outside_ci_a_missing_database_url_skips() {
    assert_eq!(pg_url_or_skip_with(false, Err("unset".into())), None);
    assert_eq!(pg_url_or_skip_with(true, Ok("u".into())).as_deref(), Some("u"));
    assert_eq!(pg_url_or_skip_with(false, Ok("u".into())).as_deref(), Some("u"));
}

/// A pool on the test database with the open migrations applied, once per
/// test binary (NAN-5988). `enrichment_marketplace_repos` is open core
/// (migration 101), so no enterprise overlay is needed.
pub(super) async fn migrated_pool(url: &str) -> PgPool {
    static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    let pool = PgPool::connect(url).await.expect("connect");
    MIGRATED
        .get_or_init(|| async {
            crate::db::run_postgres_migrations(&pool).await.expect("apply open Postgres migrations");
        })
        .await;
    pool
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
#[ignore = "db-backed; runs in pg-integration CI (marketplace::sync_service -- --ignored)"]
async fn a_failed_reparse_is_not_stamped_and_the_next_sync_retries() {
    // Locally an unset URL skips; in CI it fails (see pg_url_or_skip). A git
    // or DNS failure below fails everywhere.
    let Some(url) = pg_url_or_skip() else { return };
    let pool = migrated_pool(&url).await;
    let tag = Uuid::new_v4().simple().to_string()[..12].to_string();
    let slug = format!("nan4930-{tag}");
    let ok_slug = format!("nan4930-ok-{tag}");
    let fail_slug = format!("nan4930-zfail-{tag}");
    let data_dir = local_repo(&slug, &[&ok_slug, &fail_slug]).expect("local git repository fixture (is git installed?)");
    // validate_repo_url resolves the host (SSRF check), so this needs DNS.
    super::validate_repo_url("https://github.com/nano-rs/nano-integrations")
        .await
        .expect("validate_repo_url (needs DNS for github.com)");

    // NAN-4955: a first-party URL reads the installed content channel in
    // production. The parse/record logic under test is source-independent, so
    // drive it through the local git repository (as sync_service_tests does).
    let _git = super::use_test_git_source();
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
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.slug = '{fail_slug}' THEN RAISE EXCEPTION 'nan4930 forced catalog failure'; END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER {func} BEFORE INSERT OR UPDATE ON marketplace_catalog
           FOR EACH ROW EXECUTE FUNCTION {func}();"
    )))
    .execute(&pool)
    .await
    .unwrap();

    let service = MarketplaceSyncService::with_data_dir(pool.clone(), data_dir.path().to_path_buf());
    let first = service.sync_repository(repo_id).await;
    let after_failure = (repo_state(&pool, repo_id).await, catalog_slugs(&pool, repo_id).await);

    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP TRIGGER {func} ON marketplace_catalog; DROP FUNCTION {func}();")))
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
