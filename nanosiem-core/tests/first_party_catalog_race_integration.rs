// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4940 (codex review, finding A): the boot reconcile and a concurrent
//! repository create must never both register a first-party catalog.
//!
//! * Both paths take the same transaction-scoped advisory lock, so a create
//!   racing the reconcile either lands first (and the reconcile adopts it) or
//!   is refused as already registered.
//! * A writer that does NOT take the lock (an older replica mid-rollout) is
//!   caught by the migration 302 partial unique index; the reconcile then
//!   adopts the committed row instead of registering a `(nano-rs)` copy.
//! * Migration 302 skips the index, with a warning, when duplicates already
//!   exist, and is idempotent.
//!
//! Run with `TEST_DATABASE_URL` pointing at a disposable PostgreSQL database;
//! each test works in its own schema.

use nanosiem_core::content_catalog_defaults::{ensure_first_party_catalogs, CatalogPlan};
use nanosiem_core::db::repo_error::RepoError;
use nanosiem_core::parser_repository::{NewParserRepository, ParserRepositoryRepository};
use nanosiem_core::rule_repository::{NewRuleRepository, RuleRepositoryRepository};
use nanosiem_core::schema::SchemaId;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

/// The columns of `parser_repositories` (090) and `rule_repositories` (071 +
/// selected_paths) that the reconcile and the create path read and return.
const REPOSITORY_TABLES: &str = r#"
CREATE TABLE parser_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL UNIQUE, description TEXT,
    url TEXT NOT NULL, branch TEXT NOT NULL DEFAULT 'main',
    parsers_path TEXT DEFAULT 'parsers/',
    auto_sync_enabled BOOLEAN DEFAULT FALSE, sync_interval_hours INTEGER DEFAULT 24,
    last_synced_at TIMESTAMPTZ, last_sync_commit TEXT, last_sync_status TEXT, last_sync_error TEXT,
    parser_count INTEGER DEFAULT 0, enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), created_by UUID
);
CREATE TABLE rule_repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL UNIQUE, description TEXT,
    url TEXT NOT NULL, branch TEXT NOT NULL DEFAULT 'main',
    rules_path TEXT DEFAULT 'rules/', rule_format TEXT NOT NULL DEFAULT 'sigma',
    auto_sync_enabled BOOLEAN DEFAULT FALSE, sync_interval_hours INTEGER DEFAULT 24,
    last_synced_at TIMESTAMPTZ, last_sync_commit TEXT, last_sync_status TEXT, last_sync_error TEXT,
    rule_count INTEGER DEFAULT 0, enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), created_by UUID,
    selected_paths TEXT[]
);
"#;

const MIGRATION_302: &str = include_str!("../../migrations/postgres/302_first_party_content_catalogs.sql");

struct Schema {
    admin: PgPool,
    pool: PgPool,
    name: String,
}

impl Schema {
    async fn new(apply_migration: bool) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must reference a disposable PostgreSQL database");
        let admin = PgPool::connect(&url).await.expect("connect test PostgreSQL");
        let name = format!("first_party_race_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {name}")).execute(&admin).await.expect("create schema");
        let search_path = name.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {search_path}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("connect isolated pool");
        sqlx::raw_sql(REPOSITORY_TABLES).execute(&pool).await.expect("create repository tables");
        if apply_migration {
            sqlx::raw_sql(MIGRATION_302).execute(&pool).await.expect("apply migration 302");
        }
        Self { admin, pool, name }
    }

    async fn count(&self, table: &str, needle: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE lower(url) LIKE '%' || $1 || '%'"))
            .bind(needle)
            .fetch_one(&self.pool)
            .await
            .expect("count rows")
    }

    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.name))
            .execute(&self.admin)
            .await
            .expect("drop schema");
    }
}

fn new_parser_repo(name: &str, url: &str) -> NewParserRepository {
    NewParserRepository {
        name: name.into(),
        slug: Some(format!("slug-{}", Uuid::new_v4().simple())),
        description: None,
        url: url.into(),
        branch: Some("main".into()),
        parsers_path: Some("parsers/".into()),
        auto_sync_enabled: Some(true),
        sync_interval_hours: Some(1),
    }
}

fn new_rule_repo(name: &str, url: &str) -> NewRuleRepository {
    NewRuleRepository {
        name: name.into(),
        slug: Some(format!("slug-{}", Uuid::new_v4().simple())),
        description: None,
        url: url.into(),
        branch: Some("main".into()),
        rules_path: Some(String::new()),
        rule_format: Some("nanosiem".into()),
        auto_sync_enabled: Some(true),
        sync_interval_hours: Some(1),
    }
}

/// The race codex found: the reconcile and an admin create (under a
/// DIFFERENT name, so name/slug uniqueness cannot save it) run at once.
/// Repeated so both orderings occur. Exactly one catalog row must survive in
/// each table, and a losing create must be refused as already registered.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn concurrent_create_and_reconcile_register_one_catalog() {
    for round in 0..25 {
        let schema = Schema::new(true).await;
        let parsers = ParserRepositoryRepository::new(schema.pool.clone());
        let rules = RuleRepositoryRepository::new(schema.pool.clone());
        let parser_req = new_parser_repo("admin parsers", "https://github.com/NANO-RS/parsers.git");
        let rule_req = new_rule_repo("admin rules", "github.com/nano-rs/rules/");

        let (reconcile, parser_create, rule_create) = tokio::join!(
            ensure_first_party_catalogs(&schema.pool, SchemaId::Ocsf),
            parsers.create(&parser_req, None),
            rules.create(&rule_req, None),
        );
        let outcomes = reconcile.expect("reconcile");

        for (result, created_name) in [
            (parser_create.map(|r| r.name), "admin parsers"),
            (rule_create.map(|r| r.name), "admin rules"),
        ] {
            match result {
                Ok(name) => assert_eq!(name, created_name),
                Err(RepoError::AlreadyExists(_)) => {}
                Err(other) => panic!("round {round}: unexpected create error: {other}"),
            }
        }
        assert_eq!(schema.count("parser_repositories", "nano-rs/parsers").await, 1, "round {round}");
        assert_eq!(schema.count("rule_repositories", "nano-rs/rules").await, 1, "round {round}");
        for outcome in &outcomes {
            assert!(
                !matches!(outcome.plan, CatalogPlan::Removed),
                "round {round}: a fresh catalog is never treated as removed"
            );
            assert!(outcome.repository_id.is_some());
        }
        schema.drop().await;
    }
}

/// After the reconcile registered the catalog, a create of the same catalog
/// (any URL spelling) is refused; a third-party repository is unaffected.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn create_after_registration_is_refused() {
    let schema = Schema::new(true).await;
    ensure_first_party_catalogs(&schema.pool, SchemaId::Ocsf).await.expect("reconcile");
    let parsers = ParserRepositoryRepository::new(schema.pool.clone());
    let err = parsers
        .create(&new_parser_repo("second copy", "https://www.github.com/nano-rs/parsers/"), None)
        .await
        .expect_err("duplicate first-party catalog");
    assert!(matches!(err, RepoError::AlreadyExists(_)), "{err}");
    parsers
        .create(&new_parser_repo("someone else", "https://github.com/someone/parsers"), None)
        .await
        .expect("third-party repository");
    assert_eq!(schema.count("parser_repositories", "nano-rs/parsers").await, 1);
    schema.drop().await;
}

/// A writer that ignores the lock (an older replica) inserts the catalog
/// under the canonical name while the reconcile runs. The reconcile blocks on
/// the conflict, then adopts the committed row: no `(nano-rs)` fallback copy.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn reconcile_adopts_a_row_committed_by_an_unlocked_writer() {
    let schema = Schema::new(true).await;
    let mut writer = schema.pool.begin().await.expect("begin");
    sqlx::query(
        "INSERT INTO parser_repositories (name, slug, url, branch, auto_sync_enabled) \
         VALUES ('nano parsers', 'nano-rs/parsers', 'https://github.com/nano-rs/parsers.git', 'main', FALSE)",
    )
    .execute(&mut *writer)
    .await
    .expect("unlocked insert");

    let pool = schema.pool.clone();
    let reconcile = tokio::spawn(async move { ensure_first_party_catalogs(&pool, SchemaId::Ocsf).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    writer.commit().await.expect("commit unlocked insert");

    let outcomes = reconcile.await.expect("join").expect("reconcile");
    let parsers = outcomes
        .iter()
        .find(|o| o.catalog.url().ends_with("/parsers"))
        .expect("parsers outcome");
    assert!(matches!(parsers.plan, CatalogPlan::Current(_)), "{:?}", parsers.plan);
    assert_eq!(schema.count("parser_repositories", "nano-rs/parsers").await, 1);
    let fallback: i64 = sqlx::query_scalar("SELECT count(*) FROM parser_repositories WHERE name LIKE '%(nano-rs)'")
        .fetch_one(&schema.pool)
        .await
        .expect("count fallback");
    assert_eq!(fallback, 0);
    let marker: Option<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM first_party_content_catalogs WHERE catalog = 'parsers'")
            .fetch_one(&schema.pool)
            .await
            .expect("adoption marker");
    assert_eq!(marker, Some(parsers.repository_id.expect("id")));
    schema.drop().await;
}

/// The partial unique index rejects a second row for the same catalog under
/// any URL spelling and leaves every other repository alone.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn index_rejects_url_spelling_variants() {
    let schema = Schema::new(true).await;
    let insert = |name: &'static str, url: &'static str| {
        let pool = schema.pool.clone();
        async move {
            sqlx::query("INSERT INTO rule_repositories (name, slug, url) VALUES ($1, $1, $2)")
                .bind(name)
                .bind(url)
                .execute(&pool)
                .await
        }
    };
    insert("a", "https://github.com/nano-rs/rules").await.expect("first");
    for (name, url) in [("b", "https://GitHub.com/Nano-RS/Rules.git"), ("c", "github.com/nano-rs/rules/"), ("d", "http://www.github.com/nano-rs/rules")] {
        let err = insert(name, url).await.expect_err(url);
        let constraint = err.as_database_error().and_then(|e| e.constraint()).map(str::to_owned);
        assert_eq!(constraint.as_deref(), Some("rule_repositories_first_party_url_key"), "{url}");
    }
    insert("e", "https://github.com/nano-rs/parsers").await.expect("other first-party repo in this table");
    insert("f", "https://github.com/SigmaHQ/sigma").await.expect("third party");
    insert("g", "https://github.com/SigmaHQ/sigma").await.expect("third-party duplicates stay allowed");
    schema.drop().await;
}

/// An install that already holds duplicates keeps them: the migration skips
/// that table's index instead of failing, and stays idempotent.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn migration_skips_the_index_when_duplicates_exist() {
    let schema = Schema::new(false).await;
    sqlx::raw_sql(
        "INSERT INTO parser_repositories (name, slug, url) VALUES \
           ('p1', 'p1', 'https://github.com/nano-rs/parsers'), \
           ('p2', 'p2', 'https://github.com/nano-rs/parsers.git');",
    )
    .execute(&schema.pool)
    .await
    .expect("seed duplicates");
    sqlx::raw_sql(MIGRATION_302).execute(&schema.pool).await.expect("migration with duplicates");
    sqlx::raw_sql(MIGRATION_302).execute(&schema.pool).await.expect("migration re-run");
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname::text FROM pg_indexes WHERE schemaname = current_schema() \
         AND indexname LIKE '%first_party_url_key' ORDER BY 1",
    )
    .fetch_all(&schema.pool)
    .await
    .expect("list indexes");
    assert_eq!(indexes, vec!["rule_repositories_first_party_url_key".to_string()]);
    schema.drop().await;
}
