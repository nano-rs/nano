// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4959: upgrade from dev with a configured bring-your-own IPinfo token.
//!
//! Against a REAL PostgreSQL (own database per run):
//!
//! 1. migrate with dev's chain (every open migration except 311);
//! 2. configure BYO IPinfo the way dev allowed: the marketplace entry declares
//!    the `download_url` credential field (migration 285 shape) and the native
//!    `ipinfo_lite` source is enabled with a token URL;
//! 3. migrate with this branch's chain (311 applies);
//! 4. the native source is disabled with its URL kept (no data deletion), the
//!    catalog entry has no credential field and `requires_credential = none`;
//! 5. re-applying 311 changes nothing (idempotent).
//!
//! IOC parity (312): a ThreatFox catalog entry installed as a Deno direct
//! fetcher on dev (catalog enabled + linked custom enrichment enabled) is
//! switched off by the branch chain; its row and config stay. A first-party
//! entry that is not a bundle feed is left alone.
//!
//! The consumer side of the same upgrade (a configured BYO source no longer
//! gates the bundle install) is step 13 of
//! `platform_feed_consumer_integration`.
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:...@127.0.0.1:<own port>/nanosiem \
//!   cargo test -p nanosiem-core --test ipinfo_bundle_only_upgrade_integration -- --ignored --nocapture
//! ```

const MIGRATION_311: &str = include_str!("../../migrations/postgres/311_ipinfo_bundle_only.sql");
const MIGRATION_312: &str = include_str!("../../migrations/postgres/312_threatfox_tor_bundle_only.sql");
const BYO_URL: &str = "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=byo-upgrade-test";

async fn fresh_db() -> (sqlx::PgPool, sqlx::PgPool, String) {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL")
        .expect("NANOSIEM_TEST_DATABASE_URL must target a disposable PostgreSQL");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("ipinfo_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let (base, _) = url.rsplit_once('/').unwrap();
    let pool = sqlx::PgPool::connect(&format!("{base}/{name}")).await.unwrap();
    (admin, pool, name)
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct Source {
    enabled: bool,
    download_url: Option<String>,
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct Entry {
    credential_fields: serde_json::Value,
    requires_credential: String,
    description: Option<String>,
}

async fn source(pool: &sqlx::PgPool) -> Source {
    sqlx::query_as("SELECT enabled, download_url FROM enrichment_sources WHERE id = 'ipinfo_lite'")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn entry(pool: &sqlx::PgPool) -> Entry {
    sqlx::query_as(
        "SELECT credential_fields, requires_credential, description FROM marketplace_catalog \
         WHERE native_source_id = 'ipinfo_lite'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn upgrade_from_dev_with_a_byo_token_disables_native_ipinfo_and_drops_the_url_field() {
    let (admin, pool, name) = fresh_db().await;

    // 1. dev's chain: everything but 311 (applied in order, as dev's migrator would).
    let mut dev = sqlx::migrate!("../migrations/postgres");
    dev.migrations = dev.migrations.iter().filter(|m| m.version < 311).cloned().collect::<Vec<_>>().into();
    assert!(dev.migrations.iter().any(|m| m.version == 310 || m.version == 308), "dev chain present");
    dev.run(&pool).await.expect("dev migrations");
    let applied: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 311)")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!applied, "311 is not part of dev's chain");
    let ioc = seed_direct_threatfox(&pool).await;

    // 2. BYO IPinfo as dev allowed it.
    let before = entry(&pool).await;
    assert!(
        before.credential_fields.to_string().contains("download_url"),
        "dev's catalog entry declares download_url: {before:?}"
    );
    sqlx::query("UPDATE enrichment_sources SET enabled = true, download_url = $1 WHERE id = 'ipinfo_lite'")
        .bind(BYO_URL)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(source(&pool).await, Source { enabled: true, download_url: Some(BYO_URL.into()) });
    println!("dev state: native source enabled with a token URL, entry {before:?}");

    // 3. this branch's chain.
    let mut branch = sqlx::migrate!("../migrations/postgres");
    branch.set_ignore_missing(true);
    branch.run(&pool).await.expect("branch migrations");

    // 4. native source disabled, URL kept; no credential field left.
    assert_eq!(
        source(&pool).await,
        Source { enabled: false, download_url: Some(BYO_URL.into()) },
        "disabled, not deleted"
    );
    let after = entry(&pool).await;
    assert_eq!(after.credential_fields, serde_json::json!([]), "{after:?}");
    assert_eq!(after.requires_credential, "none");
    assert!(after.description.as_deref().unwrap_or_default().contains("platform feed bundle"));
    println!("after upgrade: native source disabled (URL kept), entry {after:?}");

    // IOC parity: the direct ThreatFox fetcher is off, the other entry untouched.
    assert_ioc_parity(&pool, &ioc).await;

    // 5. idempotent.
    sqlx::raw_sql(MIGRATION_311).execute(&pool).await.expect("re-apply 311");
    sqlx::raw_sql(MIGRATION_312).execute(&pool).await.expect("re-apply 312");
    assert_ioc_parity(&pool, &ioc).await;
    assert_eq!(source(&pool).await, Source { enabled: false, download_url: Some(BYO_URL.into()) });
    assert_eq!(entry(&pool).await, after);

    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name}")).execute(&admin).await.unwrap();
}

struct IocSeed {
    custom_enrichment: uuid::Uuid,
}

/// A ThreatFox Deno install as dev allowed it, plus an unrelated first-party entry.
async fn seed_direct_threatfox(pool: &sqlx::PgPool) -> IocSeed {
    let user: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM users LIMIT 1").fetch_optional(pool).await.unwrap();
    let user = match user {
        Some(u) => u,
        None => sqlx::query_scalar(
            "INSERT INTO users (email, username, password_hash) VALUES ('nan4959@example.invalid', 'nan4959', 'x') RETURNING id",
        )
        .fetch_one(pool)
        .await
        .expect("seed a user"),
    };
    let namespace: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM namespaces LIMIT 1").fetch_optional(pool).await.unwrap();
    let namespace = match namespace {
        Some(n) => n,
        None => sqlx::query_scalar("INSERT INTO namespaces (name) VALUES ('nan4959') RETURNING id")
            .fetch_one(pool)
            .await
            .expect("seed a namespace"),
    };
    let custom_enrichment: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO custom_enrichments (namespace_id, name, enrichment_type, code, created_by, enabled) \
         VALUES ($1, 'ThreatFox', 'data', 'export async function enrich() { return { records: [] } }', $2, true) RETURNING id",
    )
    .bind(namespace)
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed the Deno ThreatFox install");
    for (slug, linked) in [("threatfox", Some(custom_enrichment)), ("urlhaus", None)] {
        sqlx::query(
            "INSERT INTO marketplace_catalog (slug, name, category, author, source_type, execution_backend, custom_enrichment_id, installed, enabled) \
             VALUES ($1, $1, 'data', 'nano', 'system', 'deno', $2, true, true) \
             ON CONFLICT (slug) DO UPDATE SET custom_enrichment_id = EXCLUDED.custom_enrichment_id, installed = true, enabled = true",
        )
        .bind(slug)
        .bind(linked)
        .execute(pool)
        .await
        .expect("seed catalog entry");
    }
    IocSeed { custom_enrichment }
}

async fn assert_ioc_parity(pool: &sqlx::PgPool, seed: &IocSeed) {
    let enabled = |slug: &'static str| async move {
        sqlx::query_scalar::<_, bool>("SELECT enabled FROM marketplace_catalog WHERE slug = $1")
            .bind(slug)
            .fetch_one(pool)
            .await
            .unwrap()
    };
    assert!(!enabled("threatfox").await, "direct ThreatFox entry switched off");
    assert!(enabled("urlhaus").await, "non-bundle entry untouched");
    let (ce_enabled, installed): (bool, bool) = sqlx::query_as(
        "SELECT ce.enabled, mc.installed FROM custom_enrichments ce JOIN marketplace_catalog mc ON mc.custom_enrichment_id = ce.id WHERE ce.id = $1",
    )
    .bind(seed.custom_enrichment)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(!ce_enabled, "the Deno ThreatFox fetcher no longer runs");
    assert!(installed, "nothing deleted: still installed (uninstall stays the operator's call)");
}
