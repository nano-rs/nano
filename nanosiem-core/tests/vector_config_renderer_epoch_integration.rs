// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4973: durable renderer-epoch allocation, end to end through the
//! public publisher API against a disposable PostgreSQL schema.
//!
//! The failure this guards: an epoch derived from a deployer counter (a Helm
//! release revision) resets on a reinstall onto retained data, so every API is
//! fenced as a superseded renderer and Vector never gets a generation. With
//! allocation, the same build rejoins its committed generation after a
//! "reinstall" (a fresh publisher on a fresh config dir, same database), and a
//! committed epoch raised by anything else is always exceeded by a new build.

use nanosiem_core::{PublicationOutcome, VectorConfigPublisher};
use sqlx::{postgres::PgPoolOptions, PgPool};

// Same source tables the publication triggers attach to (see
// vector_config_publication_integration.rs).
const PUBLICATION_SOURCE_TABLES: &str = r#"
CREATE TABLE log_sources (
    id UUID PRIMARY KEY,
    name TEXT, source_type TEXT, source_config JSONB, credential_id UUID,
    parser_vrl TEXT, match_values TEXT[], enabled BOOLEAN, category TEXT,
    vendor TEXT, product TEXT, namespace TEXT, timezone TEXT,
    sampling_ratio DOUBLE PRECISION, sampling_exclude_condition TEXT,
    extension_vrl TEXT, extension_enabled BOOLEAN,
    dispatch_source_config_id UUID, kind TEXT, enrich_kind TEXT,
    enrich_source TEXT, target_table TEXT, normalize_vrl TEXT
);
-- NAN-2304 fences active-version changes into source_revision, so migration
-- 283 attaches triggers here.
CREATE TABLE log_source_versions (
    id SERIAL PRIMARY KEY,
    log_source_id UUID, version_number INTEGER, parser_vrl TEXT,
    output_fields JSONB, is_active BOOLEAN, extension_vrl TEXT,
    extension_enabled BOOLEAN
);
CREATE TABLE source_configurations (
    id UUID PRIMARY KEY,
    name TEXT, config_type TEXT, connection_config JSONB, credential_id UUID,
    enabled BOOLEAN, deployed BOOLEAN
);
CREATE TABLE routing_rules (
    id UUID PRIMARY KEY,
    source_configuration_id UUID
);
CREATE TABLE cloud_credentials (
    id UUID PRIMARY KEY,
    name TEXT, provider TEXT, credentials_encrypted BYTEA, nonce TEXT,
    region TEXT, active_version INTEGER
);
"#;

async fn isolated_pool() -> (PgPool, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must reference a disposable PostgreSQL database");
    let admin = PgPool::connect(&url).await.expect("connect test PostgreSQL");
    let schema = format!("vector_epoch_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
    let search_path = schema.clone();
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
        .unwrap();
    sqlx::raw_sql(PUBLICATION_SOURCE_TABLES).execute(&pool).await.unwrap();
    for (name, sql) in [
        ("229", include_str!("../../migrations/postgres/229_vector_config_publication.sql")),
        ("284", include_str!("../../migrations/postgres/284_vector_config_publication_fidelity.sql")),
        ("313", include_str!("../../migrations/postgres/313_vector_config_renderer_epochs.sql")),
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap_or_else(|e| panic!("migration {name}: {e}"));
    }
    (admin, pool, schema)
}

async fn publish_once(publisher: &VectorConfigPublisher, root: &std::path::Path, body: &str) -> PublicationOutcome {
    let sources = root.join("sources");
    tokio::fs::create_dir_all(sources.join("parsers")).await.unwrap();
    tokio::fs::write(sources.join("parsers/test.toml"), body).await.unwrap();
    let revision = publisher.source_revision().await.unwrap();
    let snapshot = publisher.prepare_snapshot(&sources).await.unwrap();
    publisher.publish(revision, &snapshot).await.unwrap()
}

async fn committed_epoch(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT current_renderer_epoch FROM vector_config_publication_state")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn same_build_rejoins_after_reinstall_and_never_flip_flops() {
    std::env::remove_var("VECTOR_CONFIG_RENDERER_EPOCH");
    let (admin, pool, schema) = isolated_pool().await;
    let body = "[transforms.t]\ntype = \"filter\"\ncondition = \"true\"\n";

    // First install: one publisher publishes generation 1 at an allocated epoch.
    let dir_a = tempfile::tempdir().unwrap();
    let a = VectorConfigPublisher::new(pool.clone(), dir_a.path(), "pod-a");
    let first = publish_once(&a, dir_a.path(), body).await;
    let PublicationOutcome::Published { generation, .. } = first else {
        panic!("first publish must publish: {first:?}");
    };
    let epoch = committed_epoch(&pool).await;
    assert!(epoch >= 1, "an allocated epoch is positive, got {epoch}");

    // Reinstall onto retained data: fresh pod, fresh emptyDir, same database
    // and same build. It must rejoin the committed generation (same epoch),
    // not be fenced as superseded and not mint a new generation.
    let dir_b = tempfile::tempdir().unwrap();
    let b = VectorConfigPublisher::new(pool.clone(), dir_b.path(), "pod-b");
    let again = publish_once(&b, dir_b.path(), body).await;
    assert!(
        matches!(again, PublicationOutcome::Reused { generation: g, .. } if g == generation),
        "same build after reinstall must reuse generation {generation}: {again:?}"
    );
    assert_eq!(committed_epoch(&pool).await, epoch, "epoch is stable per build");
    assert!(
        dir_b.path().join(format!("publications/{generation:020}/.ready")).is_file(),
        "the reinstalled pod materializes the committed generation for its Vector consumers"
    );

    let allocations: i64 = sqlx::query_scalar("SELECT count(*) FROM vector_config_renderer_epochs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(allocations, 1, "one build, one allocation");

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn a_new_build_is_allocated_above_every_known_epoch() {
    std::env::remove_var("VECTOR_CONFIG_RENDERER_EPOCH");
    let (admin, pool, schema) = isolated_pool().await;
    // Earlier builds already hold epochs up to 41 (e.g. many releases, or a
    // previous chart that pinned epochs by revision).
    for epoch in [3_i64, 41] {
        sqlx::query(
            "INSERT INTO vector_config_renderer_epochs (identity, epoch, renderer_version) \
             VALUES (encode(sha256($1::bytea), 'hex'), $2, '0.0.1')",
        )
        .bind(format!("older-build-{epoch}").into_bytes())
        .bind(epoch)
        .execute(&pool)
        .await
        .unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let publisher = VectorConfigPublisher::new(pool.clone(), dir.path(), "pod");
    let outcome = publish_once(&publisher, dir.path(), "[transforms.t]\ntype = \"filter\"\ncondition = \"true\"\n").await;
    assert!(matches!(outcome, PublicationOutcome::Published { .. }), "{outcome:?}");
    assert_eq!(committed_epoch(&pool).await, 42, "this build supersedes every older one");

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn concurrent_first_publishers_share_one_allocation() {
    std::env::remove_var("VECTOR_CONFIG_RENDERER_EPOCH");
    let (admin, pool, schema) = isolated_pool().await;
    let mut tasks = Vec::new();
    for i in 0..6 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let dir = tempfile::tempdir().unwrap();
            let publisher = VectorConfigPublisher::new(pool, dir.path(), format!("pod-{i}"));
            publish_once(&publisher, dir.path(), "[transforms.t]\ntype = \"filter\"\ncondition = \"true\"\n").await
        }));
    }
    for task in tasks {
        let outcome = task.await.unwrap();
        assert!(
            matches!(outcome, PublicationOutcome::Published { .. } | PublicationOutcome::Reused { .. } | PublicationOutcome::Stale { .. }),
            "replicas of one build never fence each other: {outcome:?}"
        );
    }
    let allocations: i64 = sqlx::query_scalar("SELECT count(*) FROM vector_config_renderer_epochs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(allocations, 1);

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
}
