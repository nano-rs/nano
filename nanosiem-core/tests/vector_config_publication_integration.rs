// SPDX-License-Identifier: AGPL-3.0-or-later

use nanosiem_core::{PublicationOutcome, VectorConfigPublisher};
use sqlx::{postgres::PgPoolOptions, PgPool};

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
    let admin = PgPool::connect(&url)
        .await
        .expect("connect test PostgreSQL");
    let schema = format!("vector_publication_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .expect("create isolated publication schema");

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
        .expect("connect isolated publication pool");

    sqlx::raw_sql(PUBLICATION_SOURCE_TABLES)
        .execute(&pool)
        .await
        .expect("create publication source tables");
    sqlx::raw_sql(include_str!(
        "../../migrations/postgres/229_vector_config_publication.sql"
    ))
    .execute(&pool)
    .await
    .expect("apply Vector publication migration");
    (admin, pool, schema)
}

async fn bundle(
    publisher: &VectorConfigPublisher,
    root: &std::path::Path,
    value: &str,
) -> nanosiem_core::SnapshotBundle {
    let sources = root.join("sources");
    tokio::fs::create_dir_all(sources.join("parsers"))
        .await
        .unwrap();
    tokio::fs::write(
        sources.join("parsers/test.toml"),
        format!("[transforms.test]\ntype = \"filter\"\ncondition = \"{value}\"\n"),
    )
    .await
    .unwrap();
    publisher.prepare_snapshot(sources).await.unwrap()
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn stale_two_node_publish_and_post_commit_restart_recovery() {
    let (admin, pool, schema) = isolated_pool().await;
    let node_a_dir = tempfile::tempdir().unwrap();
    let node_b_dir = tempfile::tempdir().unwrap();
    let node_a = VectorConfigPublisher::new(pool.clone(), node_a_dir.path(), "node-a");
    let node_b = VectorConfigPublisher::new(pool.clone(), node_b_dir.path(), "node-b");

    let source_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_configurations (id, name, config_type, connection_config, enabled, deployed) \
         VALUES ($1, 'test-source', 'http', '{}'::JSONB, TRUE, TRUE)",
    )
    .bind(source_id)
    .execute(&pool)
    .await
    .unwrap();

    let credential_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_credentials (id) VALUES ($1)")
        .bind(credential_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE source_configurations SET credential_id = $1 WHERE id = $2")
        .bind(credential_id)
        .bind(source_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("DELETE FROM cloud_credentials WHERE id = $1")
            .bind(credential_id)
            .execute(&pool)
            .await
            .is_err(),
        "an in-use source credential must be protected by the database FK"
    );

    let revision_a = node_a.source_revision().await.unwrap();
    let snapshot_a = bundle(&node_a, node_a_dir.path(), "old").await;

    // A separate API mutation advances the trigger-backed source revision while
    // node A is delayed with its old render.
    sqlx::query("UPDATE source_configurations SET enabled = NOT enabled WHERE id = $1")
        .bind(source_id)
        .execute(&pool)
        .await
        .unwrap();

    let revision_b = node_b.source_revision().await.unwrap();
    assert!(revision_b > revision_a);
    let snapshot_b = bundle(&node_b, node_b_dir.path(), "new").await;
    let generation_b = node_b
        .publish(revision_b, &snapshot_b)
        .await
        .unwrap()
        .generation()
        .unwrap();
    let (snapshot_epoch, state_epoch): (i64, i64) = sqlx::query_as(
        "SELECT snapshots.renderer_epoch, state.current_renderer_epoch \
         FROM vector_config_publication_state state \
         JOIN vector_config_snapshots snapshots \
           ON snapshots.generation = state.current_generation \
         WHERE state.singleton = TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(snapshot_epoch, state_epoch);
    assert!(state_epoch >= 0);

    assert_eq!(
        node_a.publish(revision_a, &snapshot_a).await.unwrap(),
        PublicationOutcome::Stale {
            expected_revision: revision_a,
            actual_revision: revision_b,
        }
    );

    // A restarted API has a new emptyDir. Re-rendering the same DB revision
    // reuses and rematerializes the committed generation instead of allocating
    // a new one.
    let restarted_dir = tempfile::tempdir().unwrap();
    let restarted =
        VectorConfigPublisher::new(pool.clone(), restarted_dir.path(), "node-b-restarted");
    let restarted_snapshot = bundle(&restarted, restarted_dir.path(), "new").await;
    assert_eq!(
        restarted
            .publish(revision_b, &restarted_snapshot)
            .await
            .unwrap(),
        PublicationOutcome::Reused {
            generation: generation_b,
            source_revision: revision_b,
        }
    );
    assert!(restarted_dir
        .path()
        .join(format!("publications/{generation_b:020}/.ready"))
        .exists());
    assert_eq!(
        restarted.local_current_outcome().await.unwrap(),
        Some(PublicationOutcome::Reused {
            generation: generation_b,
            source_revision: revision_b,
        })
    );

    let restarted_generation = restarted_dir
        .path()
        .join(format!("publications/{generation_b:020}"));
    tokio::fs::write(
        restarted_generation.join("parsers/test.toml"),
        b"tampered local payload",
    )
    .await
    .unwrap();
    assert_eq!(restarted.local_current_outcome().await.unwrap(), None);
    assert!(matches!(
        restarted
            .publish(revision_b, &restarted_snapshot)
            .await
            .unwrap(),
        PublicationOutcome::Reused {
            generation,
            source_revision,
        } if generation == generation_b && source_revision == revision_b
    ));
    assert!(restarted.local_current_outcome().await.unwrap().is_some());

    // Simulate local materialization failure after the DB commit. A subsequent
    // process recovers the same committed generation into its own emptyDir.
    sqlx::query("UPDATE source_configurations SET enabled = NOT enabled WHERE id = $1")
        .bind(source_id)
        .execute(&pool)
        .await
        .unwrap();
    let revision_c = restarted.source_revision().await.unwrap();
    let good_dir = tempfile::tempdir().unwrap();
    let good = VectorConfigPublisher::new(pool.clone(), good_dir.path(), "recovery-node");
    let snapshot_c = bundle(&good, good_dir.path(), "recovered").await;

    let blocked_parent = tempfile::tempdir().unwrap();
    let blocked_path = blocked_parent.path().join("not-a-directory");
    tokio::fs::write(&blocked_path, b"file").await.unwrap();
    let failing = VectorConfigPublisher::new(pool.clone(), &blocked_path, "failing-node");
    assert!(failing.publish(revision_c, &snapshot_c).await.is_err());

    let recovered = good.publish(revision_c, &snapshot_c).await.unwrap();
    assert!(matches!(recovered, PublicationOutcome::Reused { .. }));
    let recovered_generation = recovered.generation().unwrap();
    assert!(good_dir
        .path()
        .join(format!("publications/{recovered_generation:020}/.ready"))
        .exists());

    // The database rejects a direct pointer rollback as well as the Rust
    // decision fence. This protects the epoch invariant from ad hoc SQL.
    let original: (i64, String, i64, String, i64) = sqlx::query_as(
        "SELECT current_generation, current_content_hash, current_renderer_epoch, \
                current_renderer_version, published_source_revision \
         FROM vector_config_publication_state WHERE singleton = TRUE",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let higher_epoch = original.2 + 1;
    let higher_generation: i64 =
        sqlx::query_scalar("SELECT nextval('vector_config_generation_seq')::BIGINT")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO vector_config_snapshots \
         (generation, source_revision, renderer_epoch, renderer_version, content_hash, manifest, created_by) \
         VALUES ($1, $2, $3, '0.0.1', $4, '{}'::JSONB, 'epoch-test')",
    )
    .bind(higher_generation)
    .bind(original.4)
    .bind(higher_epoch)
    .bind(&original.1)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE vector_config_publication_state \
         SET current_generation = $1, current_renderer_epoch = $2, \
             current_renderer_version = '0.0.1' \
         WHERE singleton = TRUE",
    )
    .bind(higher_generation)
    .bind(higher_epoch)
    .execute(&pool)
    .await
    .unwrap();
    assert!(sqlx::query(
        "UPDATE vector_config_publication_state \
         SET current_generation = $1, current_content_hash = $2, \
             current_renderer_epoch = $3, current_renderer_version = $4 \
         WHERE singleton = TRUE",
    )
    .bind(original.0)
    .bind(&original.1)
    .bind(original.2)
    .bind(&original.3)
    .execute(&pool)
    .await
    .is_err());

    drop((node_a, node_b, restarted, failing, good));
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("drop isolated publication schema");
}
