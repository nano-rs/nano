// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902: deleting a credential that is still referenced is a conflict, not
//! a server error. It used to come back as `EncryptionError` ("Encryption
//! error: Cannot delete credential …", HTTP 500) for a source configuration,
//! and as a raw foreign-key `DatabaseError` (also 500) for a custom
//! enrichment, which the delete predicate did not check at all.
//!
//! The source-configuration and unreferenced cases run on the open schema
//! (no `custom_enrichments` table: the delete must not name it there); the
//! custom-enrichment case needs the enterprise overlay and skips without it.
//!
//! `#[ignore]`d DB suite — run with a disposable Postgres:
//! `DATABASE_URL=… NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 cargo test -p nanosiem-core
//!  --test credential_delete_in_use_integration -- --ignored`.

mod common;

use nanosiem_core::parsers::{CreateCloudCredential, CredentialRepository, CredentialRepositoryError};
use uuid::Uuid;

fn credential(name: &str) -> CreateCloudCredential {
    CreateCloudCredential {
        name: name.to_string(),
        provider: "aws_s3".to_string(),
        credentials: serde_json::json!({ "access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret" }),
        external_id: None,
        description: None,
        region: Some("us-east-1".to_string()),
        environment: None,
        expires_at: None,
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn unreferenced_credential_is_deleted() {
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());
    let cred = repo.create(&credential(&unique("nan4902-free")), None).await.unwrap();
    repo.delete(cred.id).await.expect("an unreferenced credential deletes");
    assert!(!repo.exists(cred.id).await.unwrap());
    assert!(matches!(repo.delete(cred.id).await, Err(CredentialRepositoryError::NotFound(_))));
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn credential_used_by_a_source_configuration_is_in_use_not_an_encryption_error() {
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());
    let cred = repo.create(&credential(&unique("nan4902-sc")), None).await.unwrap();
    let config_name = unique("okta-prod");
    sqlx::query(
        "INSERT INTO source_configurations (name, config_type, credential_id) VALUES ($1, 'aws_s3', $2)",
    )
    .bind(&config_name)
    .bind(cred.id)
    .execute(&pool)
    .await
    .unwrap();

    match repo.delete(cred.id).await {
        Err(err @ CredentialRepositoryError::InUse { .. }) => {
            let message = err.to_string();
            assert!(message.contains(&format!("source configuration \"{config_name}\"")), "{message}");
        }
        other => panic!("expected InUse, got {other:?}"),
    }
    assert!(repo.exists(cred.id).await.unwrap(), "an in-use credential must survive");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn credential_used_by_a_custom_enrichment_is_in_use_not_a_database_error() {
    let pool = common::migrated_pool().await;
    // `custom_enrichments` is enterprise-overlay schema; on an open-core
    // database the delete must work without it (the other tests cover that).
    let has_table: bool = sqlx::query_scalar("SELECT to_regclass('public.custom_enrichments') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    if !has_table {
        eprintln!("Skipping: custom_enrichments (enterprise overlay) not present");
        return;
    }
    let repo = CredentialRepository::new(pool.clone());
    let cred = repo.create(&credential(&unique("nan4902-ce")), None).await.unwrap();
    let user: Uuid = sqlx::query_scalar("SELECT id FROM users ORDER BY created_at LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a seeded user");
    let namespace: Uuid = sqlx::query_scalar("SELECT id FROM namespaces ORDER BY created_at LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("a seeded namespace");
    let enrichment_name = unique("vt-lookup");
    sqlx::query(
        "INSERT INTO custom_enrichments (namespace_id, name, enrichment_type, code, created_by, credential_id) \
         VALUES ($1, $2, 'data', 'export default () => ({})', $3, $4)",
    )
    .bind(namespace)
    .bind(&enrichment_name)
    .bind(user)
    .bind(cred.id)
    .execute(&pool)
    .await
    .unwrap();

    match repo.delete(cred.id).await {
        Err(err @ CredentialRepositoryError::InUse { .. }) => {
            let message = err.to_string();
            assert!(message.contains(&format!("custom enrichment \"{enrichment_name}\"")), "{message}");
        }
        other => panic!("expected InUse, got {other:?}"),
    }
    assert!(repo.exists(cred.id).await.unwrap(), "an in-use credential must survive");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn credential_used_by_a_pull_feed_is_in_use() {
    // NAN-4914 `connector_feeds.credential_id` is `ON DELETE RESTRICT` on the
    // open schema: the delete predicate and the 409 message both name it.
    let pool = common::migrated_pool().await;
    let repo = CredentialRepository::new(pool.clone());
    let cred = repo.create(&credential(&unique("nan4914-feed")), None).await.unwrap();
    let feed_name = unique("okta-pull");
    sqlx::query(
        "INSERT INTO connector_feeds (name, connector, spec_yaml, spec_sha256, source_type, credential_id) \
         VALUES ($1, 'okta', 'name: okta', repeat('a', 64), 'okta', $2)",
    )
    .bind(&feed_name)
    .bind(cred.id)
    .execute(&pool)
    .await
    .unwrap();

    match repo.delete(cred.id).await {
        Err(err @ CredentialRepositoryError::InUse { .. }) => {
            let message = err.to_string();
            assert!(message.contains(&format!("pull feed \"{feed_name}\"")), "{message}");
        }
        other => panic!("expected InUse, got {other:?}"),
    }
    assert!(repo.exists(cred.id).await.unwrap(), "an in-use credential must survive");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn restrict_reference_outside_the_predicate_is_in_use_on_every_postgres_major() {
    // NAN-4980: a reference the delete predicate does not name is refused by
    // its foreign key, and the repository maps that to InUse (409). On a real
    // install that is `threat_intel_providers.credential_id` (enterprise,
    // ON DELETE RESTRICT). PostgreSQL 18 reports a RESTRICT violation as
    // SQLSTATE 23001 (restrict_violation), not 23503; the repository matched
    // only 23503, so on the shipped postgres:18 this surfaced as a raw
    // database error (HTTP 500). A dedicated RESTRICT table stands in for the
    // unnamed referrer so the case runs on the open schema too.
    let pool = common::migrated_pool().await;
    let table = format!("nan4980_restrict_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let constraint = format!("{table}_credential_fkey");
    sqlx::query(&format!(
        "CREATE TABLE {table} (credential_id UUID CONSTRAINT {constraint} \
         REFERENCES cloud_credentials(id) ON DELETE RESTRICT)"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let repo = CredentialRepository::new(pool.clone());
    let cred = repo.create(&credential(&unique("nan4980-restrict")), None).await.unwrap();
    sqlx::query(&format!("INSERT INTO {table} (credential_id) VALUES ($1)"))
        .bind(cred.id)
        .execute(&pool)
        .await
        .unwrap();

    let outcome = repo.delete(cred.id).await;
    let survived = repo.exists(cred.id).await.unwrap();
    sqlx::query(&format!("DROP TABLE {table}")).execute(&pool).await.unwrap();
    match outcome {
        Err(err @ CredentialRepositoryError::InUse { .. }) => {
            let message = err.to_string();
            assert!(message.contains(&constraint), "{message}");
        }
        other => panic!("expected InUse, got {other:?}"),
    }
    assert!(survived, "an in-use credential must survive");
}
