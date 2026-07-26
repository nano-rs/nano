// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL regression coverage for NAN-2151.
//!
//! Publishing a custom enrichment must never duplicate its runtime credential
//! into `marketplace_catalog.config`. The source row still owns that credential;
//! an installer supplies credentials for its own identity.

mod common;

use nanosiem_core::marketplace::MarketplaceRepository;
use serde_json::{Value, json};
use uuid::Uuid;

const PUBLISHER_TOKEN: &str = "MARKER-publisher-bearer-token";
const ROTATED_SECRET: &str = "MARKER-publisher-client-secret";

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn publishing_strips_secrets_without_mutating_the_source_config() {
    let pool = common::migrated_pool().await;
    let namespace_id: Uuid = sqlx::query_scalar("SELECT id FROM namespaces LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("seeded namespace");
    let suffix = Uuid::now_v7().simple().to_string();
    let name = format!("NAN2151{}", &suffix[..12]);
    let user_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users (id, email, name, password_hash, status)
        VALUES ($1, $2, 'NAN-2151 Test', 'x', 'active')
        "#,
    )
    .bind(user_id)
    .bind(format!("nan2151-{suffix}@example.test"))
    .execute(&pool)
    .await
    .expect("create test user");

    let original = json!({
        "auth_config": {
            "auth_type": "bearer",
            "token": PUBLISHER_TOKEN,
            "client_id": "public-client"
        },
        "endpoint": "https://intel.example.test"
    });
    let enrichment_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO custom_enrichments (
            namespace_id, name, enrichment_type, code, config, created_by
        ) VALUES ($1, $2, 'agent', 'export default () => null', $3, $4)
        RETURNING id
        "#,
    )
    .bind(namespace_id)
    .bind(&name)
    .bind(&original)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("create source enrichment");

    let repo = MarketplaceRepository::new(pool.clone());
    let entry = repo
        .create_catalog_for_custom_enrichment(
            enrichment_id,
            &name,
            None,
            "agent",
            Some("export default () => null"),
            &["intel.example.test".to_string()],
            &original,
            None,
        )
        .await
        .expect("publish catalog entry");

    let stored: Value = sqlx::query_scalar("SELECT config FROM marketplace_catalog WHERE id = $1")
        .bind(entry.id)
        .fetch_one(&pool)
        .await
        .expect("read stored catalog config");

    let source_config: Value =
        sqlx::query_scalar("SELECT config FROM custom_enrichments WHERE id = $1")
            .bind(enrichment_id)
            .fetch_one(&pool)
            .await
            .expect("read source enrichment config");
    assert_eq!(
        source_config["auth_config"]["token"], PUBLISHER_TOKEN,
        "publishing mutated the source enrichment's runtime credential"
    );
    assert!(
        stored["auth_config"].get("token").is_none(),
        "publisher token was duplicated into marketplace_catalog: {stored}"
    );
    assert_eq!(stored["auth_config"]["auth_type"], "bearer");
    assert_eq!(stored["auth_config"]["client_id"], "public-client");
    assert_eq!(stored["endpoint"], "https://intel.example.test");

    // Exercise the ON CONFLICT update path as well: republishing must not
    // reintroduce a different secret.
    let updated = json!({
        "auth_config": {
            "auth_type": "oauth2",
            "client_id": "updated-public-client",
            "client_secret": ROTATED_SECRET,
            "token_url": "https://auth.example.test/token"
        }
    });
    repo.create_catalog_for_custom_enrichment(
        enrichment_id,
        &name,
        None,
        "agent",
        Some("export default () => null"),
        &["intel.example.test".to_string()],
        &updated,
        None,
    )
    .await
    .expect("republish catalog entry");

    let republished: Value =
        sqlx::query_scalar("SELECT config FROM marketplace_catalog WHERE id = $1")
            .bind(entry.id)
            .fetch_one(&pool)
            .await
            .expect("read republished catalog config");
    assert!(
        republished["auth_config"].get("client_secret").is_none(),
        "republish duplicated a rotated publisher secret: {republished}"
    );
    assert_eq!(republished["auth_config"]["auth_type"], "oauth2");
    assert_eq!(
        republished["auth_config"]["client_id"],
        "updated-public-client"
    );
    assert_eq!(
        republished["auth_config"]["token_url"],
        "https://auth.example.test/token"
    );

    repo.delete_catalog_by_custom_enrichment_id(enrichment_id)
        .await
        .expect("delete test catalog entry");
    sqlx::query("DELETE FROM custom_enrichments WHERE id = $1")
        .bind(enrichment_id)
        .execute(&pool)
        .await
        .expect("delete test enrichment");
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("delete test user");
}
