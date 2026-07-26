// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live-Postgres regression for NAN-2125.
//!
//! Run with:
//! `NANOSIEM_ALLOW_DEFAULT_KEYS=true cargo test -p nanosiem-core \
//!   --test source_config_credential_authorization_integration -- --ignored`

mod common;

use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::source_configs::{
    NewSourceConfiguration, SourceConfigRepository, SourceConfigRepositoryError,
    SourceConfigService, SourceConfigServiceError, UpdateSourceConfiguration,
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn credential_bearing_mutations_and_deployments_fail_closed() {
    let pool = common::migrated_pool().await;

    let permission_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM permissions WHERE id = 'credentials:use')")
            .fetch_one(&pool)
            .await
            .expect("query credentials:use permission");
    assert!(permission_exists);

    for (role_id, expected) in [
        (
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            true,
        ),
        (
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            true,
        ),
        (
            Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            false,
        ),
    ] {
        let granted: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM role_permissions
                WHERE role_id = $1 AND permission_id = 'credentials:use'
            )",
        )
        .bind(role_id)
        .fetch_one(&pool)
        .await
        .expect("query built-in role grant");
        assert_eq!(granted, expected, "unexpected grant for role {role_id}");
    }

    let credential_id = Uuid::now_v7();
    let config_id = Uuid::now_v7();
    let race_config_id = Uuid::now_v7();
    let suffix = Uuid::now_v7();
    let credential_name = format!("nan2125-credential-{suffix}");
    let config_name = format!("nan2125-source-{suffix}");

    sqlx::query(
        "INSERT INTO cloud_credentials
            (id, name, provider, credentials_encrypted, nonce)
         VALUES ($1, $2, 'aws_s3', $3, 'intentionally-invalid')",
    )
    .bind(credential_id)
    .bind(&credential_name)
    .bind(vec![0_u8])
    .execute(&pool)
    .await
    .expect("insert undecryptable credential fixture");

    sqlx::query(
        "INSERT INTO source_configurations
            (id, name, description, config_type, connection_config,
             credential_id, enabled, deployed)
         VALUES ($1, $2, 'original', 'aws_s3', '{}'::jsonb, $3, TRUE, FALSE)",
    )
    .bind(config_id)
    .bind(&config_name)
    .bind(credential_id)
    .execute(&pool)
    .await
    .expect("insert credential-bearing source config");

    sqlx::query(
        "INSERT INTO source_configurations
            (id, name, description, config_type, connection_config,
             enabled, deployed)
         VALUES ($1, $2, 'race-original', 'aws_s3', '{}'::jsonb, FALSE, FALSE)",
    )
    .bind(race_config_id)
    .bind(format!("nan2125-race-{suffix}"))
    .execute(&pool)
    .await
    .expect("insert credentialless race fixture");

    // Simulate the service authorizing a credentialless snapshot followed by
    // another request attaching a credential before the update reaches SQL.
    sqlx::query(
        "UPDATE source_configurations SET credential_id = $2 WHERE id = $1",
    )
    .bind(race_config_id)
    .bind(credential_id)
    .execute(&pool)
    .await
    .expect("attach credential between authorization and write");
    let race_error = SourceConfigRepository::new(pool.clone())
        .update_with_credential_guard(
            race_config_id,
            UpdateSourceConfiguration {
                description: Some("race-should-not-commit".to_string()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("credential compare-and-set must reject the stale snapshot");
    assert!(matches!(
        race_error,
        SourceConfigRepositoryError::CredentialChanged(id) if id == race_config_id
    ));
    let race_description: Option<String> =
        sqlx::query_scalar("SELECT description FROM source_configurations WHERE id = $1")
            .bind(race_config_id)
            .fetch_one(&pool)
            .await
            .expect("query race fixture");
    assert_eq!(race_description.as_deref(), Some("race-original"));

    let service = SourceConfigService::new(pool.clone());
    let denied = CredentialUseGrant::none();

    let create_error = service
        .create(
            NewSourceConfiguration {
                name: format!("nan2125-create-{suffix}"),
                description: None,
                config_type: "aws_s3".to_string(),
                connection_config: serde_json::json!({}),
                credential_id: Some(Uuid::now_v7()),
                default_source_type: None,
                routing_rules: None,
            },
            denied,
        )
        .await
        .expect_err("create must deny before probing the credential ID");
    assert!(matches!(
        create_error,
        SourceConfigServiceError::CredentialUseRequired
    ));

    let update_error = service
        .update(
            config_id,
            UpdateSourceConfiguration {
                description: Some("should-not-commit".to_string()),
                ..Default::default()
            },
            denied,
        )
        .await
        .expect_err("saved credential must protect otherwise credentialless updates");
    assert!(matches!(
        update_error,
        SourceConfigServiceError::CredentialUseRequired
    ));

    let description: Option<String> =
        sqlx::query_scalar("SELECT description FROM source_configurations WHERE id = $1")
            .bind(config_id)
            .fetch_one(&pool)
            .await
            .expect("query unchanged description");
    assert_eq!(description.as_deref(), Some("original"));

    let deploy_error = service
        .deploy(config_id, denied)
        .await
        .expect_err("deploy must deny before decrypting the invalid fixture");
    assert!(matches!(
        deploy_error,
        SourceConfigServiceError::CredentialUseRequired
    ));

    let deploy_all_error = service
        .deploy_all(denied)
        .await
        .expect_err("deploy-all must preflight credential-bearing configs");
    assert!(matches!(
        deploy_all_error,
        SourceConfigServiceError::CredentialUseRequired
    ));

    let deployment_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM source_configuration_deployments
         WHERE source_configuration_id = $1",
    )
    .bind(config_id)
    .fetch_one(&pool)
    .await
    .expect("query deployment side effects");
    assert_eq!(deployment_count, 0);

    let deployed: bool =
        sqlx::query_scalar("SELECT deployed FROM source_configurations WHERE id = $1")
            .bind(config_id)
            .fetch_one(&pool)
            .await
            .expect("query deployment state");
    assert!(!deployed);

    sqlx::query("DELETE FROM source_configurations WHERE id IN ($1, $2)")
        .bind(config_id)
        .bind(race_config_id)
        .execute(&pool)
        .await
        .expect("clean source fixture");
    sqlx::query("DELETE FROM cloud_credentials WHERE id = $1")
        .bind(credential_id)
        .execute(&pool)
        .await
        .expect("clean credential fixture");
}
