// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4935 review: rollback validates the restored GCP payload. DB-backed;
//! needs a disposable PostgreSQL at `NANOSIEM_TEST_DATABASE_URL` and skips
//! without one. Each test builds the three tables it touches in a throwaway
//! schema.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::{CredentialRepository, CredentialRepositoryError};
use crate::crypto::EncryptionService;
use crate::parsers::{CreateCloudCredential, RollbackCloudCredential, RotateCloudCredential};

async fn repo() -> Option<(CredentialRepository, PgPool, String)> {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
    let schema = format!("nan4935_{}", Uuid::new_v4().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect({
            let schema = schema.clone();
            move |conn, _| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str())
                        .await
                        .map(|_| ())
                })
            }
        })
        .connect(&url)
        .await
        .expect("connect");
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {schema};
         CREATE TABLE {schema}.cloud_credentials (
             id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL UNIQUE,
             provider TEXT NOT NULL, credentials_encrypted BYTEA NOT NULL, nonce TEXT NOT NULL,
             description TEXT, region TEXT, external_id TEXT, environment TEXT,
             expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ, active_version INT NOT NULL,
             created_by UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
             updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
         CREATE TABLE {schema}.cloud_credential_versions (
             id UUID PRIMARY KEY DEFAULT gen_random_uuid(), credential_id UUID NOT NULL,
             version_number INT NOT NULL, credentials_encrypted BYTEA NOT NULL, nonce TEXT NOT NULL,
             created_by UUID, note TEXT, is_active BOOLEAN NOT NULL DEFAULT false,
             reverted_from_version INT, external_id TEXT,
             created_at TIMESTAMPTZ NOT NULL DEFAULT now());
         CREATE TABLE {schema}.vector_config_publication_state (singleton BOOLEAN PRIMARY KEY);
         INSERT INTO {schema}.vector_config_publication_state VALUES (TRUE);"
    ))
    .execute(&pool)
    .await
    .expect("schema");
    let crypto = EncryptionService::new(&[7u8; 32]);
    Some((CredentialRepository::with_crypto(pool.clone(), crypto), pool, schema))
}

fn adc() -> serde_json::Value {
    serde_json::json!({
        "credentials_json": serde_json::json!({
            "type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r",
        }).to_string()
    })
}

/// Write a version row directly, as an older release (which only checked
/// that `credentials_json` was present) could have stored it.
async fn insert_legacy_version(
    repo: &CredentialRepository,
    pool: &PgPool,
    id: Uuid,
    version: i32,
    payload: &serde_json::Value,
) {
    let (ciphertext, nonce) = repo.encrypt_payload(payload).unwrap();
    sqlx::query(
        "INSERT INTO cloud_credential_versions \
         (credential_id, version_number, credentials_encrypted, nonce, note, is_active) \
         VALUES ($1, $2, $3, $4, 'legacy', false)",
    )
    .bind(id)
    .bind(version)
    .bind(ciphertext)
    .bind(nonce)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn rollback_to_a_legacy_invalid_gcp_version_is_refused() {
    let Some((repo, pool, schema)) = repo().await else {
        eprintln!("skipped: NANOSIEM_TEST_DATABASE_URL not set");
        return;
    };
    let cred = repo
        .create(
            &CreateCloudCredential {
                name: "pubsub".into(),
                provider: "gcp_pubsub".into(),
                external_id: None,
                credentials: adc(),
                description: None,
                region: None,
                environment: None,
                expires_at: None,
            },
            None,
        )
        .await
        .expect("valid ADC creates");
    insert_legacy_version(&repo, &pool, cred.id, 2, &serde_json::json!({"credentials_json": null}))
        .await;
    insert_legacy_version(&repo, &pool, cred.id, 3, &serde_json::json!({"credentials_json": {"type": "authorized_user"}}))
        .await;

    for version in [2, 3] {
        let err = repo
            .rollback(cred.id, &RollbackCloudCredential { version, note: None }, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialRepositoryError::InvalidCredentials(_)), "v{version}: {err:?}");
    }

    // Nothing moved: still v1 active, no new version rows, payload intact.
    let row = sqlx::query("SELECT active_version FROM cloud_credentials WHERE id = $1")
        .bind(cred.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>("active_version"), 1);
    let versions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cloud_credential_versions WHERE credential_id = $1")
        .bind(cred.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(versions, 3);
    assert_eq!(repo.get_decrypted(cred.id).await.unwrap(), adc());

    // Rotating to a bad payload is refused the same way; a valid rollback works.
    let err = repo
        .rotate(
            cred.id,
            &RotateCloudCredential { credentials: serde_json::json!({"credentials_json": null}), external_id: None, note: None },
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CredentialRepositoryError::InvalidCredentials(_)));
    let (_, v) = repo
        .rollback(cred.id, &RollbackCloudCredential { version: 1, note: None }, None)
        .await
        .expect("valid version restores");
    assert_eq!(v.reverted_from_version, Some(1));

    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&pool).await.unwrap();
}
